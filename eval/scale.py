"""Load and scalability (evaluation): what Bulkhead costs the machine, and
how the cost grows with load, projects, policies and logs.

  throughput  requests through one project's PEP as concurrent clients
              grow, with a new connection per request and with keep-alive,
              against the same clients reaching the services directly; the
              CPU time the core spends per request
  projects    N active projects: partition start, memory per partition,
              the core's memory, idle CPU, and throughput when every
              project sends requests at once
  policy      compile time (with the P3 check) and decision time as the
              policy grows, with and without the PDP's decision cache
  log         appends per second, bytes per record, and the auditor's time
              (C1-C5) as the log grows
  session     switching projects, and installing a new policy version
  sandbox     file-system, process and CPU work inside a partition and
              outside
  replay      the tool calls of the model-driven utility trials (M6b),
              replayed without the model, each through the configuration
              it was recorded in (the baseline, Bulkhead)

The services run in a process of their own and every client in its own
process, so the CPU time of this process is the core's (its PEPs, PDP and
log). Run on an otherwise idle machine; the results say which one.

usage: python -m eval.scale --workdir DIR --out FILE [experiment ...]
       python -m eval.scale --workdir DIR --out FILE --report
"""
import argparse
import collections
import copy
import datetime
import glob
import gzip
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time

import psutil
import yaml

from bulkhead.agent import native
from bulkhead.agent.scripted import Oracle
from bulkhead.core import audit as auditor
from bulkhead.core.log import DecisionLog, Signer, verify
from bulkhead.core.pdp import PDP, PolicyStore
from bulkhead.core.vault import Vault
from bulkhead.decisions import Decision
from bulkhead.env import proxy_env, trust_env
from bulkhead.pep import landlock, sandbox
from bulkhead.pep.ca import CertificateAuthority
from bulkhead.pep.http_proxy import HttpPep, PepRunner
from bulkhead.policy.compiler import compile_manifest
from bulkhead.policy.ontology import Ontology
from bulkhead.policy.schema import parse_manifest
from eval import run_eval
from testbed import setup as tb

HERE = os.path.dirname(os.path.abspath(__file__))
PROTOTYPE = os.path.dirname(HERE)
TESTBED = os.path.join(PROTOTYPE, "testbed")
HOST, PATH = "git.test", "/api/repos/oss/libfoo/issues"
ME = psutil.Process()


# -- helpers ------------------------------------------------------------------------------
def pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))], 3) if xs else None


def cpu(proc):
    t = proc.cpu_times()
    return t.user + t.system


def pss(pid):
    """Proportional set size of a process and its descendants (bytes)."""
    try:
        procs = [psutil.Process(pid)]
        procs += procs[0].children(recursive=True)
    except psutil.Error:
        return 0
    total = 0
    for p in procs:
        try:
            total += p.memory_full_info().pss
        except psutil.Error:
            pass
    return total


def uss():
    return ME.memory_full_info().uss


def onto():
    return Ontology.load(os.path.join(TESTBED, "ontology.yaml"))


def base_manifest(project="oss"):
    with open(os.path.join(TESTBED, "manifests", f"{project}.yaml")) as f:
        return yaml.safe_load(f)


class Services:
    """The testbed's services in a process of their own."""

    def __init__(self, srv):
        code = (f"import sys\nsys.path.insert(0, {PROTOTYPE!r})\n"
                "from testbed.services import Testbed\n"
                f"Testbed({srv!r}).serve()\nprint('ready', flush=True)\nsys.stdin.read()\n")
        self.proc = subprocess.Popen([sys.executable, "-c", code], cwd=PROTOTYPE,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        if self.proc.stdout.readline().strip() != "ready":
            raise RuntimeError("the services did not start")
        self.ps = psutil.Process(self.proc.pid)

    def cpu(self):
        return cpu(self.ps)

    def stop(self):
        self.proc.stdin.close()
        self.proc.wait(10)


class Core:
    """Bulkhead's core for projects that each have OSS's manifest (its own
    name, policy, vault entry, PEP, and partition)."""

    def __init__(self, ws, names, root, cache_size=8192):
        self.ws, self.root = ws, root
        self.onto = onto()
        self.store = PolicyStore(os.path.join(root, "policies"))
        base = base_manifest()
        for n in names:
            d = copy.deepcopy(base)
            d["project"] = n
            self.store.install(compile_manifest(parse_manifest(d), self.onto))
        self.ca = CertificateAuthority(os.path.join(root, "ca"))
        self.log = DecisionLog(os.path.join(root, "log.jsonl"),
                               Signer.load_or_create(os.path.join(root, "log.key")),
                               checkpoint_every=50)
        self.vault = Vault()
        for n in names:
            for site, c in tb.vault_data(ws.srv, ["oss"])["oss"].items():
                self.vault.add(n, site, Vault({n: {site: c}}).get(n, site))
        self.pdp = PDP(self.store, oracle=Oracle("deny"), cache_size=cache_size)
        self.runner = PepRunner()
        self.peps = {n: HttpPep(n, self.pdp, self.onto, self.vault, self.log, self.ca,
                                upstream_cafile=ws.ca_bundle()) for n in names}
        self.parts = {}

    def start(self, name, home):
        """Start `name`'s partition on `home`; returns it and its start time (ms)."""
        ca = os.path.join(home, ".config", "bulkhead", "ca.pem")
        os.makedirs(os.path.dirname(ca), exist_ok=True)
        shutil.copyfile(self.ca.cert_path, ca)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
               **proxy_env(f"http://127.0.0.1:{dict(sandbox.EGRESS)['tools']}"),
               **trust_env(ca)}
        hide, readonly, _ = sandbox.policy_layout(self.store.current(name), home)
        t = time.perf_counter()
        part = sandbox.Partition(name, home, env, hide=hide, readonly=readonly).start()
        ms = (time.perf_counter() - t) * 1000
        self.parts[name] = (part, self.runner.add_sock(self.peps[name], part.listeners["tools"]))
        return part, ms

    def close(self):
        for name, (part, srv) in list(self.parts.items()):
            self.runner.remove(self.peps[name], srv)
            part.stop()
        self.parts = {}
        self.runner.stop()
        self.log.close()


def fresh_home(ws, dst):
    return tb.restore(os.path.join(ws.snap, "partitions", "oss", "home"), dst)


# -- clients ------------------------------------------------------------------------------
CLIENT = r'''
import http.client, json, os, ssl, sys, time
mode, seconds, host, path, out = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")

def connect():
    if proxy:
        h, p = proxy.split("://", 1)[1].rstrip("/").rsplit(":", 1)
        c = http.client.HTTPSConnection(h, int(p), context=ctx, timeout=60)
        c.set_tunnel(host, 443)
        return c
    return http.client.HTTPSConnection(host, 443, context=ctx, timeout=60)

lat, errors, conn = [], 0, None
end = time.monotonic() + seconds
while time.monotonic() < end:
    t = time.perf_counter()
    try:
        if conn is None or mode == "new":
            if conn is not None:
                conn.close()
            conn = connect()
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        if r.status != 200:
            raise RuntimeError(r.status)
        lat.append((time.perf_counter() - t) * 1000)
    except Exception:
        errors += 1
        conn = None
with open(out, "w") as f:
    json.dump({"n": len(lat), "errors": errors, "lat": lat}, f)
'''


def write_client(home):
    path = os.path.join(home, "client.py")
    with open(path, "w") as f:
        f.write(CLIENT)
    return path


def fanout(client, mode, seconds, clients, outdir):
    os.makedirs(outdir, exist_ok=True)
    for f in glob.glob(os.path.join(outdir, "c*.json")):
        os.remove(f)
    return ["bash", "-c", f'for i in $(seq {clients}); do python3 {client} {mode} {seconds} '
                          f'{HOST} {PATH} {outdir}/c$i.json & done; wait']


def collect(outdir):
    res = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(outdir, "c*.json")))]
    return res, [x for r in res for x in r["lat"]]


# -- experiments --------------------------------------------------------------------------
def exp_throughput(ws, services, seconds=5, clients=(1, 2, 4, 8, 16, 32)):
    core = Core(ws, ["p0"], os.path.join(ws.root, "core-throughput"))
    home = fresh_home(ws, os.path.join(ws.root, "homes", "throughput"))
    part, _ = core.start("p0", home)
    client = write_client(home)
    direct_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "SSL_CERT_FILE": ws.ca_bundle()}
    rows = []
    try:
        for mode in ("keep", "new"):
            for c in clients:
                for where in ("direct", "bulkhead"):
                    outdir = os.path.join(home, "out")
                    cmd = fanout(client, mode, seconds, c, outdir)
                    c0, s0, w0 = cpu(ME), services.cpu(), time.perf_counter()
                    if where == "direct":
                        subprocess.run(cmd, env=direct_env, capture_output=True,
                                       timeout=seconds + 120)
                    else:
                        part.run(cmd, timeout=seconds + 120)
                    wall = time.perf_counter() - w0
                    core_cpu, svc_cpu = cpu(ME) - c0, services.cpu() - s0
                    res, lat = collect(outdir)
                    n = sum(r["n"] for r in res)
                    rows.append({
                        "mode": mode, "clients": c, "where": where, "seconds": seconds,
                        "requests": n, "errors": sum(r["errors"] for r in res),
                        "rps": round(n / seconds, 1), "p50_ms": pct(lat, 0.5),
                        "p95_ms": pct(lat, 0.95), "p99_ms": pct(lat, 0.99),
                        "core_cpu_ms_per_req": round(core_cpu * 1000 / n, 3) if n else None,
                        "services_cpu_ms_per_req": round(svc_cpu * 1000 / n, 3) if n else None,
                        "core_cpu_util": round(core_cpu / wall, 3)})
                    print(json.dumps(rows[-1]), flush=True)
    finally:
        core.close()
    return rows


def exp_projects(ws, services, counts=(1, 2, 4, 8, 16, 32), seconds=5):
    rows = []
    for n in counts:
        names = [f"p{i}" for i in range(n)]
        root = os.path.join(ws.root, f"core-projects-{n}")
        base = uss()
        core = Core(ws, names, root)
        homes = {nm: fresh_home(ws, os.path.join(root, "homes", nm)) for nm in names}
        try:
            starts = [core.start(nm, homes[nm])[1] for nm in names]
            time.sleep(1.0)
            core_mem = uss() - base
            mem = [pss(core.parts[nm][0].proc.pid) for nm in names]
            c0 = cpu(ME)
            time.sleep(3.0)
            idle = (cpu(ME) - c0) / 3.0
            clients = {nm: write_client(homes[nm]) for nm in names}
            results = {}

            def go(nm):
                out = os.path.join(homes[nm], "out")
                results[nm] = core.parts[nm][0].run(
                    fanout(clients[nm], "keep", seconds, 1, out), timeout=seconds + 120)
            threads = [threading.Thread(target=go, args=(nm,)) for nm in names]
            c0, s0, w0 = cpu(ME), services.cpu(), time.perf_counter()
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            wall = time.perf_counter() - w0
            core_cpu = cpu(ME) - c0
            per, lat = [], []
            for nm in names:
                res, la = collect(os.path.join(homes[nm], "out"))
                per.append(sum(r["n"] for r in res) / seconds)
                lat += la
            total = sum(per) * seconds
            rows.append({
                "projects": n, "start_ms_median": pct(starts, 0.5),
                "start_ms_max": round(max(starts), 2),
                "partition_pss_mb_median": round(pct(mem, 0.5) / 2**20, 2),
                "partitions_pss_mb_total": round(sum(mem) / 2**20, 1),
                "core_uss_mb_added": round(core_mem / 2**20, 2),
                "core_idle_cpu": round(idle, 4),
                "rps_total": round(sum(per), 1), "rps_per_project_min": round(min(per), 1),
                "rps_per_project_max": round(max(per), 1),
                "p50_ms": pct(lat, 0.5), "p95_ms": pct(lat, 0.95),
                "core_cpu_ms_per_req": round(core_cpu * 1000 / total, 3) if total else None,
                "core_cpu_util": round(core_cpu / wall, 3)})
            print(json.dumps(rows[-1]), flush=True)
        finally:
            core.close()
            shutil.rmtree(root, ignore_errors=True)
    return rows


def synthetic_manifest(n):
    """n repositories, each read allow and push ask; a tool-server grant per
    repository, and a shell grant on the whole site, which the P3 check
    reports (shadowing for every push, unbacked for unlisted repositories)."""
    repos = [f"repo://git.test/org{i}/repo{i}" for i in range(n)]
    return {"project": "big", "background": False,
            "policy": {r: {"read": "allow", "push": "ask"} for r in repos},
            "grants": {"mcp": [{"server": "github", "resource": r,
                                "ops": {"read": "allow", "push": "ask"}} for r in repos],
                       "shell": [{"site": "https://git.test",
                                  "ops": {"read": "allow", "act": "allow"}}]}}


def exp_policy(sizes=(10, 30, 100, 300, 1000, 3000), samples=2000, limit=120.0):
    o, rows = onto(), []
    for n in sizes:
        m = parse_manifest(synthetic_manifest(n))
        t = time.perf_counter()
        compiled = compile_manifest(m, o)
        compile_s = time.perf_counter() - t
        store = PolicyStore()
        store.install(compiled)
        import random
        rng = random.Random(n)
        reqs = [(f"repo://git.test/org{rng.randrange(n)}/repo{rng.randrange(n)}"
                 if i % 2 else f"repo://git.test/org{rng.randrange(n)}/repo-x",
                 rng.choice(["read", "push"])) for i in range(samples)]
        times = {}
        for label, size in (("uncached", 0), ("cached", 8192)):
            pdp = PDP(store, cache_size=size)
            for r, op in reqs:                          # warm (fills the cache)
                pdp.decide("big", "shell", r, op)
            t = time.perf_counter()
            for r, op in reqs:
                pdp.decide("big", "shell", r, op)
            times[label] = (time.perf_counter() - t) / samples * 1e6
        rows.append({"rules": n, "entries": len(compiled.entries),
                     "channel_rules": len(compiled.rules), "check_items": len(compiled.check),
                     "compile_s": round(compile_s, 4),
                     "decide_us_uncached": round(times["uncached"], 2),
                     "decide_us_cached": round(times["cached"], 2)})
        print(json.dumps(rows[-1]), flush=True)
        if compile_s > limit:
            break
    return rows


def _iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def synthetic_log(state, n, projects=10, rate=10.0):
    """A deployment's state with n PEP records over `projects` projects (OSS's
    policy each), `rate` requests per second, and the services' records of
    every forwarded request."""
    o = onto()
    store = PolicyStore(os.path.join(state, "policies"))
    names = [f"q{i}" for i in range(projects)]
    for nm in names:
        d = base_manifest()
        d["project"] = nm
        store.install(compile_manifest(parse_manifest(d), o))
    resources = [("repo://git.test/oss/libfoo", ["read", "push", "comment"]),
                 ("repo://git.test/acme/payments", ["read", "push"]),
                 ("web://docs.python.org", ["read", "act"]),
                 ("web://example.org", ["read"])]
    clock = {"t": 1.8e9}
    signer = Signer.load_or_create(os.path.join(state, "log.key"))
    log = DecisionLog(os.path.join(state, "log.jsonl"), signer, checkpoint_every=50,
                      clock=lambda: clock["t"])
    import random
    rng = random.Random(n)
    service = []
    t0 = time.perf_counter()
    for k in range(n):
        clock["t"] += 1.0 / rate
        nm = names[k % projects]
        res, ops = resources[rng.randrange(len(resources))]
        op = rng.choice(ops)
        d = store.current(nm).decide(res, op)[0]
        final = Decision.ALLOW if d == Decision.ALLOW else Decision.DENY
        log.append({"pep": "http", "project": nm, "task": f"t{k // 50}",
                    "channel": rng.choice(["tools", "browser"]),
                    "req": {"summary": f"GET {res}", "digest": "sha256:" + "0" * 64},
                    "resource": res, "op": op, "decision": str(d), "final": str(final),
                    "policy_version": 1, "mapped": True, "approval": None,
                    "outcome": "forwarded" if final == Decision.ALLOW else "blocked",
                    "status": 200 if final == Decision.ALLOW else None})
        if final == Decision.ALLOW:
            service.append({"status": 200, "service": "git", "method": "GET", "path": "/",
                            "resource": res, "op": op, "project": nm, "identity": f"{nm}-bot",
                            "ts": clock["t"] + 0.003})
    log.close()
    return service, time.perf_counter() - t0, signer


def exp_log(ws, sizes=(1000, 10000, 100000), append_n=20000):
    rows = []
    state = os.path.join(ws.root, "log-append")
    shutil.rmtree(state, ignore_errors=True)
    os.makedirs(state)
    for every in (50, 0):
        path = os.path.join(state, f"log-{every}.jsonl")
        log = DecisionLog(path, Signer.load_or_create(os.path.join(state, f"k{every}")),
                          checkpoint_every=every)
        rec = {"pep": "http", "project": "oss", "task": "t-1", "channel": "tools",
               "req": {"summary": "GET git.test/api/repos/oss/libfoo/issues",
                       "digest": "sha256:" + "0" * 64},
               "resource": "repo://git.test/oss/libfoo", "op": "read", "decision": "allow",
               "final": "allow", "policy_version": 1, "mapped": True, "approval": None,
               "rules": ["policy repo://git.test/oss/libfoo"], "outcome": "forwarded",
               "status": 200, "bytes": 512, "credential": "vault"}
        t = time.perf_counter()
        for _ in range(append_n):
            log.append(rec)
        dt = time.perf_counter() - t
        log.close()
        rows.append({"kind": "append", "checkpoint_every": every, "records": append_n,
                     "appends_per_s": round(append_n / dt), "us_per_append": round(dt / append_n
                                                                                 * 1e6, 1),
                     "bytes_per_record": round(os.path.getsize(path) / append_n, 1)})
        print(json.dumps(rows[-1]), flush=True)
    for n in sizes:
        state = os.path.join(ws.root, f"log-audit-{n}")
        shutil.rmtree(state, ignore_errors=True)
        os.makedirs(state)
        service, build_s, signer = synthetic_log(state, n)
        records = auditor.read_records(os.path.join(state, "log.jsonl"))
        times = {}
        t = time.perf_counter()
        c1 = verify(os.path.join(state, "log.jsonl"), signer.public_pem())
        times["C1"] = time.perf_counter() - t
        t = time.perf_counter()
        c2 = auditor.check_c2(records, service)
        times["C2"] = time.perf_counter() - t
        t = time.perf_counter()
        c3 = auditor.check_c3(records, auditor.load_policies(state))
        times["C3"] = time.perf_counter() - t
        t = time.perf_counter()
        c4 = auditor.check_c4(records)
        times["C4"] = time.perf_counter() - t
        t = time.perf_counter()
        c5 = auditor.check_c5(records, auditor.load_approvals(os.path.join(state, "x")))
        times["C5"] = time.perf_counter() - t
        problems = sum(map(len, (c1, c2, c3, c4, c5)))
        rows.append({"kind": "audit", "records": n, "service_records": len(service),
                     "log_mb": round(os.path.getsize(os.path.join(state, "log.jsonl")) / 2**20, 2),
                     "problems": problems,
                     **{f"{c}_s": round(v, 3) for c, v in times.items()},
                     "total_s": round(sum(times.values()), 3)})
        print(json.dumps(rows[-1]), flush=True)
        shutil.rmtree(state, ignore_errors=True)
    return rows


def exp_session(ws, services, reps=100):
    dep = run_eval.Deployment(ws)
    dep.begin_trial(Oracle("deny"), ["oss", "work"], "scale")
    root = os.path.join(ws.root, "session")
    homes = {p: tb.restore(os.path.join(ws.snap, "partitions", p, "home"),
                           os.path.join(root, p, "home")) for p in ("oss", "work")}
    sessions = dep.sessions(homes)
    rows = []
    try:
        for p in ("oss", "work"):
            sessions.partition(p)
        sessions.switch("oss")
        switch = []
        for i in range(reps):
            t = time.perf_counter()
            sessions.switch("work" if i % 2 == 0 else "oss")
            switch.append((time.perf_counter() - t) * 1000)
        compile_ms, install_ms = [], []
        for _ in range(20):
            t = time.perf_counter()
            compiled = dep.compile("work")
            compile_ms.append((time.perf_counter() - t) * 1000)
            t = time.perf_counter()
            sessions.install(compiled)
            install_ms.append((time.perf_counter() - t) * 1000)
        rows.append({"switch_ms_median": pct(switch, 0.5), "switch_ms_p95": pct(switch, 0.95),
                     "compile_ms_median": pct(compile_ms, 0.5),
                     "install_ms_median": pct(install_ms, 0.5), "reps": reps})
        print(json.dumps(rows[-1]), flush=True)
    finally:
        sessions.stop_all()
        dep.close()
    return rows


SANDBOX_WORK = r'''
import json, os, subprocess, sys, time
kind, root = sys.argv[1], sys.argv[2]
t = time.perf_counter()
if kind == "files":
    n = 0
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            os.stat(p)
            with open(p, "rb") as fh:
                fh.read()
            n += 1
elif kind == "git":
    subprocess.run(["git", "-C", root, "status", "--porcelain"], check=True,
                   capture_output=True)
elif kind == "exec":
    for _ in range(200):
        subprocess.run(["/bin/true"], check=True)
elif kind == "cpu":
    sum(i * i for i in range(3_000_000))
print(json.dumps({"ms": (time.perf_counter() - t) * 1000}))
'''


def exp_sandbox(ws, reps=7, files=10000):
    core = Core(ws, ["p0"], os.path.join(ws.root, "core-sandbox"))
    home = fresh_home(ws, os.path.join(ws.root, "homes", "sandbox"))
    tree = os.path.join(home, "tree")
    for i in range(files):
        d = os.path.join(tree, f"d{i // 100:03d}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"f{i:05d}.txt"), "w") as f:
            f.write("x" * 1024)
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "init", "-q", tree], check=True, env=env)
    subprocess.run(["git", "-C", tree, "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", tree, "-c", "user.name=b", "-c", "user.email=b@x.test",
                    "commit", "-qm", "tree"], check=True, env=env)
    script = os.path.join(home, "work.py")
    with open(script, "w") as f:
        f.write(SANDBOX_WORK)
    part, _ = core.start("p0", home)
    rows = []
    try:
        for kind in ("files", "git", "exec", "cpu"):
            ins, outs = [], []
            for _ in range(reps):
                r = part.run(["python3", script, kind, tree], timeout=300)
                ins.append(json.loads(r["stdout"])["ms"])
                r = subprocess.run(["python3", script, kind, tree], env=env,
                                   capture_output=True, text=True, timeout=300)
                outs.append(json.loads(r.stdout)["ms"])
            rows.append({"workload": kind, "outside_ms": pct(outs, 0.5),
                         "inside_ms": pct(ins, 0.5),
                         "overhead_pct": round((pct(ins, 0.5) / pct(outs, 0.5) - 1) * 100, 1)})
            print(json.dumps(rows[-1]), flush=True)
    finally:
        core.close()
    return rows


def home_of(tdir, substrate, project):
    """Where a trial's HOME is (eval.run_eval.prepare_homes)."""
    if substrate == "shared":
        return os.path.join(tdir, "home")
    return os.path.join(tdir, "partitions", project, "home")


class ReplayClient:
    """Plays a recorded trial's tool calls back, one per turn, with no model."""
    model = "replay"

    def __init__(self, calls):
        self.calls, self.i, self.calls_made = calls, 0, 0
        self.usage = collections.Counter()

    def create(self, system, tools, messages):
        self.calls_made += 1
        if self.i < len(self.calls):
            name, args = self.calls[self.i]
            self.i += 1
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": f"r{self.i}", "name": name, "input": args}]}
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "done"}]}

    def cost(self, usage=None):
        return None


def exp_replay(workdir, results, reps=3, configs=("baseline", "bulkhead")):
    from eval import model_eval
    from eval.runtimes import CONFIGS
    from testbed.services import Testbed
    rows_in = [json.loads(line) for line in gzip.open(results, "rt")]
    probes = {p["name"]: p for p in (json.load(open(f)) for f in
                                     glob.glob(os.path.join(HERE, "model_probes", "*.json")))}
    step_ms = []
    real_run_step = native.run_step

    def timed(ctx, step):
        t = time.perf_counter()
        try:
            return real_run_step(ctx, step)
        finally:
            step_ms.append((time.perf_counter() - t) * 1000)
    native.run_step = timed
    out = []
    try:
        for config in configs:
            ws = run_eval.Workspace(os.path.join(workdir, f"replay-{config}")).prepare()
            testbed = Testbed(ws.srv).serve()
            Rt = CONFIGS[config]
            dep = run_eval.Deployment(ws) if Rt.deployment else None
            picked = [r for r in rows_in if r["config"] == config and r["kind"] == "utility"]
            try:
                for rep in range(1, reps + 1):
                    for row in picked:
                        probe = dict(probes[row["probe"]])
                        tdir = os.path.join(ws.trials, f"{config}-{row['probe']}-{row['cond']}-"
                                                       f"{rep:02d}")
                        blob = json.dumps([[s["call"], s["input"]] for s in row["steps"]])
                        m = re.search(r'(/[^\s"\']*?/trials/' + re.escape(
                            f"{row['config']}-{row['id']}") + ")", blob)
                        if m:                   # the recorded HOME, then the trial folder
                            old = m.group(1)
                            blob = blob.replace(
                                home_of(old, CONFIGS[row["config"]].substrate, row["project"]),
                                home_of(tdir, Rt.substrate, row["project"]))
                            blob = blob.replace(old, tdir)
                        calls = json.loads(blob)
                        probe["max_turns"] = len(calls) + 2
                        del step_ms[:]
                        rec = model_eval.run_trial(ws, testbed, probe, row["cond"], rep, config,
                                                   dep, ReplayClient(calls), "replay")
                        out.append({"config": config, "row": row["id"], "model": row["model"],
                                    "probe": row["probe"], "rep": rep, "calls": len(calls),
                                    "ok": sum(s["status"] == "ok" for s in rec["steps"]),
                                    "success": rec.get("success"),
                                    "trial_s": round(rec["t1"] - rec["t0"], 4),
                                    "tool_ms": round(sum(step_ms), 2),
                                    "first_call_ms": round(step_ms[0], 2) if step_ms else None,
                                    "m6b_trial_s": round(row["t1"] - row["t0"], 3)})
                        print(json.dumps(out[-1]), flush=True)
            finally:
                if dep:
                    dep.close()
                testbed.stop()
    finally:
        native.run_step = real_run_step
    return out


EXPERIMENTS = ("throughput", "projects", "policy", "log", "session", "sandbox", "replay")


def _table(rows, cols):
    out = ["| " + " | ".join(h for h, _ in cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(str(r.get(k, "")) if not callable(k) else str(k(r))
                              for _, k in cols) + " |" for r in rows]
    return "\n".join(out)


def report(d):
    """Markdown tables of a results file."""
    m = d.get("machine", {})
    lines = ["# Load and scalability", "",
             f"Machine: {m.get('cpus')} vCPUs ({m.get('cpu')}), {m.get('memory_gb')} GB, "
             f"kernel {m.get('kernel')}, Python {m.get('python')}, Landlock ABI "
             f"{m.get('landlock_abi')}.", ""]
    if "throughput" in d:
        lines += ["## Throughput through one project's PEP", "",
                  "Clients in their own processes, each sending GET requests for the "
                  "duration; `keep`: one connection per client, `new`: a new connection "
                  "(CONNECT and TLS) per request. Latencies in ms; core CPU in ms per "
                  "request.", "",
                  _table(d["throughput"], [("mode", "mode"), ("clients", "clients"),
                                           ("where", "where"), ("req/s", "rps"),
                                           ("p50", "p50_ms"), ("p95", "p95_ms"),
                                           ("p99", "p99_ms"),
                                           ("core CPU/req", "core_cpu_ms_per_req"),
                                           ("core CPU util.", "core_cpu_util")]), ""]
    if "projects" in d:
        lines += ["## Active projects", "",
                  "Every project's partition started; then every project sends requests "
                  "at once (one keep-alive client each).", "",
                  _table(d["projects"], [("projects", "projects"),
                                         ("start ms (median)", "start_ms_median"),
                                         ("PSS MB per partition", "partition_pss_mb_median"),
                                         ("PSS MB, all", "partitions_pss_mb_total"),
                                         ("core MB added", "core_uss_mb_added"),
                                         ("idle core CPU", "core_idle_cpu"),
                                         ("req/s, all", "rps_total"),
                                         ("req/s per project (min-max)", lambda r:
                                          f"{r['rps_per_project_min']}-"
                                          f"{r['rps_per_project_max']}"),
                                         ("p50 ms", "p50_ms"), ("p95 ms", "p95_ms")]), ""]
    if "policy" in d:
        lines += ["## Policy size", "",
                  _table(d["policy"], [("repositories", "rules"), ("entries", "entries"),
                                       ("check items", "check_items"),
                                       ("compile s", "compile_s"),
                                       ("decide us, uncached", "decide_us_uncached"),
                                       ("decide us, cached", "decide_us_cached")]), ""]
    if "log" in d:
        lines += ["## Log and audit", "",
                  _table([r for r in d["log"] if r["kind"] == "append"],
                         [("checkpoint every", "checkpoint_every"),
                          ("appends/s", "appends_per_s"), ("us/append", "us_per_append"),
                          ("bytes/record", "bytes_per_record")]), "",
                  _table([r for r in d["log"] if r["kind"] == "audit"],
                         [("records", "records"), ("service records", "service_records"),
                          ("log MB", "log_mb"), ("C1 s", "C1_s"), ("C2 s", "C2_s"),
                          ("C3 s", "C3_s"), ("C4 s", "C4_s"), ("C5 s", "C5_s"),
                          ("total s", "total_s"), ("problems", "problems")]), ""]
    if "session" in d:
        lines += ["## Session operations (ms)", "",
                  _table(d["session"], [("switch (median)", "switch_ms_median"),
                                        ("switch (p95)", "switch_ms_p95"),
                                        ("compile", "compile_ms_median"),
                                        ("install", "install_ms_median")]), ""]
    if "sandbox" in d:
        lines += ["## Work inside a partition (ms, median)", "",
                  _table(d["sandbox"], [("workload", "workload"), ("outside", "outside_ms"),
                                        ("inside", "inside_ms"), ("overhead %",
                                                                  "overhead_pct")]), ""]
    if "replay" in d:
        rows = []
        for cfg, probe in sorted({(r["config"], r["probe"]) for r in d["replay"]}):
            rs = [r for r in d["replay"] if r["config"] == cfg and r["probe"] == probe]
            rows.append({"config": cfg, "probe": probe, "trials": len(rs),
                         "calls": pct([r["calls"] for r in rs], 0.5),
                         "success": sum(bool(r["success"]) for r in rs),
                         "tool_ms": pct([r["tool_ms"] for r in rs], 0.5),
                         "first_ms": pct([r["first_call_ms"] for r in rs
                                          if r["first_call_ms"] is not None], 0.5),
                         "trial_ms": round(pct([r["trial_s"] for r in rs], 0.5) * 1000, 1),
                         "m6b_s": pct([r["m6b_trial_s"] for r in rs], 0.5)})
        lines += ["## Replay of the model-driven utility trials (medians per trial)", "",
                  "Each configuration replays the tool calls recorded in it, three times; "
                  "harness time includes starting and stopping partitions.", "",
                  _table(rows, [("configuration", "config"), ("task", "probe"),
                                ("trials", "trials"), ("calls", "calls"),
                                ("succeeded", "success"), ("tool time ms", "tool_ms"),
                                ("first call ms", "first_ms"),
                                ("harness time ms", "trial_ms"),
                                ("with the model (M6b) s", "m6b_s")]), ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--results", default=os.path.join(HERE, "results", "m6b",
                                                       "results.jsonl.gz"),
                    help="model-driven trials to replay")
    ap.add_argument("--seconds", type=float, default=5)
    ap.add_argument("--report", action="store_true", help="print tables of --out and stop")
    ap.add_argument("experiments", nargs="*", default=list(EXPERIMENTS))
    a = ap.parse_args(argv)
    if a.report:
        with open(a.out) as f:
            print(report(json.load(f)))
        return 0
    ws = run_eval.Workspace(os.path.join(a.workdir, "ws")).prepare()
    out = {}
    if os.path.exists(a.out):
        with open(a.out) as f:
            out = json.load(f)
    out["machine"] = {"cpus": psutil.cpu_count(), "cpu": _cpu_model() or platform.processor(),
                      "memory_gb": round(psutil.virtual_memory().total / 2**30, 1),
                      "kernel": platform.release(), "python": platform.python_version(),
                      "landlock_abi": landlock.abi_version()}
    services = None
    try:
        for e in a.experiments:
            t = time.perf_counter()
            if e in ("throughput", "projects", "session") and services is None:
                services = Services(ws.srv)
            if e == "throughput":
                out[e] = exp_throughput(ws, services, a.seconds)
            elif e == "projects":
                out[e] = exp_projects(ws, services, seconds=a.seconds)
            elif e == "policy":
                out[e] = exp_policy()
            elif e == "log":
                out[e] = exp_log(ws)
            elif e == "session":
                out[e] = exp_session(ws, services)
            elif e == "sandbox":
                out[e] = exp_sandbox(ws)
            elif e == "replay":
                if services:
                    services.stop()
                    services = None
                out[e] = exp_replay(a.workdir, a.results)
            else:
                raise SystemExit(f"unknown experiment {e}")
            print(f"== {e}: {time.perf_counter() - t:.1f} s", flush=True)
            with open(a.out, "w") as f:
                json.dump(out, f, indent=1)
    finally:
        if services:
            services.stop()
    return 0


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
