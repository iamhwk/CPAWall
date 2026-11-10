"""Overhead micro-benchmarks (design, R5): what Bulkhead adds per action.

  api        an HTTPS API request on a new connection: direct, and through
             the project's PEP (TLS termination, mapping, decision, vault,
             log)
  clone      git clone of a small repository: direct, and through the PEP
  partition  starting a partition; one command in it (fork and exec)
  mcp        one tool-server call: the tool server called directly, and
             through the gateway to the tool server in the partition

The direct and mediated variants of a measure run in alternation, so a
change in load during the run affects both alike; --scale multiplies
every sample size.

usage: python -m eval.bench --workdir DIR [--out FILE] [--scale K]
"""
import argparse
import base64
import json
import os
import shutil
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

from bulkhead.agent.scripted import Oracle
from bulkhead.agent.toolservers import GitHubServer
from bulkhead.env import trust_env
from bulkhead.pep.sandbox import Partition
from eval import run_eval
from testbed import setup as tb
from testbed.services import URLS, Testbed

API = "https://git.test/api/repos/acme/payments/issues"


def summary(out):
    out = sorted(out)
    n = len(out)
    return {"n": n, "median_ms": round(statistics.median(out), 2),
            "p95_ms": round(out[int(0.95 * (n - 1))], 2)}


def _once(fn):
    t = time.perf_counter()
    fn()
    return (time.perf_counter() - t) * 1000


def timed(fn, n, warm=5):
    for _ in range(warm):
        fn()
    return summary([_once(fn) for _ in range(n)])


def timed_pair(a, b, n, warm=5):
    """Time two alternatives in alternation (ABBA), so that a change in the
    machine's load during the run affects both alike."""
    for _ in range(warm):
        a(), b()
    ta, tb_ = [], []
    for i in range(n):
        order = ((a, ta), (b, tb_)) if i % 2 == 0 else ((b, tb_), (a, ta))
        for fn, out in order:
            out.append(_once(fn))
    return summary(ta), summary(tb_)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out")
    ap.add_argument("--scale", type=int, default=1, help="multiply every sample size")
    a = ap.parse_args(argv)
    k = a.scale
    ws = run_eval.Workspace(a.workdir).prepare()
    testbed = Testbed(ws.srv).serve()
    dep = run_eval.Deployment(ws)
    dep.begin_trial(Oracle("deny"), ["oss", "work"], "bench")
    creds = ws.creds()
    res = {}
    try:
        auth = "Basic " + base64.b64encode(
            f"work-bot:{creds['git']['work-bot']}".encode()).decode()

        def direct():
            ctx = ssl.create_default_context(cafile=ws.ca_bundle())
            o = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                            urllib.request.HTTPSHandler(context=ctx))
            o.open(urllib.request.Request(API, headers={"Authorization": auth}),
                   timeout=10).read()

        def via_pep():
            ctx = ssl.create_default_context(cafile=dep.ca.cert_path)
            proxy = f"http://127.0.0.1:{dep.ports['work']}"
            o = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}),
                                            urllib.request.HTTPSHandler(context=ctx))
            o.open(API, timeout=10).read()
        res["api_direct"], res["api_pep"] = timed_pair(direct, via_pep, 200 * k)

        tmp = tempfile.mkdtemp(dir=a.workdir)
        home = tb.make_partition_home(os.path.join(tmp, "h"), "work", ws.srv)
        tb.sign_in(home, "work", ws.srv)
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home,
                "GIT_TERMINAL_PROMPT": "0"}

        def clone(env):
            def go():
                d = os.path.join(home, "c")
                subprocess.run(["git", "clone", "-q", f"{URLS['git']}/acme/payments.git", d],
                               env=env, check=True, capture_output=True)
                shutil.rmtree(d)
            return go
        res["clone_direct"], res["clone_pep"] = timed_pair(
            clone(dict(base, GIT_SSL_CAINFO=ws.ca_bundle())),
            clone(dict(base, **dep.env("work"))), 20 * k, 2)

        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp"}
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        starts = []
        for _ in range(20 * k):
            t = time.perf_counter()
            part = Partition("x", empty, env).start()
            starts.append((time.perf_counter() - t) * 1000)
            part.stop()
        res["partition_start"] = summary(starts)
        part = Partition("x", empty, env).start()
        res["partition_command"] = timed(lambda: part.run(["true"]), 50 * k)
        part.stop()

        server = GitHubServer(URLS["git"], "work-bot", creds["git"]["work-bot"],
                              env=trust_env(ws.ca_bundle()))
        homes = {p: tb.restore(os.path.join(ws.snap, "partitions", p, "home"),
                               os.path.join(tmp, "p", p, "home")) for p in ("oss", "work")}
        sessions = dep.sessions(homes)
        try:
            args = {"owner": "acme", "repo": "payments"}
            res["mcp_direct"], res["mcp_gateway"] = timed_pair(
                lambda: server.call("list_issues", args),
                lambda: sessions.gateway.call("work", "github", "list_issues", args), 30 * k)
        finally:
            sessions.stop_all()
    finally:
        dep.close()
        testbed.stop()
    print(json.dumps(res, indent=1))
    if a.out:
        with open(a.out, "w") as f:
            json.dump(res, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
