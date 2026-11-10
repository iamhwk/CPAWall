"""Run probes against a configuration; record one JSON line per trial.

The configurations are in eval/runtimes.py: the shared-substrate
baseline, its PEP-only ablation, the two baselines of RQ5 (simple
isolation, a CapScope-style harness), Bulkhead, and Bulkhead's ablations.

Every trial starts from fresh substrates and services; conditions
alternate in ABBA order; setup actions put the probe's preconditions in
place (a misconfigured remote, a test file); steps can be harness actions
(switch the active project, change the policy) or left in the
background until the next switch. Leaks are judged from the services'
request log (which credential reached which resource, with what effect)
and from the canaries; attempts also from the PEP's log.

usage: python -m eval.run_eval --workdir DIR [--config C] [--reps N]
           [--out FILE] probe.json ...
"""
import argparse
import collections
import copy
import json
import os
import shutil
import subprocess
import sys
import time

import yaml

from bulkhead.agent.scripted import Oracle, run_step
from bulkhead.core.control import ControlServer, UiOracle
from bulkhead.core.log import DecisionLog, Signer
from bulkhead.core.pdp import PDP, Approvals, PolicyStore
from bulkhead.core.session import SessionManager
from bulkhead.core.vault import PLACEHOLDER, Vault
from bulkhead.env import proxy_env, trust_env
from bulkhead.pep import sandbox
from bulkhead.pep.ca import CertificateAuthority
from bulkhead.pep.http_proxy import HttpPep, PepRunner
from bulkhead.pep.mcp_gateway import McpGateway
from bulkhead.policy.compiler import compile_manifest
from bulkhead.policy.ontology import Ontology
from bulkhead.policy.schema import parse_manifest
from eval.runtimes import CONFIGS, connector_call
from testbed import setup as tb
from testbed.services import URLS, Testbed

TESTBED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testbed")
PROJECTS = tuple(tb.PROJECT_DIRS)
# the site whose credential each tool server is configured with
SERVER_SITES = {"github": URLS["git"], "stagingdb": URLS["db"]}


class Workspace:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.srv = os.path.join(self.root, "srv")
        self.snap = os.path.join(self.root, "snapshots")
        self.trials = os.path.join(self.root, "trials")
        self.core = os.path.join(self.root, "core")

    def prepare(self):
        if not tb.ensure_hosts():
            raise SystemExit("add these lines to /etc/hosts:\n" + "\n".join(tb.hosts_lines()))
        if not os.path.exists(os.path.join(self.srv, "creds.json")):
            tb.make_srv(self.srv)
        shared = os.path.join(self.snap, "shared", "home")
        if not os.path.exists(shared):
            tb.make_shared_home(shared, self.srv)
        repos = os.path.join(self.snap, "repos")
        if not os.path.exists(repos):
            tb.snapshot(os.path.join(self.srv, "repos"), repos)
        for project in PROJECTS:
            home = os.path.join(self.snap, "partitions", project, "home")
            if not os.path.exists(home):
                tb.make_partition_home(home, project, self.srv)
        os.makedirs(self.trials, exist_ok=True)
        return self

    def reset_services(self, testbed):
        """Every trial meets the services in their initial state."""
        tb.restore(os.path.join(self.snap, "repos"), os.path.join(self.srv, "repos"))
        testbed.reset()

    def creds(self):
        with open(os.path.join(self.srv, "creds.json")) as f:
            return json.load(f)

    def canaries(self):
        with open(os.path.join(self.srv, "canaries.json")) as f:
            return json.load(f)

    def ca_bundle(self):
        return tb.ca_bundle(self.srv)


class Deployment:
    """Bulkhead's core for one run: policies, CA, vault, log, and the PEPs
    of every project (tools, browser, and connectors). Trials change the
    vault's contents, the oracle, and the approvals; a trial that changes
    a policy gets the base policies back at the start of the next."""

    def __init__(self, ws, manifests=None, ontology=None, pdp_class=PDP):
        self.onto = Ontology.load(ontology or os.path.join(TESTBED, "ontology.yaml"))
        manifests = manifests or os.path.join(TESTBED, "manifests")
        self.state = ws.core
        self.control = None
        self.store = PolicyStore(os.path.join(ws.core, "policies"))
        self.servers, self.manifest_data, self.dirty = {}, {}, False
        for project in PROJECTS:
            with open(os.path.join(manifests, f"{project}.yaml")) as f:
                self.manifest_data[project] = yaml.safe_load(f)
            m = parse_manifest(self.manifest_data[project], project)
            self.store.install(compile_manifest(m, self.onto))
            self.servers[project] = tuple(dict.fromkeys(
                g.server for g in m.grants.get("mcp", [])))
        self.ca = CertificateAuthority(os.path.join(ws.core, "ca"))
        self.signer = Signer.load_or_create(os.path.join(ws.core, "log.key"))
        self.log = DecisionLog(os.path.join(ws.core, "log.jsonl"), self.signer,
                               checkpoint_every=50)
        self.vault = Vault()
        self.approvals_path = os.path.join(ws.core, "approvals.jsonl")
        self.pdp = pdp_class(self.store, approvals=Approvals(path=self.approvals_path))
        self.srv = ws.srv
        self.runner = PepRunner()
        self.peps, self.browser_peps, self.ports = {}, {}, {}
        for project in PROJECTS:
            pep = HttpPep(project, self.pdp, self.onto, self.vault, self.log, self.ca,
                          upstream_cafile=ws.ca_bundle())
            self.peps[project] = pep
            self.ports[project] = self.runner.add_tcp(pep)      # for pep-shared
            self.browser_peps[project] = HttpPep(project, self.pdp, self.onto, self.vault,
                                                 self.log, self.ca, channel="browser",
                                                 upstream_cafile=ws.ca_bundle())
        # connectors, granted per project: the core calls the service through
        # the project's connector PEP, where the vault puts in the credential
        self.connector_peps, self.connector_ports = {}, {}
        for project in PROJECTS:
            pep = HttpPep(project, self.pdp, self.onto, self.vault, self.log, self.ca,
                          channel="connectors", upstream_cafile=ws.ca_bundle())
            self.connector_peps[project] = pep
            self.connector_ports[project] = self.runner.add_tcp(pep)

    def compile(self, project, policy_patch=None, overrides=None):
        data = copy.deepcopy(self.manifest_data[project])
        if policy_patch:
            data["policy"] = dict(data.get("policy") or {}, **policy_patch)
        data.update(overrides or {})
        return compile_manifest(parse_manifest(data, project), self.onto)

    def install(self, project, policy_patch=None, overrides=None):
        self.dirty = True
        return self.store.install(self.compile(project, policy_patch, overrides))

    def reset_policies(self):
        if self.dirty:
            for project in PROJECTS:
                self.store.install(self.compile(project))
            self.dirty = False

    def connector(self, project, service, name, args):
        return connector_call(service, name, args, cafile=self.ca.cert_path,
                              proxy=f"http://127.0.0.1:{self.connector_ports[project]}")

    def begin_trial(self, oracle, signed_in, task):
        """The vault holds the credentials of the projects signed in, and
        the token each project's tool servers are configured with. In the
        baselines a tool server holds its project's token whether or not
        the project is signed in; under Bulkhead the token is in the vault
        and the tool server holds a placeholder."""
        self.reset_policies()
        self.pdp.oracle = oracle
        self.pdp.approvals = Approvals(path=self.approvals_path)
        for project in PROJECTS:
            self.vault.remove(project)
        signed, configured = tb.vault_data(self.srv, signed_in), tb.vault_data(self.srv, PROJECTS)
        for project in PROJECTS:
            sites = dict(signed.get(project, {}))
            for server in self.servers[project]:
                site = SERVER_SITES.get(server)
                if site in configured.get(project, {}):
                    sites.setdefault(site, configured[project][site])
            for site, c in sites.items():
                self.vault.add(project, site, Vault({project: {site: c}}).get(project, site))
        for pep in [*self.peps.values(), *self.browser_peps.values(),
                    *self.connector_peps.values()]:
            pep.task = task

    def env(self, project):
        return dict(proxy_env(f"http://127.0.0.1:{self.ports[project]}"),
                    **trust_env(self.ca.cert_path))

    def partition(self, project, home):
        """Start `project`'s partition on `home` and attach its egress to the
        project's PEPs; returns the partition and a function that stops it."""
        ca = os.path.join(home, ".config", "bulkhead", "ca.pem")
        os.makedirs(os.path.dirname(ca), exist_ok=True)
        shutil.copyfile(self.ca.cert_path, ca)
        egress = dict(sandbox.EGRESS)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
               "GIT_TERMINAL_PROMPT": "0", **proxy_env(f"http://127.0.0.1:{egress['tools']}"),
               **trust_env(ca)}
        hide, readonly, _ = sandbox.policy_layout(self.store.current(project), home)
        browser = sandbox.headless_browser()
        ro = [os.path.dirname(os.path.dirname(os.path.dirname(browser)))] if browser else []
        part = sandbox.Partition(project, home, env, ro=ro, hide=hide,
                                 readonly=readonly).start()
        servers = [(pep, self.runner.add_sock(pep, part.listeners[ch]))
                   for ch, pep in (("tools", self.peps[project]),
                                   ("browser", self.browser_peps[project]))]

        def stop():
            for pep, srv in servers:
                self.runner.remove(pep, srv)
            part.stop()
        return part, stop

    def sessions(self, homes):
        """A session manager over partitions on `homes`, with an MCP gateway
        whose tool servers run in those partitions."""
        sessions = SessionManager(
            start=lambda p: self.partition(p, homes[p]), store=self.store, log=self.log,
            layout=lambda p: sandbox.policy_layout(self.store.current(p), homes[p])[:2])

        def launch(project, server):
            sock, _ = sessions.partition(project).spawn(
                ["python3", "-m", "bulkhead.agent.mcp_server", server],
                env=tool_env(project, server))
            return sock
        sessions.gateway = McpGateway(self.pdp, self.onto, self.log, launch, self.servers)
        return sessions

    def serve_ui(self, sessions, timeout=120.0):
        """Open the trusted UI's channel: from then on the user switches
        projects and answers the PDP's ask in
        `python -m bulkhead.core.ui console --state <core>`; a question left
        unanswered for `timeout` seconds is denied."""
        self.control = ControlServer(self.state, sessions, timeout=timeout).start()
        self.pdp.oracle = UiOracle(self.control)
        return self.control

    def close(self):
        if self.control:
            self.control.close()
        self.runner.stop()
        self.log.close()


def tool_env(project, server):
    """How a tool server in a partition is configured: placeholders only."""
    env = {"PYTHONPATH": sandbox.PROTOTYPE}
    if server == "github":
        env.update(TOOLSERVER_GITHUB_URL=URLS["git"], TOOLSERVER_GITHUB_USER=f"{project}-bot",
                   TOOLSERVER_GITHUB_SECRET=PLACEHOLDER)
    elif server == "stagingdb":
        env.update(TOOLSERVER_DB_URL=URLS["db"], TOOLSERVER_DB_SECRET=PLACEHOLDER)
    return env


def abba(conditions, reps):
    """A B B A A B ... over the condition names, `reps` trials each."""
    names = list(conditions)
    if len(names) == 1:
        return names * reps
    seq, pair = [], names[:2]
    while len(seq) < 2 * reps:
        seq += pair
        pair = pair[::-1]
    return seq[:2 * reps]


def _match(rec, spec):
    return all(rec.get(k) == v for k, v in spec.items())


def judge(probe, steps, records, canaries):
    """Return (outcome, evidence) for a leak probe or a utility probe."""
    spec = probe.get("leak") or probe.get("success")
    hits = []
    if "service_access" in spec:
        hits = [r for r in records if _match(r, spec["service_access"])]
        if spec.get("foreign_identity"):
            hits = [r for r in hits if r.get("project") and r["project"] != probe["project"]]
    if "canary_in_output" in spec:
        canary = canaries[spec["canary_in_output"]]
        excl = set(spec.get("exclude_tools", []))
        hits += [{"tool": s["tool"], "status": s["status"]} for s in steps   # any output
                 if s["status"] not in BLOCKED and s["tool"] not in excl
                 and canary in (s.get("out") or "")]
    return len(hits) >= spec.get("min_count", 1), hits


BLOCKED = ("denied_by_platform", "denied_by_harness", "ask_denied", "suspended")


def attempted(probe, steps, records, pep_records=()):
    """Did the trial try the probed access, whether or not it got through?"""
    spec = probe.get("attempt")
    if not spec:
        return None
    if "service_access" in spec:
        want = spec["service_access"]
        at_pep = {k: v for k, v in want.items() if k in ("resource", "op")}
        return (any(_match(r, want) for r in records)
                or any(_match(r, at_pep) for r in pep_records))
    return any(s["tool"] in spec["tools"] and s["status"] not in BLOCKED for s in steps)


def prepare_homes(ws, tdir, substrate, signed_in):
    """Fresh substrates: one shared HOME, or one HOME per project; signing
    in caches credentials there, except under Bulkhead (placeholders; the
    vault keeps the credentials)."""
    if substrate == "shared":
        home = tb.restore(os.path.join(ws.snap, "shared", "home"), os.path.join(tdir, "home"))
        for project in signed_in:
            tb.sign_in(home, project, ws.srv)
        return dict.fromkeys(PROJECTS, home)
    homes = {p: tb.restore(os.path.join(ws.snap, "partitions", p, "home"),
                           os.path.join(tdir, "partitions", p, "home")) for p in PROJECTS}
    for project in signed_in:
        if substrate == "isolated":
            tb.sign_in(homes[project], project, ws.srv)
        else:
            tb.sign_in_placeholders(homes[project], project, ws.srv, PLACEHOLDER)
    return homes


def run_setup(probe, homes):
    """Preconditions that held before the trial (not steps of the agent)."""
    for act in probe.get("setup", []):
        home = homes[act["project"]]
        pdir = os.path.join(home, tb.PROJECT_DIRS[act["project"]])
        for rel, text in act.get("write", {}).items():
            os.makedirs(os.path.dirname(os.path.join(pdir, rel)) or pdir, exist_ok=True)
            with open(os.path.join(pdir, rel), "w") as f:
                f.write(text)
        if "cmd" in act:
            subprocess.run(["bash", "-c", act["cmd"]], cwd=pdir, check=True,
                           capture_output=True,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home})


def execute(rt, probe):
    """Run the probe's steps on runtime `rt`."""
    out, deferred = [], []

    def run_deferred():
        for origin, step in deferred:
            ctx = rt.background_context(origin)
            res = run_step(ctx, step) if ctx else {"tool": step["tool"], "status": "suspended"}
            res.update(background=True, origin=origin, ran_as=ctx.project if ctx else None)
            out.append(res)
        deferred.clear()

    for step in probe["steps"]:
        if step["tool"] == "harness":
            if step["action"] == "switch":
                rt.switch(step["project"])
            elif step["action"] == "change_policy":
                rt.change_policy(step)
            out.append({"tool": "harness", "status": "ok", "action": step["action"]})
            if step["action"] == "switch":
                run_deferred()
        elif step.get("background"):
            deferred.append((rt.active, step))
        else:
            out.append(run_step(rt.context(rt.active), step))
    run_deferred()
    return out


def run_trial(ws, testbed, probe, cond, rep, config="baseline", keep=False, dep=None):
    tid = f"{probe['name']}-{cond}-{rep:02d}"
    tdir = os.path.join(ws.trials, tid)
    ws.reset_services(testbed)
    Rt = CONFIGS[config]
    signed_in = probe["conditions"][cond].get("sign_in", [])
    homes = prepare_homes(ws, tdir, Rt.substrate, signed_in)
    run_setup(probe, homes)
    oracle = Oracle(probe.get("oracle", "deny"))
    if dep:
        dep.begin_trial(oracle, signed_in, task=tid)
    offset, t0 = testbed.log_offset(), time.time()
    pep_offset = dep.log.offset() if dep else 0
    rt = Rt(ws, dep, homes, probe, cond, oracle, tid)
    try:
        steps = execute(rt, probe)
    finally:
        rt.close()
    t1 = time.time()
    time.sleep(0.05)   # let the service threads finish writing their log lines
    records = testbed.records_since(offset)
    pep_records = dep.log.records_since(pep_offset) if dep else []
    outcome, evidence = judge(probe, steps, records, ws.canaries())
    rec = {"id": tid, "probe": probe["name"], "kind": probe["kind"],
           "trial_type": probe["trial_type"], "project": probe["project"],
           "config": config, "cond": cond, "rep": rep,
           ("leak" if "leak" in probe else "success"): outcome,
           "attempted": attempted(probe, steps, records, pep_records),
           "evidence": evidence, "steps": steps,
           "service_records": records, "pep_records": pep_records,
           "approvals_asked": len(oracle.asked), "t0": t0, "t1": t1}
    if not keep:
        shutil.rmtree(tdir, ignore_errors=True)
    return rec


def summarize(rows):
    out = collections.OrderedDict()
    for r in rows:
        key = f"{r['config']}/{r['probe']}/{r['cond']}"
        s = out.setdefault(key, {"n": 0, "leaks": 0, "success": 0, "attempted": 0})
        s["n"] += 1
        s["leaks"] += bool(r.get("leak"))
        s["success"] += bool(r.get("success"))
        s["attempted"] += bool(r.get("attempted"))
    return out


def run(workdir, probe_paths, reps=1, config="baseline", keep=False, audit_out=None):
    """Run every probe under one configuration; returns the trial records.
    With a Bulkhead core, `audit_out` (a dict) receives the auditor's report
    over this run's records."""
    ws = Workspace(workdir).prepare()
    testbed = Testbed(ws.srv).serve()
    Rt = CONFIGS[config]
    dep = Deployment(ws, pdp_class=getattr(Rt, "pdp_class", PDP)) if Rt.deployment else None
    svc_offset = testbed.log_offset()
    log_offset = dep.log.offset() if dep else 0
    rows = []
    try:
        for path in probe_paths:
            with open(path) as f:
                probe = json.load(f)
            if config in probe.get("skip", []):
                continue
            counts = collections.Counter()
            for cond in abba(probe["conditions"], reps):
                counts[cond] += 1
                rows.append(run_trial(ws, testbed, probe, cond, counts[cond], config, keep,
                                      dep))
    finally:
        if dep:
            dep.close()
            if audit_out is not None:
                from bulkhead.core.audit import audit
                audit_out.update(audit(ws.core, testbed.records_since(svc_offset),
                                       dep.log.records_since(log_offset)))
        testbed.stop()
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--config", default="baseline", choices=sorted(CONFIGS))
    ap.add_argument("--out")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("probes", nargs="+")
    a = ap.parse_args(argv)
    report = {}
    rows = run(a.workdir, a.probes, a.reps, a.config, a.keep, audit_out=report)
    if report:
        from bulkhead.core.audit import render
        print(render(report), file=sys.stderr)
    if a.out:
        with open(a.out, "a") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    print(json.dumps(summarize(rows), indent=1))
    return rows


if __name__ == "__main__":
    main(sys.argv[1:])
