"""M5: the auditor, on clean runs and with injected faults.

Each fault is a plausible bug in an enforcement component; the check that
covers the condition it breaks must catch it:
  C1  a log record edited after the fact
  C2  a request that went around the PEP (the pep-shared ablation)
  C3  a PDP that decides one project's requests with another's policy
  C4  enforcement that applies each channel's own grant (per-channel)
  C5  enforcement that lets ask through without asking
"""
import glob
import json
import os
import shutil
import ssl
import tempfile
import unittest
import urllib.error
import urllib.request

from bulkhead.agent.scripted import Oracle
from bulkhead.core.audit import audit
from bulkhead.core.pdp import PDP, Verdict
from bulkhead.decisions import Decision
from bulkhead.pep.mcp_gateway import McpGateway
from eval import run_eval
from testbed.services import Testbed
from tests.support import require, sandbox_unavailable, settle, testbed_unavailable

HERE = os.path.dirname(os.path.abspath(__file__))
PROBES = sorted(glob.glob(os.path.join(HERE, "..", "eval", "probes", "*.json")))
ACME = "repo://git.test/acme/payments"


class Misattributing(PDP):
    """Decides OSS's requests with Work's policy (a wrong label)."""
    def decide(self, project, channel, resource, op, mapped=True):
        d, _, entries = super().decide("work" if project == "oss" else project, channel,
                                       resource, op, mapped)
        return d, self.store.current(project).version, entries


class PerChannel(PDP):
    """Applies each channel's own grant where it has one, as platforms do."""
    def decide(self, project, channel, resource, op, mapped=True):
        pol = self.store.current(project)
        g, rules = pol.channel_grant({"tools": "shell"}.get(channel, channel), resource, op)
        if g is None:
            return super().decide(project, channel, resource, op, mapped)
        return g, pol.version, tuple(r.source for r in rules)


class AskIsAllow(PDP):
    """Lets ask through without asking anyone."""
    def authorize(self, project, channel, resource, op, mapped=True, task=None, request=None):
        v = super().authorize(project, channel, resource, op, mapped, task, request)
        if v.policy_decision == Decision.ASK:
            v = Verdict(Decision.ALLOW, v.policy_decision, project, channel, resource, op,
                        v.version, v.entries, mapped, v.hooked, False, None)
        return v


def c2_reference(records, service, window=5.0):
    """The first C2 matcher: sort every candidate by distance in time."""
    import collections
    from bulkhead.core.audit import _epoch
    pool = collections.defaultdict(list)
    for r in records:
        if r.get("pep") == "http" and r.get("outcome") == "forwarded" and r.get("resource"):
            pool[(r["resource"], r["op"])].append([_epoch(r["ts"]), r["project"], False])
    unmatched = []
    for s in sorted(service, key=lambda s: s["ts"]):
        if s.get("status", 500) >= 400 or "resource" not in s:
            continue
        for cand in sorted(pool.get((s["resource"], s["op"]), []),
                           key=lambda c: abs(c[0] - s["ts"])):
            if (not cand[2] and abs(cand[0] - s["ts"]) <= window
                    and (s.get("project") is None or s["project"] == cand[1])):
                cand[2] = True
                break
        else:
            unmatched.append(s["n"])
    return unmatched


class MatchingTest(unittest.TestCase):
    """C2 searches sorted candidates instead of sorting them per access; on
    random runs (with equal times, other projects' records, and accesses
    outside the window) it reports exactly what the first matcher did."""

    def test_same_result_as_the_reference(self):
        import datetime
        import random
        from bulkhead.core.audit import check_c2
        rng = random.Random(7)
        for _ in range(200):
            records, service = [], []
            for i in range(rng.randint(0, 30)):
                t = 1000 + rng.choice([rng.randint(0, 40), rng.randint(0, 40) + 0.5])
                records.append({"pep": "http", "outcome": rng.choice(["forwarded"] * 4 +
                                                                     ["blocked"]),
                                "resource": rng.choice(["repo://a", "repo://b"]),
                                "op": rng.choice(["read", "push"]),
                                "project": rng.choice(["oss", "work"]),
                                "ts": datetime.datetime.fromtimestamp(
                                    t, datetime.timezone.utc).strftime(
                                        "%Y-%m-%dT%H:%M:%S.%fZ")})
            for n in range(rng.randint(0, 30)):
                service.append({"n": n, "service": "git", "method": "GET", "path": f"/{n}",
                                "status": rng.choice([200, 200, 200, 403]),
                                "resource": rng.choice(["repo://a", "repo://b"]),
                                "op": rng.choice(["read", "push"]),
                                "project": rng.choice(["oss", "work", None]),
                                "ts": 1000 + rng.randint(-5, 50) + rng.choice([0, 0.5])})
            window = rng.choice([0.0, 1.0, 5.0])
            want = c2_reference(records, service, window)
            got = [int(p.split()[2][1:-1]) for p in check_c2(records, service, window)]
            self.assertEqual(sorted(got), sorted(want))


@require(testbed_unavailable())
class FaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = run_eval.Workspace(self.tmp.name).prepare()
        self.testbed = Testbed(self.ws.srv).serve()
        self.dep = run_eval.Deployment(self.ws)
        self.dep.begin_trial(Oracle("deny"), ["oss", "work"], task="t-1")
        self.svc0 = self.testbed.log_offset()

    def tearDown(self):
        self.dep.close()
        self.testbed.stop()
        self.tmp.cleanup()

    def use(self, cls):
        pdp = cls(self.dep.store, oracle=self.dep.pdp.oracle, approvals=self.dep.pdp.approvals)
        self.dep.pdp = pdp
        for pep in list(self.dep.peps.values()) + list(self.dep.browser_peps.values()):
            pep.pdp = pdp
        return pdp

    def get(self, project, url, method="GET"):
        proxy = f"http://127.0.0.1:{self.dep.ports[project]}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": proxy}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(
                cafile=self.dep.ca.cert_path)))
        try:
            with opener.open(urllib.request.Request(url, method=method), timeout=20) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def report(self):
        settle(self.dep.log)
        self.dep.log.checkpoint()
        return audit(self.ws.core, self.testbed.records_since(self.svc0))

    def failing(self, report):
        return {c for c in ("C1", "C2", "C3", "C4", "C5") if report[c]["ok"] is False}

    def test_clean(self):
        self.assertEqual(self.get("work", "https://git.test/api/repos/acme/payments/issues"), 200)
        self.assertEqual(self.get("oss", "https://git.test/api/repos/acme/payments/issues"), 403)
        self.assertEqual(self.failing(self.report()), set())

    def test_c1_edited_record(self):
        self.get("oss", "https://git.test/api/repos/acme/payments/issues")
        self.dep.log.checkpoint()
        path = os.path.join(self.ws.core, "log.jsonl")
        with open(path) as f:
            lines = f.read().splitlines()
        rec = json.loads(lines[0])
        rec["final"] = "allow"
        lines[0] = json.dumps(rec)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.assertIn("C1", self.failing(audit(self.ws.core, [])))

    def test_c3_misattribution(self):
        self.use(Misattributing)
        # allowed by the wrong policy; the service still refuses OSS's own
        # credential, which the vault put in: the vault is per project
        self.assertEqual(self.get("oss", "https://git.test/api/repos/acme/payments/issues"), 403)
        r = self.report()
        self.assertEqual(self.failing(r), {"C3"})
        self.assertIn("policy v1 says deny", r["C3"]["problems"][0])

    def test_c4_per_channel_enforcement(self):
        self.use(PerChannel)
        gw = McpGateway(self.dep.pdp, self.dep.onto, self.dep.log,
                        lambda *a: self.fail("a blocked call must not start a tool server"),
                        self.dep.servers)
        status, _, _ = gw.call("work", "github", "push_files",
                               {"owner": "acme", "repo": "payments", "files": {}}, task="t-1")
        self.assertEqual(status, "blocked")                 # the tool server's grant: ask
        code = self.get("work", "https://git.test/acme/payments.git/info/refs"
                                "?service=git-receive-pack")
        self.assertEqual(code, 200)                         # the shell's grant: allow
        r = self.report()
        self.assertIn("C4", self.failing(r))
        self.assertIn("allow on tools; ask on mcp", r["C4"]["problems"][0])

    def test_c5_ask_without_asking(self):
        self.use(AskIsAllow)
        self.get("work", "https://cloud.test/v1/accounts/acme-staging/resources/x", "DELETE")
        r = self.report()
        self.assertEqual(self.failing(r), {"C5"})
        self.assertIn("without a trusted-UI approval", r["C5"]["problems"][0])


@require(testbed_unavailable() or sandbox_unavailable())
class RunAuditTest(unittest.TestCase):
    def test_bulkhead_run_passes_and_the_ablation_fails_c2(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = {}
            for config in ("bulkhead", "pep-shared"):
                reports[config] = {}
                run_eval.run(os.path.join(tmp, config), PROBES, 1, config,
                             audit_out=reports[config])
            ok = {c: reports["bulkhead"][c]["ok"] for c in ("C1", "C2", "C3", "C4", "C5")}
            self.assertEqual(ok, dict.fromkeys(ok, True))
            ab = reports["pep-shared"]
            self.assertFalse(ab["C2"]["ok"])
            # the proxy-ignoring code's cloud read, and the account connector's
            # chat read, which runs in the platform: both bypass the PEP
            self.assertTrue(all("cloud://acme-staging" in p or "chat://acme" in p
                                for p in ab["C2"]["problems"]))
            self.assertTrue(all(ab[c]["ok"] for c in ("C1", "C3", "C4", "C5")))


if __name__ == "__main__":
    unittest.main()
