"""M3: the bulkhead configuration contains every probe and keeps utility."""
import glob
import os
import shutil
import tempfile
import unittest

from bulkhead.agent.scripted import Oracle
from bulkhead.pep import sandbox
from eval import run_eval
from testbed import setup as tb
from testbed.services import Testbed
from tests.support import require, sandbox_unavailable, testbed_unavailable

HERE = os.path.dirname(os.path.abspath(__file__))
PROBES = sorted(glob.glob(os.path.join(HERE, "..", "eval", "probes", "*.json")))
NEEDS = testbed_unavailable() or sandbox_unavailable()


@require(NEEDS)
class BulkheadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        rows = run_eval.run(cls.tmp.name, PROBES, reps=1, config="bulkhead")
        cls.rows = {(r["probe"], r["cond"]): r for r in rows}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_leaks(self):
        for key, row in self.rows.items():
            if "leak" in row:
                self.assertFalse(row["leak"], key)

    def test_attempts_were_made(self):
        for key, row in self.rows.items():
            if "leak" in row:
                self.assertTrue(row["attempted"], key)

    def test_utility(self):
        self.assertTrue(self.rows[("U-oss-push", "default")]["success"])
        self.assertTrue(self.rows[("U-work-issues", "default")]["success"])

    def test_asks_reach_the_trusted_ui(self):
        self.assertEqual(self.rows[("L3-push-shell", "default")]["approvals_asked"], 2)

    def test_complete_mediation(self):
        for key, row in self.rows.items():
            fwd = {(p["resource"], p["op"]) for p in row["pep_records"]
                   if p.get("outcome") == "forwarded"}
            for r in row["service_records"]:
                self.assertIn((r["resource"], r["op"]), fwd, (key, r["path"]))


BROWSER = sandbox.headless_browser()


@require(NEEDS)
@unittest.skipUnless(BROWSER and shutil.which("certutil"), "no headless browser or certutil")
class PartitionBrowserTest(unittest.TestCase):
    def test_browser_goes_through_the_browser_pep(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = run_eval.Workspace(tmp).prepare()
            testbed = Testbed(ws.srv).serve()
            dep = run_eval.Deployment(ws)
            try:
                dep.begin_trial(Oracle("deny"), ["oss"], "browser")
                home = tb.restore(os.path.join(ws.snap, "partitions", "oss", "home"),
                                  os.path.join(tmp, "p", "oss", "home"))
                part, stop = dep.partition("oss", home)
                try:
                    part.trust_browser(os.path.join(home, ".config", "bulkhead", "ca.pem"))
                    ok = part.browse("https://git.test/api/repos/oss/libfoo/issues", BROWSER)
                    no = part.browse("https://git.test/api/repos/acme/payments/issues", BROWSER)
                finally:
                    stop()
                self.assertIn("Flaky test on CI", ok["stdout"])
                self.assertIn("blocked by Bulkhead", no["stdout"])
                recs = [r for r in dep.log.records_since(0) if r.get("resource")]
                self.assertTrue(all(r["channel"] == "browser" for r in recs))
                self.assertIn(("repo://git.test/oss/libfoo", "allow", "vault"),
                              {(r["resource"], r["final"], r.get("credential")) for r in recs})
            finally:
                dep.close()
                testbed.stop()


if __name__ == "__main__":
    unittest.main()
