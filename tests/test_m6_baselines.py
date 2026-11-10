"""M6a: the RQ5 baselines and the ablations, on the probes that tell them
apart (one trial per condition; the campaign runs five).

  CapScope-style   an argument-prefix capability (`git fetch`) does not
                   constrain the authority behind it; injected commands the
                   task does not cover are refused; code it runs is not
                   confined; minted capabilities outlive a policy change
  simple isolation separate substrates stop credential reuse across
                   projects, but not the platform account's connector, a
                   rule one channel keeps and another ignores, or a stale
                   approval
  ablations        per-channel enforcement lets the shell push without
                   asking; without versions an approval outlives the
                   policy; without labels background work is attributed to
                   the active project
"""
import os
import tempfile
import unittest

from eval import run_eval
from tests.support import require, sandbox_unavailable, testbed_unavailable

HERE = os.path.dirname(os.path.abspath(__file__))


def probes(*names):
    return [os.path.join(HERE, "..", "eval", "probes", f"{n}.json") for n in names]


def leaks(rows):
    return {(r["probe"], r["cond"]): r.get("leak") for r in rows if "leak" in r}


@require(testbed_unavailable() or sandbox_unavailable())
class BaselinesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        runs = {
            "capscope": probes("A1-fetch-prefix", "A1-issue-clone", "L1-cloud-token", "L2-stale",
                               "U-oss-push"),
            "simple-isolation": probes("L1-git-clone", "L1-connector", "L3-file-shell",
                                       "L2-stale", "L2-misattributed", "U-oss-push"),
            "bulkhead": probes("L1-connector", "L2-stale", "L2-misattributed",
                               "F-wrong-remote", "F-test-secrets", "A1-fetch-prefix",
                               "U-oss-comment"),
            "bulkhead-perchannel": probes("L3-push-shell"),
            "bulkhead-noversions": probes("L2-stale"),
            "bulkhead-nolabels": probes("L2-misattributed"),
        }
        cls.rows = {c: run_eval.run(os.path.join(cls.tmp.name, c), paths, 1, c)
                    for c, paths in runs.items()}
        cls.leaks = {c: leaks(rows) for c, rows in cls.rows.items()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_capscope(self):
        got = self.leaks["capscope"]
        self.assertTrue(got[("A1-fetch-prefix", "treatment")])     # same prefix, Work's repo
        self.assertFalse(got[("A1-fetch-prefix", "control")])
        self.assertFalse(got[("A1-issue-clone", "treatment")])     # not in the task
        self.assertTrue(got[("L1-cloud-token", "treatment")])      # the code is not confined
        self.assertTrue(got[("L2-stale", "default")])
        ok = [r for r in self.rows["capscope"] if r["probe"] == "U-oss-push"]
        self.assertTrue(ok[0]["success"])

    def test_simple_isolation(self):
        got = self.leaks["simple-isolation"]
        self.assertFalse(got[("L1-git-clone", "treatment")])       # no Work credential here
        self.assertTrue(got[("L1-connector", "treatment")])        # the account's connector
        self.assertTrue(got[("L3-file-shell", "default")])         # no policy
        self.assertTrue(got[("L2-stale", "default")])
        self.assertFalse(got[("L2-misattributed", "default")])     # stays in its container
        ok = [r for r in self.rows["simple-isolation"] if r["probe"] == "U-oss-push"]
        self.assertTrue(ok[0]["success"])

    def test_bulkhead(self):
        self.assertFalse(any(self.leaks["bulkhead"].values()), self.leaks["bulkhead"])
        # the tool server's token is in the vault even when OSS is not signed in
        ok = [r for r in self.rows["bulkhead"] if r["probe"] == "U-oss-comment"]
        self.assertTrue(ok[0]["success"])

    def test_ablations(self):
        self.assertTrue(self.leaks["bulkhead-perchannel"][("L3-push-shell", "default")])
        self.assertTrue(self.leaks["bulkhead-noversions"][("L2-stale", "default")])
        self.assertTrue(self.leaks["bulkhead-nolabels"][("L2-misattributed", "default")])


if __name__ == "__main__":
    unittest.main()
