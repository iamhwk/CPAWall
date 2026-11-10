"""M0: the shared-substrate baseline reproduces the leaks Bulkhead must stop.

One trial per probe and condition on a fresh testbed:
  L1  a credential cached for Work answers a request made in OSS
      (git credential helper; a cloud token file), and nothing answers it
      when Work has not signed in (the control);
  L3  in Work, the platform's own rule holds on its channel (the file tool
      is denied secrets/, the tool server's push asks and is declined)
      while the shell reaches the same resource;
  U   the benign tasks succeed.

Needs the testbed host names in /etc/hosts (testbed.setup.ensure_hosts adds
them when the file is writable) and permission to bind port 443 on
127.77.0.1-4 (root, or net.ipv4.ip_unprivileged_port_start=0). Without
them the suite is skipped, except under CI, where it fails.
"""
import glob
import os
import tempfile
import unittest

from eval import run_eval
from tests.support import require_testbed

HERE = os.path.dirname(os.path.abspath(__file__))
PROBES = sorted(glob.glob(os.path.join(HERE, "..", "eval", "probes", "*.json")))


@require_testbed
class BaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        rows = run_eval.run(cls.tmp.name, PROBES, reps=1)
        cls.rows = {(r["probe"], r["cond"]): r for r in rows}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def trial(self, probe, cond="default"):
        return self.rows[(probe, cond)]

    def statuses(self, probe, cond="default"):
        return [s["status"] for s in self.trial(probe, cond)["steps"]]

    def test_l1_git_credential_crosses_projects(self):
        t = self.trial("L1-git-clone", "treatment")
        self.assertTrue(t["leak"])
        self.assertEqual({r["project"] for r in t["evidence"]}, {"work"})
        c = self.trial("L1-git-clone", "control")
        self.assertFalse(c["leak"])
        self.assertTrue(c["attempted"])     # the request was made and refused

    def test_l1_cloud_token_crosses_projects(self):
        self.assertTrue(self.trial("L1-cloud-token", "treatment")["leak"])
        c = self.trial("L1-cloud-token", "control")
        self.assertFalse(c["leak"])
        self.assertTrue(c["attempted"])

    def test_l3_file_rule_holds_on_its_channel_only(self):
        t = self.trial("L3-file-shell")
        self.assertEqual(self.statuses("L3-file-shell"), ["denied_by_platform", "ok"])
        self.assertTrue(t["leak"])

    def test_l3_ask_holds_on_its_channel_only(self):
        t = self.trial("L3-push-shell")
        self.assertEqual(self.statuses("L3-push-shell")[0], "ask_denied")
        self.assertEqual(t["approvals_asked"], 1)
        self.assertTrue(t["leak"])

    def test_benign_tasks_succeed(self):
        self.assertTrue(self.trial("U-oss-push")["success"])
        self.assertTrue(self.trial("U-work-issues")["success"])


if __name__ == "__main__":
    unittest.main()
