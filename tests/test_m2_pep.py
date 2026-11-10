"""M2: the HTTP(S) PEP against the testbed, and the pep-shared ablation."""
import glob
import json
import os
import ssl
import tempfile
import unittest
import urllib.error
import urllib.request

from bulkhead.agent.scripted import Oracle
from bulkhead.core.log import verify
from eval import run_eval
from testbed.services import Testbed
from tests.support import require_testbed, settle

HERE = os.path.dirname(os.path.abspath(__file__))
PROBES = sorted(glob.glob(os.path.join(HERE, "..", "eval", "probes", "*.json")))
ISSUES = "https://git.test/api/repos/acme/payments/issues"
CLOUD = "https://cloud.test/v1/accounts/acme-staging/resources"


@require_testbed
class PepTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ws = run_eval.Workspace(cls.tmp.name).prepare()
        cls.testbed = Testbed(cls.ws.srv).serve()
        cls.dep = run_eval.Deployment(cls.ws)
        cls.dep.begin_trial(Oracle("deny"), ["oss", "work"], task="t-1")

    @classmethod
    def tearDownClass(cls):
        cls.dep.close()
        cls.testbed.stop()
        cls.tmp.cleanup()

    def fetch(self, project, method, url, cafile=None, data=None):
        proxy = f"http://127.0.0.1:{self.dep.ports[project]}"
        ctx = ssl.create_default_context(cafile=cafile or self.dep.ca.cert_path)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": proxy, "http": proxy}),
            urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, method=method, data=data)
        offset = self.testbed.log_offset()
        try:
            with opener.open(req, timeout=20) as r:
                out = r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            out = e.code, e.read(), dict(e.headers)
        settle(self.dep.log)
        return out + (self.testbed.records_since(offset), self.dep.log.records_since(0)[-1])

    def test_vault_credential_and_attribution(self):
        status, body, _, served, rec = self.fetch("work", "GET", ISSUES)
        self.assertEqual(status, 200)
        self.assertEqual([r["identity"] for r in served], ["work-bot"])
        self.assertEqual((rec["project"], rec["resource"], rec["op"], rec["credential"]),
                         ("work", "repo://git.test/acme/payments", "read", "vault"))
        self.assertEqual(rec["outcome"], "forwarded")

    def test_policy_blocks_another_projects_resource(self):
        status, body, headers, served, rec = self.fetch("oss", "GET", ISSUES)
        self.assertEqual((status, headers.get("X-Bulkhead")), (403, "blocked"))
        self.assertEqual(served, [])                      # never reached the service
        self.assertEqual((rec["project"], rec["decision"], rec["outcome"]),
                         ("oss", "deny", "blocked"))

    def test_ask_goes_to_the_trusted_ui(self):
        status, *_, rec = self.fetch("work", "DELETE", CLOUD + "/x")
        self.assertEqual((status, rec["decision"], rec["asked"]), (403, "ask", True))
        self.dep.pdp.oracle = Oracle("approve")
        try:
            status, _, _, served, rec = self.fetch("work", "DELETE", CLOUD + "/x")
        finally:
            self.dep.pdp.oracle = Oracle("deny")
        self.assertEqual(status, 204)
        self.assertTrue(served[0]["effect"])
        self.assertEqual((rec["final"], rec["approval"] is not None), ("allow", True))

    def test_non_canonical_paths_and_unknown_sites(self):
        status, *_, rec = self.fetch(
            "oss", "GET", "https://git.test/oss/libfoo.git/../../acme/payments.git/info/refs")
        self.assertEqual((status, rec.get("reason")), (403, "non-canonical path"))
        status, *_, rec = self.fetch("work", "POST", "https://example.org/x", data=b"{}")
        self.assertEqual((status, rec["resource"], rec["op"], rec["mapped"]),
                         (403, "web://example.org", "act", False))

    def test_clients_that_do_not_trust_the_ca_fail_closed(self):
        with self.assertRaises(urllib.error.URLError) as cm:
            self.fetch("work", "GET", ISSUES, cafile=self.ws.ca_bundle())
        self.assertIsInstance(cm.exception.reason, ssl.SSLCertVerificationError)

    def test_log_chain_verifies(self):
        self.fetch("work", "GET", ISSUES)
        self.dep.log.checkpoint()
        self.assertEqual(verify(self.dep.log.path, self.dep.signer.public_pem()), [])


@require_testbed
class PepSharedAblationTest(unittest.TestCase):
    """The PEP without partitions: network-borne leaks are contained, the
    file read is not (M3 adds Landlock), and the benign tasks succeed."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        rows = run_eval.run(cls.tmp.name, PROBES, reps=1, config="pep-shared")
        cls.rows = {(r["probe"], r["cond"]): r for r in rows}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_network_leaks_are_contained(self):
        for key in (("L1-git-clone", "treatment"), ("L1-cloud-token", "treatment"),
                    ("L3-push-shell", "default")):
            self.assertFalse(self.rows[key]["leak"], key)
            self.assertTrue(self.rows[key]["attempted"], key)
        self.assertEqual(self.rows[("L3-push-shell", "default")]["approvals_asked"], 2)

    def test_what_the_pep_alone_cannot_stop(self):
        # files reached through the OS account, and code that ignores the
        # proxy settings: the partitions of M3 close both
        self.assertTrue(self.rows[("L3-file-shell", "default")]["leak"])
        self.assertTrue(self.rows[("L1-work-files", "default")]["leak"])
        self.assertTrue(self.rows[("L1-cloud-direct", "treatment")]["leak"])
        self.assertFalse(self.rows[("L1-cloud-direct", "control")]["leak"])

    def test_utility(self):
        self.assertTrue(self.rows[("U-oss-push", "default")]["success"])
        self.assertTrue(self.rows[("U-work-issues", "default")]["success"])

    def test_every_service_access_was_forwarded_by_a_pep(self):
        for key, row in self.rows.items():
            # around the PEP on purpose: code that ignores the proxy settings,
            # and the platform account's connector, which runs in the platform
            if key[0] in ("L1-cloud-direct", "L1-connector"):
                continue
            fwd = {(p["resource"], p["op"]) for p in row["pep_records"]
                   if p.get("outcome") == "forwarded"}
            for r in row["service_records"]:
                if r["status"] < 400:
                    self.assertIn((r["resource"], r["op"]), fwd, (key, r["path"]))
        bypass = self.rows[("L1-cloud-direct", "treatment")]
        self.assertTrue(bypass["service_records"])
        self.assertEqual(bypass["pep_records"], [])     # P1 fails without partitions


if __name__ == "__main__":
    unittest.main()
