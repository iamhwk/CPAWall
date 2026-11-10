"""M1: analyzer (channel inconsistency, inherited authority, conflicts)."""
import unittest

from bulkhead.policy import analyzer
from bulkhead.policy.analyzer import Reach
from bulkhead.policy.compiler import compile_manifest
from bulkhead.policy.schema import parse_manifest
from tests.support import compiled, inventory, ontology

GIT_WORK = "git credential helper: work-bot"


class AnalyzerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.onto = ontology()
        cls.policies = {"oss": compiled("oss"), "work": compiled("work")}

    def test_channel_inconsistency(self):
        f = analyzer.channel_findings(self.policies["work"])
        rel = {(x.kind, x.detail["relation"]) for x in f}
        self.assertIn(("excess", "shadowing"), rel)
        self.assertIn(("excess", "unbacked"), rel)
        self.assertEqual(analyzer.channel_findings(self.policies["oss"]), [])

    def test_inherited_authority_on_a_shared_substrate(self):
        shared = [Reach("oss", "repo://git.test/acme/*", "read", GIT_WORK),
                  Reach("oss", "repo://git.test/acme/*", "push", GIT_WORK),
                  Reach("oss", "cloud://acme-staging", "read", "token file: work-bot"),
                  Reach("oss", "file://~/work/payments/**", "read", "OS account"),
                  Reach("oss", "repo://git.test/oss/libfoo", "push", "git credential helper: oss-bot"),
                  Reach("work", "file://~/work/payments/secrets/staging.env", "read", "OS account")]
        f = analyzer.inherited_findings(self.policies, shared)
        got = {(x.project, x.detail["resource"], x.detail["op"]) for x in f}
        self.assertIn(("oss", "repo://git.test/acme/{any}", "push"), got)
        self.assertIn(("oss", "cloud://acme-staging", "read"), got)
        self.assertIn(("oss", "file://~/work/payments/{any}", "read"), got)
        self.assertIn(("work", "file://~/work/payments/secrets/staging.env", "read"), got)
        self.assertNotIn(("oss", "repo://git.test/oss/libfoo", "push"), got)

    def test_inherited_authority_in_partitions(self):
        own = [Reach("oss", "repo://git.test/oss/libfoo", "push", "vault: oss-bot"),
               Reach("oss", "file://~/oss/libfoo/**", "write", "Landlock")]
        self.assertEqual(analyzer.inherited_findings(self.policies, own), [])

    def test_conflicts(self):
        def client(name, other):
            return compile_manifest(parse_manifest({
                "project": name, "conflicts": [other],
                "policy": {f"repo://git.test/{name}/*": {"read": "allow"},
                           "repo://git.test/shared/*": {"read": "allow"}},
                "grants": {}}), self.onto)
        pols = {"bank-a": client("bank-a", "bank-b"), "bank-b": client("bank-b", "bank-a")}
        f = analyzer.conflict_findings(pols, self.onto, ["repo://git.test/shared/notes"],
                                       {"bank-a": "home:/h", "bank-b": "home:/h"})
        resources = {x.detail.get("resource") for x in f}
        self.assertIn("repo://git.test/shared/notes", resources)
        self.assertNotIn("repo://git.test/bank-a/{any}", resources)
        self.assertTrue(any(x.detail.get("substrate") == "home:/h" for x in f))
        self.assertEqual(analyzer.conflict_findings(pols, self.onto, (),
                                                    {"bank-a": "p1", "bank-b": "p2"})[1:], [])

    def test_report(self):
        text = analyzer.report(self.policies, analyzer.analyze(self.policies, self.onto,
                                                               inventory=inventory()))
        self.assertIn("== work: policy uninstalled (declared)", text)
        self.assertIn("repo://git.test/acme/*", text)
        self.assertIn("shadowing", text)


if __name__ == "__main__":
    unittest.main()
