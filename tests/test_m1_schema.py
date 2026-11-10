"""M1: manifest schema."""
import unittest

from bulkhead.policy.schema import ManifestError, load_manifest, parse_manifest
from tests.support import testbed_file


def base(**kw):
    d = {"project": "p", "grants": {"shell": [{"resource": "repo://git.test/a/b",
                                               "ops": {"read": "allow"}}]}}
    d.update(kw)
    return d


class SchemaTest(unittest.TestCase):
    def test_testbed_manifests(self):
        for name in ("oss", "work"):
            m = load_manifest(testbed_file("manifests", f"{name}.yaml"))
            self.assertEqual(m.project, name)
            self.assertIsNotNone(m.policy)

    def test_rejects(self):
        cases = {
            "two targets": base(grants={"shell": [{"resource": "repo://a/b", "site": "*",
                                                   "ops": {"read": "allow"}}]}),
            "fs without path": base(grants={"fs": [{"resource": "file://~/x/**",
                                                    "ops": {"read": "allow"}}]}),
            "path on the shell": base(grants={"shell": [{"path": "~/x", "ops": {"read": "allow"}}]}),
            "mcp without server": base(grants={"mcp": [{"resource": "repo://a/b",
                                                        "ops": {"read": "allow"}}]}),
            "bad decision": base(policy={"repo://a/b": {"read": "maybe"}}),
            "unknown field": base(owner="me"),
            "unknown channel": base(grants={"email": []}),
            "empty policy": base(policy={}),
            "bad project name": base(project="Work Project"),
            "no operations": base(grants={"shell": [{"resource": "repo://a/b", "ops": {}}]}),
        }
        for why, data in cases.items():
            with self.assertRaises(ManifestError, msg=why):
                parse_manifest(data)


if __name__ == "__main__":
    unittest.main()
