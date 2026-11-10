"""M1: request mapping (development aid; testbed/ontology.yaml)."""
import unittest

from bulkhead.decisions import Decision
from tests.support import ontology

GIT = "https://git.test/acme/payments.git"


class MappingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.o = ontology()

    def m(self, method, url):
        x = self.o.map_request(method, url)
        return x.resource, x.op, x.mapped

    def test_fetch_and_push_differ_by_endpoint(self):
        repo = "repo://git.test/acme/payments"
        self.assertEqual(self.m("GET", GIT + "/info/refs?service=git-upload-pack"),
                         (repo, "read", True))
        self.assertEqual(self.m("GET", GIT + "/info/refs?service=git-receive-pack"),
                         (repo, "push", True))
        self.assertEqual(self.m("POST", GIT + "/git-upload-pack"), (repo, "read", True))
        self.assertEqual(self.m("POST", GIT + "/git-receive-pack"), (repo, "push", True))

    def test_service_apis(self):
        self.assertEqual(self.m("POST", "https://git.test/api/repos/acme/payments/issues/1/comments"),
                         ("repo://git.test/acme/payments", "comment", True))
        self.assertEqual(self.m("DELETE", "https://cloud.test/v1/accounts/acme-staging/resources/x"),
                         ("cloud://acme-staging", "delete", True))
        self.assertEqual(self.m("POST", "https://db.test/staging/exec"), ("db://staging", "write", True))
        self.assertEqual(self.m("GET", "https://chat.test/channels/acme/messages"),
                         ("chat://acme", "read", True))

    def test_fallback_to_origin(self):
        self.assertEqual(self.m("GET", "https://example.org/a?b=c"), ("web://example.org", "read", False))
        self.assertEqual(self.m("POST", "https://example.org:8443/a"),
                         ("web://example.org:8443", "act", False))
        self.assertEqual(self.m("PUT", "https://git.test/unknown"), ("web://git.test", "act", False))

    def test_non_canonical_paths_are_marked(self):
        for path in ("/oss/libfoo.git/../../acme/payments.git/info/refs",
                     "/acme%2Fpayments.git/info/refs", "/acme/./payments.git/info/refs"):
            x = self.o.map_request("GET", "https://git.test" + path)
            self.assertFalse(x.canonical, path)
            self.assertFalse(x.mapped, path)

    def test_tools(self):
        x = self.o.map_tool("github", "push_files", {"owner": "acme", "repo": "payments"})
        self.assertEqual((x.resource, x.op), ("repo://git.test/acme/payments", "push"))
        self.assertIsNone(self.o.map_tool("github", "push_files", {"owner": "acme"}))
        self.assertIsNone(self.o.map_tool("github", "push_files",
                                          {"owner": "acme", "repo": "payments/../x"}))
        self.assertIsNone(self.o.map_tool("github", "delete_repo", {}))

    def test_operation_classes(self):
        self.assertEqual(self.o.expand_ops("repo", {"read": "allow", "act": "ask"}),
                         {"read": Decision.ALLOW, "push": Decision.ASK, "comment": Decision.ASK})
        self.assertEqual(self.o.expand_ops("repo", {"act": "allow", "push": "deny"}),
                         {"push": Decision.DENY, "comment": Decision.ALLOW})
        with self.assertRaises(ValueError):
            self.o.expand_ops("repo", {"push": "allow"}, classes_only=True)
        with self.assertRaises(ValueError):
            self.o.expand_ops("repo", {"delete": "allow"})

    def test_web_wildcard_is_not_a_named_resource(self):
        self.assertEqual(self.o.site_patterns("*"), ["web://*"])
        self.assertEqual(self.o.site_patterns("https://git.test"),
                         ["repo://git.test/*/*", "web://git.test"])


if __name__ == "__main__":
    unittest.main()
