"""M4: the MCP gateway, with tool servers running in the partitions."""
import os
import tempfile
import unittest

from bulkhead.agent.scripted import Oracle
from eval import run_eval
from testbed import setup as tb
from testbed.services import Testbed
from tests.support import require, sandbox_unavailable, settle, testbed_unavailable


@require(testbed_unavailable() or sandbox_unavailable())
class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ws = run_eval.Workspace(cls.tmp.name).prepare()
        cls.testbed = Testbed(cls.ws.srv).serve()
        cls.dep = run_eval.Deployment(cls.ws)
        cls.dep.begin_trial(Oracle("deny"), ["oss", "work"], task="t-1")
        homes = {p: tb.restore(os.path.join(cls.ws.snap, "partitions", p, "home"),
                               os.path.join(cls.tmp.name, "p", p, "home"))
                 for p in ("oss", "work")}
        cls.sessions = cls.dep.sessions(homes)
        cls.gw = cls.sessions.gateway

    @classmethod
    def tearDownClass(cls):
        cls.sessions.stop_all()
        cls.dep.close()
        cls.testbed.stop()
        cls.tmp.cleanup()

    def call(self, project, server, tool, args):
        offset = self.dep.log.offset()
        out = self.gw.call(project, server, tool, args, task="t-1")
        settle(self.dep.log)
        return out, self.dep.log.records_since(offset)

    def test_only_declared_and_mappable_tools_are_offered(self):
        work = {t["name"] for t in self.gw.list_tools("work")}
        self.assertEqual(work, {"github.list_issues", "github.add_comment", "github.push_files",
                                "stagingdb.query", "stagingdb.execute"})
        self.assertEqual({t["name"] for t in self.gw.list_tools("oss")},
                         {"github.list_issues", "github.add_comment", "github.push_files"})

    def test_allowed_call_runs_in_the_partition_with_the_vault(self):
        (status, out, verdict), recs = self.call("work", "github", "list_issues",
                                                 {"owner": "acme", "repo": "payments"})
        self.assertEqual(status, "ok")
        self.assertIn("Rotate the staging key", out)
        by_channel = {r["channel"]: r for r in recs}
        self.assertEqual(by_channel["mcp"]["outcome"], "forwarded")
        self.assertEqual((by_channel["tools"]["project"], by_channel["tools"]["credential"]),
                         ("work", "vault"))

    def test_denied_call_never_reaches_the_tool_server(self):
        (status, out, verdict), recs = self.call("oss", "github", "list_issues",
                                                 {"owner": "acme", "repo": "payments"})
        self.assertEqual(status, "blocked")
        self.assertEqual([(r["channel"], r["final"]) for r in recs], [("mcp", "deny")])

    def test_ask_and_unmappable_calls(self):
        (status, _, verdict), _ = self.call("work", "stagingdb", "execute",
                                            {"db": "staging", "sql": "DELETE FROM t"})
        self.assertEqual((status, str(verdict.policy_decision), verdict.asked),
                         ("blocked", "ask", True))
        (status, _, _), _ = self.call("work", "github", "push_files",
                                      {"owner": "acme", "repo": "payments/../x", "files": {}})
        self.assertEqual(status, "blocked")
        (status, _, _), _ = self.call("oss", "stagingdb", "query",
                                      {"db": "staging", "sql": "SELECT 1"})
        self.assertEqual(status, "blocked")       # not a tool server of OSS

    def test_database_read(self):
        (status, out, _), recs = self.call("work", "stagingdb", "query",
                                           {"db": "staging", "sql": "SELECT 1"})
        self.assertEqual(status, "ok")
        self.assertIn("payments_api_key", out)


if __name__ == "__main__":
    unittest.main()
