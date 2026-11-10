"""M4: trusted UI: terminal approvals and reports."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from bulkhead.core import ui
from eval import run_eval
from tests.support import require, testbed_file, testbed_unavailable


class TtyOracleTest(unittest.TestCase):
    def ask(self, answer, task="t-1"):
        master, slave = os.openpty()
        try:
            os.write(master, answer.encode() + b"\n")
            q = {"project": "work", "op": "push", "resource": "repo://git.test/acme/payments",
                 "channel": "shell", "request": "git push", "version": 3, "task": task}
            return ui.TtyOracle(os.ttyname(slave))(q)
        finally:
            os.close(master)
            os.close(slave)

    def test_scopes(self):
        self.assertEqual(self.ask("y"), {"approve": True, "scope": "request"})
        self.assertEqual(self.ask("t"), {"approve": True, "scope": "task"})
        self.assertEqual(self.ask("p")["scope"], "project")
        self.assertFalse(self.ask(""))
        self.assertFalse(self.ask("t", task=None))


@require(testbed_unavailable())
class ReportTest(unittest.TestCase):
    def test_authority_log_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = run_eval.Workspace(tmp).prepare()
            dep = run_eval.Deployment(ws)
            dep.pdp.authorize("oss", "shell", "repo://git.test/acme/payments", "read")
            dep.close()
            outs = {}
            for cmd in (["authority", "--ontology", testbed_file("ontology.yaml")], ["log"],
                        ["verify"]):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = ui.main([cmd[0], "--state", ws.core, *cmd[1:]])
                outs[cmd[0]] = (code, buf.getvalue())
            self.assertIn("== work: policy v1 (declared)", outs["authority"][1])
            self.assertIn("shadowing", outs["authority"][1])
            self.assertEqual(outs["verify"], (0, "log verifies\n"))


if __name__ == "__main__":
    unittest.main()
