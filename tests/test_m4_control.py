"""M4: the trusted UI's channel into the core: switching, approvals,
status, and who can reach it."""
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout

from bulkhead.core import control, ui
from bulkhead.core.pdp import PolicyStore
from bulkhead.core.session import SessionManager
from bulkhead.decisions import Decision
from tests.support import (compiled, require, sandbox_unavailable, testbed_unavailable)

PROTOTYPE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTION = {"project": "work", "channel": "tools", "resource": "repo://git.test/acme/payments",
            "op": "push", "version": 1, "task": "t-1", "request": "POST git-receive-pack"}
CONNECT = """
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect({address!r})
    s.sendall(b'{{"cmd": "switch", "project": "oss"}}\\n')
    print('reached:', s.recv(4096))
except OSError as e:
    print('refused:', e)
"""


class FakePartition:
    def __init__(self):
        self.frozen = False

    def freeze(self):
        self.frozen = True

    def thaw(self):
        self.frozen = False


class ControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        store = PolicyStore()
        store.install(compiled("oss"))
        store.install(compiled("work"))
        self.sessions = SessionManager(start=lambda p: (FakePartition(), lambda: None),
                                       store=store)
        self.server = control.ControlServer(self.tmp.name, self.sessions, timeout=5).start()

    def tearDown(self):
        self.server.close()
        self.tmp.cleanup()

    def main(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ui.main([*argv, "--state", self.tmp.name])
        return code, buf.getvalue()

    def answer_in_thread(self, oracle, q=QUESTION):
        out = {}
        t = threading.Thread(target=lambda: out.update(answer=oracle(q)))
        t.start()
        return t, out

    def test_switch_and_status(self):
        self.sessions.partition("oss")
        self.assertEqual(self.main("switch", "oss")[0], 0)
        code, text = self.main("switch", "work")
        self.assertEqual((code, self.sessions.active), (0, "work"))
        self.assertIn("active project: work (frozen: oss)", text)
        code, text = self.main("status")
        self.assertIn("active project: work", text)
        self.assertIn("oss      policy v1   partition frozen", text)

    def test_unknown_project_is_refused(self):
        code, text = self.main("switch", "elsewhere")
        self.assertEqual((code, self.sessions.active), (1, None))
        self.assertIn("no project 'elsewhere'", text)

    def test_answers_reach_the_pdp(self):
        oracle = control.UiOracle(self.server)
        for answer, expected in (("t", {"approve": True, "scope": "task"}),
                                 ("p", {"approve": True, "scope": "project", "ttl": 3600}),
                                 ("n", False)):
            t, out = self.answer_in_thread(oracle)
            client = ui.Client(self.tmp.name)
            client.send({"cmd": "subscribe"})
            ask = None
            while ask is None:
                for msg in client.feed(client.sock.recv(65536)):
                    if msg.get("type") == "ask":
                        ask = msg
            self.assertEqual((ask["project"], ask["op"]), ("work", "push"))
            self.assertTrue(client.call({"cmd": "answer", "id": ask["id"], "answer": answer})["ok"])
            t.join(5)
            client.close()
            self.assertEqual(out["answer"], expected)

    def test_an_unanswered_question_is_denied(self):
        self.server.timeout = 0.2
        self.assertFalse(control.UiOracle(self.server)(QUESTION))

    def test_console(self):
        """A person at the console: sees the question, answers it, switches."""
        t, out = self.answer_in_thread(control.UiOracle(self.server))
        proc = subprocess.Popen([sys.executable, "-u", "-m", "bulkhead.core.ui", "console",
                                 "--state", self.tmp.name], cwd=PROTOTYPE, text=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        try:
            seen = ""
            while "-> answer: y 1" not in seen:
                line = proc.stdout.readline()
                self.assertTrue(line, seen)
                seen += line
            proc.stdin.write("y\nswitch work\n")
            proc.stdin.flush()
            t.join(5)
            self.assertEqual(out["answer"], {"approve": True, "scope": "request"})
            deadline = time.monotonic() + 5
            while self.sessions.active != "work" and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(self.sessions.active, "work")
            proc.stdin.write("quit\n")
            proc.stdin.flush()
            self.assertEqual(proc.wait(5), 0)
        finally:
            proc.kill()
            proc.stdout.close()
            proc.stdin.close()

    def test_no_core(self):
        with tempfile.TemporaryDirectory() as other:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = ui.main(["status", "--state", other])
        self.assertEqual(code, 1)
        self.assertIn("no Bulkhead core is serving", buf.getvalue())


@require(sandbox_unavailable())
class OtherNamespaceTest(unittest.TestCase):
    def test_another_network_namespace_cannot_connect(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore()
            store.install(compiled("oss"))
            sessions = SessionManager(start=lambda p: (FakePartition(), lambda: None),
                                      store=store)
            server = control.ControlServer(tmp, sessions).start()
            try:
                code = ("import os; os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)\n" +
                        CONNECT.format(address=control.control_address(tmp)))
                r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                   timeout=30)
                self.assertIn("refused:", r.stdout, r.stderr)
                self.assertIsNone(sessions.active)
                # the same code in our own namespace gets through
                r = subprocess.run([sys.executable, "-c",
                                    CONNECT.format(address=control.control_address(tmp))],
                                   capture_output=True, text=True, timeout=30)
                self.assertIn("reached:", r.stdout, r.stderr)
                self.assertEqual(sessions.active, "oss")
            finally:
                server.close()


@require(testbed_unavailable() or sandbox_unavailable())
class TrustedUiTest(unittest.TestCase):
    """End to end: partitions, the PEP, the PDP, and the trusted UI."""

    def setUp(self):
        from bulkhead.agent.scripted import Oracle
        from eval import run_eval
        from testbed import setup as tb
        from testbed.services import Testbed
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = run_eval.Workspace(self.tmp.name).prepare()
        self.testbed = Testbed(self.ws.srv).serve()
        self.dep = run_eval.Deployment(self.ws)
        self.dep.begin_trial(Oracle("deny"), ["oss", "work"], task="t-1")
        self.homes = {p: tb.restore(os.path.join(self.ws.snap, "partitions", p, "home"),
                                    os.path.join(self.tmp.name, "p", p, "home"))
                      for p in ("oss", "work")}
        self.sessions = self.dep.sessions(self.homes)
        self.server = self.dep.serve_ui(self.sessions, timeout=20)
        # start the partitions here: the sandbox ties a partition's life to
        # the thread that starts it (PR_SET_PDEATHSIG), and the pushes run
        # in short-lived threads
        for project in ("oss", "work"):
            self.sessions.partition(project)

    def tearDown(self):
        self.sessions.stop_all()
        self.dep.close()
        self.testbed.stop()
        self.tmp.cleanup()

    def test_a_partition_cannot_reach_the_trusted_ui(self):
        r = self.sessions.partition("oss").run(
            ["python3", "-c", CONNECT.format(address=self.server.address)])
        self.assertIn("refused:", r["stdout"], r["stderr"])
        self.assertIsNone(self.sessions.active)

    def push(self, message):
        return self.sessions.partition("work").run(
            ["bash", "-c", f"git commit --allow-empty -qm {message} && git push -q"],
            cwd=os.path.join(self.homes["work"], "work", "payments"), timeout=60)

    def test_a_push_waits_for_the_trusted_ui(self):
        client = ui.Client(self.ws.core, timeout=30)
        try:
            client.send({"cmd": "subscribe"})
            peps = [*self.dep.peps.values(), *self.dep.browser_peps.values(),
                    *self.dep.connector_peps.values()]
            for answer, expect_exit in (("t", 0), ("n", 128)):
                for pep in peps:                  # each push is a task of its own
                    pep.task = f"push-{answer}"
                out = {}
                t = threading.Thread(target=lambda: out.update(r=self.push(answer)))
                t.start()
                ask = None
                while ask is None:
                    for msg in client.feed(client.sock.recv(65536)):
                        if msg.get("type") == "ask":
                            ask = msg
                self.assertEqual((ask["project"], ask["op"], ask["resource"]),
                                 ("work", "push", "repo://git.test/acme/payments"))
                client.send({"cmd": "answer", "id": ask["id"], "answer": answer})
                t.join(60)
                self.assertEqual(out["r"]["exit"], expect_exit, out["r"]["stderr"])
        finally:
            client.close()
        verdicts = [r for r in self.dep.log.records_since(0)
                    if r.get("op") == "push" and r.get("project") == "work"]
        self.assertEqual({r["final"] for r in verdicts}, {"allow", "deny"})
        self.assertEqual(Decision.parse(verdicts[0]["decision"]), Decision.ASK)


if __name__ == "__main__":
    unittest.main()
