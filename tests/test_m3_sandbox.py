"""M3: partitions (namespaces, Landlock, egress) without the testbed."""
import os
import random
import socket
import tempfile
import threading
import unittest

from bulkhead.pep.sandbox import Partition
from tests.support import require_sandbox

ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp"}


@require_sandbox
class PartitionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.tmp.name
        cls.home = os.path.join(root, "oss", "home")
        cls.other = os.path.join(root, "work", "home")
        for d in (os.path.join(cls.home, "proj", "secrets"), os.path.join(cls.home, "docs"),
                  cls.other):
            os.makedirs(d)
        files = {os.path.join(cls.home, "proj", "secrets", "key.env"): "KEY=1\n",
                 os.path.join(cls.home, "proj", "README"): "readme\n",
                 os.path.join(cls.home, "docs", "guide"): "guide\n",
                 os.path.join(cls.other, "notes"): "other project\n"}
        for path, text in files.items():
            with open(path, "w") as f:
                f.write(text)
        os.environ["BULKHEAD_TEST_OUTSIDE"] = "must-not-leak"
        cls.part = Partition("oss", cls.home, ENV,
                             hide=[os.path.join(cls.home, "proj", "secrets")],
                             readonly=[os.path.join(cls.home, "docs")]).start()

    @classmethod
    def tearDownClass(cls):
        cls.part.stop()
        os.environ.pop("BULKHEAD_TEST_OUTSIDE", None)
        cls.tmp.cleanup()

    def sh(self, cmd, timeout=20):
        return self.part.run(["bash", "-c", cmd], cwd=self.home, timeout=timeout)

    def test_landlock_applied(self):
        self.assertGreaterEqual(self.part.summary["landlock"]["abi"], 1)

    def test_own_files(self):
        r = self.sh("cat proj/README && echo new > proj/new && cat proj/new")
        self.assertEqual((r["exit"], r["stdout"]), (0, "readme\nnew\n"))

    def test_hidden_and_read_only_folders(self):
        r = self.sh("ls -A proj/secrets; cat proj/secrets/key.env")
        self.assertNotEqual(r["exit"], 0)
        self.assertNotIn("KEY=1", r["stdout"])
        self.assertNotEqual(self.sh("echo x > proj/secrets/x")["exit"], 0)
        self.assertEqual(self.sh("cat docs/guide")["stdout"], "guide\n")
        self.assertNotEqual(self.sh("echo x >> docs/guide")["exit"], 0)

    def test_other_projects_files(self):
        r = self.sh(f"cat {self.other}/notes")
        self.assertNotEqual(r["exit"], 0)
        self.assertNotIn("other project", r["stdout"])

    def test_scrubbed_environment(self):
        out = self.sh("env")["stdout"]
        self.assertNotIn("must-not-leak", out)
        self.assertIn(f"HOME={self.home}", out)

    def test_no_route_out_except_egress(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            r = self.sh(f"python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), 2)\"")
            self.assertNotEqual(r["exit"], 0)
        finally:
            srv.close()
        got = {}

        def accept():
            conn, _ = self.part.listeners["tools"].accept()
            got["data"] = conn.recv(16)
            conn.close()
        t = threading.Thread(target=accept)
        t.start()
        r = self.sh("python3 -c \"import socket; socket.create_connection(('127.0.0.1', 3128), 2).sendall(b'egress')\"")
        t.join(10)
        self.assertEqual((r["exit"], got.get("data")), (0, b"egress"))

    def test_host_sockets_under_run_are_hidden(self):
        with tempfile.TemporaryDirectory(dir="/run") if os.access("/run", os.W_OK) \
                else tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "host.sock")
            srv = socket.socket(socket.AF_UNIX)
            srv.bind(path)
            srv.listen(1)
            try:
                code = f"import socket; socket.socket(socket.AF_UNIX).connect({path!r})"
                r = self.sh(f"python3 -c \"{code}\"")
                self.assertNotEqual(r["exit"], 0)
            finally:
                srv.close()

    def test_processes_outside_cannot_be_signalled(self):
        r = self.sh(f"kill -0 {os.getpid()}")
        self.assertNotEqual(r["exit"], 0)

    def test_timeout(self):
        r = self.part.run(["sleep", "5"], timeout=0.5)
        self.assertTrue(r["timed_out"])


@require_sandbox
class LifecycleTest(unittest.TestCase):
    def test_stop_kills_every_process_in_the_partition(self):
        marker = f"{31 + random.random():.9f}"            # appears in no other command
        with tempfile.TemporaryDirectory() as home:
            part = Partition("x", home, ENV).start()
            r = part.run(["bash", "-c", f"sleep {marker} & echo started"])
            self.assertEqual(r["exit"], 0)
            self.assertTrue(self.running(marker))
            part.stop()
            self.assertEqual(self.running(marker), [])

    @staticmethod
    def running(marker):
        found = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if f.read().split(b"\0")[:2] == [b"sleep", marker.encode()]:
                        found.append(pid)
            except OSError:
                pass
        return found


if __name__ == "__main__":
    unittest.main()
