"""M3: Landlock wrapper, exercised in child processes."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from bulkhead.pep import landlock
from tests.support import require

HERE = os.path.dirname(os.path.abspath(__file__))
CHILD = r"""
import ctypes, json, os, sys
sys.path.insert(0, sys.argv[1])
from bulkhead.pep import landlock
allowed, other, scoped = sys.argv[2], sys.argv[3], sys.argv[4] == "1"
ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)              # no_new_privs
summary = landlock.restrict([(allowed, landlock.READ_ONLY)], scoped=scoped)
out = {"abi": summary["abi"], "scoped": summary["scoped"]}
def attempt(name, fn):
    try:
        fn()
        out[name] = "ok"
    except OSError as e:
        out[name] = e.__class__.__name__
attempt("read_allowed", lambda: open(os.path.join(allowed, "a.txt")).read())
attempt("write_allowed", lambda: open(os.path.join(allowed, "a.txt"), "w").write("x"))
attempt("read_other", lambda: open(os.path.join(other, "b.txt")).read())
attempt("signal_parent", lambda: os.kill(os.getppid(), 0))
print(json.dumps(out))
"""


@require(None if landlock.abi_version() >= 1 else "Landlock is not available")
class LandlockTest(unittest.TestCase):
    def child(self, scoped):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            for d, name in ((a, "a.txt"), (b, "b.txt")):
                with open(os.path.join(d, name), "w") as f:
                    f.write("data")
            r = subprocess.run([sys.executable, "-c", CHILD, os.path.join(HERE, ".."), a, b,
                                "1" if scoped else "0"], capture_output=True, text=True,
                               timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)

    def test_allow_list(self):
        out = self.child(scoped=False)
        self.assertEqual(out["read_allowed"], "ok")
        self.assertEqual(out["write_allowed"], "PermissionError")
        self.assertEqual(out["read_other"], "PermissionError")

    def test_signal_scoping(self):
        if landlock.abi_version() < 6:
            self.skipTest("signal scoping needs Landlock ABI 6")
        self.assertEqual(self.child(scoped=False)["signal_parent"], "ok")
        out = self.child(scoped=True)
        self.assertTrue(out["scoped"])
        self.assertEqual(out["signal_parent"], "PermissionError")


if __name__ == "__main__":
    unittest.main()
