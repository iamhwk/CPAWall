"""M4: session manager: lazy partitions, switching, policy installs."""
import os
import random
import tempfile
import time
import unittest

from bulkhead.agent.scripted import Oracle
from bulkhead.decisions import Decision
from eval import run_eval
from testbed import setup as tb
from testbed.services import Testbed
from tests.support import compiled, require, sandbox_unavailable, testbed_unavailable

LOOP = """
import time, urllib.request, urllib.error
while True:
    try:
        urllib.request.urlopen('https://git.test/api/repos/acme/payments/issues', timeout=5)
    except Exception:
        pass
    time.sleep(0.1)
"""


def state(marker):
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if f.read().split(b"\0")[:2] == [b"sleep", marker.encode()]:
                    with open(f"/proc/{pid}/stat") as g:
                        return g.read().rsplit(")", 1)[1].split()[0]
        except OSError:
            pass
    return None


@require(testbed_unavailable() or sandbox_unavailable())
class SessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = run_eval.Workspace(self.tmp.name).prepare()
        self.testbed = Testbed(self.ws.srv).serve()
        self.dep = run_eval.Deployment(self.ws)
        self.oracle = Oracle("deny")
        self.dep.begin_trial(self.oracle, ["oss", "work"], task="t-1")
        self.homes = {p: tb.restore(os.path.join(self.ws.snap, "partitions", p, "home"),
                                    os.path.join(self.tmp.name, "p", p, "home"))
                      for p in ("oss", "work")}
        self.sessions = self.dep.sessions(self.homes)

    def tearDown(self):
        self.sessions.stop_all()
        self.dep.close()
        self.testbed.stop()
        self.tmp.cleanup()

    def sleeper(self, project):
        marker = f"{40 + random.random():.9f}"
        r = self.sessions.partition(project).run(["bash", "-c", f"sleep {marker} &"])
        self.assertEqual(r["exit"], 0)
        time.sleep(0.1)
        return marker

    def test_switch_freezes_projects_that_may_not_work_in_the_background(self):
        self.sessions.switch("oss")
        oss = self.sleeper("oss")                 # OSS: background false
        self.sessions.switch("work")
        work = self.sleeper("work")               # Work: background true
        self.assertEqual(state(oss), "T")
        self.sessions.switch("oss")
        self.assertEqual(state(oss), "S")
        self.assertEqual(state(work), "S")        # Work keeps running
        events = [r["event"] for r in self.dep.log.records_since(0) if r.get("event")]
        self.assertEqual(events.count("switch"), 3)

    def test_attribution_does_not_follow_the_active_project(self):
        self.sessions.install(compiled("oss", background=True))
        self.sessions.switch("oss")
        part = self.sessions.partition("oss")
        part.run(["bash", "-c", f"python3 -c \"{LOOP}\" > /dev/null 2>&1 &"])
        time.sleep(0.5)
        offset = self.dep.log.offset()
        self.sessions.switch("work")              # the user turns to Work
        time.sleep(1.0)
        recs = [r for r in self.dep.log.records_since(offset)
                if r.get("resource") == "repo://git.test/acme/payments"]
        self.assertTrue(recs)
        self.assertTrue(all(r["project"] == "oss" and r["final"] == "deny" for r in recs))

    def test_install_restarts_a_partition_whose_layout_changes(self):
        work = self.sessions.partition("work")
        hidden = work.run(["cat", "work/payments/secrets/staging.env"], cwd=self.homes["work"])
        self.assertNotEqual(hidden["exit"], 0)
        data = compiled("work").to_dict()
        relaxed = [e for e in data["entries"] if "secrets" not in e[0]]
        from bulkhead.policy.compiler import CompiledPolicy
        v = self.sessions.install(CompiledPolicy.from_dict(dict(data, entries=relaxed)))
        self.assertEqual(v, 2)
        again = self.sessions.partition("work")
        self.assertIsNot(again, work)
        shown = again.run(["cat", "work/payments/secrets/staging.env"], cwd=self.homes["work"])
        self.assertEqual(shown["exit"], 0)

    def test_approvals_lapse_with_a_new_version(self):
        self.dep.pdp.oracle = Oracle([{"approve": True, "scope": "project"}])
        v1 = self.dep.pdp.authorize("work", "shell", "repo://git.test/acme/payments", "push")
        self.assertEqual(v1.decision, Decision.ALLOW)
        self.sessions.install(compiled("work"))
        v2 = self.dep.pdp.authorize("work", "shell", "repo://git.test/acme/payments", "push")
        self.assertEqual((v2.version, v2.decision, v2.asked), (2, Decision.DENY, True))


if __name__ == "__main__":
    unittest.main()
