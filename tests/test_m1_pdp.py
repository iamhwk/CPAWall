"""M1: PDP with versions, approvals, tighten-only hooks."""
import os
import tempfile
import unittest

from bulkhead.core.pdp import PDP, Approvals, PolicyStore
from bulkhead.decisions import Decision
from tests.support import compiled

A, Q, D = Decision.ALLOW, Decision.ASK, Decision.DENY
ACME = "repo://git.test/acme/payments"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Oracle:
    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def __call__(self, q):
        self.asked.append(q)
        return self.answers.pop(0) if self.answers else False


def pdp(oracle=None, clock=None, archive=None, **changes):
    store = PolicyStore(archive)
    store.install(compiled("work", **changes))
    store.install(compiled("oss"))
    return PDP(store, oracle, Approvals(clock or Clock()))


class DecideTest(unittest.TestCase):
    def test_pure_and_channel_blind(self):
        p = pdp()
        a = p.decide("work", "shell", ACME, "push")
        self.assertEqual(a, p.decide("work", "mcp", ACME, "push"))
        self.assertEqual(a[0], Q)
        self.assertEqual(a[1], 1)
        self.assertIn("policy repo://git.test/acme/*", a[2])
        self.assertEqual(p.decide("oss", "shell", ACME, "read")[0], D)

    def test_versions_are_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(tmp)
            self.assertEqual(store.install(compiled("work")), 1)
            self.assertEqual(store.install(compiled("work")), 2)
            self.assertEqual(store.current("work").version, 2)
            old = PolicyStore.load_archived(os.path.join(tmp, "work", "v1.json"))
            self.assertEqual(old.version, 1)
            self.assertEqual(old.decide(ACME, "push")[0], Q)

    def test_unmapped_state_changing_requests_are_capped(self):
        web = {"web://*": {"read": "allow", "act": "allow"}}
        grants = {"browser": [{"site": "*", "ops": {"read": "allow", "act": "allow"}}]}
        p = pdp(policy=web, grants=grants)
        self.assertEqual(p.decide("work", "browser", "web://example.org", "act", mapped=False)[0], Q)
        self.assertEqual(p.decide("work", "browser", "web://example.org", "read", mapped=False)[0], A)
        p = pdp(policy=web, grants=grants, unmapped="deny")
        self.assertEqual(p.decide("work", "browser", "web://example.org", "act", mapped=False)[0], D)


    def test_cached_decisions_follow_the_version(self):
        p = pdp()
        p.cache_size = 2
        self.assertEqual(p.decide("work", "shell", ACME, "push")[:2], (Q, 1))
        self.assertEqual(p.decide("work", "shell", ACME, "push")[:2], (Q, 1))   # cached
        p.store.install(compiled("work", policy={"repo://git.test/acme/*": {
            "read": "allow", "push": "allow"}}))
        self.assertEqual(p.decide("work", "shell", ACME, "push")[:2], (A, 2))   # new key
        p.decide("work", "shell", ACME, "read")
        p.decide("oss", "shell", ACME, "read")
        self.assertEqual(len(p._cache), 2)                                       # bounded
        uncached = PDP(p.store, cache_size=0)
        self.assertEqual(uncached.decide("work", "mcp", ACME, "push")[:2], (A, 2))
        self.assertEqual(len(uncached._cache), 0)


class AskTest(unittest.TestCase):
    def test_without_a_trusted_ui_ask_is_deny(self):
        v = pdp().authorize("work", "shell", ACME, "push")
        self.assertEqual((v.policy_decision, v.decision, v.asked), (Q, D, False))

    def test_declined_and_approved(self):
        o = Oracle(False, True)
        p = pdp(o)
        v = p.authorize("work", "shell", ACME, "push", request="git push")
        self.assertEqual((v.decision, v.asked, v.approval), (D, True, None))
        v = p.authorize("work", "mcp", ACME, "push")
        self.assertEqual((v.decision, v.asked), (A, True))
        self.assertIsNotNone(v.approval)
        self.assertEqual(o.asked[0]["request"], "git push")
        v = p.authorize("work", "mcp", ACME, "push")      # request scope: asked again
        self.assertTrue(v.asked)

    def test_task_scope(self):
        o = Oracle({"approve": True, "scope": "task"})
        p = pdp(o)
        self.assertEqual(p.authorize("work", "shell", ACME, "push", task="t1").decision, A)
        v = p.authorize("work", "mcp", ACME, "push", task="t1")
        self.assertEqual((v.decision, v.asked), (A, False))
        v = p.authorize("work", "mcp", ACME, "push", task="t2")
        self.assertEqual((v.decision, v.asked), (D, True))

    def test_project_scope_with_a_time_limit(self):
        clock = Clock()
        p = pdp(Oracle({"approve": True, "scope": "project", "ttl": 60}), clock)
        self.assertEqual(p.authorize("work", "shell", ACME, "push").decision, A)
        clock.t += 30
        self.assertFalse(p.authorize("work", "shell", ACME, "push").asked)
        clock.t += 31
        v = p.authorize("work", "shell", ACME, "push")
        self.assertEqual((v.decision, v.asked), (D, True))

    def test_approvals_lapse_with_the_version(self):
        p = pdp(Oracle({"approve": True, "scope": "project"}))
        self.assertEqual(p.authorize("work", "shell", ACME, "push").decision, A)
        p.store.install(compiled("work"))                 # v2: same content, new version
        v = p.authorize("work", "shell", ACME, "push")
        self.assertEqual((v.version, v.decision, v.asked), (2, D, True))

    def test_approvals_do_not_cross_projects(self):
        p = pdp(Oracle({"approve": True, "scope": "project"}))
        p.authorize("work", "shell", ACME, "push")
        self.assertEqual(p.authorize("oss", "shell", ACME, "push").decision, D)


class HookTest(unittest.TestCase):
    def test_hooks_only_tighten(self):
        p = pdp(Oracle(True))
        p.add_hook(lambda *a: A)                  # would loosen: ignored
        v = p.authorize("oss", "shell", ACME, "read")
        self.assertEqual((v.decision, v.hooked), (D, None))
        p.add_hook(lambda pr, c, r, o, d: D if o == "read" else None)
        v = p.authorize("work", "shell", ACME, "read")
        self.assertEqual((v.policy_decision, v.decision, v.hooked), (A, D, D))
        self.assertEqual(v.record()["decision"], "allow")
        self.assertEqual(v.record()["final"], "deny")


if __name__ == "__main__":
    unittest.main()
