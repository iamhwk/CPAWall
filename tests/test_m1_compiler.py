"""M1: compiler (policy or meet, P3 check) on the running example."""
import unittest

from bulkhead.decisions import Decision
from bulkhead.policy.compiler import CompileError, CompiledPolicy, compile_manifest
from bulkhead.policy.schema import parse_manifest
from tests.support import compiled, ontology

A, Q, D = Decision.ALLOW, Decision.ASK, Decision.DENY
ACME = "repo://git.test/acme/payments"
LIBFOO = "repo://git.test/oss/libfoo"
SECRET = "file://~/work/payments/secrets/staging.env"


def items(pol, kind=None, channel=None, op=None, witness=None):
    return [i for i in pol.check if (kind is None or i.kind == kind)
            and (channel is None or i.channel == channel) and (op is None or i.op == op)
            and (witness is None or i.witness == witness)]


def small(policy, grants, **kw):
    data = {"project": "t", "grants": grants, **kw}
    if policy is not None:
        data["policy"] = policy
    return compile_manifest(parse_manifest(data), ontology())


class RunningExampleTest(unittest.TestCase):
    def test_oss_declared(self):
        p = compiled("oss")
        self.assertEqual(p.decide(ACME, "read")[0], D)   # a clone during review: denied
        self.assertEqual(p.decide(LIBFOO, "push")[0], A)
        self.assertEqual(p.decide("web://example.org", "read")[0], A)
        self.assertEqual(p.decide("repo://git.test/x/y", "read")[0], D)   # web wildcard
        self.assertEqual(p.check, ())

    def test_work_declared(self):
        p = compiled("work")
        self.assertEqual(p.mode, "declared")
        self.assertEqual(p.decide(ACME, "read")[0], A)
        self.assertEqual(p.decide(ACME, "push")[0], Q)
        self.assertEqual(p.decide(ACME, "comment")[0], D)
        self.assertEqual(p.decide(LIBFOO, "push")[0], D)
        self.assertEqual(p.decide(SECRET, "read")[0], D)    # overlapping entries: the minimum
        self.assertEqual(p.decide("file://~/work/payments/README.md", "write")[0], A)

    def test_work_check_reports_the_shells_site_grant(self):
        p = compiled("work")
        shadow = items(p, "excess", "shell", "push", ACME)
        self.assertEqual(len(shadow), 1)
        self.assertEqual((shadow[0].granted, shadow[0].policy, shadow[0].relation),
                         (A, Q, "shadowing"))
        other = items(p, "excess", "shell", "push", LIBFOO)
        self.assertEqual((other[0].granted, other[0].policy, other[0].relation),
                         (A, D, "unbacked"))
        self.assertEqual(items(p, channel="mcp"), [])
        self.assertEqual(items(p, channel="fs"), [])
        self.assertEqual(items(p, "relaxed"), [])

    def test_work_meet(self):
        p = compiled("work", drop_policy=True)
        self.assertEqual(p.mode, "meet")
        self.assertEqual(p.decide(ACME, "push")[0], Q)      # min(shell allow, mcp ask)
        self.assertEqual(p.decide(LIBFOO, "push")[0], A)    # only the shell defines it
        self.assertEqual(p.decide(SECRET, "read")[0], D)
        self.assertEqual(p.decide("db://staging", "write")[0], Q)
        found = items(p, "excess", "shell", "push", ACME)
        self.assertEqual(found[0].relation, "shadowing")
        self.assertEqual(items(p, "excess", witness=LIBFOO), [])   # the meet lets it stand
        self.assertEqual(items(p, "relaxed"), [])                  # never under the meet


class RelationTest(unittest.TestCase):
    def test_relaxed(self):
        p = small({"file://~/w/**": {"read": "allow"}},
                  {"fs": [{"path": "~/w", "ops": {"read": "allow"}},
                          {"path": "~/w/secrets", "ops": {"read": "deny"}}]})
        r = items(p, "relaxed", "fs", "read")
        self.assertTrue(r)
        self.assertTrue(all(i.granted == D and i.policy == A for i in r))

    def test_exception_and_correlation(self):
        policy = {"repo://git.test/acme/*": {"push": "ask"}}
        exc = small(policy, {"mcp": [{"server": "github", "resource": ACME,
                                      "ops": {"push": "allow"}}]})
        self.assertEqual(items(exc, "excess", "mcp", "push", ACME)[0].relation, "exception")
        cor = small(policy, {"shell": [{"resource": "repo://git.test/*/payments",
                                        "ops": {"push": "allow"}}]})
        self.assertEqual(items(cor, "excess", "shell", "push", ACME)[0].relation, "correlation")

    def test_errors(self):
        for policy, grants in (
                ({"mail://x": {"read": "allow"}}, {}),
                ({"repo://git.test/a/b": {"delete": "allow"}}, {}),
                (None, {"shell": [{"site": "https://git.test", "ops": {"push": "allow"}}]}),
                (None, {"fs": [{"path": "work", "ops": {"read": "allow"}}]})):
            with self.assertRaises(CompileError):
                small(policy, grants or {"shell": [{"resource": ACME, "ops": {"read": "allow"}}]})


class SerializationTest(unittest.TestCase):
    def test_round_trip(self):
        p = compiled("work").with_version(3)
        q = CompiledPolicy.from_dict(p.to_dict())
        self.assertEqual(q.digest(), p.digest())
        self.assertEqual(q.version, 3)
        self.assertEqual(q.check, p.check)
        for r, o in ((ACME, "push"), (SECRET, "read"), (LIBFOO, "read")):
            self.assertEqual(q.decide(r, o), p.decide(r, o))

    def test_digest_depends_on_the_policy_only(self):
        self.assertEqual(compiled("work").digest(), compiled("work", background=False).digest())
        self.assertNotEqual(compiled("work").digest(), compiled("work", unmapped="deny").digest())


if __name__ == "__main__":
    unittest.main()
