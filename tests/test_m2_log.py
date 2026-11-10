"""M2: hash-chained log with signed checkpoints."""
import json
import os
import tempfile
import unittest

from bulkhead.core.log import DecisionLog, Signer, verify


class LogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "log.jsonl")
        self.signer = Signer.load_or_create(os.path.join(self.tmp.name, "log.key"))
        self.pub = self.signer.public_pem()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, n=10, every=4):
        log = DecisionLog(self.path, self.signer, checkpoint_every=every)
        for i in range(n):
            log.append({"project": "oss", "resource": f"repo://git.test/a/{i}", "op": "read",
                        "decision": "allow"})
        log.close()
        return log

    def lines(self):
        with open(self.path) as f:
            return f.read().splitlines()

    def rewrite(self, lines):
        with open(self.path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def test_intact(self):
        self.write()
        self.assertEqual(verify(self.path, self.pub), [])
        cps = open(self.path + ".checkpoints").read().splitlines()
        self.assertEqual([json.loads(c)["seq"] for c in cps], [4, 8, 10])

    def test_edit_is_detected(self):
        self.write()
        lines = self.lines()
        rec = json.loads(lines[2])
        rec["decision"] = "deny"
        lines[2] = json.dumps(rec)
        self.rewrite(lines)
        self.assertTrue(any("hash does not match" in p for p in verify(self.path, self.pub)))

    def test_edit_with_rehash_breaks_the_chain(self):
        from bulkhead.core.log import canonical, record_hash
        self.write()
        lines = self.lines()
        rec = json.loads(lines[2])
        rec["decision"] = "deny"
        rec["hash"] = record_hash(rec)
        lines[2] = canonical(rec)
        self.rewrite(lines)
        self.assertTrue(any("prev does not match" in p for p in verify(self.path, self.pub)))

    def test_rewritten_chain_is_caught_by_the_checkpoints(self):
        from bulkhead.core.log import GENESIS, canonical, record_hash
        self.write()
        prev, out = GENESIS, []
        for i, line in enumerate(self.lines()):
            rec = json.loads(line)
            if i == 2:
                rec["decision"] = "deny"
            rec["prev"] = prev
            rec["hash"] = prev = record_hash(rec)
            out.append(canonical(rec))
        self.rewrite(out)
        problems = verify(self.path, self.pub)
        self.assertFalse(any("prev" in p or "hash does not" in p for p in problems))
        self.assertTrue(any(p.startswith("checkpoint 4") for p in problems))
        # rewriting the checkpoints too needs the key: without it, the
        # signatures fail
        hashes = {json.loads(x)["seq"]: json.loads(x)["hash"] for x in out}
        cps = [json.loads(x) for x in open(self.path + ".checkpoints").read().splitlines()]
        with open(self.path + ".checkpoints", "w") as f:
            for cp in cps:
                f.write(canonical(dict(cp, hash=hashes[cp["seq"]])) + "\n")
        self.assertEqual(verify(self.path), [])
        self.assertTrue(all("bad signature" in p for p in verify(self.path, self.pub)))

    def test_deletion_and_reordering(self):
        self.write()
        lines = self.lines()
        self.rewrite(lines[:3] + lines[4:])
        self.assertTrue(verify(self.path, self.pub))
        self.rewrite([lines[1], lines[0]] + lines[2:])
        self.assertTrue(verify(self.path, self.pub))

    def test_truncation_before_a_checkpoint(self):
        self.write()
        self.rewrite(self.lines()[:6])
        self.assertTrue(any("does not reach" in p for p in verify(self.path, self.pub)))

    def test_forged_checkpoint(self):
        self.write()
        other = Signer.load_or_create(os.path.join(self.tmp.name, "other.key"))
        self.assertTrue(any("bad signature" in p for p in verify(self.path, other.public_pem())))

    def test_resume_and_unfixed_tail(self):
        self.write(5, every=4)
        log = DecisionLog(self.path, self.signer, checkpoint_every=4)
        rec = log.append({"project": "work"})
        self.assertEqual(rec["seq"], 6)
        self.assertEqual(verify(self.path, self.pub), ["records 6-6 are after the last checkpoint"])
        log.close()
        self.assertEqual(verify(self.path, self.pub), [])

    def test_key_is_private(self):
        self.assertEqual(os.stat(os.path.join(self.tmp.name, "log.key")).st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
