"""M1: resource patterns."""
import unittest

from bulkhead.policy import patterns as P


class MatchTest(unittest.TestCase):
    def test_schemes_never_match_each_other(self):
        self.assertTrue(P.match("web://*", "web://example.org"))
        self.assertFalse(P.match("web://*", "repo://git.test/acme/payments"))

    def test_star_is_one_segment(self):
        self.assertTrue(P.match("repo://git.test/acme/*", "repo://git.test/acme/payments"))
        self.assertFalse(P.match("repo://git.test/acme/*", "repo://git.test/acme/a/b"))
        self.assertFalse(P.match("repo://git.test/acme/*", "repo://git.test/oss/libfoo"))
        self.assertTrue(P.match("repo://git.test/acme-*/x", "repo://git.test/acme-eu/x"))

    def test_double_star_is_zero_or_more_segments(self):
        pat = "file://~/work/payments/**"
        self.assertTrue(P.match(pat, "file://~/work/payments"))
        self.assertTrue(P.match(pat, "file://~/work/payments/secrets/staging.env"))
        self.assertFalse(P.match(pat, "file://~/work/payments-old/x"))
        self.assertTrue(P.match("file:///srv/**", "file:///srv/a"))

    def test_validate(self):
        for bad in ("repo:/x", "://x", "repo://a//b", "repo://a/b**"):
            with self.assertRaises(ValueError, msg=bad):
                P.validate(bad)
        P.validate("file:///srv/**")


class RelationTest(unittest.TestCase):
    def test_covers(self):
        self.assertTrue(P.covers("repo://git.test/*/*", "repo://git.test/acme/*"))
        self.assertFalse(P.covers("repo://git.test/acme/*", "repo://git.test/*/*"))
        self.assertTrue(P.covers("file://~/w/**", "file://~/w/secrets/**"))
        self.assertFalse(P.covers("file://~/w/*", "file://~/w/**"))
        self.assertTrue(P.covers("repo://git.test/acme/*", "repo://git.test/acme/payments"))
        self.assertFalse(P.covers("web://*", "repo://git.test/acme/payments"))

    def test_overlaps(self):
        self.assertTrue(P.overlaps("repo://git.test/acme/*", "repo://git.test/*/payments"))
        self.assertFalse(P.overlaps("repo://git.test/acme/*", "repo://git.test/oss/*"))
        self.assertTrue(P.overlaps("file://~/w/**", "file://~/w/secrets/x"))

    def test_intersection(self):
        self.assertEqual(P.intersection("repo://git.test/*/payments", "repo://git.test/acme/*"),
                         "repo://git.test/acme/payments")
        self.assertEqual(P.intersection("file://~/w/**", "file://~/w/secrets/*"),
                         "file://~/w/secrets/*")
        self.assertIsNone(P.intersection("repo://git.test/acme/*", "repo://git.test/oss/*"))
        self.assertIsNone(P.intersection("web://*", "repo://git.test/a/b"))

    def test_witnesses(self):
        self.assertEqual(P.witnesses("file://~/w/**"), ["file://~/w", "file://~/w/{any}"])
        self.assertEqual(P.witnesses("repo://git.test/acme-*/x"),
                         ["repo://git.test/acme-{any}/x"])
        w = P.witnesses("repo://git.test/*/*")[0]
        self.assertTrue(P.is_witness(w))
        self.assertTrue(P.match("repo://git.test/*/*", w))
        self.assertFalse(P.match("repo://git.test/acme/*", w))


if __name__ == "__main__":
    unittest.main()
