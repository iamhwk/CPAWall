"""M2: credential vault and the deployment CA."""
import base64
import ssl
import tempfile
import unittest

from bulkhead.core.vault import PLACEHOLDER, Credential, Vault, is_placeholder
from bulkhead.pep.ca import CertificateAuthority


def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.v = Vault({"work": {"https://git.test": {"kind": "basic", "user": "work-bot",
                                                      "secret": "s3"}}})

    def test_inject_where_absent_or_placeholder(self):
        h, how = self.v.inject("work", "https://git.test", [("Accept", "*/*")])
        self.assertEqual(how, "vault")
        self.assertIn(("Authorization", basic("work-bot", "s3")), h)
        h, how = self.v.inject("work", "https://git.test",
                               [("Authorization", basic("work-bot", PLACEHOLDER))])
        self.assertEqual((how, h), ("vault", [("Authorization", basic("work-bot", "s3"))]))

    def test_request_credentials_are_left_alone(self):
        own = [("Authorization", "Bearer users-own-token")]
        self.assertEqual(self.v.inject("work", "https://git.test", own), (own, "request"))

    def test_no_credential_for_project_or_site(self):
        ph = [("Authorization", "Bearer " + PLACEHOLDER)]
        self.assertEqual(self.v.inject("oss", "https://git.test", ph), ([], "none"))
        self.assertEqual(self.v.inject("work", "https://cloud.test", []), ([], "none"))

    def test_placeholders(self):
        self.assertTrue(is_placeholder("Bearer " + PLACEHOLDER))
        self.assertTrue(is_placeholder(basic("x", PLACEHOLDER + "-git")))
        self.assertFalse(is_placeholder(basic("x", "real")))
        self.assertEqual(Vault.strip_placeholders([("authorization", "Bearer " + PLACEHOLDER)]), [])
        self.assertEqual(Credential("bearer", "t").header(), "Bearer t")


def handshake(server_ctx, client_ctx, host):
    s_in, s_out, c_in, c_out = (ssl.MemoryBIO() for _ in range(4))
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=host)
    for _ in range(10):
        for side, out, peer_in in ((client, c_out, s_in), (server, s_out, c_in)):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
            peer_in.write(out.read())
        if client.version() and server.version():
            return client
    raise AssertionError("handshake did not finish")


class CATest(unittest.TestCase):
    def test_minted_certificates_verify_against_the_ca_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = CertificateAuthority(tmp)
            trusting = ssl.create_default_context(cafile=ca.cert_path)
            c = handshake(ca.server_context("git.test"), trusting, "git.test")
            self.assertEqual(c.selected_alpn_protocol(), None)
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(ca.server_context("git.test"), trusting, "cloud.test")
            other = CertificateAuthority(tmp + "/other")
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(ca.server_context("git.test"),
                          ssl.create_default_context(cafile=other.cert_path), "git.test")
            self.assertIs(ca.server_context("GIT.test"), ca.server_context("git.test"))
            again = CertificateAuthority(tmp)          # reloads the same CA
            handshake(again.server_context("db.test"), trusting, "db.test")


if __name__ == "__main__":
    unittest.main()
