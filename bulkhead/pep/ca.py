"""The deployment's CA, which only partitions trust (design, consideration 5).

The HTTP(S) PEP terminates TLS for every CONNECT with a certificate for
the requested host, minted here on first use and cached. Partitions get
the CA certificate through the CA variables (bulkhead.env); the key stays
in the core.
"""
import datetime
import ipaddress
import os
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _write(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class CertificateAuthority:
    def __init__(self, directory, days=365):
        self.dir = directory
        self.days = days
        self.cert_path = os.path.join(directory, "ca.pem")
        self._key_path = os.path.join(directory, "ca.key")
        self._leaves = os.path.join(directory, "leaves")
        self._contexts = {}
        self._lock = threading.Lock()
        os.makedirs(self._leaves, exist_ok=True)
        os.chmod(self._leaves, 0o700)
        if os.path.exists(self._key_path):
            with open(self._key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(f.read(), None)
            with open(self.cert_path, "rb") as f:
                self._cert = x509.load_pem_x509_certificate(f.read())
        else:
            self._create()

    def _create(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bulkhead deployment CA")])
        self._cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=self.days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()),
                           critical=False)
            .sign(self._key, hashes.SHA256()))
        _write(self._key_path, _pem_key(self._key), 0o600)
        _write(self.cert_path, self._cert.public_bytes(serialization.Encoding.PEM))

    def _leaf(self, host):
        now = datetime.datetime.now(datetime.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256()))
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
        path = os.path.join(self._leaves, safe + ".pem")
        _write(path, cert.public_bytes(serialization.Encoding.PEM) + _pem_key(key), 0o600)
        return path

    def server_context(self, host):
        """A TLS server context presenting a certificate for `host`."""
        host = host.lower()
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(self._leaf(host))
                ctx.set_alpn_protocols(["http/1.1"])
                self._contexts[host] = ctx
            return ctx
