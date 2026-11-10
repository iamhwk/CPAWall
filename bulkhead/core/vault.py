"""Per-project credential vault (design, consideration 6).

Long-lived credentials stay in the core, one set per project and site.
Tools inside a partition hold at most a placeholder. The PEP calls
`inject` only for a request that is allowed and that the mapping
attributes to a named resource. Then it replaces a placeholder, or adds
the credential where the request carries none; a credential the request
brings itself is left alone. Requests that are not injected lose their
placeholders.
"""
import base64
import json
from dataclasses import dataclass

PLACEHOLDER = "bulkhead-placeholder"


@dataclass(frozen=True)
class Credential:
    kind: str                 # 'basic' or 'bearer'
    secret: str
    user: str | None = None

    def header(self):
        if self.kind == "basic":
            raw = f"{self.user}:{self.secret}".encode()
            return "Basic " + base64.b64encode(raw).decode()
        if self.kind == "bearer":
            return "Bearer " + self.secret
        raise ValueError(f"unknown credential kind {self.kind!r}")


def is_placeholder(value):
    scheme, _, rest = (value or "").partition(" ")
    rest = rest.strip()
    if scheme.lower() == "bearer":
        return rest == "" or rest.startswith(PLACEHOLDER)
    if scheme.lower() == "basic":
        try:
            _, _, pw = base64.b64decode(rest).decode().partition(":")
        except Exception:
            return False
        return pw.startswith(PLACEHOLDER)
    return False


def _auth(headers):
    return [v for k, v in headers if k.lower() == "authorization"]


def _without_auth(headers):
    return [(k, v) for k, v in headers if k.lower() != "authorization"]


class Vault:
    def __init__(self, data=None):
        self._creds = {}
        for project, sites in (data or {}).items():
            for site, c in sites.items():
                self.add(project, site, Credential(c["kind"], c["secret"], c.get("user")))

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls(json.load(f))

    def add(self, project, site, credential):
        self._creds.setdefault(project, {})[site] = credential

    def remove(self, project, site=None):
        if site is None:
            self._creds.pop(project, None)
        else:
            self._creds.get(project, {}).pop(site, None)

    def get(self, project, site):
        return self._creds.get(project, {}).get(site)

    def inject(self, project, site, headers):
        """Return (headers, how), how in {'vault', 'request', 'none'}."""
        current = _auth(headers)
        if current and not all(is_placeholder(v) for v in current):
            return headers, "request"
        cred = self.get(project, site)
        if cred is None:
            return _without_auth(headers), "none"
        return _without_auth(headers) + [("Authorization", cred.header())], "vault"

    @staticmethod
    def strip_placeholders(headers):
        current = _auth(headers)
        if current and all(is_placeholder(v) for v in current):
            return _without_auth(headers)
        return headers
