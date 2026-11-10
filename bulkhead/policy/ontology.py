"""Request mapping: site requests and tool calls to (resource, operation).

This is a development aid. The design document says only that the PEPs
map requests declaratively (consideration 2); this module, with the data
in testbed/ontology.yaml, is that mapping for the testbed.

The mapping data declares:
- schemes: the operations of each resource scheme, each with a class,
  either read or act (state-changing);
- sites: for each origin, the resource patterns that a site-level grant
  covers, and request rules (method, path template, query) that name a
  resource and an operation;
- tools: for each tool server, a resource template and an operation for
  each tool.

A request that no rule maps falls back to its origin: (web://host, read)
for GET, HEAD and OPTIONS, and (web://host, act) otherwise. The PDP caps
an unmapped act at the manifest's `unmapped` setting (ask by default).
Requests with non-canonical paths ('.', '..', encoded '/') are marked so
that the PEP can refuse them: a mapping is only as good as its agreement
with how the service reads the path.
"""
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

from ..decisions import Decision
from . import patterns

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CLASSES = ("read", "act")


@dataclass(frozen=True)
class Mapping:
    resource: str
    op: str
    mapped: bool                  # False if it fell back to the origin
    site: str | None = None       # origin of a web request
    rule: str | None = None       # which rule matched, for the log
    canonical: bool = True        # False: the PEP must refuse the request


def origin(url):
    """'https://Git.Test:443/x' -> 'https://git.test'."""
    u = urlsplit(url)
    sch = (u.scheme or "https").lower()
    host = (u.hostname or "").lower()
    port = u.port
    if port is None or (sch, port) in (("https", 443), ("http", 80)):
        return f"{sch}://{host}"
    return f"{sch}://{host}:{port}"


def _host(origin_):
    return origin_.split("://", 1)[1]


_PARAM = re.compile(r"\{(\w+)(\*\*)?\}")


def _path_regex(template):
    out, pos = [], 0
    for m in _PARAM.finditer(template):
        out.append(re.escape(template[pos:m.start()]))
        out.append(f"(?P<{m[1]}>.+)" if m[2] else f"(?P<{m[1]}>[^/]+?)")
        pos = m.end()
    out.append(re.escape(template[pos:]))
    return re.compile("".join(out) + r"\Z")


@dataclass(frozen=True)
class _Rule:
    method: str
    regex: re.Pattern
    query: tuple                  # ((name, value), ...) that must be present
    resource: str
    op: str
    label: str


class Ontology:
    def __init__(self, data):
        self.schemes = {}
        for name, spec in (data.get("schemes") or {}).items():
            ops = dict(spec["ops"])
            for op, cls in ops.items():
                if cls not in CLASSES:
                    raise ValueError(f"scheme {name}: class of {op} must be read or act")
            self.schemes[name] = ops
        self.sites = {}
        for site, spec in (data.get("sites") or {}).items():
            key = origin(site)
            for pat in spec.get("resources", []):
                self._check_pattern(patterns.validate(pat))
            rules = []
            for i, r in enumerate(spec.get("requests", [])):
                self._check_op(patterns.scheme(r["resource"]), r["op"])
                query = tuple(sorted((r.get("query") or {}).items()))
                label = f"{key} {r['method'].upper()} {r['path']}" + (
                    "?" + "&".join(f"{k}={v}" for k, v in query) if query else "")
                rules.append(_Rule(r["method"].upper(), _path_regex(r["path"]), query,
                                   r["resource"], r["op"], label))
            self.sites[key] = {"resources": list(spec.get("resources", [])), "rules": rules}
        self.tools = {}
        for server, tools in (data.get("tools") or {}).items():
            for tool, spec in tools.items():
                self._check_op(patterns.scheme(spec["resource"]), spec["op"])
            self.tools[server] = dict(tools)

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls(yaml.safe_load(f))

    # -- operations ----------------------------------------------------------
    def _check_pattern(self, pattern):
        if patterns.scheme(pattern) not in self.schemes:
            raise ValueError(f"unknown scheme in {pattern!r}")

    def _check_op(self, scheme, op):
        if op not in self.schemes.get(scheme, {}):
            raise ValueError(f"scheme {scheme} has no operation {op!r}")

    def ops(self, scheme):
        try:
            return self.schemes[scheme]
        except KeyError:
            raise ValueError(f"unknown scheme {scheme!r}") from None

    def op_class(self, scheme, op):
        return self.ops(scheme)[op]

    def expand_ops(self, scheme, table, classes_only=False):
        """Expand an operation table: a class key (read, act) stands for all
        operations of that class; a named operation overrides its class."""
        ops = self.ops(scheme)
        out = {}
        for key, d in table.items():
            if key in CLASSES and key not in ops:
                for op, cls in ops.items():
                    if cls == key:
                        out.setdefault(op, Decision.parse(d))
        for key, d in table.items():
            if key in ops:
                if classes_only and key not in CLASSES:
                    raise ValueError(f"site grants take read and act, not {key!r}")
                out[key] = Decision.parse(d)
            elif key not in CLASSES:
                raise ValueError(f"scheme {scheme} has no operation {key!r}")
        return out

    # -- site-level grants ---------------------------------------------------
    def site_patterns(self, site):
        """The resource patterns that a grant on `site` covers. '*' is any
        web origin, never a named resource."""
        if site == "*":
            return ["web://*"]
        key = origin(site)
        out = list(self.sites.get(key, {}).get("resources", []))
        out.append(f"web://{_host(key)}")
        return out

    # -- mapping -------------------------------------------------------------
    def map_request(self, method, url):
        method = method.upper()
        u = urlsplit(url)
        key = origin(url)
        raw = u.path or "/"
        canonical = _canonical(raw)
        path = unquote(raw)
        query = parse_qs(u.query, keep_blank_values=True)
        site = self.sites.get(key)
        if site and canonical:
            for rule in site["rules"]:
                if rule.method != method:
                    continue
                m = rule.regex.match(path)
                if not m or any(query.get(k, [None])[0] != v for k, v in rule.query):
                    continue
                return Mapping(rule.resource.format(**m.groupdict()), rule.op, True, key,
                               rule.label)
        op = "read" if method in READ_METHODS else "act"
        return Mapping(f"web://{_host(key)}", op, False, key, None, canonical)

    def map_tool(self, server, tool, args):
        """(resource, op) of a tool call, or None if the tool is unknown or
        its arguments do not name a resource."""
        spec = self.tools.get(server, {}).get(tool)
        if spec is None:
            return None
        try:
            values = {k: str(v) for k, v in (args or {}).items()}
            if any("/" in v or v in ("", ".", "..") for k, v in values.items()
                   if "{" + k + "}" in spec["resource"]):
                return None
            resource = spec["resource"].format(**values)
        except (KeyError, IndexError, ValueError):
            return None
        return Mapping(resource, spec["op"], True, None, f"{server}.{tool}")


def _canonical(raw_path):
    """No '.' or '..' segments, no encoded '/' or '\\', no empty segments."""
    low = raw_path.lower()
    if "%2f" in low or "%5c" in low or "\\" in raw_path:
        return False
    path = unquote(raw_path)
    if path != "/" and posixpath.normpath(path) != path.rstrip("/"):
        return False
    return "//" not in path
