"""Resource names and patterns: ``scheme://segment/segment/...``.

A pattern names a set of resources of one scheme. Within a segment, ``*``
and ``?`` match as in fnmatch, never across ``/``; a segment that is
exactly ``**`` matches zero or more segments. Schemes never match each
other, so a web wildcard (``web://*``) never covers a repository
(design, consideration 2).

Witnesses stand in for the resources a pattern names when the compiler
compares grants with the policy: a wildcard segment becomes ``{any}``,
which only a wildcard matches, so a witness from ``repo://git.test/*/*``
reads as "any other repository on git.test".
"""
import fnmatch
import itertools
from functools import lru_cache

ANY = "{any}"
_GLOB = frozenset("*?[")


def split(name):
    """'repo://git.test/acme/x' -> ('repo', ('git.test', 'acme', 'x'))."""
    scheme, sep, rest = name.partition("://")
    if not sep or not scheme or not scheme.isalnum():
        raise ValueError(f"not a resource name or pattern: {name!r}")
    rest = rest.rstrip("/")
    return scheme, tuple(rest.split("/")) if rest else ()


def scheme(name):
    return split(name)[0]


def is_glob(segment):
    return any(c in _GLOB for c in segment)


def validate(pattern):
    """Raise ValueError unless `pattern` is well formed."""
    _, segs = split(pattern)
    for i, seg in enumerate(segs):
        if seg == "" and i > 0:      # a leading empty segment is the root of a path
            raise ValueError(f"empty segment in {pattern!r}")
        if "**" in seg and seg != "**":
            raise ValueError(f"'**' must be a whole segment in {pattern!r}")
    return pattern


@lru_cache(maxsize=1 << 16)
def match(pattern, name):
    """Does `pattern` match the resource `name` (or witness)?"""
    ps, p = split(pattern)
    rs, r = split(name)
    return ps == rs and _match(p, r)


def _match(p, r):
    @lru_cache(maxsize=None)
    def m(i, j):
        if i == len(p):
            return j == len(r)
        if p[i] == "**":
            return m(i + 1, j) or (j < len(r) and m(i, j + 1))
        return j < len(r) and fnmatch.fnmatchcase(r[j], p[i]) and m(i + 1, j + 1)
    return m(0, 0)


def _seg_covers(a, b):
    """Does segment pattern `a` match every name segment pattern `b` matches?"""
    if a == b or a == "*":
        return True
    if not is_glob(b):
        return fnmatch.fnmatchcase(b, a)
    return False          # conservative: two different globs


def _seg_overlaps(a, b):
    if not is_glob(a):
        return fnmatch.fnmatchcase(a, b)
    if not is_glob(b):
        return fnmatch.fnmatchcase(b, a)
    pa, pb = _literal_prefix(a), _literal_prefix(b)
    return pa.startswith(pb) or pb.startswith(pa)   # may overlap


def _literal_prefix(seg):
    for i, c in enumerate(seg):
        if c in _GLOB:
            return seg[:i]
    return seg


@lru_cache(maxsize=1 << 14)
def covers(p, q):
    """Is every resource that `q` names also named by `p`?  (p contains q)"""
    ps, a = split(p)
    qs, b = split(q)
    if ps != qs:
        return False

    @lru_cache(maxsize=None)
    def c(i, j):
        if i == len(a):
            return j == len(b)
        if a[i] == "**":
            return c(i + 1, j) or (j < len(b) and c(i, j + 1))
        if j == len(b) or b[j] == "**":
            return False
        return _seg_covers(a[i], b[j]) and c(i + 1, j + 1)
    return c(0, 0)


@lru_cache(maxsize=1 << 14)
def overlaps(p, q):
    """May some resource be named by both `p` and `q`?"""
    ps, a = split(p)
    qs, b = split(q)
    if ps != qs:
        return False

    @lru_cache(maxsize=None)
    def o(i, j):
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] == "**":
            return o(i + 1, j) or (j < len(b) and o(i, j + 1))
        if j < len(b) and b[j] == "**":
            return o(i, j + 1) or (i < len(a) and o(i + 1, j))
        if i == len(a) or j == len(b):
            return False
        return _seg_overlaps(a[i], b[j]) and o(i + 1, j + 1)
    return o(0, 0)


def intersection(p, q):
    """A pattern for the resources both `p` and `q` name, or None if they
    name none in common or the intersection is not a single pattern that
    this module can state (patterns with '**' that neither covers)."""
    if not overlaps(p, q):
        return None
    if covers(p, q):
        return q
    if covers(q, p):
        return p
    ps, a = split(p)
    _, b = split(q)
    if "**" in a or "**" in b or len(a) != len(b):
        return None
    out = []
    for x, y in zip(a, b):
        if x == y or (not is_glob(x) and fnmatch.fnmatchcase(x, y)) or y == "*":
            out.append(x)
        elif (not is_glob(y) and fnmatch.fnmatchcase(y, x)) or x == "*":
            out.append(y)
        else:
            return None       # two different globs: no single pattern
    return f"{ps}://" + "/".join(out)


def _witness_segment(seg):
    if not is_glob(seg):
        return seg
    if seg in ("*", "**"):
        return ANY
    out, i = [], 0
    while i < len(seg):           # 'acme-*' -> 'acme-{any}'
        ch = seg[i]
        if ch == "[":
            end = seg.find("]", i + 1)
            i = len(seg) if end < 0 else end + 1
            out.append(ANY)
        elif ch in "*?":
            while i < len(seg) and seg[i] in "*?":
                i += 1
            out.append(ANY)
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def witnesses(pattern):
    """Representative names for `pattern`: '**' is tried as no segment and
    as one; every other wildcard becomes {any}."""
    sch, segs = split(pattern)
    stars = [i for i, s in enumerate(segs) if s == "**"]
    out = []
    for choice in itertools.product((False, True), repeat=min(len(stars), 2)):
        keep = dict(zip(stars, choice))
        parts = [_witness_segment(s) for i, s in enumerate(segs) if keep.get(i, True)]
        name = f"{sch}://" + "/".join(parts)
        if name not in out:
            out.append(name)
    return out


def is_witness(name):
    """True if `name` stands for resources not named individually."""
    return ANY in name


def specificity(pattern):
    """Literal segments first, then fewer wildcards: for ordering reports."""
    _, segs = split(pattern)
    return (sum(not is_glob(s) for s in segs), -sum(s == "**" for s in segs))
