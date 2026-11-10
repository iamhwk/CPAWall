"""Policy compiler (design, Section 4.3: Normalize, Tabulate, Policy, Check).

    manifest + request mapping
      -> rules <pi, c, rho, o, d>                       (Normalize)
      -> G_pi(c, r, o): min over c's matching rules     (Tabulate)
      -> I_pi = the declared policy, else the meet      (Policy)
      -> grants above I_pi and below it                 (Check, P3)

Decisions follow one rule everywhere: the minimum over the matching
entries that list the operation, deny if none (consideration 3). Under
the meet the entries are all channel rules, so I_pi(r, o) is the minimum
of G_pi over the channels that define (r, o), and deny where none does.
"""
import hashlib
import json
from dataclasses import dataclass, replace

from ..decisions import Decision
from . import patterns


@dataclass(frozen=True)
class Rule:
    """A channel's grant on one pattern and operation."""
    channel: str
    pattern: str
    op: str
    decision: Decision
    source: str


@dataclass(frozen=True)
class Entry:
    """A reference-policy entry."""
    pattern: str
    op: str
    decision: Decision
    source: str


@dataclass(frozen=True)
class CheckItem:
    """One P3 finding at one witness.

    kind      'excess': G > I, a grant the policy does not back;
              'relaxed': G < I, a grant that enforcing the policy relaxes
    relation  for excess: 'unbacked' (no policy entry names the resource),
              'shadowing' (the grant covers the stricter entry),
              'correlation' (they partly overlap), or 'exception' (the
              grant is a narrower carve-out of the stricter entry)
    """
    kind: str
    channel: str
    op: str
    granted: Decision
    policy: Decision
    witness: str
    rules: tuple
    entries: tuple
    relation: str = ""


@dataclass(frozen=True)
class CompiledPolicy:
    project: str
    mode: str                         # 'declared' or 'meet'
    entries: tuple
    rules: tuple
    check: tuple = ()
    background: bool = False
    conflicts: tuple = ()
    unmapped: Decision = Decision.ASK
    version: int | None = None

    def decide(self, resource, op):
        """I_pi(r, o) and the entries that match: deny if none."""
        hits = tuple(e for e in self.entries
                     if e.op == op and patterns.match(e.pattern, resource))
        return (min(e.decision for e in hits) if hits else Decision.DENY), hits

    def channel_grant(self, channel, resource, op):
        """G_pi(c, r, o), or None where the channel defines nothing."""
        hits = tuple(r for r in self.rules
                     if r.channel == channel and r.op == op and patterns.match(r.pattern, resource))
        return (min(r.decision for r in hits) if hits else None), hits

    def channels(self):
        return sorted({r.channel for r in self.rules})

    # -- serialization ---------------------------------------------------------
    def policy_dict(self):
        """The part that decisions depend on (P^v_pi)."""
        return {"project": self.project, "mode": self.mode, "unmapped": str(self.unmapped),
                "entries": [[e.pattern, e.op, str(e.decision), e.source]
                            for e in self.entries]}

    def digest(self):
        blob = json.dumps(self.policy_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()

    def to_dict(self):
        d = self.policy_dict()
        d.update(version=self.version, digest=self.digest(), background=self.background,
                 conflicts=list(self.conflicts),
                 rules=[[r.channel, r.pattern, r.op, str(r.decision), r.source]
                        for r in self.rules],
                 check=[{"kind": c.kind, "channel": c.channel, "op": c.op,
                         "granted": str(c.granted), "policy": str(c.policy),
                         "witness": c.witness, "rules": list(c.rules),
                         "entries": list(c.entries), "relation": c.relation}
                        for c in self.check])
        return d

    @classmethod
    def from_dict(cls, d):
        P = Decision.parse
        return cls(project=d["project"], mode=d["mode"],
                   entries=tuple(Entry(p, o, P(x), s) for p, o, x, s in d["entries"]),
                   rules=tuple(Rule(c, p, o, P(x), s) for c, p, o, x, s in d.get("rules", [])),
                   check=tuple(CheckItem(c["kind"], c["channel"], c["op"], P(c["granted"]),
                                         P(c["policy"]), c["witness"], tuple(c["rules"]),
                                         tuple(c["entries"]), c["relation"])
                               for c in d.get("check", [])),
                   background=d.get("background", False),
                   conflicts=tuple(d.get("conflicts", [])),
                   unmapped=P(d.get("unmapped", "ask")), version=d.get("version"))

    def with_version(self, version):
        return replace(self, version=version)


class CompileError(ValueError):
    pass


def path_pattern(path):
    """'~/work/payments' -> 'file://~/work/payments/**' (the folder and below)."""
    path = path.rstrip("/")
    if not (path == "~" or path.startswith("~/") or path.startswith("/")):
        raise CompileError(f"file paths start with ~/ or /: {path!r}")
    return f"file://{path}/**"


def _targets(grant, onto):
    """[(pattern, {op: decision})] that one grant expands to."""
    if grant.path is not None:
        return [(path_pattern(grant.path), onto.expand_ops("file", grant.ops))]
    if grant.resource is not None:
        pat = patterns.validate(grant.resource)
        return [(pat, onto.expand_ops(patterns.scheme(pat), grant.ops))]
    return [(pat, onto.expand_ops(patterns.scheme(pat), grant.ops, classes_only=True))
            for pat in onto.site_patterns(grant.site)]


def normalize(manifest, onto):
    rules = []
    for channel, grants in manifest.grants.items():
        for i, g in enumerate(grants):
            src = f"grants.{channel}[{i}] {g.target()}"
            if g.server:
                src += f" (server {g.server})"
            if g.service:
                src += f" (service {g.service})"
            try:
                for pat, table in _targets(g, onto):
                    rules += [Rule(channel, pat, op, d, src) for op, d in table.items()]
            except ValueError as e:
                raise CompileError(f"{manifest.project}: {src}: {e}") from None
    return tuple(rules)


def declared_entries(manifest, onto):
    out = []
    for pat, table in manifest.policy.items():
        try:
            patterns.validate(pat)
            ops = onto.expand_ops(patterns.scheme(pat), table)
        except ValueError as e:
            raise CompileError(f"{manifest.project}: policy {pat}: {e}") from None
        out += [Entry(pat, op, d, f"policy {pat}") for op, d in ops.items()]
    return tuple(out)


def _relation(rules, entries, granted, policy):
    if not entries:
        return "unbacked"
    loose = [r.pattern for r in rules if r.decision == granted]
    strict = [e.pattern for e in entries if e.decision == policy]
    found = set()
    for p in loose:
        for q in strict:
            if patterns.covers(p, q):
                found.add("shadowing")
            elif patterns.covers(q, p):
                found.add("exception")
            else:
                found.add("correlation")
    for rel in ("shadowing", "correlation", "exception"):
        if rel in found:
            return rel
    return "unbacked"


def witnesses(compiled, onto, inventory=()):
    """The inventory, representatives of every pattern, and representatives
    of every pairwise intersection, so that partial overlaps are seen."""
    pats = sorted({r.pattern for r in compiled.rules} | {e.pattern for e in compiled.entries})
    pats = [p for p in pats if patterns.scheme(p) in onto.schemes]
    meets = [patterns.intersection(p, q) for i, p in enumerate(pats) for q in pats[i + 1:]]
    pats += [m for m in meets if m and m not in pats]
    names = list(inventory) + [w for p in pats for w in patterns.witnesses(p)]
    return [w for w in dict.fromkeys(names) if patterns.scheme(w) in onto.schemes]


def check(compiled, onto, inventory=()):
    """Compare every channel's grant with the policy at every witness."""
    items = []
    for w in witnesses(compiled, onto, inventory):
        for op in onto.ops(patterns.scheme(w)):
            policy, entries = compiled.decide(w, op)
            for c in compiled.channels():
                granted, rules = compiled.channel_grant(c, w, op)
                if granted is None or granted == policy:
                    continue
                deciding = tuple(e for e in entries if e.decision == policy)
                kind = "excess" if granted > policy else "relaxed"
                rel = _relation(rules, deciding, granted, policy) if kind == "excess" else ""
                items.append(CheckItem(kind, c, op, granted, policy, w,
                                       tuple(dict.fromkeys(r.source for r in rules
                                                           if r.decision == granted)),
                                       tuple(dict.fromkeys(e.source for e in deciding)),
                                       rel))
    return tuple(items)


def compile_manifest(manifest, onto, inventory=()):
    rules = normalize(manifest, onto)
    if manifest.policy is not None:
        mode, entries = "declared", declared_entries(manifest, onto)
    else:
        mode = "meet"
        entries = tuple(Entry(r.pattern, r.op, r.decision, f"meet: {r.source}") for r in rules)
    compiled = CompiledPolicy(project=manifest.project, mode=mode, entries=entries,
                              rules=rules, background=manifest.background,
                              conflicts=tuple(manifest.conflicts),
                              unmapped=Decision.parse(manifest.unmapped))
    return replace(compiled, check=check(compiled, onto, inventory))
