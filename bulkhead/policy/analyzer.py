"""Analyzer and effective-authority report (design, Section 4.3, Analyze).

(a) Channel inconsistency: the compiler's P3 check, grouped per grant.
    Grants above the policy are reported with their relation to the
    stricter entry (shadowing, correlation, exception) or as unbacked;
    grants below it are listed because enforcing the policy relaxes them.
(b) Inherited authority: substrate state reachable from a project (a
    cached credential, a token file, a folder the OS account can open)
    that enables some (r, o) with I_pi(r, o) < allow. Under a shared
    substrate this predicts L1; the facts come from a substrate scan.
(c) Cross-project conflicts: projects that the user marks as
    conflicting share a resource their policies grant, or a substrate.

usage: python -m bulkhead.policy.analyzer --ontology O.yaml
           [--inventory I.yaml] [--reach R.json] [--json] manifest.yaml ...
"""
import argparse
import collections
import json
import sys
from dataclasses import dataclass, field

import yaml

from ..decisions import Decision
from . import patterns
from .compiler import compile_manifest
from .ontology import Ontology
from .schema import load_manifest


@dataclass(frozen=True)
class Reach:
    """Substrate state reachable from `project` that enables (resource, op)."""
    project: str
    resource: str              # a name or a pattern
    op: str
    via: str                   # e.g. "git credential helper: work-bot"


@dataclass
class Finding:
    kind: str                  # excess | relaxed | inherited | conflict
    project: str
    summary: str
    detail: dict = field(default_factory=dict)

    def to_dict(self):
        return {"kind": self.kind, "project": self.project, "summary": self.summary,
                **self.detail}


def _names(resource):
    return [resource] if not any(patterns.is_glob(s) for s in patterns.split(resource)[1]) \
        else patterns.witnesses(resource)


def channel_findings(compiled):
    """Group the P3 check per grant, decision pair, and relation."""
    groups = collections.OrderedDict()
    for it in compiled.check:
        key = (it.kind, it.channel, it.rules, it.granted, it.policy, it.relation, it.entries)
        ops = groups.setdefault(key, collections.OrderedDict()).setdefault(it.witness, [])
        if it.op not in ops:
            ops.append(it.op)
    out = []
    for (kind, channel, rules, granted, policy, rel, entries), table in groups.items():
        by_ops = collections.OrderedDict()
        for name, ops in table.items():
            by_ops.setdefault(tuple(ops), []).append(name)
        where = "; ".join(f"{'/'.join(ops)} on {', '.join(names)}"
                          for ops, names in by_ops.items())
        rel_txt = f", {rel}" if rel else ""
        word = "above" if kind == "excess" else "below"
        out.append(Finding(kind, compiled.project,
                           f"{'; '.join(rules)}: {granted}, {word} the policy's "
                           f"{policy}{rel_txt}: {where}",
                           {"channel": channel, "granted": str(granted),
                            "policy": str(policy), "relation": rel,
                            "resources": {name: ops for name, ops in table.items()},
                            "grants": list(rules), "entries": list(entries)}))
    return out


def inherited_findings(policies, reach):
    out = []
    for fact in reach:
        pol = policies.get(fact.project)
        if pol is None:
            continue
        for name in _names(fact.resource):
            d, _ = pol.decide(name, fact.op)
            if d < Decision.ALLOW:
                out.append(Finding("inherited", fact.project,
                                   f"{fact.via} enables {fact.op} on {name}; the policy "
                                   f"says {d}",
                                   {"resource": name, "op": fact.op, "via": fact.via,
                                    "policy": str(d)}))
    return out


def conflict_findings(policies, onto, inventory=(), substrates=None):
    """Pairs of projects marked as conflicting that share a granted resource
    or a substrate (`substrates`: project -> substrate id)."""
    pairs = set()
    for p, pol in policies.items():
        for q in pol.conflicts:
            if q in policies and q != p:
                pairs.add(tuple(sorted((p, q))))
    out = []
    for p, q in sorted(pairs):
        a, b = policies[p], policies[q]
        names = list(inventory) + [w for e in a.entries + b.entries
                                   for w in patterns.witnesses(e.pattern)]
        shared = []
        for name in dict.fromkeys(names):
            sch = patterns.scheme(name)
            if sch not in onto.schemes:
                continue
            ops = list(onto.ops(sch))
            ga = [o for o in ops if a.decide(name, o)[0] > Decision.DENY]
            gb = [o for o in ops if b.decide(name, o)[0] > Decision.DENY]
            if ga and gb:
                shared.append({"resource": name, p: ga, q: gb})
        for s in shared:
            out.append(Finding("conflict", p, f"{p} and {q} are marked as conflicting, "
                               f"and both may use {s['resource']}",
                               {"with": q, **s}))
        if substrates and substrates.get(p) is not None and substrates.get(p) == substrates.get(q):
            out.append(Finding("conflict", p, f"{p} and {q} are marked as conflicting, "
                               f"and share the substrate {substrates[p]}",
                               {"with": q, "substrate": substrates[p]}))
    return out


def analyze(policies, onto, reach=(), inventory=(), substrates=None):
    """All findings for a set of compiled policies (project -> policy)."""
    out = []
    for p in sorted(policies):
        out += channel_findings(policies[p])
    out += inherited_findings(policies, reach)
    out += conflict_findings(policies, onto, inventory, substrates)
    return out


def _policy_lines(pol):
    table = collections.OrderedDict()
    for e in pol.entries:
        table.setdefault(e.pattern, []).append(f"{e.op}={e.decision}")
    width = max((len(p) for p in table), default=0)
    return [f"    {p:<{width}}  {' '.join(ops)}" for p, ops in table.items()]


def report(policies, findings):
    """The effective-authority report, as text (shown by the trusted UI)."""
    lines = []
    by = collections.defaultdict(list)
    for f in findings:
        by[(f.project, f.kind)].append(f)
    titles = (("excess", "Channel grants above the policy (P3; the policy tightens them)"),
              ("relaxed", "Channel grants below the policy (the policy relaxes them)"),
              ("inherited", "Inherited authority (substrate state the policy does not grant)"),
              ("conflict", "Conflicts with other projects"))
    for p in sorted(policies):
        pol = policies[p]
        v = f"v{pol.version}" if pol.version else "uninstalled"
        lines.append(f"== {p}: policy {v} ({pol.mode}), {pol.digest()[:19]}")
        lines.append("  Effective authority (enforced on every channel; anything else: deny)")
        lines += _policy_lines(pol)
        for kind, title in titles:
            items = by.get((p, kind), [])
            lines.append(f"  {title}: {len(items) or 'none'}")
            lines += [f"    - {f.summary}" for f in items]
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ontology", required=True)
    ap.add_argument("--inventory")
    ap.add_argument("--reach", help="JSON list of {project, resource, op, via}")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("manifests", nargs="+")
    a = ap.parse_args(argv)
    onto = Ontology.load(a.ontology)
    inventory = []
    if a.inventory:
        with open(a.inventory) as f:
            inventory = yaml.safe_load(f)["resources"]
    reach = []
    if a.reach:
        with open(a.reach) as f:
            reach = [Reach(**r) for r in json.load(f)]
    policies = {}
    for path in a.manifests:
        pol = compile_manifest(load_manifest(path), onto, inventory)
        policies[pol.project] = pol
    findings = analyze(policies, onto, reach, inventory)
    if a.json:
        print(json.dumps([f.to_dict() for f in findings], indent=1))
    else:
        print(report(policies, findings))
    return findings


if __name__ == "__main__":
    main(sys.argv[1:])
