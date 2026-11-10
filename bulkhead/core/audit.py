"""Auditor (design, Section 4.6): five conformance checks over a run.

  C1 integrity     the hash chain and the signed checkpoints verify
  C2 mediation     every access a service recorded has a record that a PEP
                   forwarded it (else P1 failed)
  C3 faithfulness  every decision equals decide() recomputed from the
                   archived policy version, for the project of the socket
                   it arrived on (P2)
  C4 consistency   no (project, resource, operation, version) received
                   different decisions on different channels (P3)
  C5 approvals     every final allow is backed: the policy allowed it, or
                   it asked and a trusted-UI approval of matching project,
                   resource, operation, version and scope answered

usage: python -m bulkhead.core.audit --state DIR [--service-log FILE]
"""
import argparse
import bisect
import collections
import datetime
import glob
import json
import os
import sys

from ..decisions import Decision
from .log import read_records, verify
from .pdp import PolicyStore

CHECKS = ("C1", "C2", "C3", "C4", "C5")
_DECIDED = ("http", "mcp")


def _epoch(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def load_policies(state):
    out = {}
    for path in glob.glob(os.path.join(state, "policies", "*", "v*.json")):
        pol = PolicyStore.load_archived(path)
        out[(pol.project, pol.version)] = pol
    return out


def load_approvals(path):
    try:
        with open(path) as f:
            return {a["id"]: a for a in map(json.loads, filter(str.strip, f))}
    except FileNotFoundError:
        return {}


def _decided(records):
    return [r for r in records if r.get("pep") in _DECIDED and r.get("resource")
            and r.get("policy_version") is not None]


def check_c2(records, service, window=5.0):
    """Match every successful service access to one forwarded PEP record:
    the nearest unmatched one in time, within `window` seconds, for the same
    resource and operation and, where the service knows it, the same
    project; ties go to the earlier record. Candidates are kept sorted by
    time, so each access costs a binary search and a scan of its window."""
    pools = collections.defaultdict(list)
    for i, r in enumerate(records):
        if r.get("pep") == "http" and r.get("outcome") == "forwarded" and r.get("resource"):
            pools[(r["resource"], r["op"])].append((_epoch(r["ts"]), i, r["project"]))
    index = {}
    for key, pool in pools.items():
        pool.sort()
        index[key] = ([t for t, _, _ in pool], pool, [False] * len(pool))
    problems = []
    for s in sorted(service, key=lambda s: s["ts"]):
        if s.get("status", 500) >= 400 or "resource" not in s:
            continue
        entry = index.get((s["resource"], s["op"]))
        best = None
        if entry:
            times, pool, used = entry
            t, want = s["ts"], s.get("project")

            def eligible(j):
                return not used[j] and (want is None or pool[j][2] == want)
            k = bisect.bisect_left(times, t)
            j = k - 1                                   # nearest earlier candidate
            while j >= 0 and t - times[j] <= window and not eligible(j):
                j -= 1
            if j >= 0 and t - times[j] <= window:
                m = j                                   # the first of equal times
                while m > 0 and times[m - 1] == times[j]:
                    m -= 1
                    if eligible(m):
                        j = m
                best = (t - times[j], pool[j][1], j)
            j = k                                       # nearest later candidate
            while j < len(pool) and times[j] - t <= window and not eligible(j):
                j += 1
            if j < len(pool) and times[j] - t <= window:
                cand = (times[j] - t, pool[j][1], j)
                if best is None or cand < best:
                    best = cand
        if best is not None:
            entry[2][best[2]] = True
        else:
            problems.append(f"{s['service']} {s['method']} {s['path']}: {s['op']} on "
                            f"{s['resource']} by {s.get('identity') or 'anonymous'} has no "
                            f"forwarded PEP record")
    return problems


def check_c3(records, policies):
    problems, memo = [], {}
    for r in _decided(records):
        pol = policies.get((r["project"], r["policy_version"]))
        if pol is None:
            problems.append(f"seq {r['seq']}: no archived policy v{r['policy_version']} "
                            f"for {r['project']}")
            continue
        key = (r["project"], r["policy_version"], r["resource"], r["op"])
        if key not in memo:                     # decisions are pure: compute each once
            memo[key] = pol.decide(r["resource"], r["op"])[0]
        d = memo[key]
        if not r.get("mapped", True) and r["op"] != "read":
            d = min(d, pol.unmapped)
        if str(d) != r.get("decision"):
            problems.append(f"seq {r['seq']}: {r['project']} {r['op']} {r['resource']} was "
                            f"decided {r.get('decision')}, policy v{r['policy_version']} "
                            f"says {d}")
    return problems


def check_c4(records):
    seen = collections.defaultdict(dict)
    for r in _decided(records):
        key = (r["project"], r["resource"], r["op"], r["policy_version"])
        seen[key].setdefault(r.get("decision"), set()).add(r["channel"])
    return [f"{p} {o} {res} (v{v}): " + "; ".join(f"{d} on {', '.join(sorted(ch))}"
                                                 for d, ch in sorted(ds.items()))
            for (p, res, o, v), ds in seen.items() if len(ds) > 1]


def check_c5(records, approvals):
    problems, used = [], collections.Counter()
    for r in _decided(records):
        if r.get("final") != "allow":
            continue
        if r.get("decision") == "allow":
            continue
        where = f"seq {r['seq']}: {r['project']} {r['op']} {r['resource']}"
        if r.get("decision") != "ask":
            problems.append(f"{where}: allowed although the policy says {r.get('decision')}")
            continue
        a = approvals.get(r.get("approval"))
        if a is None:
            problems.append(f"{where}: ask became allow without a trusted-UI approval")
            continue
        if (a["project"], a["resource"], a["op"], a["version"]) != (
                r["project"], r["resource"], r["op"], r["policy_version"]):
            problems.append(f"{where}: approval {a['id']} is for {a['project']} {a['op']} "
                            f"{a['resource']} v{a['version']}")
            continue
        used[a["id"]] += 1
        if a["scope"] == "request" and used[a["id"]] > 1:
            problems.append(f"{where}: one-request approval {a['id']} used again")
        elif a["scope"] == "task" and r.get("task") != a.get("task"):
            problems.append(f"{where}: task approval {a['id']} used in task {r.get('task')}")
        elif a["scope"] == "project" and a.get("expires") and _epoch(r["ts"]) > a["expires"]:
            problems.append(f"{where}: project approval {a['id']} had expired")
    return problems


def audit(state, service=None, records=None, window=5.0):
    """Run C1-C5 over a deployment's state directory. `records` (default:
    the whole log) and `service` (the services' access records) can be
    narrowed to one run."""
    log_path = os.path.join(state, "log.jsonl")
    pub = None
    key = os.path.join(state, "log.key.pub")
    if os.path.exists(key):
        with open(key, "rb") as f:
            pub = f.read()
    records = read_records(log_path) if records is None else records
    problems = {
        "C1": verify(log_path, pub),
        "C2": check_c2(records, service or [], window) if service is not None else None,
        "C3": check_c3(records, load_policies(state)),
        "C4": check_c4(records),
        "C5": check_c5(records, load_approvals(os.path.join(state, "approvals.jsonl"))),
    }
    return {c: ({"ok": None, "count": 0, "problems": []} if p is None else
                {"ok": not p, "count": len(p), "problems": p[:50]})
            for c, p in problems.items()} | {"records": len(records)}


def render(report):
    names = {"C1": "integrity", "C2": "mediation", "C3": "faithfulness",
             "C4": "consistency", "C5": "approvals"}
    lines = [f"audit over {report['records']} records"]
    for c in CHECKS:
        r = report[c]
        state = "not run" if r["ok"] is None else ("ok" if r["ok"] else f"{r['count']} problem(s)")
        lines.append(f"  {c} {names[c]:<13} {state}")
        lines += [f"      - {p}" for p in r["problems"][:10]]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bulkhead auditor (C1-C5)")
    ap.add_argument("--state", required=True)
    ap.add_argument("--service-log", help="the services' access records (JSON lines)")
    a = ap.parse_args(argv)
    service = read_records(a.service_log) if a.service_log else None
    report = audit(a.state, service)
    print(render(report))
    return 0 if all(report[c]["ok"] in (True, None) for c in CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
