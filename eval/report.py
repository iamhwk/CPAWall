"""Tables from a campaign's results (markdown).

usage: python -m eval.report results.jsonl [--audits audits.json]
"""
import argparse
import collections
import gzip
import json
import statistics
import sys

CONFIGS = ("baseline", "pep-shared", "capscope", "simple-isolation", "bulkhead",
           "bulkhead-perchannel", "bulkhead-noversions", "bulkhead-nolabels")
ORDER = ("directed", "benign", "content", "code")


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        return [json.loads(line) for line in f if line.strip()]


def cells(rows):
    out = collections.OrderedDict()
    for r in rows:
        measure = "leak" if "leak" in r else "success"
        key = (r["trial_type"], r["kind"], r["probe"], r["cond"], measure)
        c = out.setdefault(key, {}).setdefault(r["config"], {"n": 0, "k": 0, "att": 0,
                                                               "asked": 0, "has_att": False})
        c["n"] += 1
        c["k"] += bool(r.get(measure))
        c["att"] += bool(r.get("attempted"))
        c["has_att"] |= r.get("attempted") is not None
        c["asked"] += r.get("approvals_asked", 0)
    return out


def table(rows, configs=CONFIGS, what="k"):
    """One row per probe and condition; leaks (or successes) per config."""
    data = cells(rows)
    configs = [c for c in configs if any(c in v for v in data.values())]
    head = "| Type | Class | Probe | Condition | " + " | ".join(configs) + " |"
    lines = [head, "|" + "---|" * (4 + len(configs))]
    for key in sorted(data, key=lambda k: (k[4] != "leak", ORDER.index(k[0])
                                           if k[0] in ORDER else 9, k[2], k[3])):
        ttype, kind, probe, cond, measure = key
        vals = []
        for c in configs:
            v = data[key].get(c)
            if v is None:
                vals.append("n/a")
            elif what == "att" and not v["has_att"]:
                vals.append("–")
            else:
                vals.append(f"{v[what]}/{v['n']}")
        label = kind if measure == "leak" else "utility"
        lines.append(f"| {ttype} | {label} | {probe} | {cond} | " + " | ".join(vals) + " |")
    return "\n".join(lines)


def timing(rows, configs=CONFIGS):
    by = collections.defaultdict(list)
    for r in rows:
        by[r["config"]].append(r["t1"] - r["t0"])
    lines = ["| Configuration | Trials | Median trial (s) | p95 (s) |", "|---|---|---|---|"]
    for c in configs:
        ts = sorted(by.get(c, []))
        if ts:
            lines.append(f"| {c} | {len(ts)} | {statistics.median(ts):.3f} | "
                         f"{ts[int(0.95 * (len(ts) - 1))]:.3f} |")
    return "\n".join(lines)


def audits(report):
    lines = ["| Configuration | C1 | C2 | C3 | C4 | C5 |", "|---|---|---|---|---|---|"]
    for c, rep in report.items():
        vals = []
        for k in ("C1", "C2", "C3", "C4", "C5"):
            r = rep.get(k, {})
            vals.append("–" if r.get("ok") is None else ("ok" if r["ok"] else f"{r['count']} found"))
        lines.append(f"| {c} | " + " | ".join(vals) + " |")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--audits")
    a = ap.parse_args(argv)
    rows = load(a.results)
    print("## Leaks (or successes) per configuration\n")
    print(table(rows))
    print("\n## Attempts\n")
    print(table(rows, what="att"))
    print("\n## Trial time\n")
    print(timing(rows))
    if a.audits:
        with open(a.audits) as f:
            print("\n## Auditor\n")
            print(audits(json.load(f)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
