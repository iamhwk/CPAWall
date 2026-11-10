"""Tables from model-driven trials (markdown).

For each model: leaks (or successes), attempts and API refusals per probe,
condition and configuration; turns and cost per configuration.

usage: python -m eval.model_report results-MODEL.jsonl [...]
"""
import collections
import json
import statistics
import sys

from eval.report import load

CONFIGS = ("baseline", "capscope", "simple-isolation", "bulkhead")
ORDER = {"directed": 0, "benign": 1, "content": 2, "code": 3}


def tables(rows):
    lines = []
    by_model = collections.OrderedDict()
    for r in rows:
        by_model.setdefault(r["model"], []).append(r)
    for model, rs in by_model.items():
        configs = [c for c in CONFIGS if any(r["config"] == c for r in rs)]
        cells = collections.OrderedDict()
        for r in sorted(rs, key=lambda r: (ORDER.get(r["trial_type"], 9), r["probe"], r["cond"])):
            measure = "leak" if "leak" in r else "success"
            key = (r["trial_type"], r["kind"], r["probe"], r["cond"], measure)
            c = cells.setdefault(key, {}).setdefault(
                r["config"], {"n": 0, "k": 0, "att": 0, "ref": 0, "rerun": False})
            c["n"] += 1
            c["k"] += bool(r.get(measure))
            c["att"] += bool(r.get("attempted"))
            c["ref"] += r.get("stop") == "refusal"
            c["rerun"] |= bool(r.get("rerun"))
        lines.append(f"## {model}\n")
        lines.append("Each cell gives the leaks (or, for utility, the successes) out of the "
                     "trials, then in brackets the trials in which the model attempted the "
                     "access and those the API refused. A dash means not measured.\n")
        head = "| Type | Class | Probe | Condition | " + " | ".join(configs) + " |"
        lines += [head, "|" + "---|" * (4 + len(configs))]
        for (tt, kind, probe, cond, measure), per in cells.items():
            row = [tt, kind if measure == "leak" else "utility", probe, cond]
            for cfg in configs:
                c = per.get(cfg)
                if not c:
                    row.append("–")
                    continue
                extra = []
                if measure == "leak":
                    extra.append(f"att {c['att']}")
                if c["ref"]:
                    extra.append(f"ref {c['ref']}")
                row.append(f"{c['k']}/{c['n']}" + (f" ({', '.join(extra)})" if extra else "")
                           + (" †" if c["rerun"] else ""))
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        if any(c["rerun"] for per in cells.values() for c in per.values()):
            lines += ["† Run again after a fault in the setup was fixed (see meta.json).", ""]
        lines.append("| Configuration | Trials | Median turns | Median time (s) | Cost (USD) |")
        lines.append("|---|---|---|---|---|")
        for cfg in configs:
            cr = [r for r in rs if r["config"] == cfg]
            cost = sum(r.get("cost") or 0 for r in cr)
            lines.append(f"| {cfg} | {len(cr)} | {statistics.median(r['turns'] for r in cr):.0f} "
                         f"| {statistics.median(r['t1'] - r['t0'] for r in cr):.1f} "
                         f"| {cost:.2f} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    rows = []
    for path in (argv if argv is not None else sys.argv[1:]):
        rows += load(path)
    print(tables(rows))


if __name__ == "__main__":
    main()
