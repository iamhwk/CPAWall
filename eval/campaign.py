"""Run every configuration over every probe; write results, audits, tables.

usage: python -m eval.campaign --workdir DIR --out DIR [--reps N]
           [--configs C ...] [probe.json ...]
"""
import argparse
import glob
import gzip
import json
import os
import platform
import sys
import time

from bulkhead.pep import landlock
from eval import report, run_eval
from eval.runtimes import CONFIGS

HERE = os.path.dirname(os.path.abspath(__file__))


def trim(row):
    """Keep what the tables and the auditor need; outputs are cut short."""
    row = dict(row)
    row["steps"] = [dict(s, out=(s.get("out") or "")[:400], err=(s.get("err") or "")[:400])
                    for s in row["steps"]]
    return row


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--configs", nargs="*", default=list(CONFIGS))
    ap.add_argument("probes", nargs="*")
    a = ap.parse_args(argv)
    probes = a.probes or sorted(glob.glob(os.path.join(HERE, "probes", "*.json")))
    os.makedirs(a.out, exist_ok=True)
    rows, audits = [], {}
    started = time.time()
    for config in a.configs:
        t = time.time()
        rep = {}
        got = run_eval.run(os.path.join(a.workdir, config), probes, a.reps, config,
                           audit_out=rep)
        rows += got
        if rep:
            audits[config] = {k: (dict(v, problems=v["problems"][:10]) if isinstance(v, dict)
                                  else v) for k, v in rep.items()}
        print(f"{config}: {len(got)} trials, {time.time() - t:.1f} s", file=sys.stderr)
    with gzip.open(os.path.join(a.out, "results.jsonl.gz"), "wt") as f:
        for r in rows:
            f.write(json.dumps(trim(r)) + "\n")
    with open(os.path.join(a.out, "audits.json"), "w") as f:
        json.dump(audits, f, indent=1)
    meta = {"reps": a.reps, "configs": a.configs, "probes": [os.path.basename(p) for p in probes],
            "trials": len(rows), "seconds": round(time.time() - started, 1),
            "python": platform.python_version(), "kernel": platform.release(),
            "landlock_abi": landlock.abi_version()}
    with open(os.path.join(a.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    with open(os.path.join(a.out, "tables.md"), "w") as f:
        f.write("## Leaks (or successes) per configuration\n\n" + report.table(rows) + "\n\n")
        f.write("## Attempts\n\n" + report.table(rows, what="att") + "\n\n")
        f.write("## Trial time\n\n" + report.timing(rows) + "\n\n")
        f.write("## Auditor\n\n" + report.audits(audits) + "\n")
    print(json.dumps(meta), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
