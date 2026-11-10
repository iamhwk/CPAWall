"""A hands-on walkthrough of Bulkhead on the running example (paper,
Section 5.1): projects OSS and Work, the testbed's services, partitions,
PEPs, the PDP, and the trusted UI.

  terminal 1:  python -m eval.walkthrough --workdir /tmp/bh-walk
  terminal 2:  python -m bulkhead.core.ui console --state /tmp/bh-walk/core

Terminal 1 gives you a shell prompt in the partition of the project that
is active; switch projects, and answer the PDP's questions, in the trusted
UI in terminal 2. Each line you type runs in the partition as code the
agent runs there would, and counts as one task, so an answer `t` covers
the rest of that line (a git push makes two requests). `cd` is
remembered per project. Both projects are signed in to every service, so
the vault holds Work's credentials too: whether a request gets them is up
to the policy alone. Type `exit` to stop; the log, the policies, and the
services' access log stay in the work directory for the reports and the
auditor.
"""
import argparse
import itertools
import os
import shlex
import sys

from bulkhead.agent.scripted import Oracle
from eval.run_eval import PROJECTS, Deployment, Workspace
from testbed import setup as tb
from testbed.services import Testbed

MARK = "@@bulkhead-cwd@@"
GUIDE = """\
Bulkhead walkthrough. State directory: {core}

1. In terminal 2, start the trusted UI and make OSS active:
     python -m bulkhead.core.ui console --state {core}
     switch oss
2. Here, as code a pull request brings to OSS, try the employer's repository:
     git clone https://git.test/acme/payments.git /tmp/payments
   OSS's policy grants nothing on it: refused. Nor does OSS's partition hold
   a credential to try: on a shared OS account, git's credential store would
   hold Work's (the pilot of Section 4); here it is empty:
     cat ~/.git-credentials
3. In the trusted UI: switch work   (OSS is frozen while Work is active)
4. Here, push to Work's main branch from the shell:
     cd work/payments
     git commit --allow-empty -m walkthrough && git push
   Work's shell setting would allow it, but the policy says ask: the trusted
   UI asks you. Answer t to allow it, or n to refuse it.
5. Work's policy hides its secrets from every channel, the shell included:
     cat secrets/staging.env
6. Afterwards: python -m bulkhead.core.ui log --state {core} -n 20
               python -m bulkhead.core.ui verify --state {core}
               python -m bulkhead.core.audit --state {core} --service-log {srv}/access.jsonl
Press Enter to refresh the prompt after a switch; exit stops everything.
"""


def run(part, cwd, line, timeout):
    """Run `line` with bash in the partition from `cwd`; returns the result
    and the directory the line ended in."""
    script = f"cd {shlex.quote(cwd)} && {{ {line}\n}}; rc=$?; printf '\\n{MARK}%s' \"$PWD\"; exit $rc"
    r = part.run(["bash", "-c", script], timeout=timeout)
    out, sep, new_cwd = r["stdout"].rpartition("\n" + MARK)
    if not sep:
        out, new_cwd = r["stdout"], cwd
    return r, out, new_cwd


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--timeout", type=float, default=300,
                    help="seconds a question waits for the trusted UI before it is denied")
    a = ap.parse_args(argv)
    ws = Workspace(a.workdir).prepare()
    testbed = Testbed(ws.srv).serve()
    dep = Deployment(ws)
    dep.begin_trial(Oracle("deny"), list(PROJECTS), task=None)
    homes = {p: tb.restore(os.path.join(ws.snap, "partitions", p, "home"),
                           os.path.join(ws.root, "walkthrough", p, "home")) for p in PROJECTS}
    sessions = dep.sessions(homes)
    dep.serve_ui(sessions, timeout=a.timeout)
    cwds = dict(homes)
    peps = [*dep.peps.values(), *dep.browser_peps.values(), *dep.connector_peps.values()]
    print(GUIDE.format(core=ws.core, srv=ws.srv))
    try:
        for n in itertools.count(1):
            project = sessions.active
            here = os.path.relpath(cwds[project], homes[project]) if project else ""
            try:
                line = input(f"[{project or 'no project'}] {'~' if here == '.' else '~/' + here}$ ")
            except EOFError:
                break
            line = line.strip()
            if line in ("exit", "quit"):
                break
            if not line:
                continue
            project = sessions.active
            if project is None:
                print("No project is active: in the trusted UI, type  switch oss")
                continue
            for pep in peps:
                pep.task = f"walkthrough-{n}"
            r, out, cwds[project] = run(sessions.partition(project), cwds[project], line,
                                        a.timeout + 60)
            sys.stdout.write(out if out.endswith("\n") or not out else out + "\n")
            sys.stdout.write(r["stderr"])
            if r["exit"]:
                print(f"(exit {r['exit']})")
    except KeyboardInterrupt:
        print()
    finally:
        sessions.stop_all()
        dep.close()
        testbed.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
