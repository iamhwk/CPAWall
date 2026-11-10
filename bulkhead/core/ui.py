"""Trusted UI (design, Section 4.5; paper, Fig. 2): the user's only way to
switch projects and to answer approvals, and the reports.

The console and the switch and status commands talk to a running core
over its control channel (bulkhead.core.control), which no partition can
reach. The reports read a deployment's state directory (its archived
policies and its log). TtyOracle is the alternative for a core that runs
in the user's own terminal: it asks on that terminal. The experiments use
scripted oracles instead.

usage: python -m bulkhead.core.ui console --state DIR     approve, switch
       python -m bulkhead.core.ui switch PROJECT --state DIR
       python -m bulkhead.core.ui status --state DIR
       python -m bulkhead.core.ui authority --state DIR --ontology O.yaml
       python -m bulkhead.core.ui log --state DIR [-n 20]
       python -m bulkhead.core.ui verify --state DIR
"""
import argparse
import glob
import json
import os
import selectors
import socket
import sys

from . import control
from .log import read_records, verify
from .pdp import PolicyStore

SCOPE_WORDS = {"request": "for this request", "task": "for this task",
               "project": "for the project, for an hour"}
HELP = """Trusted UI. Commands:
  switch PROJECT     make PROJECT the active project
  status             the active project, partitions, policy versions
  y | t | p | n [N]  answer question #N (default: the oldest pending):
                     y this request, t this task, p the project for an hour,
                     n deny
  help, quit
"""


class TtyOracle:
    """Asks on /dev/tty: y = this request, t = this task, p = the project
    for an hour; anything else declines."""

    def __init__(self, tty="/dev/tty"):
        self.tty = tty

    def __call__(self, q):
        try:                      # a terminal is not seekable: one file each way
            with open(self.tty, "w") as out, open(self.tty) as inp:
                out.write(question_text(q))
                out.flush()
                answer = inp.readline()
        except OSError:
            return False
        return control.approval(answer, q)


def question_text(q):
    tag = f"#{q['id']} " if "id" in q else ""
    return (f"\n[bulkhead] {tag}{q['project']} asks to {q['op']} {q['resource']}\n"
            f"  via {q['channel']}: {q.get('request') or ''}\n"
            f"  (policy v{q['version']}) allow? [y]es / [t]ask / [p]roject / [N]o ")


class Client:
    """A connection to a running core's control channel."""

    def __init__(self, state, timeout=10.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(control.control_address(state))
        except OSError as e:
            self.sock.close()
            raise ConnectionError(f"no Bulkhead core is serving {state} "
                                  f"({e.strerror or e}); is it running?") from None
        self.buf = b""

    def send(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def feed(self, data):
        """Messages completed by `data`."""
        self.buf += data
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            if line.strip():
                out.append(json.loads(line))
        return out

    def call(self, obj):
        self.send(obj)
        while True:
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("the core closed the connection")
            for msg in self.feed(data):
                if msg.get("type") == "reply":
                    return msg

    def close(self):
        self.sock.close()


def show_status(st, out):
    out.write(f"active project: {st['active'] or '(none)'}\n")
    for p, info in st["projects"].items():
        bg = "  (may work in the background)" if info["background"] else ""
        out.write(f"  {p:<8} policy v{info['version']:<3} partition {info['partition']}{bg}\n")
    if st["pending"]:
        out.write(f"  questions pending: {', '.join('#' + str(q['id']) for q in st['pending'])}\n")


def show_switch(reply, out):
    frozen = f" (frozen: {', '.join(reply['frozen'])})" if reply.get("frozen") else ""
    out.write(f"active project: {reply['active']}{frozen}\n")


def settled_text(msg, q):
    what = f"{q['project']} {q['op']} {q['resource']}" if q else ""
    scope = control.approval(msg["answer"], q or {"task": True})
    if msg["answer"] == "timeout":
        verdict = "no answer in time: denied"
    elif scope:
        verdict = "allowed " + SCOPE_WORDS[scope["scope"]]
    else:
        verdict = "denied"
    return f"#{msg['id']} {what}: {verdict}\n"


def console(state, inp=None, out=None):
    """Answer the PDP's questions and switch projects until `quit`."""
    inp, out = inp or sys.stdin, out or sys.stdout
    try:
        client = Client(state, timeout=None)
    except ConnectionError as e:
        out.write(f"{e}\n")
        return 1
    client.send({"cmd": "subscribe"})
    client.send({"cmd": "status"})
    out.write(HELP)
    pending = {}                                   # id -> question, oldest first
    sel = selectors.DefaultSelector()
    sel.register(client.sock, selectors.EVENT_READ, "core")
    sel.register(inp.fileno(), selectors.EVENT_READ, "user")
    typed = b""

    def handle(msg):
        kind = msg.get("type")
        if kind == "ask":
            pending[msg["id"]] = msg
            out.write(question_text(msg) + f"  -> answer: y {msg['id']}\n")
        elif kind == "settled":
            out.write(settled_text(msg, pending.pop(msg["id"], None)))
        elif kind == "reply":
            if not msg.get("ok"):
                out.write(f"error: {msg.get('error')}\n")
            elif msg.get("cmd") == "status":
                show_status(msg, out)
            elif msg.get("cmd") == "switch":
                show_switch(msg, out)

    def command(line):
        words = line.split()
        if not words:
            return True
        word = words[0].lower()
        if word in ("y", "yes", "t", "task", "p", "project", "n", "no"):
            if len(words) > 1:
                qid = int(words[1].lstrip("#")) if words[1].lstrip("#").isdigit() else None
            else:
                qid = next(iter(pending), None)
            if qid is None:
                out.write("no question is pending\n")
            else:
                client.send({"cmd": "answer", "id": qid, "answer": word})
        elif word == "switch" and len(words) == 2:
            client.send({"cmd": "switch", "project": words[1]})
        elif word == "status":
            client.send({"cmd": "status"})
        elif word in ("help", "?"):
            out.write(HELP)
        elif word in ("quit", "exit"):
            return False
        else:
            out.write("unknown command; type help\n")
        return True

    try:
        while True:
            out.flush()
            for key, _ in sel.select():
                if key.data == "core":
                    data = client.sock.recv(65536)
                    if not data:
                        out.write("the core has stopped\n")
                        return 1
                    for msg in client.feed(data):
                        handle(msg)
                else:
                    data = os.read(inp.fileno(), 4096)
                    if not data:
                        return 0
                    typed += data
                    while b"\n" in typed:
                        line, typed = typed.split(b"\n", 1)
                        if not command(line.decode(errors="replace").strip()):
                            return 0
    finally:
        out.flush()
        client.close()


def latest_policies(state):
    out = {}
    for project_dir in sorted(glob.glob(os.path.join(state, "policies", "*"))):
        versions = sorted(glob.glob(os.path.join(project_dir, "v*.json")),
                          key=lambda p: int(os.path.basename(p)[1:-5]))
        if versions:
            pol = PolicyStore.load_archived(versions[-1])
            out[pol.project] = pol
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bulkhead trusted UI")
    ap.add_argument("command", choices=("console", "switch", "status", "authority", "log",
                                        "verify"))
    ap.add_argument("project", nargs="?", help="for switch: the project to make active")
    ap.add_argument("--state", required=True, help="the core's state directory")
    ap.add_argument("--ontology")
    ap.add_argument("-n", type=int, default=20)
    a = ap.parse_args(argv)
    log_path = os.path.join(a.state, "log.jsonl")
    if a.command == "console":
        return console(a.state)
    if a.command in ("switch", "status"):
        if a.command == "switch" and not a.project:
            ap.error("switch needs a project")
        try:
            client = Client(a.state)
        except ConnectionError as e:
            print(e)
            return 1
        try:
            if a.command == "switch":
                reply = client.call({"cmd": "switch", "project": a.project})
            else:
                reply = client.call({"cmd": "status"})
        finally:
            client.close()
        if not reply.get("ok"):
            print(f"error: {reply.get('error')}")
            return 1
        (show_switch if a.command == "switch" else show_status)(reply, sys.stdout)
        return 0
    if a.command == "authority":
        from ..policy.analyzer import analyze, report
        from ..policy.ontology import Ontology
        policies = latest_policies(a.state)
        onto = Ontology.load(a.ontology) if a.ontology else None
        findings = analyze(policies, onto) if onto else []
        print(report(policies, findings))
    elif a.command == "log":
        for r in read_records(log_path)[-a.n:]:
            what = r.get("event") or f"{r.get('op')} {r.get('resource')}"
            print(f"{r['seq']:>6} {r['ts'][11:19]} {r.get('project', '-'):<6} "
                  f"{r.get('channel', '-'):<8} {what:<48} {r.get('final', '')} "
                  f"{r.get('outcome', '')}")
    else:
        pub = os.path.join(a.state, "log.key.pub")
        with open(pub, "rb") as f:
            problems = verify(log_path, f.read())
        print("log verifies" if not problems else "\n".join(problems))
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
