"""The trusted UI's channel into the core (design, Section 4.5; paper, Fig. 2).

The user switches the active project and answers the PDP's `ask` here
and nowhere else. The core listens on a Unix socket in the abstract
namespace, which belongs to the core's network namespace: a partition has
a network namespace of its own (and, from Landlock ABI 6, its abstract
sockets are scoped as well), so nothing in a partition can reach the
socket. The core also accepts a
peer only if it runs as the core's OS user in the core's network
namespace. The agent therefore has no interface to the session manager or
to approvals.

The protocol is one JSON object per line. The trusted UI sends

  {"cmd": "status"}                    active project, each project's policy
                                       version and partition, questions pending
  {"cmd": "switch", "project": P}      make P the active project
  {"cmd": "subscribe"}                 receive the PDP's questions (a console)
  {"cmd": "answer", "id": N, "answer": "y" | "t" | "p" | "n"}

and the core replies to each with {"type": "reply", "ok": ..., ...}. A
subscribed console also receives {"type": "ask", "id": N, ...} for every
question, including those pending when it subscribes, and
{"type": "settled", "id": N, "answer": ...} once a question is answered,
from any console, or times out. A question nobody answers in time is
denied: the PDP fails closed.
"""
import hashlib
import json
import os
import socket
import struct
import threading
import time

PROJECT_TTL = 3600          # an answer for the project holds for an hour
_SCOPES = {"y": "request", "yes": "request", "t": "task", "task": "task",
           "p": "project", "project": "project"}


def control_address(state):
    """The abstract socket name of the core whose state is in `state`."""
    digest = hashlib.sha256(os.path.realpath(state).encode()).hexdigest()[:32]
    return b"\0bulkhead-ui-" + digest.encode()


def approval(answer, q):
    """The PDP oracle's value for an answer: y (this request), t (this
    task), p (the project, for an hour); anything else declines."""
    scope = _SCOPES.get((answer or "").strip().lower())
    if scope is None or (scope == "task" and not q.get("task")):
        return False
    out = {"approve": True, "scope": scope}
    if scope == "project":
        out["ttl"] = PROJECT_TTL
    return out


def _peer_ok(sock):
    """The peer runs as our OS user, in our network namespace."""
    size = struct.calcsize("3i")
    pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET,
                                                         socket.SO_PEERCRED, size))
    if uid != os.getuid():
        return False
    try:
        return os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net")
    except OSError:
        return False


class _Conn:
    def __init__(self, sock):
        self.sock, self.lock, self.subscribed = sock, threading.Lock(), False

    def send(self, obj):
        data = (json.dumps(obj, default=str) + "\n").encode()
        with self.lock:
            try:
                self.sock.sendall(data)
                return True
            except OSError:
                return False


class ControlServer:
    def __init__(self, state, sessions, timeout=120.0):
        """`sessions` is the core's SessionManager; a question the user does
        not answer within `timeout` seconds is denied."""
        self.state, self.sessions, self.timeout = state, sessions, timeout
        self.address = control_address(state)
        self.cond = threading.Condition()
        self.pending, self.answers = {}, {}
        self.conns = set()
        self._next, self._closed, self.sock = 1, False, None

    # -- lifecycle -------------------------------------------------------
    def start(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        s.bind(self.address)
        s.listen(16)
        self.sock = s
        threading.Thread(target=self._accept, name="trusted-ui", daemon=True).start()
        return self

    def close(self):
        with self.cond:
            self._closed = True
            self.cond.notify_all()
            conns = list(self.conns)
        if self.sock:
            for op in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
                try:
                    op()
                except OSError:
                    pass
        for c in conns:
            try:
                c.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _accept(self):
        while True:
            try:
                sock, _ = self.sock.accept()
            except OSError:
                return
            if not _peer_ok(sock):
                sock.close()
                continue
            conn = _Conn(sock)
            with self.cond:
                self.conns.add(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            for line in conn.sock.makefile("rb"):
                if line.strip():
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        conn.send({"type": "reply", "ok": False, "error": "not JSON"})
                        continue
                    conn.send(dict(self._handle(conn, msg), type="reply", cmd=msg.get("cmd")))
        except OSError:
            pass
        finally:
            with self.cond:
                self.conns.discard(conn)
            conn.sock.close()

    # -- commands --------------------------------------------------------
    def _handle(self, conn, msg):
        cmd = msg.get("cmd")
        if cmd == "status":
            return dict(self.status(), ok=True)
        if cmd == "switch":
            project = msg.get("project")
            if project not in self.sessions.store.projects():
                return {"ok": False, "error": f"no project {project!r}"}
            rec = self.sessions.switch(project, by="trusted-ui")
            return {"ok": True, "active": project, "frozen": rec.get("frozen", []),
                    "seq": rec.get("seq")}
        if cmd == "subscribe":
            with self.cond:
                conn.subscribed = True
                waiting = [dict(q) for q in self.pending.values() if q["id"] not in self.answers]
            for q in waiting:
                conn.send(dict(q, type="ask"))
            return {"ok": True}
        if cmd == "answer":
            qid = msg.get("id")
            with self.cond:
                if qid not in self.pending or qid in self.answers:
                    return {"ok": False, "error": f"no question #{qid} is pending"}
                self.answers[qid] = str(msg.get("answer", ""))
                self.cond.notify_all()
            return {"ok": True, "id": qid}
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def status(self):
        s = self.sessions
        with s.lock:
            parts = {p: "frozen" if part.frozen else "running"
                     for p, (part, _, _) in s.parts.items()}
            active = s.active
        projects = {}
        for p in s.store.projects():
            policy = s.store.current(p)
            projects[p] = {"version": policy.version, "background": bool(policy.background),
                           "partition": parts.get(p, "not started")}
        with self.cond:
            pending = [dict(q) for q in self.pending.values()]
        return {"active": active, "projects": projects, "pending": pending}

    # -- the PDP's questions ---------------------------------------------
    def ask(self, question):
        """Put `question` to every console and wait for the first answer;
        None if none comes in time (the PDP then denies)."""
        with self.cond:
            qid, self._next = self._next, self._next + 1
            q = dict(question, id=qid)
            self.pending[qid] = q
            consoles = [c for c in self.conns if c.subscribed]
        for c in consoles:
            c.send(dict(q, type="ask"))
        deadline = time.monotonic() + self.timeout
        with self.cond:
            while qid not in self.answers and not self._closed:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self.cond.wait(left)
            answer = self.answers.pop(qid, None)
            self.pending.pop(qid, None)
            consoles = [c for c in self.conns if c.subscribed]
        for c in consoles:
            c.send({"type": "settled", "id": qid,
                    "answer": answer if answer is not None else "timeout"})
        return answer


class UiOracle:
    """The PDP's oracle when the user answers on the trusted UI's console."""

    def __init__(self, server):
        self.server, self.asked = server, []

    def __call__(self, q):
        self.asked.append(q)
        return approval(self.server.ask(q), q)
