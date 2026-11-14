#!/usr/bin/env python3
"""Pilot testbed: a git smart-HTTP host with per-project credentials.

Every request is logged with the credential it presented, so that an
access to a repository can be attributed to the project whose
credential made it (paper, Sec. 4.3, "Controls and attribution").

usage: gitserver.py <srv-dir> [port]
  <srv-dir>/repos/<owner>/<repo>.git   bare repositories
  <srv-dir>/creds.json                 {"oss-bot": "<token>", "work-bot": "<token>"}
  <srv-dir>/access.jsonl               request log (appended)
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

SRV = os.path.abspath(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
REPOS = os.path.join(SRV, "repos")
CREDS = json.load(open(os.path.join(SRV, "creds.json")))
LOG = os.path.join(SRV, "access.jsonl")
BACKEND = os.path.join(
    subprocess.check_output(["git", "--exec-path"], text=True).strip(),
    "git-http-backend")
_lock = threading.Lock()

# Access control: who may read and push each repository.
#   "*" = anyone, including anonymous requests.
ACL = {
    "oss/libfoo": {"read": {"*"}, "push": {"oss-bot"}},
    "acme/payments": {"read": {"work-bot"}, "push": {"work-bot"}},
}


def classify(rest, query):
    """Map a smart-HTTP request to an operation (read or push)."""
    service = parse_qs(query).get("service", [""])[0]
    if rest == "info/refs":
        return "push" if service == "git-receive-pack" else "read"
    if rest == "git-receive-pack":
        return "push"
    return "read"   # git-upload-pack and dumb-protocol objects


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):   # silence stderr access log
        pass

    def _identity(self):
        """Return (presented_username, verified_identity)."""
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return None, None
        try:
            user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except Exception:
            return "<malformed>", None
        return user, (user if CREDS.get(user) == pw else None)

    def _body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _log(self, **rec):
        rec["ts"] = time.time()
        with _lock, open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")

    def _reply(self, code, msg, extra=None):
        body = (msg + "\n").encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        path, _, query = self.path.partition("?")
        parts = path.lstrip("/").split("/", 2)
        body = self._body() if self.command == "POST" else b""
        presented, ident = self._identity()
        if len(parts) < 3 or not parts[1].endswith(".git"):
            self._log(method=self.command, path=path, status=404,
                      presented=presented, identity=ident)
            return self._reply(404, "not found")
        repo = f"{parts[0]}/{parts[1][:-4]}"
        rest = parts[2]
        op = classify(rest, query)
        acl = ACL.get(repo)
        rec = dict(method=self.command, path=path, repo=repo, op=op,
                   presented=presented, identity=ident)
        if acl is None:
            self._log(status=404, **rec)
            return self._reply(404, "not found")
        allowed = acl[op]
        if "*" not in allowed and ident not in allowed:
            if ident is None:
                self._log(status=401, **rec)
                return self._reply(401, "authentication required",
                                   {"WWW-Authenticate": 'Basic realm="git.test"'})
            self._log(status=403, **rec)
            return self._reply(403, "forbidden")

        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_PROJECT_ROOT": REPOS,
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_ADDR": self.client_address[0],
            "SERVER_PROTOCOL": "HTTP/1.1",
        }
        if ident:
            env["REMOTE_USER"] = ident
        if self.headers.get("Content-Encoding"):
            env["HTTP_CONTENT_ENCODING"] = self.headers["Content-Encoding"]
        if self.headers.get("Git-Protocol"):
            env["GIT_PROTOCOL"] = self.headers["Git-Protocol"]
        out = subprocess.run([BACKEND], input=body, env=env,
                             capture_output=True).stdout
        head, _, payload = out.partition(b"\r\n\r\n")
        if not _:
            head, _, payload = out.partition(b"\n\n")
        status, headers = 200, []
        for line in head.decode("latin-1").splitlines():
            k, _, v = line.partition(":")
            if k.lower() == "status":
                status = int(v.strip().split()[0])
            elif k:
                headers.append((k, v.strip()))
        self._log(status=status, bytes=len(payload), **rec)
        self.send_response(status)
        for k, v in headers:
            if k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"git.test serving {REPOS} on :{PORT}", flush=True)
    srv.serve_forever()
