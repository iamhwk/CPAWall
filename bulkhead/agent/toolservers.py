"""Tool servers used by the scripted agent.

GitHubServer stands in for a GitHub-like MCP server configured with one
account's token, as such servers are on real platforms. In the baseline it
holds the real token. Under Bulkhead it runs inside the partition with a
placeholder, and its requests leave through the partition's PEP, which
puts in the real token where the policy allows; from M4 the MCP gateway
also mediates each call.

usage (one call, as a process):
  python -m bulkhead.agent.toolservers github <tool> '<json arguments>'
with TOOLSERVER_GITHUB_URL, _USER and _SECRET in the environment.
"""
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote


class GitHubServer:
    def __init__(self, base_url, user=None, secret=None, env=None):
        self.base = base_url.rstrip("/")
        self.user, self.secret = user, secret
        self.env = env or {}   # the server's proxy and CA variables (bulkhead.env)

    def call(self, name, args):
        fn = {"list_issues": self.list_issues, "add_comment": self.add_comment,
              "push_files": self.push_files}.get(name)
        if fn is None:
            return "error", f"unknown tool {name}"
        return fn(**args)

    def _auth(self):
        if not self.user:
            return {}
        raw = f"{self.user}:{self.secret}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def _api(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=dict(self._auth(),
                                                  **{"Content-Type": "application/json"}))
        handlers = [urllib.request.ProxyHandler(
            {k: self.env[v] for k, v in (("http", "http_proxy"), ("https", "https_proxy"))
             if self.env.get(v)})]
        if self.env.get("SSL_CERT_FILE"):
            handlers.append(urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=self.env["SSL_CERT_FILE"])))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=30) as r:
                return "ok", r.read().decode()
        except urllib.error.HTTPError as e:
            return "error", f"HTTP {e.code}: {e.read().decode(errors='replace')}"

    def list_issues(self, owner, repo):
        return self._api("GET", f"/api/repos/{owner}/{repo}/issues")

    def add_comment(self, owner, repo, n, body):
        return self._api("POST", f"/api/repos/{owner}/{repo}/issues/{n}/comments",
                         {"body": body})

    def push_files(self, owner, repo, files, message="update", branch="main"):
        scheme, _, rest = self.base.partition("://")
        cred = f"{quote(self.user)}:{quote(self.secret)}@" if self.user else ""
        url = f"{scheme}://{cred}{rest}/{owner}/{repo}.git"
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(PATH=os.environ.get("PATH", "/usr/bin:/bin"), HOME=tmp,
                       GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
                       GIT_AUTHOR_NAME="bot", GIT_AUTHOR_EMAIL="bot@example.test",
                       GIT_COMMITTER_NAME="bot", GIT_COMMITTER_EMAIL="bot@example.test",
                       **self.env)
            wt = os.path.join(tmp, "wt")
            steps = [["git", "clone", "-q", url, wt]]
            for cmd in steps:
                p = subprocess.run(cmd, env=env, capture_output=True, text=True)
                if p.returncode:
                    return "error", p.stderr.replace(self.secret or "\0", "***")
            for rel, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(wt, rel)) or wt, exist_ok=True)
                with open(os.path.join(wt, rel), "w") as f:
                    f.write(text)
            for cmd in (["git", "add", "-A"], ["git", "commit", "-q", "-m", message],
                        ["git", "push", "-q", "origin", f"HEAD:{branch}"]):
                p = subprocess.run(cmd, cwd=wt, env=env, capture_output=True, text=True)
                if p.returncode:
                    return "error", p.stderr.replace(self.secret or "\0", "***")
        return "ok", f"pushed {len(files)} file(s) to {owner}/{repo}"


class StagingDbServer:
    """A staging-database tool server: query (read) and execute (write)."""

    def __init__(self, base_url, secret=None, env=None):
        self.base = base_url.rstrip("/")
        self.secret = secret
        self.env = env or {}

    def call(self, name, args):
        fn = {"query": "query", "execute": "exec"}.get(name)
        if fn is None:
            return "error", f"unknown tool {name}"
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        req = urllib.request.Request(f"{self.base}/{quote(str(args.get('db', '')))}/{fn}",
                                     data=json.dumps({"sql": args.get("sql", "")}).encode(),
                                     method="POST", headers=headers)
        handlers = [urllib.request.ProxyHandler(
            {k: self.env[v] for k, v in (("http", "http_proxy"), ("https", "https_proxy"))
             if self.env.get(v)})]
        if self.env.get("SSL_CERT_FILE"):
            handlers.append(urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=self.env["SSL_CERT_FILE"])))
        try:
            with urllib.request.build_opener(*handlers).open(req, timeout=30) as r:
                return "ok", r.read().decode()
        except urllib.error.HTTPError as e:
            return "error", f"HTTP {e.code}: {e.read().decode(errors='replace')}"


def from_env(server, environ=None):
    """A tool server configured from TOOLSERVER_* variables, as tool
    servers are configured by their platform."""
    environ = os.environ if environ is None else environ
    env = {k: v for k, v in environ.items() if k in PASS_VARS}
    if server == "github":
        return GitHubServer(environ["TOOLSERVER_GITHUB_URL"], environ.get("TOOLSERVER_GITHUB_USER"),
                            environ.get("TOOLSERVER_GITHUB_SECRET"), env=env)
    if server == "stagingdb":
        return StagingDbServer(environ["TOOLSERVER_DB_URL"], environ.get("TOOLSERVER_DB_SECRET"),
                               env=env)
    raise ValueError(f"unknown tool server {server}")


PASS_VARS = ("SSL_CERT_FILE", "GIT_SSL_CAINFO", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
             "NODE_EXTRA_CA_CERTS", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
             "ALL_PROXY", "all_proxy", "no_proxy", "NO_PROXY")


def main(argv):
    server, tool = argv[0], argv[1]
    args = json.loads(argv[2]) if len(argv) > 2 else {}
    try:
        status, out = from_env(server).call(tool, args)
    except Exception as e:     # noqa: BLE001 - a failed call is a result
        status, out = "error", f"{type(e).__name__}: {e}"
    print(json.dumps({"status": status, "out": out}))
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
