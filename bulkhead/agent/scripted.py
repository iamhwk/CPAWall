"""Scripted agent: replays a JSON script of tool calls deterministically.

Security properties must not depend on model behavior (design,
consideration 10), so trials drive the channels with scripts. The tools
model the channels of an agent platform: a shell, a file tool, a web
(HTTP) tool, and tool servers (MCP).

In the shared-substrate baseline the tools also apply the platform's own
per-channel settings (allow lists, deny rules, ask), the way a coding agent
does. Under Bulkhead the settings are not consulted (``settings=None``):
every tool runs inside the project's partition (``partition``), and
enforcement happens at the PEP and in the kernel. The file tool, the web
tool and the tool servers then run as processes in the partition, as the
shell does.

Script format:
  {"name": ..., "project": "oss",
   "steps": [{"tool": "shell", "cmd": "git clone ..."},
             {"tool": "fs.read", "path": "secrets/staging.env"},
             {"tool": "fs.write", "path": "notes.txt", "text": "..."},
             {"tool": "http", "method": "GET", "url": "...", "headers": {}, "body": null},
             {"tool": "mcp", "server": "github", "name": "push_files", "args": {...}}]}
"""
import fnmatch
import json
import os
import re
import shlex
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field

MAX_OUT = 4000
SEPARATORS = {"&&", "||", ";", "|", "&"}


class Oracle:
    """Answers 'ask': 'deny', 'approve', or a scripted list of answers, each
    a boolean or a dict with approve, scope and ttl (an answer scoped beyond
    one request)."""

    def __init__(self, spec="deny"):
        self.spec = list(spec) if isinstance(spec, (list, tuple)) else spec
        self.asked = []

    def __call__(self, request):
        self.asked.append(request)
        if isinstance(self.spec, list):
            return self.spec.pop(0) if self.spec else False
        return self.spec == "approve"


@dataclass
class Context:
    project: str
    project_dir: str
    home: str
    env: dict = field(default_factory=dict)      # proxy and CA variables, if any
    settings: dict | None = None                  # emulated platform settings
    oracle: Oracle = field(default_factory=Oracle)
    tool_servers: dict = field(default_factory=dict)
    timeout: float = 60.0
    partition: object = None                      # bulkhead.pep.sandbox.Partition
    tool_env: dict = field(default_factory=dict)  # tool servers in the partition
    gateway: object = None                        # bulkhead.pep.mcp_gateway.McpGateway
    task: str | None = None
    capabilities: dict | None = None    # CapScope-style: minted from the trusted task
    connectors: object = None           # callable(service, name, args) -> (status, out)
    platform_approvals: dict | None = None   # the platform's "don't ask again" answers


def _trim(text):
    return text if len(text) <= MAX_OUT else text[:MAX_OUT] + "...[truncated]"


_SKIP = {"for", "select", "case", "function"}          # headers that run no command
_DROP = {"while", "until", "if", "elif", "then", "else", "do", "done", "fi", "esac",
         "!", "{", "}", "time"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def segments(cmd):
    """The commands a command line runs, as argument vectors: split at
    control operators, parentheses and newlines; shell keywords and leading
    variable assignments are not commands, and loop headers run none."""
    lex = shlex.shlex(cmd.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    out, cur = [], []
    for tok in lex:
        if tok in SEPARATORS or tok in ("(", ")"):
            out.append(cur)
            cur = []
        else:
            cur.append(tok)
    out.append(cur)
    argvs = []
    for argv in out:
        while argv and (argv[0] in _DROP or _ASSIGN.match(argv[0])):
            argv = argv[1:]
        if argv and argv[0] not in _SKIP:
            argvs.append(argv)
    return argvs


def subprocess_env(ctx):
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
           "HOME": ctx.home, "LANG": "C.UTF-8", "TMPDIR": os.path.join(ctx.home, "tmp"),
           "GIT_TERMINAL_PROMPT": "0"}
    env.update(ctx.env)
    return env


def _result(step, status, **kw):
    return dict(tool=step["tool"], status=status, **kw)


_WRITE = ("import os, sys; p = sys.argv[1]; "
          "os.makedirs(os.path.dirname(p) or '.', exist_ok=True); "
          "open(p, 'w').write(sys.stdin.read())")
_HTTP = """
import json, sys, urllib.error, urllib.request
s = json.loads(sys.argv[1])
body = s.get("body")
data = body.encode() if isinstance(body, str) else (
    json.dumps(body).encode() if body is not None else None)
req = urllib.request.Request(s["url"], data=data, method=s.get("method", "GET"),
                             headers=s.get("headers", {}))
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        out = {"status": "ok", "http": r.status, "out": r.read().decode(errors="replace")}
except urllib.error.HTTPError as e:
    out = {"status": "error", "http": e.code, "out": e.read().decode(errors="replace")}
except Exception as e:
    out = {"status": "error", "reason": str(getattr(e, "reason", e))}
print(json.dumps(out))
"""


def _in_partition(ctx, step, argv, stdin=None, env=None, parse=False):
    r = ctx.partition.run(argv, cwd=ctx.project_dir, env=dict(ctx.env, **(env or {})),
                          stdin=stdin, timeout=ctx.timeout)
    if r["timed_out"]:
        return _result(step, "error", reason="timeout", out=_trim(r["stdout"]))
    if parse:
        try:
            out = json.loads(r["stdout"].strip().splitlines()[-1])
        except (ValueError, IndexError):
            return _result(step, "error", exit=r["exit"], out=_trim(r["stdout"]),
                           err=_trim(r["stderr"]))
        return _result(step, out.pop("status", "error"),
                       **{k: (_trim(v) if isinstance(v, str) else v) for k, v in out.items()})
    return _result(step, "ok" if r["exit"] == 0 else "error", exit=r["exit"],
                   out=_trim(r["stdout"]), err=_trim(r["stderr"]))


def run_shell(ctx, step):
    cmd = step["cmd"]
    if ctx.settings is not None:
        allow = set(ctx.settings.get("shell", {}).get("allow", []))
        if "$(" in cmd or "`" in cmd:
            return _result(step, "denied_by_platform", reason="command substitution")
        try:
            argvs = segments(cmd)
        except ValueError as e:
            return _result(step, "denied_by_platform", reason=f"unparsable: {e}")
        for argv in argvs:
            if os.path.basename(argv[0]) not in allow:
                return _result(step, "denied_by_platform", reason=f"not allowed: {argv[0]}")
    if ctx.partition is not None:
        return _in_partition(ctx, step, ["bash", "-c", cmd])
    try:
        p = subprocess.run(["bash", "-c", cmd], cwd=ctx.project_dir, env=subprocess_env(ctx),
                           capture_output=True, text=True, timeout=ctx.timeout)
    except subprocess.TimeoutExpired:
        return _result(step, "error", reason="timeout")
    return _result(step, "ok" if p.returncode == 0 else "error", exit=p.returncode,
                   out=_trim(p.stdout), err=_trim(p.stderr))


def _fs_denied(ctx, rel):
    if ctx.settings is None:
        return False
    for pat in ctx.settings.get("fs", {}).get("deny", []):
        base = pat.rstrip("*").rstrip("/")
        if fnmatch.fnmatch(rel, pat.replace("**", "*")) or rel == base or \
                rel.startswith(base + "/"):
            return True
    return False


def run_fs(ctx, step):
    full = os.path.normpath(os.path.join(ctx.project_dir, step["path"]))
    rel = os.path.relpath(full, ctx.project_dir)
    if _fs_denied(ctx, rel):
        return _result(step, "denied_by_platform", reason=f"deny rule matches {rel}")
    if ctx.partition is not None:
        if step["tool"] == "fs.read":
            return _in_partition(ctx, step, ["cat", "--", full])
        return _in_partition(ctx, step, ["python3", "-c", _WRITE, full],
                             stdin=step.get("text", ""))
    try:
        if step["tool"] == "fs.read":
            with open(full) as f:
                return _result(step, "ok", out=_trim(f.read()))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(step.get("text", ""))
        return _result(step, "ok")
    except OSError as e:
        return _result(step, "error", reason=str(e))


def run_http(ctx, step):
    if ctx.partition is not None:
        return _in_partition(ctx, step, ["python3", "-c", _HTTP, json.dumps(step)], parse=True)
    env = subprocess_env(ctx)
    proxies = {k: env[v] for k, v in (("http", "http_proxy"), ("https", "https_proxy"))
               if env.get(v)}
    handlers = [urllib.request.ProxyHandler(proxies)]
    if env.get("SSL_CERT_FILE"):
        handlers.append(urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=env["SSL_CERT_FILE"])))
    opener = urllib.request.build_opener(*handlers)
    body = step.get("body")
    data = body.encode() if isinstance(body, str) else (
        json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(step["url"], data=data, method=step.get("method", "GET"),
                                 headers=step.get("headers", {}))
    try:
        with opener.open(req, timeout=ctx.timeout) as r:
            return _result(step, "ok", http=r.status,
                           out=_trim(r.read().decode(errors="replace")))
    except urllib.error.HTTPError as e:
        return _result(step, "error", http=e.code, out=_trim(e.read().decode(errors="replace")))
    except (urllib.error.URLError, OSError) as e:
        return _result(step, "error", reason=str(getattr(e, "reason", e)))


def _platform_ask(ctx, server, name, args):
    """The platform asks the user; an answer scoped beyond one request is
    kept for the rest of the session ("don't ask again"), as platforms
    keep such answers in memory."""
    key = f"{server}.{name}"
    if ctx.platform_approvals is not None and key in ctx.platform_approvals:
        return True
    answer = ctx.oracle({"server": server, "name": name, "args": args})
    if isinstance(answer, dict):
        ok = bool(answer.get("approve"))
        if ok and answer.get("scope", "request") != "request" and \
                ctx.platform_approvals is not None:
            ctx.platform_approvals[key] = answer.get("scope")
        return ok
    return bool(answer)


def run_mcp(ctx, step):
    server, name = step["server"], step["name"]
    if ctx.settings is not None:
        table = ctx.settings.get("mcp", {}).get(server, {})
        decision = table.get(name, table.get("*", "deny"))
        if decision == "deny":
            return _result(step, "denied_by_platform", reason=f"{server}.{name}: deny")
        if decision == "ask" and not _platform_ask(ctx, server, name, step.get("args", {})):
            return _result(step, "ask_denied", reason=f"{server}.{name}: ask, not approved")
    if ctx.gateway is not None:
        status, out, _ = ctx.gateway.call(ctx.project, server, name, step.get("args", {}),
                                          ctx.task)
        return _result(step, status, out=_trim(out))
    if ctx.partition is not None:
        return _in_partition(ctx, step, ["python3", "-m", "bulkhead.agent.toolservers", server,
                                         name, json.dumps(step.get("args", {}))],
                             env=ctx.tool_env, parse=True)
    srv = ctx.tool_servers.get(server)
    if srv is None:
        return _result(step, "error", reason=f"no tool server {server}")
    try:
        status, out = srv.call(name, step.get("args", {}))
    except Exception as e:   # a tool server failure is a step error
        return _result(step, "error", reason=f"{type(e).__name__}: {e}")
    return _result(step, status, out=_trim(out))


def run_connector(ctx, step):
    """A first-party connector of the platform account (chat, say)."""
    if ctx.connectors is None:
        return _result(step, "error", reason="no connectors")
    status, out = ctx.connectors(step["service"], step["name"], step.get("args", {}))
    return _result(step, status, out=_trim(out))


# -- capability checks in the style of CapScope (Bouras et al., LMPL '26) ----------
def _arg_prefix(cap, argv):
    """Every element of `cap` equals argv's, except that the last may be a
    string prefix of argv's element at that position."""
    if len(argv) < len(cap):
        return False
    *head, last = cap
    return argv[:len(head)] == head and argv[len(head)].startswith(last)


def _args_prefix(cap_args, args):
    for k, v in (cap_args or {}).items():
        a = args.get(k)
        if isinstance(v, str) and isinstance(a, str):
            if not a.startswith(v):
                return False
        elif a != v:
            return False
    return True


def capability_check(ctx, step):
    """None if the step holds a capability, else the reason it does not.
    The web tool is left to process sandboxing, as CapScope leaves it."""
    caps, tool = ctx.capabilities, step["tool"]
    if tool == "shell":
        cmd = step["cmd"]
        if "$(" in cmd or "`" in cmd:
            return "command substitution"
        try:
            argvs = segments(cmd)
        except ValueError as e:
            return f"unparsable: {e}"
        for argv in argvs:
            if not any(_arg_prefix(c, argv) for c in caps.get("execute", [])):
                return f"no execute capability for {' '.join(argv)}"
        return None
    if tool in ("fs.read", "fs.write"):
        full = os.path.normpath(os.path.join(ctx.project_dir, step["path"]))
        kind = "read" if tool == "fs.read" else "write"
        roots = [os.path.normpath(os.path.join(ctx.home, p[2:]) if p.startswith("~/") else p)
                 for p in caps.get(kind, [])]
        if any(full == r or full.startswith(r + "/") for r in roots):
            return None
        return f"no {kind} capability for {full}"
    if tool == "mcp":
        for c in caps.get("tools", []):
            if (c["server"], c["tool"]) == (step["server"], step["name"]) and \
                    _args_prefix(c.get("args"), step.get("args", {})):
                return None
        return f"no capability for {step['server']}.{step['name']}"
    if tool == "connector":
        if any((c["service"], c["name"]) == (step["service"], step["name"])
               for c in caps.get("connectors", [])):
            return None
        return f"no capability for connector {step['service']}.{step['name']}"
    return None


TOOLS = {"shell": run_shell, "fs.read": run_fs, "fs.write": run_fs, "http": run_http,
         "mcp": run_mcp, "connector": run_connector}


def run_step(ctx, step):
    if ctx.capabilities is not None:
        reason = capability_check(ctx, step)
        if reason:
            return _result(step, "denied_by_harness", reason=reason)
    return TOOLS[step["tool"]](ctx, step)


def run_script(script, ctx):
    """Run every step in order; a failed step does not stop the script."""
    return [run_step(ctx, step) for step in script["steps"]]


def load_script(path):
    with open(path) as f:
        return json.load(f)
