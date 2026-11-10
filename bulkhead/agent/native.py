"""Native agent harness on the Anthropic Messages API (design, M6).

A model drives the same tools as the scripted agent: a shell, a file
tool, a web tool, and the project's tool servers. Each tool call becomes
a step and runs through the configuration's context (bulkhead.agent.
scripted.run_step), so the model meets exactly the enforcement the
scripted probes meet: the platform's settings in the baselines, the
CapScope-style capabilities, or the partition, PEPs and gateway under
Bulkhead. The harness itself enforces nothing.

The API key is read from ANTHROPIC_API_KEY or, failing that, from the
file ~/.config/bulkhead/anthropic_api_key; it is never logged.
"""
import json
import os
import time
import urllib.error
import urllib.request
from collections import Counter

from .mcp_server import TOOLS as MCP_TOOLS
from .scripted import run_step

API = "https://api.anthropic.com/v1/messages"
KEY_FILE = os.path.expanduser("~/.config/bulkhead/anthropic_api_key")
# USD per million tokens: input, output, cache read, 5-minute cache write.
# From a third-party listing that cites Anthropic's pricing page (verified
# 2026-10-08); used only to estimate the cost of a run.
PRICES = {"claude-sonnet-5-5": (2.00, 10.00, 0.10, 2.50),
          "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125)}

BASE_TOOLS = [
    {"name": "shell",
     "description": "Run a bash command in the project folder and return its exit code, "
                    "standard output and standard error.",
     "input_schema": {"type": "object", "properties": {"command": {"type": "string"}},
                      "required": ["command"]}},
    {"name": "read_file",
     "description": "Read a text file. Paths are relative to the project folder unless "
                    "absolute.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "write_file",
     "description": "Write a text file, creating folders as needed. Paths are relative to "
                    "the project folder unless absolute.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"},
                                                      "content": {"type": "string"}},
                      "required": ["path", "content"]}},
    {"name": "fetch",
     "description": "Make an HTTP(S) request and return the status and the response body.",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "method": {"type": "string"},
         "body": {"type": "string"}}, "required": ["url"]}},
]


class ApiError(RuntimeError):
    pass


def api_key():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key and os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            key = f.read().strip()
    if not key:
        raise ApiError("no API key: set ANTHROPIC_API_KEY or write " + KEY_FILE)
    return key


class Client:
    def __init__(self, model, max_tokens=2048, timeout=180):
        self.model, self.max_tokens, self.timeout = model, max_tokens, timeout
        self._key = api_key()
        self.usage = Counter()
        self.calls = 0

    def create(self, system, tools, messages):
        body = {"model": self.model, "max_tokens": self.max_tokens,
                "system": [{"type": "text", "text": system,
                            "cache_control": {"type": "ephemeral"}}],
                "tools": tools, "messages": messages}
        data = json.dumps(body).encode()
        for attempt in range(6):
            req = urllib.request.Request(API, data=data, method="POST", headers={
                "x-api-key": self._key, "anthropic-version": "2023-06-01",
                "content-type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    resp = json.loads(r.read())
                break
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace").replace(self._key, "[key]")
                if e.code in (429, 500, 502, 503, 529) and attempt < 5:
                    time.sleep(min(60, 2 ** attempt * 2))
                    continue
                raise ApiError(f"HTTP {e.code}: {text[:500]}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < 5:
                    time.sleep(min(60, 2 ** attempt * 2))
                    continue
                raise ApiError(str(e).replace(self._key, "[key]")) from None
        self.calls += 1
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                  "cache_creation_input_tokens"):
            self.usage[k] += resp.get("usage", {}).get(k) or 0
        return resp

    def cost(self, usage=None):
        u = self.usage if usage is None else usage
        p = PRICES.get(self.model)
        if not p:
            return None
        return (u["input_tokens"] * p[0] + u["output_tokens"] * p[1]
                + u["cache_read_input_tokens"] * p[2]
                + u["cache_creation_input_tokens"] * p[3]) / 1e6


def tools_for(servers):
    """Tool definitions offered to the model: the base tools and, for each
    tool server the project has, its tools named server__tool."""
    out = [dict(t) for t in BASE_TOOLS]
    for server in servers:
        for t in MCP_TOOLS.get(server, []):
            out.append({"name": f"{server}__{t['name']}",
                        "description": f"[{server} tool server] {t['description']}",
                        "input_schema": t["inputSchema"]})
    return out


def to_step(name, args, home):
    """A tool call as a scripted step; None if the tool is unknown."""
    expand = (lambda p: os.path.join(home, p[2:]) if isinstance(p, str) and
              p.startswith("~/") else p)
    if name == "shell":
        return {"tool": "shell", "cmd": str(args.get("command", ""))}
    if name == "read_file":
        return {"tool": "fs.read", "path": expand(args.get("path", ""))}
    if name == "write_file":
        return {"tool": "fs.write", "path": expand(args.get("path", "")),
                "text": str(args.get("content", ""))}
    if name == "fetch":
        return {"tool": "http", "url": str(args.get("url", "")),
                "method": str(args.get("method") or "GET").upper(), "body": args.get("body")}
    if "__" in name:
        server, tool = name.split("__", 1)
        return {"tool": "mcp", "server": server, "name": tool, "args": dict(args)}
    return None


def result_text(res, limit=6000):
    st = res.get("status")
    if st == "denied_by_platform":
        return f"Permission denied by the platform's settings: {res.get('reason')}"
    if st == "denied_by_harness":
        return f"Not permitted by the harness: {res.get('reason')}"
    if st == "ask_denied":
        return "The user was asked to approve this action and declined."
    parts = []
    if res.get("exit") is not None:
        parts.append(f"exit code {res['exit']}")
    if res.get("http") is not None:
        parts.append(f"HTTP {res['http']}")
    for key, label in (("out", ""), ("err", "stderr:\n"), ("reason", "")):
        if res.get(key):
            parts.append(label + str(res[key]))
    text = "\n".join(parts) or "(no output)"
    return text if len(text) <= limit else text[:limit] + "\n[output truncated]"


def run_agent(client, rt, prompt, system, tools, max_turns=15):
    """Let the model work on `prompt` in the runtime's active project.

    Returns the executed steps (each with the tool call that caused it),
    the final answer, the number of model turns and why the loop stopped.
    """
    messages = [{"role": "user", "content": prompt}]
    steps, final, stop, turns = [], "", "max_turns", 0
    usage0 = Counter(client.usage)
    for turns in range(1, max_turns + 1):
        resp = client.create(system, tools, messages)
        content = resp.get("content", [])
        messages.append({"role": "assistant", "content": content})
        calls = [c for c in content if c.get("type") == "tool_use"]
        text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
        if text:
            final = text
        if resp.get("stop_reason") != "tool_use" or not calls:
            stop = resp.get("stop_reason") or "end_turn"
            break
        results = []
        for call in calls:
            ctx = rt.context(rt.active)
            step = to_step(call["name"], call.get("input") or {}, ctx.home)
            if step is None:
                res = {"tool": call["name"], "status": "error", "reason": "unknown tool"}
            else:
                try:
                    res = run_step(ctx, step)
                except Exception as e:      # noqa: BLE001 - a failing tool is a result
                    res = {"tool": step["tool"], "status": "error",
                           "reason": f"{type(e).__name__}: {e}"}
            steps.append(dict(res, call=call["name"], input=call.get("input") or {}))
            results.append({"type": "tool_result", "tool_use_id": call["id"],
                            "content": result_text(res),
                            "is_error": res.get("status") != "ok"})
        messages.append({"role": "user", "content": results})
    usage = Counter({k: client.usage[k] - usage0.get(k, 0) for k in client.usage})
    return {"steps": steps, "final": final, "turns": turns, "stop": stop,
            "usage": dict(usage), "cost": client.cost(usage)}
