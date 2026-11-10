"""MCP gateway (design, Section 4.4).

The gateway sits between the agent and the tool servers of a project. It
is an MCP client to each tool server, which runs inside the project's
partition (spawned there, speaking MCP over its stdio), and offers the
agent only the tools that the project declares and that the request
mapping can name: a tool whose call cannot be mapped to a resource and an
operation cannot be decided, so it is not offered. Tool names are
prefixed with their server, so two servers cannot shadow each other's
tools.

Every tools/call is mapped to (resource, operation), decided by the PDP
on the mcp channel, and logged. A denied call never reaches the tool
server. An allowed one runs in the partition, and the tool server's own
requests then pass the project's PEP, where the vault puts in the real
credential: the tool server holds only a placeholder (consideration 6).
"""
import itertools
import json
import socket
import threading

from ..core.log import canonical, digest
from ..decisions import Decision

PROTOCOL = "2025-06-18"


class McpError(RuntimeError):
    pass


class McpClient:
    """JSON-RPC over a stream socket, one message per line."""

    def __init__(self, sock, timeout=60):
        self.sock, self.timeout = sock, timeout
        self.rfile = sock.makefile("rb")
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.info = self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                                "clientInfo": {"name": "bulkhead-gateway",
                                                               "version": "0.1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg):
        self.sock.sendall((json.dumps(msg) + "\n").encode())

    def request(self, method, params=None):
        with self.lock:
            rid = next(self.ids)
            self.sock.settimeout(self.timeout)
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
            while True:
                line = self.rfile.readline()
                if not line:
                    raise McpError("tool server closed the connection")
                msg = json.loads(line)
                if msg.get("id") != rid:
                    continue                  # notifications and stray replies
                if "error" in msg:
                    raise McpError(msg["error"].get("message", "error"))
                return msg["result"]

    def tools(self):
        return self.request("tools/list").get("tools", [])

    def call(self, name, args):
        r = self.request("tools/call", {"name": name, "arguments": args})
        text = "".join(c.get("text", "") for c in r.get("content", []) if c.get("type") == "text")
        return ("error" if r.get("isError") else "ok"), text

    def close(self):
        try:
            self.rfile.close()
            self.sock.close()
        except OSError:
            pass


class McpGateway:
    """launcher(project, server) -> socket connected to a tool server
    running in the project's partition; servers: project -> declared
    server names."""

    call_timeout = 120

    def __init__(self, pdp, onto, log, launcher, servers):
        self.pdp, self.onto, self.log = pdp, onto, log
        self.launcher, self.servers = launcher, servers
        self.clients = {}
        self.lock = threading.Lock()

    def _client(self, project, server):
        with self.lock:
            key = (project, server)
            if key not in self.clients:
                self.clients[key] = McpClient(self.launcher(project, server))
            return self.clients[key]

    def list_tools(self, project):
        out = []
        for server in self.servers.get(project, ()):
            for tool in self._client(project, server).tools():
                if tool["name"] in self.onto.tools.get(server, {}):
                    out.append(dict(tool, name=f"{server}.{tool['name']}"))
        return out

    def _record(self, project, task, server, tool, args, verdict=None, **extra):
        rec = {"pep": "mcp", "project": project, "task": task, "channel": "mcp",
               "req": {"summary": f"{server}.{tool}", "digest": digest(canonical(args))}}
        if verdict is not None:
            rec.update(verdict.record())
        rec.update(extra)
        return self.log.append(rec) if self.log else rec

    def call(self, project, server, tool, args, task=None):
        """Returns (status, output, verdict); status 'blocked' if denied."""
        args = args or {}
        if server not in self.servers.get(project, ()):
            self._record(project, task, server, tool, args, outcome="blocked",
                         reason="tool server not declared", decision="deny", final="deny")
            return "blocked", f"blocked by Bulkhead: {server} is not a tool server of {project}", None
        mapping = self.onto.map_tool(server, tool, args)
        if mapping is None:
            self._record(project, task, server, tool, args, outcome="blocked",
                         reason="call names no resource", decision="deny", final="deny")
            return "blocked", "blocked by Bulkhead: the call names no resource", None
        verdict = self.pdp.authorize(project, "mcp", mapping.resource, mapping.op, True, task,
                                     f"{server}.{tool}")
        if verdict.decision != Decision.ALLOW:
            self._record(project, task, server, tool, args, verdict, outcome="blocked")
            return ("blocked", f"blocked by Bulkhead: {mapping.op} on {mapping.resource} is "
                    f"{verdict.policy_decision} for {project} (policy v{verdict.version})", verdict)
        # an approval answers for the call: the tool server's own requests on
        # the same resource and operation are covered while the call runs, so
        # the user is not asked twice for one action
        covering = None
        if verdict.approval:
            granted = next((a for a in self.pdp.approvals.items if a.id == verdict.approval),
                           None)
            if granted is not None and granted.scope == "request":
                covering = self.pdp.approvals.grant(project, mapping.resource, mapping.op,
                                                    verdict.version, scope="project",
                                                    ttl=self.call_timeout, by="gateway-call")
        try:
            status, out = self._client(project, server).call(tool, args)
        except (McpError, OSError, ValueError) as e:
            self._record(project, task, server, tool, args, verdict, outcome="error",
                         reason=str(e))
            return "error", str(e), verdict
        finally:
            if covering is not None:
                self.pdp.approvals.revoke(covering.id)
        self._record(project, task, server, tool, args, verdict, outcome="forwarded",
                     result=status)
        return status, out, verdict

    def close_project(self, project):
        with self.lock:
            for key in [k for k in self.clients if k[0] == project]:
                self.clients.pop(key).close()

    def close(self):
        with self.lock:
            for c in self.clients.values():
                c.close()
            self.clients = {}
