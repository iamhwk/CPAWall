"""A minimal MCP server over stdio hosting one tool server (stdlib only).

JSON-RPC 2.0, one message per line, as MCP's stdio transport frames it:
initialize, tools/list, tools/call and ping. It runs inside a partition,
configured like any tool server through its environment (placeholders
instead of tokens); its HTTP requests leave through the partition's PEP.

usage: python -m bulkhead.agent.mcp_server github|stagingdb
"""
import json
import sys

from .toolservers import from_env

_REPO = {"owner": {"type": "string"}, "repo": {"type": "string"}}
TOOLS = {
    "github": [
        {"name": "list_issues", "description": "List a repository's issues.",
         "inputSchema": {"type": "object", "properties": _REPO, "required": ["owner", "repo"]}},
        {"name": "add_comment", "description": "Comment on an issue.",
         "inputSchema": {"type": "object", "required": ["owner", "repo", "n", "body"],
                         "properties": dict(_REPO, n={"type": "integer"},
                                            body={"type": "string"})}},
        {"name": "push_files", "description": "Commit files and push them to a branch.",
         "inputSchema": {"type": "object", "required": ["owner", "repo", "files"],
                         "properties": dict(_REPO, files={"type": "object"},
                                            message={"type": "string"},
                                            branch={"type": "string"})}},
    ],
    "stagingdb": [
        {"name": "query", "description": "Run a read-only query.",
         "inputSchema": {"type": "object", "required": ["db", "sql"],
                         "properties": {"db": {"type": "string"}, "sql": {"type": "string"}}}},
        {"name": "execute", "description": "Run a statement that changes data.",
         "inputSchema": {"type": "object", "required": ["db", "sql"],
                         "properties": {"db": {"type": "string"}, "sql": {"type": "string"}}}},
    ],
}


def handle(server, srv, msg):
    method, params = msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": f"bulkhead-{server}", "version": "0.1"}}
    if method == "tools/list":
        return {"tools": TOOLS[server]}
    if method == "tools/call":
        try:
            status, out = srv.call(params.get("name"), params.get("arguments") or {})
        except Exception as e:     # noqa: BLE001 - a failed call is a result
            status, out = "error", f"{type(e).__name__}: {e}"
        return {"content": [{"type": "text", "text": out}], "isError": status != "ok"}
    if method == "ping":
        return {}
    raise LookupError(method)


def main(argv):
    server = argv[0]
    srv = from_env(server)
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue                          # notifications need no answer
        try:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": handle(server, srv, msg)}
        except LookupError as e:
            reply = {"jsonrpc": "2.0", "id": msg["id"],
                     "error": {"code": -32601, "message": f"method not found: {e}"}}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
