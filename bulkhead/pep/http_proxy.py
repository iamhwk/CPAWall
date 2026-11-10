"""HTTP(S) policy enforcement point (design, Section 4.4).

One PEP serves one project, on sockets that the core created for that
project's partition, so every request it sees is attributed to that
project by construction (consideration 4). For each request it:

  1. accepts CONNECT and terminates TLS with a certificate from the
     deployment's CA (or takes an absolute-form http:// request);
  2. maps the request to (resource, operation) with the request mapping,
     and refuses non-canonical paths and protocol upgrades;
  3. asks the PDP, off the event loop because `ask` may wait for the
     trusted UI;
  4. if allowed, injects the project's credential from the vault (only
     for named resources), forwards the request, and relays the response;
     otherwise answers 403;
  5. appends one record to the hash-chained log: metadata and digests,
     never content.

Hosts listed as infrastructure (the LLM API) are forwarded for every
project, without a decision, and logged (consideration 5).
"""
import asyncio
import json
import ssl
import threading
from urllib.parse import urlsplit

from ..core.log import digest
from ..decisions import Decision
from ..policy.ontology import origin as origin_of
from . import httpmsg
from .httpmsg import HttpError


def _authority(target):
    """'git.test:443' -> ('git.test', 443)."""
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit() or not host:
        raise HttpError(400, "CONNECT needs host:port")
    return host.strip("[]").lower(), int(port)


class HttpPep:
    def __init__(self, project, pdp, onto, vault, log, ca, channel="tools",
                 upstream_cafile=None, infra=(), max_body=64 << 20, upstream_timeout=120):
        self.project, self.pdp, self.onto = project, pdp, onto
        self.vault, self.log, self.ca, self.channel = vault, log, ca, channel
        self.infra = {h.lower() for h in infra}
        self.max_body, self.timeout = max_body, upstream_timeout
        self.task = None                     # set by the session manager
        self.upstream_ctx = ssl.create_default_context()
        if upstream_cafile:
            self.upstream_ctx.load_verify_locations(upstream_cafile)
        self.servers = []

    # -- listeners --------------------------------------------------------------
    async def serve_tcp(self, host="127.0.0.1", port=0):
        srv = await asyncio.start_server(self._client, host, port)
        self.servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    async def serve_unix(self, path):
        srv = await asyncio.start_unix_server(self._client, path)
        self.servers.append(srv)
        return path

    async def serve_sock(self, sock):
        """Accept on a listening socket made elsewhere: a partition's egress
        listener, which lives in the partition's network namespace."""
        srv = await asyncio.start_server(self._client, sock=sock)
        self.servers.append(srv)
        return srv

    async def stop_server(self, srv):
        srv.close()
        if hasattr(srv, "close_clients"):
            srv.close_clients()
        try:
            await asyncio.wait_for(srv.wait_closed(), 2)
        except asyncio.TimeoutError:
            pass
        if srv in self.servers:
            self.servers.remove(srv)

    async def close(self):
        for srv in self.servers:
            srv.close()
            await srv.wait_closed()
        self.servers = []

    async def _client(self, reader, writer):
        conn = _Connection(self, reader, writer)
        try:
            await conn.run()
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError, TimeoutError):
            pass
        finally:
            await conn.close()

    # -- records --------------------------------------------------------------
    def record(self, req, verdict=None, outcome="blocked", **extra):
        rec = {"pep": "http", "project": self.project, "task": self.task,
               "channel": self.channel, "req": req}
        if verdict is not None:
            rec.update(verdict.record())
        rec.update(outcome=outcome, **extra)
        return self.log.append(rec) if self.log else rec


class _Connection:
    """One client connection: at most one CONNECT tunnel, then requests."""

    def __init__(self, pep, reader, writer):
        self.pep, self.reader, self.writer = pep, reader, writer
        self.tunnel = None                   # origin after CONNECT
        self.upstreams = {}

    async def close(self):
        for _, w in self.upstreams.values():
            w.close()
        self.upstreams = {}
        try:
            self.writer.close()
        except Exception:
            pass

    async def _error(self, status, reason, close=True):
        body = json.dumps({"error": reason}).encode()
        self.writer.write(httpmsg.serialize(
            f"HTTP/1.1 {status} {reason}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
             ("Connection", "close" if close else "keep-alive")]) + body)
        await self.writer.drain()

    async def run(self):
        while True:
            try:
                head = await httpmsg.read_head(self.reader)
            except HttpError as e:
                await self._error(e.status, e.reason)
                return
            if head is None:
                return
            start, headers = head
            parts = start.split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                await self._error(400, "malformed request line")
                return
            method, target, _ = parts
            if method == "CONNECT":
                if self.tunnel or not await self._connect(target):
                    return
                continue
            if not await self._request(method.upper(), target, headers):
                return

    async def _connect(self, target):
        try:
            host, port = _authority(target)
        except HttpError as e:
            await self._error(e.status, e.reason)
            return False
        self.writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await self.writer.drain()
        try:
            await self.writer.start_tls(self.pep.ca.server_context(host))
        except (ssl.SSLError, ConnectionError, OSError) as e:
            self.pep.record({"summary": f"CONNECT {target}", "digest": digest(target)},
                            outcome="error", reason=f"TLS handshake failed: {e!r}")
            return False
        self.tunnel = origin_of(f"https://{host}:{port}")
        return True

    def _url(self, target):
        if self.tunnel:
            if target.startswith("/"):
                return self.tunnel + target
            if origin_of(target) == self.tunnel:
                return target
            raise HttpError(400, "request outside the tunnel's origin")
        if target.startswith(("http://", "https://")):
            return target
        raise HttpError(400, "not a proxy request")

    async def _request(self, method, target, headers):
        pep = self.pep
        try:
            url = self._url(target)
        except HttpError as e:
            await self._error(e.status, e.reason)
            return False
        u = urlsplit(url)
        site = origin_of(url)
        summary = f"{method} {u.hostname}{u.path or '/'}"
        req = {"summary": summary, "digest": digest(f"{method} {url}\n")}
        if httpmsg.get(headers, "upgrade"):
            pep.record(req, outcome="blocked", reason="protocol upgrade")
            await self._error(501, "protocol upgrades are not mediated")
            return False

        verdict, mapping = None, None
        if (u.hostname or "").lower() in pep.infra:
            extra = {"resource": f"infra://{u.hostname}", "op": "call",
                     "decision": "allow", "final": "allow", "infra": True}
        else:
            mapping = pep.onto.map_request(method, url)
            if not mapping.canonical:
                pep.record(req, outcome="blocked", resource=mapping.resource, op=mapping.op,
                           decision="deny", final="deny", reason="non-canonical path")
                await self._error(403, "non-canonical request path")
                return False
            verdict = await asyncio.get_running_loop().run_in_executor(
                None, lambda: pep.pdp.authorize(pep.project, pep.channel, mapping.resource,
                                                mapping.op, mapping.mapped, pep.task, summary))
            extra = {}
            if verdict.decision != Decision.ALLOW:
                pep.record(req, verdict, outcome="blocked", rule=mapping.rule)
                body = {"error": "blocked by Bulkhead", "project": pep.project,
                        "resource": mapping.resource, "op": mapping.op,
                        "decision": str(verdict.policy_decision),
                        "policy_version": verdict.version}
                data = json.dumps(body).encode()
                self.writer.write(httpmsg.serialize(
                    "HTTP/1.1 403 Forbidden",
                    [("Content-Type", "application/json"), ("X-Bulkhead", "blocked"),
                     ("Content-Length", str(len(data))), ("Connection", "close")]) + data)
                await self.writer.drain()
                return False

        if (httpmsg.get(headers, "expect") or "").lower() == "100-continue":
            self.writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await self.writer.drain()
        try:
            body = await httpmsg.read_body(self.reader, headers, pep.max_body)
        except HttpError as e:
            await self._error(e.status, e.reason)
            return False
        req["digest"] = digest(f"{method} {url}\n".encode() + body)

        fwd = httpmsg.without(headers, httpmsg.HOP_BY_HOP | {"host", "content-length"})
        named = mapping is not None and mapping.mapped and not mapping.resource.startswith("web:")
        if named:
            fwd, how = pep.vault.inject(pep.project, site, fwd)
        else:
            fwd = pep.vault.strip_placeholders(fwd)
            how = "request" if httpmsg.get(fwd, "authorization") else "none"
        host_hdr = site.split("://", 1)[1]
        fwd = [("Host", host_hdr)] + fwd
        if body or method in ("POST", "PUT", "PATCH"):
            fwd.append(("Content-Length", str(len(body))))
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        message = httpmsg.serialize(f"{method} {path} HTTP/1.1", fwd) + body

        try:
            status, nbytes, reusable, close = await self._forward(site, message, method)
        except (HttpError, OSError, ssl.SSLError, asyncio.IncompleteReadError,
                asyncio.TimeoutError) as e:
            status = e.status if isinstance(e, HttpError) else 502
            pep.record(req, verdict, outcome="error", credential=how, reason=str(e),
                       **extra)
            await self._error(status, "upstream error")
            return False
        pep.record(req, verdict, outcome="forwarded", status=status, bytes=nbytes,
                   credential=how, rule=mapping.rule if mapping else None, **extra)
        if not reusable:
            self._drop(site)
        return not close

    def _drop(self, site):
        conn = self.upstreams.pop(site, None)
        if conn:
            conn[1].close()

    async def _open(self, site):
        scheme, _, hostport = site.partition("://")
        host, _, port = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
        port = int(port) if port else (443 if scheme == "https" else 80)
        if scheme == "https":
            return await asyncio.wait_for(asyncio.open_connection(
                host, port, ssl=self.pep.upstream_ctx, server_hostname=host), 30)
        return await asyncio.wait_for(asyncio.open_connection(host, port), 30)

    async def _forward(self, site, message, method):
        reused = site in self.upstreams
        for attempt in (0, 1):
            if site not in self.upstreams:
                self.upstreams[site] = await self._open(site)
            r, w = self.upstreams[site]
            progress = {}
            try:
                w.write(message)
                await w.drain()
                return await httpmsg.relay_response(r, self.writer, method, self.pep.timeout,
                                                    progress)
            except (HttpError, ConnectionError, asyncio.IncompleteReadError):
                self._drop(site)
                # a reused connection may have been closed by the server while
                # idle: retry once on a fresh one, if nothing reached the client
                if attempt or not reused or progress.get("sent"):
                    raise
                reused = False


class PepRunner:
    """Runs PEP listeners on an event loop in a background thread."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.peps = []

    def call(self, coro, timeout=30):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def add_tcp(self, pep, host="127.0.0.1", port=0):
        self.peps.append(pep)
        return self.call(pep.serve_tcp(host, port))

    def add_unix(self, pep, path):
        self.peps.append(pep)
        return self.call(pep.serve_unix(path))

    def add_sock(self, pep, sock):
        if pep not in self.peps:
            self.peps.append(pep)
        return self.call(pep.serve_sock(sock))

    def remove(self, pep, srv):
        self.call(pep.stop_server(srv))

    def stop(self):
        for pep in self.peps:
            try:
                self.call(pep.close())
            except Exception:
                pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()
