"""Allow-all forwarder: the egress of the simple-isolation baseline.

Simple isolation gives every project its own substrate and sign-ins but
no policy, PDP, or log (design, consideration 10; paper, Sec. 3.6). Its
partitions still need a way out, so their egress listeners are served by
this forwarder: it accepts CONNECT and relays the bytes both ways, with
no TLS termination, no decision, and no record.
"""
import asyncio

from .httpmsg import HttpError, read_head


class Forwarder:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.servers = []

    async def serve_sock(self, sock):
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
        for srv in list(self.servers):
            await self.stop_server(srv)

    async def _client(self, reader, writer):
        try:
            head = await read_head(reader)
            if head is None:
                return
            method, target, _ = head[0].split(" ", 2)
            if method != "CONNECT":
                writer.write(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
                return
            host, _, port = target.rpartition(":")
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(host.strip("[]"), int(port)), self.timeout)
        except (HttpError, ValueError, OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def pipe(r, w):
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    w.close()
                except OSError:
                    pass
        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
