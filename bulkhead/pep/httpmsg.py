"""Minimal HTTP/1.1 message handling for the PEP, on asyncio streams.

Only what a forward proxy needs: read a head, read a request body
(Content-Length or chunked; both at once is refused, against request
smuggling), and relay a response body in its own framing.
"""
import asyncio

HOP_BY_HOP = frozenset({"connection", "proxy-connection", "keep-alive", "proxy-authorization",
                        "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
                        "expect"})


class HttpError(Exception):
    def __init__(self, status, reason):
        super().__init__(f"{status} {reason}")
        self.status, self.reason = status, reason


def get(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def get_all(headers, name):
    name = name.lower()
    return [v for k, v in headers if k.lower() == name]


def without(headers, names):
    names = {n.lower() for n in names}
    listed = set()
    for v in get_all(headers, "connection"):         # headers named in Connection
        listed |= {x.strip().lower() for x in v.split(",") if x.strip()}
    return [(k, v) for k, v in headers if k.lower() not in names and k.lower() not in listed]


def serialize(start, headers):
    lines = [start] + [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


async def read_head(reader):
    """(start line, [(name, value)]), or None at a clean end of stream."""
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as e:
        if not e.partial.strip():
            return None
        raise HttpError(400, "incomplete message head") from None
    except asyncio.LimitOverrunError:
        raise HttpError(431, "message head too large") from None
    lines = data.lstrip(b"\r\n").decode("latin-1").split("\r\n")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            raise HttpError(400, "obsolete line folding")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip() or " " in name:
            raise HttpError(400, "malformed header")
        headers.append((name, value.strip()))
    return lines[0], headers


def body_framing(headers):
    """('chunked', None), ('length', n), or ('none', 0) for a request."""
    te = get_all(headers, "transfer-encoding")
    cl = get_all(headers, "content-length")
    if te and cl:
        raise HttpError(400, "both Transfer-Encoding and Content-Length")
    if te:
        if ",".join(te).replace(" ", "").lower() != "chunked":
            raise HttpError(501, "unsupported transfer coding")
        return "chunked", None
    if cl:
        if len(set(cl)) != 1 or not cl[0].isdigit():
            raise HttpError(400, "bad Content-Length")
        return "length", int(cl[0])
    return "none", 0


async def _chunked(reader, out_writer=None, limit=None):
    """Read (and, with out_writer, relay raw) a chunked body."""
    body, total = bytearray(), 0
    while True:
        line = await reader.readuntil(b"\r\n")
        if out_writer:
            out_writer.write(line)
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            raise HttpError(400, "bad chunk size") from None
        if size == 0:
            while True:                                  # trailers, then the end
                t = await reader.readuntil(b"\r\n")
                if out_writer:
                    out_writer.write(t)
                if t == b"\r\n":
                    return bytes(body), total
        data = await reader.readexactly(size)
        total += size
        if limit is not None and total > limit:
            raise HttpError(413, "body too large")
        crlf = await reader.readexactly(2)
        if crlf != b"\r\n":
            raise HttpError(400, "bad chunk")
        if out_writer:
            out_writer.write(data + crlf)
            await out_writer.drain()
        else:
            body += data


async def read_body(reader, headers, limit):
    kind, n = body_framing(headers)
    if kind == "chunked":
        return (await _chunked(reader, limit=limit))[0]
    if kind == "length":
        if n > limit:
            raise HttpError(413, "body too large")
        return await reader.readexactly(n)
    return b""


async def relay_response(reader, writer, method, timeout=120, progress=None):
    """Relay one response from `reader` to `writer`.

    Returns (status, body bytes, upstream reusable, client must close).
    `progress['sent']` becomes True once anything reached the client, after
    which a failed request must not be retried.
    """
    progress = {} if progress is None else progress
    while True:
        head = await asyncio.wait_for(read_head(reader), timeout)
        if head is None:
            raise HttpError(502, "upstream closed the connection")
        start, headers = head
        parts = start.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise HttpError(502, "malformed upstream status line")
        status = int(parts[1])
        progress["sent"] = True
        if 100 <= status < 200 and status != 101:
            writer.write(serialize(start, headers))       # interim response
            continue
        break
    upstream_close = (get(headers, "connection") or "").lower() == "close"
    fwd = without(headers, {"connection", "keep-alive", "proxy-connection"})
    if method == "HEAD" or status in (204, 304) or status < 200:
        writer.write(serialize(start, fwd))
        await writer.drain()
        return status, 0, not upstream_close, False
    te = (get(headers, "transfer-encoding") or "").lower()
    cl = get(headers, "content-length")
    if "chunked" in te:
        writer.write(serialize(start, fwd))
        _, n = await _chunked(reader, writer)
        await writer.drain()
        return status, n, not upstream_close, False
    if cl is not None and cl.isdigit():
        writer.write(serialize(start, fwd))
        remaining, n = int(cl), 0
        while remaining:
            data = await reader.read(min(remaining, 1 << 16))
            if not data:
                raise HttpError(502, "upstream body truncated")
            writer.write(data)
            await writer.drain()
            remaining -= len(data)
            n += len(data)
        return status, n, not upstream_close, False
    writer.write(serialize(start, fwd + [("Connection", "close")]))   # body ends at EOF
    n = 0
    while True:
        data = await reader.read(1 << 16)
        if not data:
            break
        writer.write(data)
        await writer.drain()
        n += len(data)
    return status, n, False, True
