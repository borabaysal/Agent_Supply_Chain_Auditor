"""Logging forward proxy (HTTP CONNECT + plain HTTP), asyncio, stdlib only.

It logs, it does not block: every request is forwarded. TLS is never intercepted. HTTPS
goes through as an opaque CONNECT tunnel, so the proxy learns host:port, timing and byte
counts and nothing else. That's enough to answer "where does my agent talk to?" without
holding anyone's plaintext or needing a CA certificate.

Safety defaults:
- listens on 127.0.0.1 only; non-loopback listening requires explicit --allow CIDRs;
- clients outside the allow-list are refused (an open proxy is an abuse magnet);
- header block capped at 64 KiB, upstream connect timeout 15 s, max concurrent conns.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import time
from pathlib import Path

from . import attrib, sampler
from .log import EgressLog

log = logging.getLogger("asca.egress")

MAX_HEADER = 64 * 1024
CONNECT_TIMEOUT = 15.0
BUF = 64 * 1024


class Proxy:
    def __init__(self, logdir: Path, *, host: str = "127.0.0.1", port: int = 8899,
                 allow: list[str] | None = None, hermes_home: Path | None = None,
                 max_conns: int = 512, sample_every: float = 0.0, attribute: bool = True,
                 sampler_ignore: list[str] | None = None):
        self.host, self.port = host, port
        self.elog = EgressLog(logdir)
        nets = allow or ["127.0.0.0/8", "::1/128"]
        self.allow = [ipaddress.ip_network(n, strict=False) for n in nets]
        self.cron = attrib.CronContext(hermes_home)
        self.sem = asyncio.Semaphore(max_conns)
        self.sample_every = sample_every
        self.attribute = attribute
        self.server: asyncio.base_events.Server | None = None
        self.sampler = sampler.Sampler(self_pid=os.getpid(), ignore=sampler_ignore)
        self.stats = {"connections": 0, "refused": 0, "errors": 0}

    # ----------------------------------------------------------------- lifecycle
    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port, limit=MAX_HEADER)
        sock = self.server.sockets[0].getsockname()
        self.port = sock[1]
        self.elog.write({"kind": "proxy_start", "listen": f"{sock[0]}:{sock[1]}", "pid": os.getpid()})
        loop = asyncio.get_running_loop()
        if self.sample_every > 0:
            loop.create_task(self._sample_loop())
        loop.create_task(self._heartbeat_loop())
        return self

    async def _heartbeat_loop(self, every: float = 3600.0):
        # lets the summary tell "idle but alive" apart from "proxy dead"
        while True:
            await asyncio.sleep(every)
            self.elog.write({"kind": "heartbeat", "pid": os.getpid(), **self.stats})

    async def serve_forever(self):
        async with self.server:
            await self.server.serve_forever()

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.elog.write({"kind": "proxy_stop", "pid": os.getpid(), **self.stats})
        self.elog.close()

    async def _sample_loop(self):
        while True:
            try:
                for rec in await asyncio.to_thread(self.sampler.sample):
                    self.elog.write(rec)
            except Exception as exc:  # never let sampling kill the proxy
                log.warning("sampler error: %s", exc)
            await asyncio.sleep(self.sample_every)

    # ----------------------------------------------------------------- per conn
    def _allowed(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return False
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        return any(a in n for n in self.allow)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or ("?", 0)
        sockname = writer.get_extra_info("sockname") or ("?", 0)
        if not self._allowed(peer[0]):
            self.stats["refused"] += 1
            self.elog.write({"kind": "refused", "client_ip": peer[0]})
            writer.close()
            return
        async with self.sem:
            self.stats["connections"] += 1
            started = time.time()
            # attribute *before* reading: the client socket is guaranteed to exist now
            client = (await asyncio.to_thread(attrib.attribute, peer[:2], sockname[:2], attrib.PROC, os.getpid())
                      if self.attribute else attrib.Client())
            rec = {"ts": started, "client": client.to_dict(), "cron": self.cron.running()}
            try:
                await self._serve(reader, writer, rec)
            except Exception as exc:
                self.stats["errors"] += 1
                rec.setdefault("error", f"{type(exc).__name__}: {exc}"[:200])
            finally:
                rec["duration_ms"] = int((time.time() - started) * 1000)
                if rec.get("kind"):
                    self.elog.write(rec)
                try:
                    writer.close()
                except Exception:
                    pass

    async def _serve(self, reader, writer, rec):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            rec.update(kind="bad_request", error="header too large")
            writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
            return
        except asyncio.IncompleteReadError:
            return  # client went away before sending a request; nothing to log
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            rec.update(kind="bad_request", error="malformed request line")
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        if method.upper() == "CONNECT":
            await self._connect(target, reader, writer, rec)
        else:
            await self._http(method, target, version, lines[1:], reader, writer, rec)

    async def _open(self, host: str, port: int, rec: dict):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, limit=BUF), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError) as exc:
            rec.update(status=502, error=f"upstream: {type(exc).__name__}: {exc}"[:200])
            return None, None
        pn = w.get_extra_info("peername")
        if pn:
            rec["ip"] = pn[0]
        return r, w

    async def _connect(self, target, reader, writer, rec):
        host, port = _split_hostport(target, 443)
        rec.update(kind="connect", host=host.lower(), port=port)
        ur, uw = await self._open(host, port, rec)
        if ur is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        rec["status"] = 200
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        up, down = await _pipe_both(reader, writer, ur, uw)
        rec.update(bytes_up=up, bytes_down=down)

    async def _http(self, method, target, version, header_lines, reader, writer, rec):
        if not target.lower().startswith("http://"):
            rec.update(kind="bad_request", error="non-proxy request")
            writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        rest = target[7:]
        hostport, _, path = rest.partition("/")
        host, port = _split_hostport(hostport, 80)
        path = "/" + path
        rec.update(kind="http", method=method.upper()[:10], host=host.lower(), port=port, path=path)
        ur, uw = await self._open(host, port, rec)
        if ur is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        # origin-form request; drop hop-by-hop + proxy headers; one request per connection
        keep = [h for h in header_lines if h and h.split(":", 1)[0].strip().lower() not in
                ("proxy-connection", "proxy-authorization", "connection", "keep-alive")]
        out = f"{method} {path} {version}\r\n" + "".join(h + "\r\n" for h in keep) + "Connection: close\r\n\r\n"
        uw.write(out.encode("latin-1"))
        await uw.drain()
        up, down = await _pipe_both(reader, writer, ur, uw)
        rec.update(bytes_up=up + len(out), bytes_down=down)
        first = getattr(ur, "_asca_first", b"")
        if first.startswith(b"HTTP/"):
            try:
                rec["status"] = int(first.split(b" ", 2)[1])
            except (IndexError, ValueError):
                pass


def _split_hostport(s: str, default: int) -> tuple[str, int]:
    s = s.strip()
    if s.startswith("["):  # [v6]:port
        host, _, rest = s[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif s.count(":") == 1:
        host, port = s.split(":")
    else:
        host, port = s, ""
    try:
        return host, int(port) if port else default
    except ValueError:
        return host, default


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, mark_first=None) -> int:
    n = 0
    try:
        while True:
            chunk = await src.read(BUF)
            if not chunk:
                break
            if mark_first is not None and n == 0:
                mark_first._asca_first = chunk[:32]
            n += len(chunk)
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            if dst.can_write_eof():
                dst.write_eof()
        except (OSError, RuntimeError):
            pass
    return n


async def _pipe_both(cr, cw, ur, uw) -> tuple[int, int]:
    up_t = asyncio.create_task(_pipe(cr, uw))
    down_t = asyncio.create_task(_pipe(ur, cw, mark_first=ur))
    down = await down_t
    # upstream finished: give the client side a moment to flush, then stop
    try:
        up = await asyncio.wait_for(up_t, 1)
    except asyncio.TimeoutError:
        up_t.cancel()
        up = 0
    try:
        uw.close()
    except Exception:
        pass
    return up, down


def run(logdir: Path, host: str, port: int, allow: list[str] | None, hermes_home: Path | None,
        sample_every: float, pidfile: Path | None, sampler_ignore: list[str] | None = None) -> None:
    async def main():
        p = await Proxy(logdir, host=host, port=port, allow=allow, hermes_home=hermes_home,
                        sample_every=sample_every, sampler_ignore=sampler_ignore).start()
        if pidfile:
            pidfile.write_text(f"{os.getpid()}\n")
        print(f"asca-egress: listening on {host}:{p.port}, logging to {logdir}", flush=True)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        server_task = asyncio.create_task(p.serve_forever())
        await stop.wait()
        server_task.cancel()
        await p.close()
        if pidfile:
            pidfile.unlink(missing_ok=True)

    asyncio.run(main())
