"""Proxy-bypass detector: periodically sample established outbound TCP sockets.

The proxy only sees programs that honour HTTPS_PROXY. Anything that ignores it, like a
hard-coded socket, a library with trust_env off, or a malicious script, goes direct. The
sampler reads /proc/net/tcp{,6}, keeps ESTABLISHED sockets to non-local addresses that
aren't the proxy's own upstream legs, and attributes them by inode like the proxy does.

Polling can't see connections shorter than the interval, so treat it as a tripwire
rather than a complete record. For complete coverage, block direct egress at the
firewall/network level and allow only the proxy out.
"""
from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path

from . import attrib

ESTABLISHED = "01"


def _is_external(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (a.is_loopback or a.is_private or a.is_link_local or a.is_multicast or a.is_unspecified
                or a.is_reserved)


class Sampler:
    def __init__(self, self_pid: int | None = None, proc: Path = attrib.PROC, external_only: bool = True,
                 ignore: list[str] | None = None):
        self.self_pid = self_pid
        self.ignore = [i for i in (ignore or []) if i]   # substrings of the process command / agent label
        self.proc = proc
        self.external_only = external_only
        self._seen: dict[tuple, float] = {}   # (inode) -> first seen; report each socket once

    def _own_inodes(self) -> set[int]:
        if not self.self_pid:
            return set()
        out = set()
        try:
            for fd in (self.proc / str(self.self_pid) / "fd").iterdir():
                try:
                    t = os.readlink(fd)
                except OSError:
                    continue
                if t.startswith("socket:["):
                    out.add(int(t[8:-1]))
        except OSError:
            pass
        return out

    def sample(self) -> list[dict]:
        own = self._own_inodes()
        recs = []
        live = set()
        for fam in ("tcp", "tcp6"):
            try:
                rows = attrib.parse_proc_net((self.proc / "net" / fam).read_text())
            except OSError:
                continue
            for row in rows:
                if row["state"] != ESTABLISHED or not row["inode"] or row["inode"] in own:
                    continue
                try:
                    rip = attrib.decode_hex_ip(row["remote"][0])
                except ValueError:
                    continue
                if self.external_only and not _is_external(rip):
                    continue
                live.add(row["inode"])
                if row["inode"] in self._seen:
                    continue
                self._seen[row["inode"]] = time.time()
                pid = attrib.pid_for_inode(row["inode"], self.proc)
                client = attrib.describe(pid, self.proc) if pid else attrib.Client()
                if any(i in client.proc or i == client.agent for i in self.ignore):
                    continue
                recs.append({"kind": "direct", "ip": rip, "port": row["remote"][1], "uid": row["uid"],
                             "client": client.to_dict()})
        # forget closed sockets so inode reuse is reported again
        for k in list(self._seen):
            if k not in live:
                del self._seen[k]
        return recs
