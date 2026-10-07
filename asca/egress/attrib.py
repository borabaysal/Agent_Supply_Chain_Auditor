"""Attribute a local TCP connection to the process (and agent / cron job) that opened it.

Linux-only, read-only, same-user: we look the client's socket up in /proc/net/tcp{,6},
find the inode in /proc/<pid>/fd, then walk the parent chain. Processes owned by another
user can't be inspected; they are reported as ``unknown`` rather than guessed.

Labels, in order of preference:
1. ``ASCA_EGRESS_LABEL`` in the process's (or an ancestor's) environment, set it on any
   agent/cron script you want named explicitly;
2. a well-known agent recognised from the command line (Hermes gateway/TUI/dashboard,
   Claude Code, Codex, goose, Gemini CLI);
3. the process's short command name.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

PROC = Path("/proc")

KNOWN_AGENTS = [
    (re.compile(r"\bhermes\b.*\bgateway run\b"), "hermes-gateway"),
    (re.compile(r"\btui_gateway\b"), "hermes-tui"),
    (re.compile(r"\bhermes\b.*\bdashboard\b"), "hermes-dashboard"),
    (re.compile(r"\bhermes\b.*\bcron\b"), "hermes-cron"),
    (re.compile(r"(^|/)claude(\s|$)|@anthropic-ai/claude-code"), "claude-code"),
    (re.compile(r"(^|/)codex(\s|$)|@openai/codex"), "codex"),
    (re.compile(r"(^|/)goose(\s|$)"), "goose"),
    (re.compile(r"(^|/)gemini(\s|$)|@google/gemini-cli"), "gemini-cli"),
]


@dataclass
class Client:
    pid: int | None = None
    proc: str = "unknown"            # short command of the connecting process
    agent: str = "unknown"           # label (see module doc)
    chain: list[str] = field(default_factory=list)  # short commands, child -> ancestors

    def to_dict(self) -> dict:
        return {"pid": self.pid, "proc": self.proc, "agent": self.agent, "chain": self.chain}


def _hex_addr(ip: str, port: int) -> tuple[str, int]:
    """Encode an address the way /proc/net/tcp{,6} does (host-endian 32-bit words)."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        return addr.packed[::-1].hex().upper(), 4
    b = addr.packed
    words = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
    return words.hex().upper(), 6


def parse_proc_net(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, remote, state, uid, inode = parts[1], parts[2], parts[3], parts[7], parts[9]
        lip, lport = local.split(":")
        rip, rport = remote.split(":")
        rows.append({"local": (lip, int(lport, 16)), "remote": (rip, int(rport, 16)), "state": state,
                     "uid": int(uid), "inode": int(inode)})
    return rows


def decode_hex_ip(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    ip = ipaddress.IPv6Address(raw)
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)


def find_inode(client_ip: str, client_port: int, server_ip: str, server_port: int, proc: Path = PROC) -> int | None:
    """Inode of the *client-side* socket (local = client addr, remote = proxy addr)."""
    candidates = []
    for ip, port, sip in ((client_ip, client_port, server_ip),):
        for fam in ("tcp", "tcp6"):
            try:
                text = (proc / "net" / fam).read_text()
            except OSError:
                continue
            for row in parse_proc_net(text):
                if row["local"][1] != port or row["remote"][1] != server_port:
                    continue
                try:
                    if decode_hex_ip(row["local"][0]) == _norm(ip) and decode_hex_ip(row["remote"][0]) == _norm(sip):
                        candidates.append(row["inode"])
                except ValueError:
                    continue
    return next((c for c in candidates if c), None)


def _norm(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return str(a)


def pid_for_inode(inode: int, proc: Path = PROC, skip: set[int] | None = None) -> int | None:
    target = f"socket:[{inode}]"
    for d in proc.iterdir():
        if not d.name.isdigit():
            continue
        pid = int(d.name)
        if skip and pid in skip:
            continue
        try:
            for fd in (d / "fd").iterdir():
                try:
                    if os.readlink(fd) == target:
                        return pid
                except OSError:
                    continue
        except OSError:
            continue
    return None


def _cmdline(pid: int, proc: Path = PROC) -> str:
    try:
        return (proc / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _ppid(pid: int, proc: Path = PROC) -> int | None:
    try:
        stat = (proc / str(pid) / "stat").read_text()
        return int(stat[stat.rindex(")") + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def _env_label(pid: int, proc: Path = PROC) -> str | None:
    try:
        env = (proc / str(pid) / "environ").read_bytes().split(b"\0")
    except OSError:
        return None
    for kv in env:
        if kv.startswith(b"ASCA_EGRESS_LABEL="):
            return kv.split(b"=", 1)[1].decode("utf-8", "replace")[:64] or None
    return None


def short(cmd: str) -> str:
    """'/opt/x/.venv/bin/python3 -m tui_gateway.entry' -> 'python3 -m tui_gateway.entry' (≤60 chars)."""
    if not cmd:
        return "?"
    parts = cmd.split()
    parts[0] = parts[0].rsplit("/", 1)[-1]
    if len(parts) > 1 and "/" in parts[1] and not parts[1].startswith("-"):
        parts[1] = parts[1].rsplit("/", 1)[-1]
    s = " ".join(parts)
    return s if len(s) <= 60 else s[:59] + "…"


def describe(pid: int, proc: Path = PROC, max_depth: int = 12) -> Client:
    chain_cmds: list[str] = []
    label = None
    agent = None
    cur: int | None = pid
    depth = 0
    while cur and cur > 1 and depth < max_depth:
        cmd = _cmdline(cur, proc)
        chain_cmds.append(cmd)
        if label is None:
            label = _env_label(cur, proc)
        if agent is None:
            for rx, name in KNOWN_AGENTS:
                if rx.search(cmd):
                    agent = name
                    break
        cur = _ppid(cur, proc)
        depth += 1
    shorts = [short(c) for c in chain_cmds if c]
    return Client(pid=pid, proc=shorts[0] if shorts else "?", agent=label or agent or (shorts[0] if shorts else "?"),
                  chain=shorts[:6])


def attribute(peer: tuple, sock: tuple, proc: Path = PROC, self_pid: int | None = None) -> Client:
    """peer = client (ip, port), sock = proxy listening (ip, port) as seen on this connection."""
    try:
        inode = find_inode(peer[0], peer[1], sock[0], sock[1], proc)
        if inode is None:
            return Client()
        pid = pid_for_inode(inode, proc, skip={self_pid} if self_pid else None)
        return describe(pid, proc) if pid else Client()
    except Exception:  # attribution is best-effort and must never break proxying
        return Client()


class CronContext:
    """Which Hermes cron jobs were running at a given moment (correlation, not proof)."""

    def __init__(self, hermes_home: Path | None, ttl: float = 5.0):
        self.db = hermes_home / "cron" / "executions.db" if hermes_home else None
        self.jobs = hermes_home / "cron" / "jobs.json" if hermes_home else None
        self.ttl = ttl
        self._cache: tuple[float, list[str]] = (0.0, [])
        self._names: tuple[float, dict] = (0.0, {})

    def _job_names(self) -> dict:
        now = time.monotonic()
        if now - self._names[0] < 60 and self._names[1]:
            return self._names[1]
        names = {}
        try:
            for j in json.loads(self.jobs.read_text(encoding="utf-8")).get("jobs", []):
                names[j.get("id")] = j.get("name") or j.get("id")
        except (OSError, ValueError, AttributeError):
            pass
        self._names = (now, names)
        return names

    def running(self) -> list[str]:
        if not self.db or not self.db.exists():
            return []
        now = time.monotonic()
        if now - self._cache[0] < self.ttl:
            return self._cache[1]
        out: list[str] = []
        try:
            con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True, timeout=0.5)
            try:
                rows = con.execute("SELECT DISTINCT job_id FROM executions WHERE status IN ('claimed','running')")
                names = self._job_names()
                out = sorted(names.get(r[0], r[0]) for r in rows)
            finally:
                con.close()
        except sqlite3.Error:
            out = []
        self._cache = (now, out)
        return out
