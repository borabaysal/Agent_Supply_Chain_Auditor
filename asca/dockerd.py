"""Docker daemon reachable over TCP without client-certificate auth (``host.docker-api-exposed``).

Grounding: Carbonato (ThreatDown, Sep 2026; CSA research note) compromises Docker hosts whose
daemon API is reachable over the network without authentication, starts a privileged container,
installs Hermes Agent and swaps its persona to take orders over Telegram. Anyone who can reach an
unauthenticated Docker API is root on the host: they can mount ``/`` into a container.

What is read (text only; nothing is run and the daemon is never contacted):
- ``/etc/docker/daemon.json`` (and the rootless ``~/.config/docker/daemon.json``,
  snap ``/var/snap/docker/current/config/daemon.json``): ``hosts`` and ``tlsverify``.
- systemd units and drop-ins for docker (``ExecStart= … -H tcp://…``), ``/etc/default/docker``
  ``DOCKER_OPTS`` and ``/etc/sysconfig/docker`` ``OPTIONS``.

Only ``--tlsverify`` (client certificates) authenticates callers; ``--tls`` alone encrypts but lets
anyone in, so it counts as unauthenticated.

| Listener without --tlsverify | Severity |
|---|---|
| all interfaces (``tcp://0.0.0.0``, ``tcp://:2375``, ``[::]``) | critical |
| a specific non-loopback address (LAN, VPN/tailnet) | high |
| loopback only | medium (any local process or container with host networking gets root) |

Docker Desktop on macOS doesn't offer a TCP listener; its "Expose daemon on tcp://localhost:2375
without TLS" setting exists on Windows only and isn't read here.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

from .model import Finding, Severity

RULE = "host.docker-api-exposed"
THREATDOWN = "https://www.threatdown.com/blog/carbonato/"

SYSTEMD_UNITS = ["/etc/systemd/system/docker.service", "/lib/systemd/system/docker.service",
                 "/usr/lib/systemd/system/docker.service"]
SYSTEMD_DROPINS = ["/etc/systemd/system/docker.service.d", "/run/systemd/system/docker.service.d"]
OPTION_FILES = [("/etc/default/docker", "DOCKER_OPTS"), ("/etc/sysconfig/docker", "OPTIONS")]
DAEMON_JSON = ["/etc/docker/daemon.json", "/var/snap/docker/current/config/daemon.json"]

_TCP = re.compile(r"^tcp://(?P<host>\[[^\]]*\]|[^:/]*)(?::(?P<port>\d+))?", re.I)


def _hosts_from_args(args: list[str]) -> tuple[list[str], bool]:
    hosts, verify = [], False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-H", "--host") and i + 1 < len(args):
            hosts.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--host="):
            hosts.append(a.split("=", 1)[1])
        elif a.startswith("-H") and len(a) > 2:
            hosts.append(a[2:].lstrip("="))
        elif a == "--tlsverify" or a.startswith("--tlsverify=") and a.split("=", 1)[1].lower() in ("true", "1"):
            verify = True
        i += 1
    return hosts, verify


def _split(text: str) -> list[str]:
    try:
        return shlex.split(text, comments=False)
    except ValueError:
        return text.split()


def _classify(host: str) -> Severity | None:
    m = _TCP.match(host.strip())
    if not m:
        return None                                 # unix:// or fd:// sockets: local permissions apply
    h = m.group("host").strip("[]").lower()
    if h in ("", "0.0.0.0", "::", "*"):
        return Severity.CRITICAL
    if h in ("localhost", "::1") or h.startswith("127."):
        return Severity.MEDIUM
    return Severity.HIGH


def _finding(host: str, sev: Severity, where: str, how: str) -> Finding:
    scope = {Severity.CRITICAL: "on every network interface", Severity.HIGH: "on a network address",
             Severity.MEDIUM: "on loopback"}[sev]
    return Finding(
        rule=RULE, category="host", severity=sev,
        title=f"Docker API listens {scope} without client-certificate auth (`{host}`)",
        location=where, subject=host,
        detail=(f"{how} Anyone who can reach this port controls Docker, which means root on the host: they can "
                f"start a privileged container with `/` mounted. Carbonato spreads exactly this way and then "
                f"installs Hermes Agent with a rewritten persona ({THREATDOWN})."
                + (" Loopback limits it to this machine, but any local process, and any container using host "
                   "networking, still gets root." if sev == Severity.MEDIUM else "")),
        remediation=("Remove the tcp:// listener and use the default unix socket (`docker context` or SSH: "
                     "`DOCKER_HOST=ssh://user@host`). If you really need TCP, require client certificates "
                     "(`--tlsverify` with `tlscacert`/`tlscert`/`tlskey`) and bind it to a private address only. "
                     "Then `sudo systemctl daemon-reload && sudo systemctl restart docker`."),
    )


def audit(root: Path = Path("/"), home: Path | None = None, stats: dict | None = None) -> list[Finding]:
    """root: filesystem root to read from (tests point it at a fixture tree)."""
    stats = stats if stats is not None else {}
    sources: list[tuple[str, list[str], bool]] = []     # (where, hosts, tlsverify)

    def rp(p: str) -> Path:
        return root / p.lstrip("/")

    jsons = [rp(p) for p in DAEMON_JSON] + ([home / ".config/docker/daemon.json"] if home else [])
    json_verify = False
    for p in jsons:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        verify = doc.get("tlsverify") is True
        json_verify = json_verify or verify
        hosts = doc.get("hosts") or []
        if isinstance(hosts, str):
            hosts = [hosts]
        sources.append((str(p), [h for h in hosts if isinstance(h, str)], verify))

    dropins: list[Path] = []
    for d in SYSTEMD_DROPINS:
        try:
            dropins += sorted(rp(d).glob("*.conf"))
        except OSError:
            pass

    def execstarts(p: Path) -> tuple[list[str], bool]:
        """(ExecStart command lines, whether an empty `ExecStart=` resets the base unit's)."""
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], False
        joined = re.sub(r"\\\n\s*", " ", text)              # continuation lines
        cmds, reset = [], False
        for line in joined.splitlines():
            m = re.match(r"\s*ExecStart\s*=\s*(.*)", line)
            if m:
                if m.group(1).strip():
                    cmds.append(m.group(1))
                else:
                    reset = True
        return cmds, reset

    drop_cmds = [(p, *execstarts(p)) for p in dropins]
    overridden = any(reset for _, _, reset in drop_cmds)     # the base unit's ExecStart no longer runs
    for p in [rp(u) for u in SYSTEMD_UNITS] if not overridden else []:
        for cmd in execstarts(p)[0]:
            sources.append((str(p), *_hosts_from_args(_split(cmd))))
    for p, cmds, _ in drop_cmds:
        for cmd in cmds:
            sources.append((str(p), *_hosts_from_args(_split(cmd))))

    for path, var in OPTION_FILES:
        p = rp(path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = re.match(rf"\s*(?:export\s+)?{var}\s*=\s*(.+)", line)
            if m:
                val = m.group(1).strip().strip("\"'")
                hosts, verify = _hosts_from_args(_split(val))
                sources.append((str(p), hosts, verify))

    stats["docker_daemon_configs"] = len(sources)
    out: list[Finding] = []
    seen = set()
    for where, hosts, verify in sources:
        for h in hosts:
            sev = _classify(h)
            if sev is None or verify or json_verify or (where, h) in seen:
                continue
            seen.add((where, h))
            how = (f"`{where}` makes dockerd listen on `{h}`"
                   + (" and nothing sets `--tlsverify`." if "2376" not in h else
                      "; port 2376 is the TLS port by convention, but `--tlsverify` isn't set, so no client "
                      "certificate is required."))
            out.append(_finding(h, sev, where, how))
    return out
