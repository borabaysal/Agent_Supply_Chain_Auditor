"""Daily diff: what did agents talk to in this window that they had never talked to before?

Baseline (``baseline.json``) maps every destination host to first/last seen and the set of
agents that used it. A summary run:
  1. reads log records in (last_run, now],
  2. computes new hosts, new registrable domains, new agent→host pairs, direct (proxy-
     bypassing) connections, IP-literal destinations, and failures,
  3. folds the window into the baseline (unless --no-learn), and
  4. returns a report; the CLI sends Telegram only when there is a difference
     (or when the proxy looks dead, because silence must never mean "fine" by accident).
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .log import iter_records

# second-level public suffixes common enough to matter; not a full PSL, on purpose (stdlib only)
_MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.nz", "com.br", "com.cn",
                 "com.tr", "co.in", "co.kr", "com.mx", "com.sg", "github.io", "herokuapp.com", "vercel.app",
                 "netlify.app", "pages.dev", "workers.dev", "fly.dev", "onrender.com", "azurewebsites.net",
                 "cloudfront.net", "amazonaws.com", "r2.dev", "web.app", "firebaseapp.com", "ngrok.io",
                 "ngrok-free.app", "trycloudflare.com", "repl.co"}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def ip_bucket(ip: str) -> str:
    """Coarse network for direct-connection baselines: /24 for IPv4, /48 for IPv6."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False))


def registrable(host: str) -> str:
    """'api.eu.example.co.uk' -> 'example.co.uk'. Hosting suffixes (e.g. github.io) count as
    public, so 'evil.github.io' stays distinct from 'good.github.io'."""
    host = host.lower().rstrip(".")
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    for n in (3, 2):  # longest matching suffix wins
        suf = ".".join(labels[-n:])
        if suf in _MULTI_SUFFIX:
            return ".".join(labels[-(n + 1):]) if len(labels) > n else host
    return ".".join(labels[-2:])


@dataclass
class Diff:
    window: tuple[float, float]
    total: int = 0
    hosts: Counter = field(default_factory=Counter)
    new_domains: dict = field(default_factory=dict)      # domain -> {hosts, agents, count}
    new_hosts: dict = field(default_factory=dict)        # host (under a known domain) -> {agents, count}
    new_pairs: dict = field(default_factory=dict)        # (agent, host) -> count, host already known
    direct: dict = field(default_factory=dict)           # (agent, ip:port) -> {count, host_hint}
    ip_literals: dict = field(default_factory=dict)      # ip:port -> {agents, count}
    failures: Counter = field(default_factory=Counter)   # host -> count
    agents: Counter = field(default_factory=Counter)
    proxy_alive: bool = True
    corrupt_lines: int = 0
    first_run: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.new_domains or self.new_hosts or self.new_pairs or self.direct or self.ip_literals
                    or not self.proxy_alive)


def load_baseline(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("hosts"), dict):
            return d
    except (OSError, ValueError):
        pass
    return {"version": 1, "hosts": {}, "direct": {}, "last_run": 0}


def save_baseline(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def _agent(r: dict) -> str:
    c = r.get("client") or {}
    label = c.get("agent") or "unknown"
    cron = r.get("cron") or []
    # a connection from a generic tool during a single running cron job is most likely that job's
    if cron and len(cron) == 1 and not label.startswith(("hermes-", "claude", "codex", "goose", "gemini")):
        return f"{label} [cron: {cron[0]}]"
    return label


def compute(logdir: Path, baseline: dict, *, since: float | None = None, until: float | None = None,
            stale_hours: float = 26.0) -> Diff:
    until = until or time.time()
    since = since if since is not None else (baseline.get("last_run") or until - 86400)
    d = Diff(window=(since, until), first_run=not baseline["hosts"])
    known_hosts = baseline["hosts"]
    known_domains = {registrable(h) for h in known_hosts}
    known_direct = baseline.get("direct", {})
    ip_to_host: dict[str, str] = {}
    saw_proxy_activity = False
    records = list(iter_records(logdir, since, until))
    for r in records:
        if r.get("kind") == "_corrupt":
            d.corrupt_lines += r.get("count", 0)
            continue
        if r.get("kind") in ("proxy_start", "proxy_stop", "heartbeat"):
            saw_proxy_activity = True
            continue
        if r.get("kind") in ("connect", "http") and r.get("host"):
            saw_proxy_activity = True
            if r.get("ip"):
                ip_to_host[r["ip"]] = r["host"]
    for r in records:
        kind = r.get("kind")
        if kind not in ("connect", "http", "direct"):
            continue
        agent = _agent(r)
        d.total += 1
        d.agents[agent] += 1
        if kind == "direct":
            key = f"{agent}|{ip_bucket(r.get('ip', ''))}:{r.get('port')}"
            if key not in known_direct:
                e = d.direct.setdefault(key, {"agent": agent, "dest": f"{r.get('ip')}:{r.get('port')}",
                                              "net": ip_bucket(r.get("ip", "")), "count": 0,
                                              "host_hint": ip_to_host.get(r.get("ip"), "")})
                e["count"] += 1
            continue
        host = r["host"]
        d.hosts[host] += 1
        if r.get("error") or (isinstance(r.get("status"), int) and r["status"] >= 500):
            d.failures[host] += 1
        if is_ip(host):
            k = f"{host}:{r.get('port')}"
            if host not in known_hosts:
                e = d.ip_literals.setdefault(k, {"agents": set(), "count": 0})
                e["agents"].add(agent)
                e["count"] += 1
            continue
        dom = registrable(host)
        if host not in known_hosts:
            if dom not in known_domains:
                e = d.new_domains.setdefault(dom, {"hosts": set(), "agents": set(), "count": 0})
                e["hosts"].add(host)
                e["agents"].add(agent)
                e["count"] += 1
            else:
                e = d.new_hosts.setdefault(host, {"agents": set(), "count": 0})
                e["agents"].add(agent)
                e["count"] += 1
        elif agent not in known_hosts[host].get("agents", []):
            d.new_pairs[(agent, host)] = d.new_pairs.get((agent, host), 0) + 1
    # dead-proxy detection: nothing at all from the proxy in a long window
    if (until - since) >= stale_hours * 3600 * 0.9 and not saw_proxy_activity:
        d.proxy_alive = False
    return d


def learn(baseline: dict, logdir: Path, diff: Diff) -> dict:
    since, until = diff.window
    for r in iter_records(logdir, since, until):
        kind = r.get("kind")
        agent = _agent(r) if kind in ("connect", "http", "direct") else None
        if kind in ("connect", "http") and r.get("host"):
            e = baseline["hosts"].setdefault(r["host"], {"first_seen": r["ts"], "agents": [], "count": 0})
            e["last_seen"] = r["ts"]
            e["count"] = e.get("count", 0) + 1
            if agent not in e["agents"]:
                e["agents"].append(agent)
                e["agents"].sort()
        elif kind == "direct":
            key = f"{agent}|{ip_bucket(r.get('ip', ''))}:{r.get('port')}"
            e = baseline.setdefault("direct", {}).setdefault(key, {"first_seen": r["ts"], "count": 0})
            e["last_seen"] = r["ts"]
            e["count"] += 1
    baseline["last_run"] = until
    return baseline


def _fmt_set(s) -> str:
    s = sorted(s)
    return ", ".join(s[:3]) + (f" +{len(s) - 3}" if len(s) > 3 else "")


def to_markdown(d: Diff, host_label: str = "") -> str:
    t0 = datetime.fromtimestamp(d.window[0], timezone.utc).strftime("%Y-%m-%d %H:%M")
    t1 = datetime.fromtimestamp(d.window[1], timezone.utc).strftime("%Y-%m-%d %H:%M")
    out = [f"# Agent egress summary{f' ({host_label})' if host_label else ''}", "",
           f"Window: {t0} → {t1} UTC · connections: {d.total} · destinations: {len(d.hosts)} · "
           f"agents: {len(d.agents)}", ""]
    if d.first_run:
        out += ["_First run: everything below becomes the baseline._", ""]
    if not d.proxy_alive:
        out += ["## ⚠️ No proxy activity in this window", "",
                "The proxy wrote nothing, not even a start record. It is probably down, or no agent is "
                "routed through it. New destinations would not be detected.", ""]

    def section(title, rows, header):
        if rows:
            out.extend([f"## {title}", "", header, "|" + "---|" * (header.count("|") - 1), *rows, ""])

    section("🆕 New domains", [f"| `{k}` | {_fmt_set(v['hosts'])} | {_fmt_set(v['agents'])} | {v['count']} |"
                              for k, v in sorted(d.new_domains.items())], "| domain | hosts | agents | conns |")
    section("🔸 New hosts under known domains", [f"| `{k}` | {_fmt_set(v['agents'])} | {v['count']} |"
                                                for k, v in sorted(d.new_hosts.items())], "| host | agents | conns |")
    section("🔁 Known host, first use by this agent", [f"| {a} | `{h}` | {n} |" for (a, h), n in sorted(d.new_pairs.items())],
            "| agent | host | conns |")
    section("🔢 IP-literal destinations", [f"| `{k}` | {_fmt_set(v['agents'])} | {v['count']} |"
                                          for k, v in sorted(d.ip_literals.items())], "| dest | agents | conns |")
    section("🚧 Direct connections that bypassed the proxy",
            [f"| {v['agent']} | `{v['dest']}` | {v['host_hint'] or '—'} | {v['count']} |"
             for _, v in sorted(d.direct.items())], "| agent | dest | likely host | seen |")
    if d.hosts:
        out += ["## Top destinations", "", "| host | conns | failures |", "|---|---|---|"]
        out += [f"| `{h}` | {n} | {d.failures.get(h, 0)} |" for h, n in d.hosts.most_common(15)]
        out.append("")
    if d.agents:
        out += ["## By agent", "", "| agent | conns |", "|---|---|"]
        out += [f"| {a} | {n} |" for a, n in d.agents.most_common(20)]
        out.append("")
    if d.corrupt_lines:
        out += [f"_{d.corrupt_lines} corrupt log line(s) skipped._", ""]
    if not d.has_changes and not d.first_run:
        out += ["No new destinations. ✅", ""]
    return "\n".join(out)


def to_telegram(d: Diff, host_label: str, report_path: str | None, max_items: int = 6) -> str:
    from html import escape as e
    parts = [f"🌐 <b>Agent egress: {'changes detected' if d.has_changes else 'no changes'}</b>",
             f"Host: <code>{e(host_label)}</code> · last {round((d.window[1] - d.window[0]) / 3600)}h · "
             f"{d.total} conns · {len(d.hosts)} destinations"]
    if not d.proxy_alive:
        parts.append("⚠️ <b>No proxy activity.</b> The proxy is probably down, or no agent is routed through it.")

    def block(title, items):
        if not items:
            return
        parts.append("")
        parts.append(f"<b>{title} ({len(items)})</b>")
        for line in items[:max_items]:
            parts.append(line)
        if len(items) > max_items:
            parts.append(f"…and {len(items) - max_items} more")

    block("🆕 New domains", [f"• <code>{e(k)}</code> by {e(_fmt_set(v['agents']))} ({v['count']}×)"
                            for k, v in sorted(d.new_domains.items())])
    block("🚧 Bypassed proxy", [f"• {e(v['agent'])} → <code>{e(v['dest'])}</code>"
                               + (f" ({e(v['host_hint'])})" if v['host_hint'] else "")
                               for _, v in sorted(d.direct.items())])
    block("🔢 IP literals", [f"• <code>{e(k)}</code> by {e(_fmt_set(v['agents']))}" for k, v in sorted(d.ip_literals.items())])
    block("🔸 New hosts (known domain)", [f"• <code>{e(k)}</code> by {e(_fmt_set(v['agents']))}"
                                         for k, v in sorted(d.new_hosts.items())])
    block("🔁 New agent→host", [f"• {e(a)} → <code>{e(h)}</code>" for (a, h), _ in sorted(d.new_pairs.items())])
    if report_path:
        parts += ["", f"Report: <code>{e(report_path)}</code>"]
    text = "\n".join(parts)
    return text if len(text) <= 4096 else text[:4076] + "\n…(truncated)"
