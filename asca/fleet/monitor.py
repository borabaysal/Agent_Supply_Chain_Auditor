"""Fleet patch status: compare each instance's running version with the release feed.

For each instance: releases newer than its version → security fixes and hardening items
it is missing, plus any tracked advisory (built-in table, advisory file) that affects the
running version. The run state is saved, so `--telegram change` alerts only when something
moves: a new release, an instance upgraded or downgraded, a target that becomes unreachable
or comes back, or the feed starting or stopping failing.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from .releases import Release, parse_version
from .targets import Observation


@dataclass
class InstanceStatus:
    obs: Observation
    behind: list[Release] = field(default_factory=list)      # newer releases
    advisories: list[tuple[str, str, str]] = field(default_factory=list)   # (id, severity, fixed)
    unknown_version: bool = False
    ahead: bool = False                                       # newer than any published release
    # How long it has been behind: counted from the publish date of the oldest release it is missing.
    # None when that date is unknown; the count is then left out rather than guessed.
    behind_since: str | None = None                           # YYYY-MM-DD
    days_behind: int | None = None

    @property
    def oldest_missing(self) -> Release | None:
        return self.behind[0] if self.behind else None

    @property
    def fixes(self):
        return [(r, i) for r in self.behind for i in r.fixes]

    @property
    def hardening(self):
        return [(r, i) for r in self.behind for i in r.hardening]

    @property
    def fix_keys(self) -> list[str]:
        return sorted({i.key() for _, i in self.fixes} | {a[0] for a in self.advisories})

    @property
    def needs_patch(self) -> bool:
        return bool(self.fixes or self.advisories)

    def to_dict(self) -> dict:
        return {**self.obs.to_dict(), "releases_behind": [r.vstr for r in self.behind],
                "security_fixes_behind": len(self.fixes), "hardening_behind": len(self.hardening),
                "advisories": [{"id": a, "severity": s, "fixed": f} for a, s, f in self.advisories],
                "unknown_version": self.unknown_version, "ahead_of_latest": self.ahead,
                "behind_since": self.behind_since, "days_behind": self.days_behind}


@dataclass
class FleetStatus:
    generated_at: str
    latest: Release | None
    instances: list[InstanceStatus]
    feed_error: str | None = None

    @property
    def any_behind(self) -> bool:
        return any(i.needs_patch for i in self.instances)

    @property
    def any_unreachable(self) -> bool:
        return any(i.unknown_version for i in self.instances)

    @property
    def ok(self) -> bool:
        return not (self.any_behind or self.any_unreachable or self.feed_error)

    def signature(self) -> str:
        """What 'changed' means for alerting. Ignores timestamps and wording of notes."""
        sig = {"latest": self.latest.vstr if self.latest else None, "feed_error": bool(self.feed_error),
               "inst": sorted((i.obs.name, i.obs.version, tuple(i.fix_keys), i.unknown_version)
                              for i in self.instances)}
        return hashlib.sha256(json.dumps(sig, sort_keys=True).encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {"generated_at": self.generated_at, "ok": self.ok, "signature": self.signature(),
                "feed_error": self.feed_error,
                "latest": self.latest.to_dict() if self.latest else None,
                "instances": [i.to_dict() for i in self.instances]}


def evaluate(observations: list[Observation], releases: list[Release], *,
             advisories: list[tuple] = (), feed_error: str | None = None,
             now: datetime | None = None) -> FleetStatus:
    """advisories: tuples (id, lo, hi, fixed, Severity, summary) as in asca.hermes."""
    now = now or datetime.now(timezone.utc)
    latest = releases[-1] if releases else None
    out = []
    for o in observations:
        v = parse_version(o.version or "")
        st = InstanceStatus(obs=o)
        if not v:
            st.unknown_version = True
            out.append(st)
            continue
        st.behind = sorted((r for r in releases if r.version > v), key=lambda r: r.version)
        st.ahead = bool(latest) and v > latest.version
        if st.behind:
            st.behind_since, st.days_behind = behind_for(st.behind[0].published, now)
        seen_ids = {x for r in st.behind for i in r.fixes for x in i.ids}
        for adv, lo, hi, fixed, sev, _summary in advisories:
            if lo <= v <= hi and adv not in seen_ids:
                st.advisories.append((adv, sev.value if hasattr(sev, "value") else str(sev), fixed))
        out.append(st)
    return FleetStatus(generated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"), latest=latest, instances=out,
                       feed_error=feed_error)


def behind_for(published: str | None, now: datetime) -> tuple[str | None, int | None]:
    """(date, whole days since it) for a release's publish date; (None, None) if missing or invalid.
    Calendar days in UTC, so a release published yesterday at 23:00 counts as 1 day."""
    try:
        d = datetime.strptime((published or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None, None
    days = (now.astimezone(timezone.utc).date() - d).days
    return (d.isoformat(), days) if days >= 0 else (None, None)


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def short_date(iso: str | None) -> str:
    """'2026-11-10' -> '10 Nov' (locale-independent)."""
    try:
        d = datetime.strptime((iso or "")[:10], "%Y-%m-%d")
    except ValueError:
        return ""
    return f"{d.day} {_MONTHS[d.month - 1]}"


def for_days(days: int | None) -> str:
    """' for 3 days' / ' for 1 day' / ' since today' / '' (unknown: left out, never guessed)."""
    if days is None:
        return ""
    return " since today" if days == 0 else f" for {_plural(days, 'day')}"


def since_note(i: "InstanceStatus") -> str:
    """'v0.23.1 released 10 Nov' (or 'oldest missing: v0.22.4, released 4 Nov'); '' if the date is unknown."""
    r = i.oldest_missing
    if not r or i.behind_since is None:
        return ""
    when = short_date(i.behind_since)
    return f"v{r.vstr} released {when}" if len(i.behind) == 1 else f"oldest missing: v{r.vstr}, released {when}"


# ------------------------------------------------------------------ state

def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(path: Path, status: FleetStatus, *, last_alert_at: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    data = status.to_dict()
    if last_alert_at:
        data["last_alert_at"] = last_alert_at
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def needs_attention(s: FleetStatus) -> bool:
    """Anything a reminder should repeat: behind (with or without security fixes), unreadable, feed down."""
    return bool(s.feed_error) or any(i.behind or i.unknown_version or i.advisories for i in s.instances)


REMIND_SLACK_S = 2 * 3600   # daily jobs drift by minutes; don't let "3 days" slip to 4


def reminder_due(prev: dict, cur: FleetStatus, days: int, now: datetime) -> bool:
    if days <= 0 or not needs_attention(cur):
        return False
    last = prev.get("last_alert_at")
    if not last:
        return False   # no record yet (state from an older asca): start the clock instead of alerting now
    try:
        t = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return (now - t).total_seconds() >= days * 86400 - REMIND_SLACK_S


def changes(prev: dict, cur: FleetStatus) -> list[str]:
    """Human-readable list of what moved since the previous run (empty = nothing)."""
    if not prev:
        return ["first run"]
    if prev.get("signature") == cur.signature():
        return []
    msgs = []
    pl = (prev.get("latest") or {}).get("version")
    if cur.latest and pl != cur.latest.vstr:
        n = len(cur.latest.fixes)
        msgs.append(f"new release v{cur.latest.vstr}" + (f" with {n} security fix{'es' if n != 1 else ''}" if n else ""))
    before = {i["name"]: i for i in prev.get("instances", [])}
    for i in cur.instances:
        p = before.get(i.obs.name)
        if p is None:
            msgs.append(f"{i.obs.name}: now monitored")
            continue
        if p.get("version") != i.obs.version:
            if i.obs.version and p.get("version"):
                msgs.append(f"{i.obs.name}: v{p['version']} → v{i.obs.version}")
            elif not i.obs.version:
                msgs.append(f"{i.obs.name}: version unreadable")
            else:
                msgs.append(f"{i.obs.name}: reachable again (v{i.obs.version})")
    for name in set(before) - {i.obs.name for i in cur.instances}:
        msgs.append(f"{name}: no longer monitored")
    if bool(prev.get("feed_error")) != bool(cur.feed_error):
        msgs.append("release feed failing" if cur.feed_error else "release feed recovered")
    return msgs or ["security status changed"]


# ------------------------------------------------------------------ rendering

def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def headline(i: InstanceStatus) -> str:
    if i.unknown_version:
        return f"{i.obs.name}: version unknown ({i.obs.error or 'unreadable'})"
    v = i.obs.version
    if i.needs_patch:
        n = len(i.fix_keys)
        extra = f", plus {_plural(len(i.hardening), 'hardening item')}" if i.hardening else ""
        return (f"{i.obs.name} (v{v}) is {_plural(n, 'security fix', 'security fixes')} behind"
                f" across {_plural(len(i.behind), 'release')}{for_days(i.days_behind)}{extra}")
    if i.behind:
        return (f"{i.obs.name} (v{v}) is {_plural(len(i.behind), 'release')} behind{for_days(i.days_behind)}, "
                f"no listed security fixes" + (f" ({_plural(len(i.hardening), 'hardening item')})" if i.hardening else ""))
    return f"{i.obs.name} (v{v}) is up to date" + (" (ahead of latest release)" if i.ahead else "")


def to_markdown(s: FleetStatus) -> str:
    out = ["# Hermes fleet patch status", "",
           f"Generated: {s.generated_at} · latest release: "
           + (f"v{s.latest.vstr} ({s.latest.published})" if s.latest else "unknown"), ""]
    if s.feed_error:
        out += [f"> ⚠️ Release feed error: `{s.feed_error}`. Counts below may be stale or empty.", ""]
    out += ["| instance | running | releases behind | security fixes | hardening | status |",
            "|---|---|---|---|---|---|"]
    for i in s.instances:
        status = "❔ unknown" if i.unknown_version else "🟥 patch" if i.needs_patch else "🟨 behind" if i.behind else "✅ current"
        out.append(f"| {i.obs.name} | {i.obs.version or '—'} | {len(i.behind)} | {len(i.fix_keys)} | "
                   f"{len(i.hardening)} | {status} |")
    out.append("")
    for i in s.instances:
        if i.behind and not i.needs_patch and not i.unknown_version:
            out += [f"## {i.obs.name}", "", headline(i) + ".", "",
                    "Newer: " + ", ".join(f"[v{r.vstr}]({r.url}) ({r.published})" for r in reversed(i.behind)), "",
                    "Upgrade when convenient: `docker pull nousresearch/hermes-agent:stable` and recreate the "
                    "container, or `hermes update` for git installs.", ""]
            continue
        if not (i.needs_patch or i.unknown_version):
            continue
        out += [f"## {i.obs.name}", "", headline(i), ""]
        if i.unknown_version:
            out += [f"- source: `{i.obs.spec}`", f"- error: {i.obs.error}", ""]
            continue
        for a, sev, fixed in i.advisories:
            out.append(f"- **{a}** ({sev}), fixed in {fixed}")
        for r in reversed(i.behind):
            if not r.fixes:
                continue
            out.append(f"- **v{r.vstr}** ({r.published}), [{r.tag}]({r.url})")
            for it in r.fixes:
                out.append(f"  - {('_' + it.group + ':_ ') if it.group else ''}{it.text}")
        out += ["", "Upgrade: `docker pull nousresearch/hermes-agent:stable` and recreate the container, "
                    "or `hermes update` for git installs.", ""]
    from ..report import dashboard_md
    out += dashboard_md()
    return "\n".join(out)


def to_telegram(s: FleetStatus, *, what_changed: list[str], report_path: str | None = None,
                max_fixes: int = 6, reminder_days: int = 0) -> str:
    """reminder_days > 0: this is a periodic "still behind" reminder, not a change alert."""
    e = escape
    behind = [i for i in s.instances if i.needs_patch]
    lagging = [i for i in s.instances if i.behind and not i.needs_patch]
    if s.feed_error and not s.instances:
        title = "⚠️ <b>Hermes patch monitor: release feed failing</b>"
    elif behind:
        worst = max(behind, key=lambda i: len(i.fix_keys))
        title = (f"🛡️ <b>{e(worst.obs.name)}: {_plural(len(worst.fix_keys), 'security fix', 'security fixes')} behind"
                 f"{for_days(worst.days_behind)}</b>" + (f" ({e(since_note(worst))})" if since_note(worst) else ""))
        if len(behind) > 1:
            title += f" (+{len(behind) - 1} more instance{'s' if len(behind) > 2 else ''})"
    elif s.any_unreachable:
        title = "❔ <b>Hermes patch monitor: an instance's version is unreadable</b>"
    elif lagging:
        # behind, but no listed security fixes: not "patched" — say what it is
        worst = max(lagging, key=lambda i: len(i.behind))
        note = since_note(worst)
        title = (f"🟨 <b>{e(worst.obs.name)}: {_plural(len(worst.behind), 'release')} behind"
                 f"{for_days(worst.days_behind)}</b> ({e(note) + ', ' if note else ''}no security fixes)")
        if len(lagging) > 1:
            title += f" (+{len(lagging) - 1} more instance{'s' if len(lagging) > 2 else ''})"
    else:
        title = "✅ <b>Hermes fleet is up to date</b>"
    if reminder_days:
        title = "⏰ Reminder · " + title
    parts = [title]
    if s.latest:
        parts.append(f"Latest: <b>v{e(s.latest.vstr)}</b> ({e(s.latest.published)})")
    parts.append("")
    for i in s.instances:
        icon = "❔" if i.unknown_version else "🟥" if i.needs_patch else "🟨" if i.behind else "✅"
        parts.append(f"{icon} {e(headline(i))}")
    shown = 0
    for i in behind:
        items = [(a, f"{a} ({sev})") for a, sev, _ in i.advisories] + \
                [(it.key(), f"v{r.vstr}: {(it.group + ': ') if it.group else ''}{it.text}") for r, it in i.fixes]
        seen = set()
        lines = []
        for k, txt in items:
            if k in seen:
                continue
            seen.add(k)
            lines.append(txt)
        if lines:
            parts += ["", f"<b>Missing on {e(i.obs.name)}:</b>"]
            for txt in lines[:max_fixes]:
                parts.append(f"• {e(txt if len(txt) <= 160 else txt[:159] + '…')}")
            if len(lines) > max_fixes:
                parts.append(f"…and {len(lines) - max_fixes} more")
            shown += 1
    if s.feed_error:
        parts += ["", f"⚠️ Feed error: <code>{e(s.feed_error[:150])}</code>"]
    if reminder_days:
        parts += ["", f"Nothing changed since the last alert; this repeats every {_plural(reminder_days, 'day')} "
                      f"while an instance is behind (<code>--remind-days</code>)."]
    elif what_changed and what_changed != ["first run"]:
        parts += ["", "Changed: " + e("; ".join(what_changed))]
    if behind or lagging:
        parts += ["", "Upgrade: <code>docker pull nousresearch/hermes-agent:stable</code> + recreate, "
                      "or <code>hermes update</code>."]
    if report_path:
        parts.append(f"Report: <code>{e(report_path)}</code>")
    text = "\n".join(parts)
    from ..report import with_dashboard_tg
    return with_dashboard_tg(text if len(text) <= 4096 else text[:4076] + "\n…(truncated)")
