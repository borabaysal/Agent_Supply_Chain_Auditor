"""asca dashboard: one self-contained HTML page per host with every asca job's status and the fixes to act on.

    asca dashboard [--state-dir DIR] [-o PATH] [--host-label NAME] [--stale-hours 26]

It reads only the reports asca already wrote under the state dir (audit, skills, inventory, fleet,
egress) and writes one HTML file (mode 0600) next to them, by default ``<state-dir>/dashboard.html``.
Run it after each scheduled job; the macOS runner and the example wrappers do.

Safe by construction:
- no server, no listening port, no network: it's a file you open in a browser;
- no JavaScript and a strict Content-Security-Policy (``default-src 'none'``), so nothing in the page
  can run or load anything;
- every value is HTML-escaped. Findings quote scanned content (skill names, file paths, commands)
  that an attacker can choose, so the page treats all of it as text;
- reports never contain secret values (4-char prefix, length, short hash), and neither does this page.

``dashboard-state.json`` next to the page remembers when each finding was first seen, so the page can
mark what's new and list what was fixed recently.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
ACT_ON = {"critical", "high", "medium"}          # shown expanded; low/info folded away
NEW_WINDOW = timedelta(hours=36)                  # "new" badge: first seen within a day and a half
RESOLVED_SHOW = timedelta(days=7)
RESOLVED_KEEP = timedelta(days=14)
HISTORY_RUNS = 21

# Where each job's report lives. Both layouts in use: the Hermes wrappers (audit report at the
# state root, others in subfolders) and scripts/macos/asca-run.sh (one subfolder per job).
CANDIDATES = {
    "audit": ("audit/latest.json", "latest.json"),
    "skills": ("skills/skills-latest.json", "skills-latest.json"),
    "inventory": ("inventory/inventory-latest.json", "inventory-latest.json"),
    "fleet": ("fleet/fleet-latest.json", "fleet-latest.json"),
    "egress": ("egress/summary-latest.md",),
}
LABELS = {"audit": "Supply-chain audit", "skills": "Skills & fake apps", "inventory": "IDE & agent inventory",
          "fleet": "Hermes patch level", "egress": "Network egress"}
TRACKS_RESOLUTION = {"audit", "skills"}   # inventory findings are one-run change events, not open issues

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


def e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


# ------------------------------------------------------------------ reading reports

@dataclass
class Job:
    key: str
    path: Path | None = None
    generated: datetime | None = None
    status: str = "missing"        # pass | warn | fail | error | missing
    summary: str = ""
    findings: list[dict] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    text: str = ""
    error: str | None = None
    stale: bool = False
    now: datetime | None = None    # page-build time, for "behind for N days"

    @property
    def label(self) -> str:
        return LABELS[self.key]


def _parse_time(s) -> datetime | None:
    if not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def discover(state_dir: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for key, rels in CANDIDATES.items():
        for rel in rels:
            p = state_dir / rel
            if p.is_file():
                if key == "audit" and not _is_audit(p):
                    continue
                found[key] = p
                break
    return found


def _is_audit(p: Path) -> bool:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True   # let load() report it as unreadable rather than hide it
    return d.get("tool") == "agent-supply-chain-auditor" and "skills_scanned" not in (d.get("stats") or {})


def load(key: str, path: Path | None, now: datetime | None = None) -> Job:
    j = Job(key=key, path=path, now=now)
    if path is None:
        return j
    try:
        if key == "egress":
            j.text = path.read_text(encoding="utf-8", errors="replace")
            j.generated = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            _egress(j)
            return j
        d = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            raise ValueError("not a JSON object")
    except (OSError, ValueError) as exc:
        j.status, j.error = "error", f"report unreadable: {type(exc).__name__}"
        return j
    j.data = d
    j.generated = _parse_time(d.get("generated_at"))
    if key == "fleet":
        _fleet(j)
    else:
        j.findings = [f for f in d.get("findings") or [] if isinstance(f, dict)]
        active = [f for f in j.findings if not f.get("suppressed")]
        if key == "inventory":
            n_items = sum(v for v in (d.get("counts") or {}).values() if isinstance(v, int))
            loud = [f for f in active if f.get("severity") != "info"]
            j.status = "fail" if d.get("result") == "FAIL" else "warn" if loud else "pass"
            j.summary = (f"{n_items} items tracked · " + (f"{len(loud)} change(s) to review" if loud else "no changes")
                         + (" · first run (baseline)" if d.get("first_run") else ""))
        else:
            c = d.get("counts") or {}
            j.status = "fail" if d.get("result") == "FAIL" else ("warn" if c.get("medium") else "pass")
            j.summary = " · ".join(f"{c.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low")) + \
                (f" · {c['suppressed']} accepted" if c.get("suppressed") else "")
    return j


def _fleet(j: Job) -> None:
    d = j.data
    insts = [i for i in d.get("instances") or [] if isinstance(i, dict)]
    latest = (d.get("latest") or {}).get("version")
    worst = "pass"
    bits = []
    for i in insts:
        if i.get("unknown_version"):
            worst = "error"
            bits.append(f"{i.get('name')}: version unreadable")
        elif i.get("security_fixes_behind") or i.get("advisories"):
            worst = "fail"
            bits.append(f"{i.get('name')} v{i.get('version')}: {i.get('security_fixes_behind', 0)} security fix(es) "
                        f"behind{_fleet_for(i, j.now)}")
        elif i.get("releases_behind"):
            worst = worst if worst in ("fail", "error") else "warn"
            n = len(i["releases_behind"])
            bits.append(f"{i.get('name')} v{i.get('version')}: {n} release{'s' if n != 1 else ''} "
                        f"behind{_fleet_for(i, j.now)}, no security fixes")
        else:
            bits.append(f"{i.get('name')} v{i.get('version')}: up to date")
    if d.get("feed_error"):
        worst = "error" if worst == "pass" else worst
        bits.append("release feed failing")
    j.status = worst
    j.summary = (f"latest v{latest} · " if latest else "") + "; ".join(bits)


def _egress(j: Job) -> None:
    t = j.text
    if "No proxy activity" in t:
        j.status, j.summary = "fail", "no proxy activity: the egress proxy may be down"
    elif re.search(r"^## (🆕|🔸|🔁|🔢|🚧)", t, re.M):
        heads = re.findall(r"^## (?:🆕|🔸|🔁|🔢|🚧) (.+)$", t, re.M)
        j.status, j.summary = "warn", "; ".join(heads)
    else:
        j.status, j.summary = "pass", "no new destinations"
    m = re.search(r"connections: (\d+)", t)
    if m:
        j.summary = f"{m.group(1)} connections · " + j.summary


def audit_history(audit_path: Path | None, limit: int = HISTORY_RUNS) -> list[dict]:
    if audit_path is None:
        return []
    out = []
    for p in sorted(audit_path.parent.glob("history-*.json"))[-limit:]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({"when": d.get("generated_at", p.stem[8:]), "result": d.get("result"), "counts": d.get("counts") or {}})
    return out


# ------------------------------------------------------------------ first-seen / resolved memory

def _fkey(job: str, f: dict) -> str:
    return f"{job}:{f.get('fingerprint') or f.get('rule', '') + '|' + f.get('subject', '')}"


def update_memory(state_path: Path, jobs: dict[str, Job], now: datetime) -> dict:
    try:
        mem = json.loads(state_path.read_text(encoding="utf-8"))
        seen = mem.get("seen") if isinstance(mem.get("seen"), dict) else {}
        fresh = False
    except (OSError, ValueError):
        seen, fresh = {}, True
    ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    current = set()
    for key, j in jobs.items():
        for f in j.findings:
            if f.get("suppressed") or f.get("severity") == "info":
                continue
            k = _fkey(key, f)
            current.add(k)
            rec = seen.get(k) or {"first": None if fresh else ts}
            rec.update(last=ts, title=f.get("title", ""), sev=f.get("severity", ""), job=key)
            rec.pop("resolved", None)
            seen[k] = rec
    for k, rec in list(seen.items()):
        job = rec.get("job")
        if k in current:
            continue
        j = jobs.get(job)
        if job not in TRACKS_RESOLUTION or j is None or j.status in ("error", "missing"):
            if job not in TRACKS_RESOLUTION:
                seen.pop(k)
            continue          # report missing/unreadable: don't claim anything was fixed
        rec.setdefault("resolved", ts)
        r = _parse_time(rec["resolved"])
        if r and now - r > RESOLVED_KEEP:
            seen.pop(k)
    mem = {"version": 1, "updated": ts, "seen": seen}
    _write_private(state_path, json.dumps(mem, indent=1, ensure_ascii=False) + "\n")
    return mem


# ------------------------------------------------------------------ rendering

STYLE = """
:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--mut:#9aa3ad;--bd:#2a2f38;--code:#0b0d11;
--crit:#ff4d6d;--high:#ff8c42;--med:#f2c94c;--low:#56a8f5;--info:#8a94a0;--ok:#3ecf8e;--warn:#f2c94c;--bad:#ff5c5c}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--mut:#5b6570;--bd:#dde1e6;--code:#f1f3f5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 18px 60px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:30px 0 10px}
.mut{color:var(--mut)}code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:1px 5px;border-radius:4px;word-break:break-all}
.banner{border:1px solid var(--bd);border-left:6px solid var(--ok);background:var(--card);border-radius:10px;
padding:14px 16px;margin:16px 0}
.banner.fail{border-left-color:var(--bad)}.banner.warn{border-left-color:var(--warn)}.banner.error{border-left-color:var(--bad)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px}
.card h3{margin:0 0 6px;font-size:14px;display:flex;justify-content:space-between;gap:8px;align-items:center}
.pill{font-size:11px;font-weight:700;border-radius:999px;padding:2px 8px;white-space:nowrap;color:#111}
.pass{background:var(--ok)}.warn{background:var(--warn)}.fail,.error{background:var(--bad)}.missing{background:var(--info)}
.stale{background:#b388ff}
.banner.pass,.banner.warn,.banner.fail,.banner.error,.banner.missing{background:var(--card);color:var(--fg)}
.sev{display:inline-block;min-width:64px;text-align:center}.critical{background:var(--crit)}.high{background:var(--high)}
.medium{background:var(--med)}.low{background:var(--low)}.info{background:var(--info)}
.new{background:#7c4dff;color:#fff}
.f{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin:10px 0}
.f h4{margin:0 0 6px;font-size:14px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.f dl{display:grid;grid-template-columns:52px 1fr;gap:4px 10px;margin:6px 0 0}.f dt{color:var(--mut)}.f dd{margin:0}
pre.cmd{background:var(--code);border:1px solid var(--bd);border-radius:6px;padding:7px 9px;margin:6px 0 0;
white-space:pre-wrap;word-break:break-all;user-select:all;-webkit-user-select:all}
details{margin:10px 0}summary{cursor:pointer;color:var(--mut)}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
.trend{display:flex;gap:4px;align-items:flex-end;height:64px;margin-top:6px}
.bar{width:16px;display:flex;flex-direction:column-reverse;border-radius:3px;overflow:hidden;background:var(--bd)}
.bar i{display:block}
pre.md{background:var(--code);border:1px solid var(--bd);border-radius:8px;padding:10px;white-space:pre-wrap;max-height:360px;overflow:auto}
footer{margin-top:40px;color:var(--mut);font-size:12.5px}
"""

STATUS_TEXT = {"pass": "OK", "warn": "REVIEW", "fail": "ACTION", "error": "ERROR", "missing": "NOT RUN"}


def _ago(t: datetime | None, now: datetime) -> str:
    if t is None:
        return "unknown time"
    s = int((now - t).total_seconds())
    if s < 0:
        return t.strftime("%Y-%m-%d %H:%M UTC")
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400 * 2:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"


def _fix_html(text: str) -> str:
    """Remediation text with `backticked` commands as one-click-select boxes."""
    if not text:
        return ""
    parts = re.split(r"`([^`]+)`", text)
    prose, cmds = [], []
    for i, p in enumerate(parts):
        if i % 2:
            prose.append(f"<code>{e(p)}</code>")
            if len(p) > 12 and (" " in p or "/" in p):
                cmds.append(p)
        else:
            prose.append(e(p))
    out = "".join(prose)
    for c in cmds:
        out += f'<pre class="cmd" title="click to select">{e(c)}</pre>'
    return out


def _finding_html(f: dict, job: Job, mem: dict, now: datetime) -> str:
    sev = f.get("severity", "info") if f.get("severity") in SEV_RANK else "info"
    rec = mem["seen"].get(_fkey(job.key, f), {})
    first = _parse_time(rec.get("first"))
    new = first is not None and now - first <= NEW_WINDOW
    since = f' · first seen {e(first.strftime("%Y-%m-%d"))}' if first else ""
    rows = [("where", f"<code>{e(f.get('location'))}</code>")]
    if f.get("detail"):
        rows.append(("why", e(f["detail"])))
    if f.get("remediation"):
        rows.append(("fix", _fix_html(f["remediation"])))
    return (f'<div class="f"><h4><span class="pill sev {sev}">{sev.upper()}</span>'
            + ('<span class="pill new">NEW</span>' if new else "")
            + f'<span>{e(f.get("title"))}</span></h4>'
            f'<div class="mut">{e(job.label)} · <code>{e(f.get("rule"))}</code>{since}</div>'
            "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl></div>")


def _rel(p: Path | None, root: Path | None) -> str:
    if p is None:
        return ""
    try:
        return str(p.relative_to(root)) if root else str(p)
    except ValueError:
        return str(p)


def _card(j: Job, now: datetime, root: Path | None = None) -> str:
    st = j.status
    pills = f'<span class="pill {st}">{STATUS_TEXT[st]}</span>'
    if j.stale:
        pills = '<span class="pill stale">STALE</span> ' + pills
    body = e(j.summary) if j.summary else ""
    if j.error:
        body = e(j.error)
    when = (f"last run {e(_ago(j.generated, now))}" + (f' ({e(j.generated.strftime("%Y-%m-%d %H:%M"))} UTC)'
                                                         if j.generated else "")) if j.path else "no report found"
    return (f'<div class="card"><h3><span>{e(j.label)}</span><span>{pills}</span></h3>'
            f"<div>{body}</div><div class='mut' style='margin-top:6px'>{when}</div>"
            + (f"<div class='mut'><code>{e(_rel(j.path, root))}</code></div>" if j.path else "") + "</div>")


def _trend(hist: list[dict]) -> str:
    if len(hist) < 2:
        return ""
    peak = max(1, max(h["counts"].get("critical", 0) + h["counts"].get("high", 0) + h["counts"].get("medium", 0)
                      for h in hist))
    bars = []
    for h in hist:
        c = h["counts"]
        hi = c.get("critical", 0) + c.get("high", 0)
        me = c.get("medium", 0)
        tip = f'{h["when"]}: {h["result"]} · {hi} critical/high · {me} medium'
        bars.append(f'<div class="bar" title="{e(tip)}" style="height:{max(6, int(60 * (hi + me) / peak))}px">'
                    f'<i style="height:{int(100 * hi / max(1, hi + me))}%;background:var(--high)"></i>'
                    f'<i style="height:{int(100 * me / max(1, hi + me))}%;background:var(--med)"></i></div>')
    return ("<h2>Audit trend</h2><div class='mut'>Last " + str(len(hist)) +
            " runs, oldest left. Orange = critical/high, yellow = medium. Hover for details.</div>"
            f"<div class='trend'>{''.join(bars)}</div>")


def _fleet_days(i: dict, now: datetime | None) -> int | None:
    """Days behind, recounted at page-build time from the stored publish date (the fleet job runs once a day)."""
    from .fleet.monitor import behind_for
    if not i.get("releases_behind") or not isinstance(i.get("behind_since"), str):
        return None
    return behind_for(i["behind_since"], now or datetime.now(timezone.utc))[1]


def _fleet_for(i: dict, now: datetime | None) -> str:
    from .fleet.monitor import for_days
    return for_days(_fleet_days(i, now))


def _fleet_html(j: Job) -> str:
    if j.status == "missing":
        return ""
    from .fleet.monitor import short_date
    rows = []
    for i in j.data.get("instances") or []:
        if not isinstance(i, dict):
            continue
        days = _fleet_days(i, j.now)
        since = (f"{days} day{'s' if days != 1 else ''} (since {short_date(i.get('behind_since'))})"
                 if days is not None else "—")
        rows.append(f"<tr><td>{e(i.get('name'))}</td><td>v{e(i.get('version'))}</td>"
                    f"<td>{e(', '.join('v' + str(x) for x in i.get('releases_behind') or []) or '—')}</td>"
                    f"<td>{e(since)}</td>"
                    f"<td>{e(i.get('security_fixes_behind', 0))}</td></tr>")
    latest = j.data.get("latest") or {}
    url = latest.get("url") if isinstance(latest.get("url"), str) else ""
    link = (f' · <a href="{e(url)}" rel="noreferrer noopener">release notes</a>'
            if url.startswith("https://github.com/") else "")
    tip = ""
    if j.status in ("warn", "fail"):
        tip = ("<div class='f'><dl><dt>fix</dt><dd>Upgrade Hermes:"
               "<pre class='cmd'>docker pull nousresearch/hermes-agent:stable</pre>"
               "then recreate the container, or run <code>hermes update</code> on a git install.</dd></dl></div>")
    return (f"<h2>Hermes patch level</h2><div class='mut'>Latest release: v{e(latest.get('version'))} "
            f"({e(latest.get('published'))}){link}</div>"
            "<table><tr><th>instance</th><th>running</th><th>newer releases</th><th>behind for</th>"
            "<th>security fixes missing</th></tr>"
            + "".join(rows) + "</table>" + tip)


def render(jobs: dict[str, Job], *, host: str, now: datetime, mem: dict, history: list[dict],
           state_dir: Path, stale_hours: float) -> str:
    present = [j for j in jobs.values() if j.status != "missing"]
    rank = {"fail": 0, "error": 1, "warn": 2, "pass": 3}
    worst = min((j.status for j in present), key=lambda s: rank.get(s, 9), default="missing")
    stale = [j for j in present if j.stale]
    act, later = [], []
    for key in ("audit", "skills", "inventory"):
        j = jobs.get(key)
        if not j:
            continue
        for f in j.findings:
            if f.get("suppressed"):
                continue
            (act if f.get("severity") in ACT_ON else later).append((j, f))

    def order(item):
        j, f = item
        rec = mem["seen"].get(_fkey(j.key, f), {})
        first = _parse_time(rec.get("first"))
        is_new = first is not None and now - first <= NEW_WINDOW
        return (SEV_RANK.get(f.get("severity"), 9), not is_new, j.key, f.get("title", ""))

    act.sort(key=order)
    later.sort(key=order)
    n_new = sum(1 for j, f in act + later
                if (t := _parse_time(mem["seen"].get(_fkey(j.key, f), {}).get("first"))) and now - t <= NEW_WINDOW)

    headline = {"fail": "Something needs your attention", "error": "A job couldn't produce a result",
                "warn": "Nothing urgent; a few things to review", "pass": "All clear",
                "missing": "No asca reports found yet"}[worst]
    bits = [f"{len(act)} to act on (critical/high/medium)", f"{len(later)} lower-priority"]
    if n_new:
        bits.append(f"{n_new} new since yesterday")
    if stale:
        bits.append("stale: " + ", ".join(j.label for j in stale))

    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>",
         f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
         "<meta name='referrer' content='no-referrer'><meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>asca · {e(host)}</title><style>{STYLE}</style></head><body><main>",
         f"<h1>asca dashboard · {e(host)}</h1>",
         f"<div class='mut'>Generated {e(now.strftime('%Y-%m-%d %H:%M'))} UTC · asca {e(__version__)} · "
         f"reports from <code>{e(state_dir)}</code></div>",
         f"<div class='banner {worst}'><b>{e(headline)}</b><div class='mut'>{e(' · '.join(bits))}</div>"
         + (f"<div style='margin-top:6px'>⚠️ No new report for over {int(stale_hours)} h from: "
            f"{e(', '.join(j.label for j in stale))}. Check that the scheduled job still runs.</div>" if stale else "")
         + "</div>",
         "<div class='cards'>" + "".join(_card(j, now, state_dir) for j in jobs.values()) + "</div>"]

    h.append("<h2>Act on these</h2>")
    if act:
        h += [_finding_html(f, j, mem, now) for j, f in act]
    else:
        h.append("<div class='mut'>Nothing at medium or above. ✅</div>")
    if later:
        h.append(f"<details><summary>Lower-priority findings ({len(later)})</summary>"
                 + "".join(_finding_html(f, j, mem, now) for j, f in later) + "</details>")

    resolved = []
    for k, rec in mem["seen"].items():
        r = _parse_time(rec.get("resolved"))
        if r and now - r <= RESOLVED_SHOW:
            resolved.append((r, rec))
    if resolved:
        resolved.sort(key=lambda x: x[0], reverse=True)
        h.append("<h2>Fixed recently</h2><table><tr><th>gone since</th><th>severity</th><th>finding</th></tr>"
                 + "".join(f"<tr><td>{e(r.strftime('%Y-%m-%d'))}</td><td>{e(rec.get('sev'))}</td>"
                           f"<td>{e(rec.get('title'))}</td></tr>" for r, rec in resolved) + "</table>")

    sup = [(j, f) for key in ("audit", "skills", "inventory") if (j := jobs.get(key))
           for f in j.findings if f.get("suppressed")]
    if sup:
        h.append(f"<details><summary>Accepted in a baseline ({len(sup)})</summary><table>"
                 "<tr><th>finding</th><th>reason</th></tr>"
                 + "".join(f"<tr><td>{e(f.get('title'))}</td><td>{e(f.get('suppress_reason'))}</td></tr>"
                           for j, f in sup) + "</table></details>")

    h.append(_trend(history))
    if "fleet" in jobs:
        h.append(_fleet_html(jobs["fleet"]))
    eg = jobs.get("egress")
    if eg and eg.text:
        h.append(f"<h2>Network egress</h2><pre class='md'>{e(eg.text[:20000])}</pre>")
    h.append("<footer>Static page: no scripts, no network, nothing to log in to. Rebuilt after each scheduled asca "
             "run; to refresh by hand run <code>python3 -m asca dashboard</code>. Reports never contain secret "
             "values, and neither does this page.</footer></main></body></html>")
    return "\n".join(h)


# ------------------------------------------------------------------ output + CLI

def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def default_state_dir() -> Path:
    return Path(os.environ.get("ASCA_STATE") or
                Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "asca")


def build(state_dir: Path, out: Path, *, host: str, stale_hours: float = 26.0,
          now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    paths = discover(state_dir)
    jobs = {k: load(k, paths.get(k), now) for k in CANDIDATES if k in paths}
    for j in jobs.values():
        j.stale = j.generated is not None and (now - j.generated) > timedelta(hours=stale_hours)
    mem = update_memory(out.with_name("dashboard-state.json"), jobs, now)
    page = render(jobs, host=host, now=now, mem=mem, history=audit_history(paths.get("audit")),
                  state_dir=state_dir, stale_hours=stale_hours)
    _write_private(out, page)
    return {"jobs": {k: j.status for k, j in jobs.items()}, "stale": [k for k, j in jobs.items() if j.stale]}


def run(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="asca dashboard", description=__doc__.split("\n\n")[0])
    p.add_argument("--state-dir", type=Path, help="where the asca jobs write their reports "
                   "(default $ASCA_STATE or ~/.local/state/asca)")
    p.add_argument("-o", "--output", type=Path, help="HTML file to write (default <state-dir>/dashboard.html)")
    p.add_argument("--host-label", default=None, help="name shown in the page title (default: hostname)")
    p.add_argument("--stale-hours", type=float, default=26.0,
                   help="flag a job whose newest report is older than this (default 26, for daily jobs)")
    p.add_argument("--quiet", action="store_true", help="print nothing on success (for scheduled wrappers)")
    args = p.parse_args(argv)
    state_dir = (args.state_dir or default_state_dir()).expanduser()
    if not state_dir.is_dir():
        print(f"asca dashboard: no state dir at {state_dir}", file=sys.stderr)
        return 2
    out = (args.output or state_dir / "dashboard.html").expanduser()
    try:
        res = build(state_dir, out, host=args.host_label or socket.gethostname(), stale_hours=args.stale_hours)
    except OSError as exc:
        print(f"asca dashboard: cannot write {out}: {exc}", file=sys.stderr)
        return 2
    if not args.quiet:
        found = ", ".join(f"{k}={v}" for k, v in res["jobs"].items()) or "no reports found"
        print(f"asca dashboard: wrote {out} ({found})")
    return 0
