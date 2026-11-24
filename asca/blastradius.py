"""Agent key blast radius: one card per leaked key on the asca dashboard.

A key an agent saw rarely sits in one place: the ``.env`` it read, a dozen transcripts that
echoed it, a "don't ask again" allow rule, an MCP ``env`` block. asca reports each copy as its
own finding; this groups them by the key's hash tag (``sha256:`` + 8 hex, the same tag every
report uses, never the value) and shows, per key:

- the provider and the masked form (4-char prefix and length, as in the reports),
- every place a copy was found, by agent and kind (config, transcripts, allow rule, MCP …),
- how long it has been exposed (earliest first-seen date in the dashboard's memory),
- whether it's **still your live key**: the values in your agents' ``.env`` files are hashed in
  memory and compared with the tags. Values are never written or shown. A key that's still live
  needs rotating; a copy of a rotated key just needs deleting.
- the provider's revoke steps, once.

Keys accepted in a baseline (e.g. "rotated on …") are listed separately, and flagged if the
"rotated" key is in fact still live.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path

from . import respond

TAG = re.compile(r"sha256:([0-9a-f]{8})")
MASK = re.compile(r"(\S{0,8}… \(len=\d+, sha256:[0-9a-f]{8}\))")
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_AGENTS = ((".claude", "Claude Code"), (".codex", "Codex"), (".cursor", "Cursor"), (".gemini", "Gemini CLI"),
           (".openclaw", "OpenClaw"), (".config/goose", "goose"), ("Code/User", "VS Code"), (".hermes", "Hermes"))
_KIND = {"secret.session-history": "transcripts", "secret.agent-allowlist": "allow rule",
         "secret.command-password": "typed into a command", "secret.command-password-private": "typed into a command",
         "secret.git-remote-url": "git remote URL", "secret.mcp-url": "MCP server URL"}
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _agent(text: str) -> str:
    m = re.search(r"\((Hermes|Claude Code|Codex|Cursor|Gemini CLI|OpenClaw|goose)[^)]*\)", text)
    if m:
        return m.group(1)
    hh = os.environ.get("HERMES_HOME")          # a Hermes home outside ~/.hermes (e.g. a container volume)
    if hh and hh.rstrip("/") + "/" in text:
        return "Hermes"
    return next((name for needle, name in _AGENTS if needle in text), "file")


def _kind(f: dict) -> str:
    rule, loc = f.get("rule", ""), f.get("location", "")
    if rule in _KIND:
        return _KIND[rule]
    low = loc.lower()
    if "mcp" in low:
        return "MCP config"
    if low.endswith((".env", "/.env")) or "/.env" in low:
        return ".env file"
    if "/cron/" in low:
        return "cron job"
    if "/memories/" in low:
        return "memory"
    if "/skills/" in low or "/plugins/" in low:
        return "skill or plugin"
    return "config or file"


def _count(f: dict) -> str:
    m = re.search(r"in (\d+) transcript file", f.get("detail", ""))
    return f"{m.group(1)} files" if m else ""


def live_tags(env_files: list[Path]) -> dict[str, str]:
    """tag -> 'VAR in file' for every value in the given .env files. Values stay in memory only."""
    out: dict[str, str] = {}
    for p in env_files:
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for ln in lines:
            m = _ENV_LINE.match(ln)
            if not m:
                continue
            val = m.group(2)
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                val = val[1:-1]
            val = val.strip()
            if len(val) < 12:
                continue
            out.setdefault(hashlib.sha256(val.encode("utf-8")).hexdigest()[:8], f"{m.group(1)} in {p}")
            del val
    return out


def default_env_files(home: Path | None = None) -> list[Path]:
    home = home or Path.home()
    hh = os.environ.get("HERMES_HOME")
    cands = [Path(hh) / ".env"] if hh else []
    cands += [home / ".hermes" / ".env", home / ".openclaw" / ".env", home / ".config" / "goose" / ".env"]
    seen, out = set(), []
    for c in cands:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r not in seen and c.is_file():
            seen.add(r)
            out.append(c)
    return out


def group(jobs: dict, fkey, mem: dict) -> tuple[list[dict], list[dict]]:
    """(active keys, accepted keys). Each key: tag, label, mask, sev, first, places[], steps."""
    keys: dict[tuple[bool, str], dict] = {}
    for jkey in ("audit", "skills", "inventory"):
        j = jobs.get(jkey)
        if not j:
            continue
        for f in j.findings:
            if not str(f.get("rule", "")).startswith("secret."):
                continue
            m = TAG.search(f"{f.get('subject', '')} {f.get('detail', '')}")
            if not m:
                continue
            accepted = bool(f.get("suppressed"))
            k = keys.setdefault((accepted, m.group(1)), {"tag": m.group(1), "label": None, "mask": "", "sev": "info",
                                                         "first": None, "places": [], "reason": ""})
            title = f"{f.get('title', '')} {f.get('subject', '')}"
            k["label"] = k["label"] or next((lb for lb in sorted(respond.STEPS, key=len, reverse=True)
                                             if lb.lower() in title.lower()), None) or f.get("title", "secret")
            mm = MASK.search(f.get("detail", ""))
            k["mask"] = k["mask"] or (mm.group(1) if mm else f"sha256:{m.group(1)}")
            if _SEV.get(f.get("severity"), 9) < _SEV.get(k["sev"], 9):
                k["sev"] = f.get("severity")
            first = (mem.get("seen", {}).get(fkey(jkey, f)) or {}).get("first")
            if first and (k["first"] is None or first < k["first"]):
                k["first"] = first
            k["reason"] = k["reason"] or f.get("suppress_reason", "")
            k["places"].append({"agent": _agent(f"{f.get('detail', '')} {f.get('location', '')}"), "kind": _kind(f),
                                "where": f.get("location", ""), "count": _count(f), "job": jkey})
    active = [k for (acc, _), k in keys.items() if not acc]
    accepted = [k for (acc, _), k in keys.items() if acc and (False, k["tag"]) not in keys]
    for k in active + accepted:
        k["steps"] = respond.STEPS.get(k["label"], "")
    active.sort(key=lambda k: (_SEV.get(k["sev"], 9), -len(k["places"])))
    return active, accepted


def render(jobs: dict, fkey, mem: dict, now: datetime, live: dict[str, str], esc, parse_time) -> str:
    active, accepted = group(jobs, fkey, mem)
    if not active and not accepted:
        return ""
    switch = any(f.get("rule") == "host.revoke-switch" and not f.get("suppressed")
                 for j in jobs.values() if j for f in getattr(j, "findings", []))
    fix_first = ("Remove the delete-on-revoke switch first (see host.revoke-switch), then rotate from a clean device, "
                 "then delete every copy above. " if switch else "Rotate it first, then delete every copy above. ")
    h = ["<h2>Leaked keys: where each one is</h2>",
         "<div class='mut'>Every copy of the same key grouped by its hash tag (never the value). "
         "<b>Still live</b> means the same value is in one of your agents' current .env files: rotate it. "
         "A copy of a key you already rotated only needs deleting.</div>"]
    for k in active:
        first = parse_time(k["first"]) if k["first"] else None
        days = (now - first).days if first else None
        age = (f"exposed {days} day{'s' if days != 1 else ''} (first seen {first.strftime('%Y-%m-%d')})"
               if first else "exposed since before the dashboard started tracking")
        is_live = live.get(k["tag"])
        status = (f"<span class='pill fail'>still live</span> <span class='mut'>{esc(is_live.split(' in ')[0])} "
                  f"in your .env</span>" if is_live else
                  "<span class='pill pass'>not in your current .env</span> <span class='mut'>probably rotated "
                  "already: verify, then delete the copies</span>" if live else
                  "<span class='mut'>no agent .env found to compare</span>")
        agents = sorted({p["agent"] for p in k["places"]})
        rows = "".join(f"<tr><td>{esc(p['agent'])}</td><td>{esc(p['kind'])}{(' · ' + esc(p['count'])) if p['count'] else ''}"
                       f"</td><td><code>{esc(p['where'])}</code></td></tr>" for p in k["places"][:12])
        more = (f"<tr><td colspan='3' class='mut'>… {len(k['places']) - 12} more</td></tr>"
                if len(k["places"]) > 12 else "")
        h.append(f"<div class='f'><h4><span class='pill sev {esc(k['sev'])}'>{esc(k['sev'].upper())}</span>"
                 f"<b>{esc(k['label'])}</b> <code>{esc(k['mask'])}</code></h4>"
                 f"<div>{status}</div>"
                 f"<div class='mut'>{len(k['places'])} place{'s' if len(k['places']) != 1 else ''} across "
                 f"{esc(', '.join(agents))} · {esc(age)}</div>"
                 f"<table><tr><th>agent</th><th>kind</th><th>where</th></tr>{rows}{more}</table>"
                 + (f"<dl><dt>fix</dt><dd>{fix_first if is_live or not live else 'Delete every copy above. '}"
                    f"{esc(k['steps'])}</dd></dl>" if k["steps"] or is_live else "")
                 + "</div>")
    if accepted:
        flagged = [k for k in accepted if live.get(k["tag"])]
        h.append(f"<details{' open' if flagged else ''}><summary>Accepted keys still on disk ({len(accepted)})"
                 + (f" · ⚠️ {len(flagged)} still live" if flagged else "") + "</summary><table>"
                 "<tr><th>key</th><th>places</th><th>live?</th><th>accepted because</th></tr>"
                 + "".join(f"<tr><td>{esc(k['label'])} <code>{esc(k['mask'])}</code></td><td>{len(k['places'])}</td>"
                           f"<td>{'⚠️ still live: ' + esc(live[k['tag']].split(' in ')[0]) if live.get(k['tag']) else ('no' if live else '?')}"
                           f"</td><td>{esc(k['reason'][:160])}</td></tr>" for k in accepted)
                 + "</table></details>")
    return "\n".join(h)
