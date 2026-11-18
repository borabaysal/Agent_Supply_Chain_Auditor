"""``asca spend``: a tripwire for stolen AI keys (LLMjacking). Opt-in, online, read-only.

A stolen API key is usually found by its bill: someone runs it hard, often on models you
never use. Run this hourly; it alerts when spend jumps, so you can revoke the key the same day.

**OpenRouter** (any normal key, ``OPENROUTER_API_KEY``): ``GET /api/v1/key`` returns that key's
cumulative ``usage``. asca stores one sample per run (numbers only) and compares today's spend
with the median of the last 7 complete days, and the last hour with a normal day.

**Anthropic** (an **Admin key**, ``ANTHROPIC_ADMIN_KEY``, ``sk-ant-admin01-…``; normal API keys
can't read usage): the Cost API gives daily cost, compared the same way; the Usage API grouped
by API key and model shows an **API key or model that has never been used before** in your
organisation, a common sign of a key being resold.

What it can't do: neither provider reports where requests come from (Anthropic's
``inference_geo`` is where the model ran, not the caller), so there is no "new region" alert.

Keys come from the environment or your agents' ``.env`` files (``--env-file``), are sent only to
their own provider's API host, and are never printed or stored; the state file keeps numbers,
a short hash per key, and Anthropic API key IDs and model names (not secret).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import statistics
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from . import __version__, blastradius, report
from .model import Finding, Severity

OPENROUTER = "https://openrouter.ai/api/v1"
ANTHROPIC = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"
KEEP_DAYS = 9
MIN_HISTORY_DAYS = 3
_ENV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _get(url: str, headers: dict, timeout: float = 20.0):
    for base in (OPENROUTER, ANTHROPIC):
        if url.startswith(base + "/"):
            break
    else:
        raise ValueError(f"refusing to send a key to {url}")
    req = urllib.request.Request(url, headers=headers | {"User-Agent": f"asca/{__version__}"}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:     # noqa: S310 (fixed https hosts)
        return json.load(r)


def _tag(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def find_keys(env_files: list[Path], env: dict | None = None) -> dict[str, str]:
    """{OPENROUTER_API_KEY, ANTHROPIC_ADMIN_KEY, ANTHROPIC_API_KEY} from the environment, then the .env files."""
    env = dict(os.environ) if env is None else env
    want = ("OPENROUTER_API_KEY", "ANTHROPIC_ADMIN_KEY", "ANTHROPIC_API_KEY")
    out = {k: env[k].strip() for k in want if env.get(k, "").strip()}
    for p in env_files:
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for ln in lines:
            m = _ENV.match(ln)
            if m and m.group(1) in want and m.group(1) not in out:
                v = m.group(2).strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                    v = v[1:-1]
                if v:
                    out[m.group(1)] = v
    return out


def _day(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")


def _usage_at(samples: list[dict], t: datetime) -> float | None:
    """Cumulative usage at the last sample taken at or before t."""
    best = None
    for s in samples:
        st = datetime.fromisoformat(s["t"])
        if st <= t and (best is None or st >= datetime.fromisoformat(best["t"])):
            best = s
    return None if best is None else float(best["usage"])


def judge(today_spend: float, daily: list[float], hour_spend: float | None, *, factor: float, min_usd: float,
          max_daily: float | None) -> tuple[Severity | None, str]:
    """(severity, why) for one provider. daily = complete previous days (newest last)."""
    if max_daily is not None and today_spend > max_daily:
        return Severity.HIGH, f"today's spend ${today_spend:.2f} is over your ceiling of ${max_daily:.2f}"
    if len(daily) < MIN_HISTORY_DAYS:
        return None, f"learning: {len(daily)} of {MIN_HISTORY_DAYS} days of history"
    base = statistics.median(daily[-7:])
    if today_spend > max(base * factor, base + min_usd):
        return Severity.HIGH, (f"today's spend ${today_spend:.2f} is {today_spend / base:.1f}× the 7-day median "
                               f"(${base:.2f}/day)" if base > 0 else
                               f"today's spend ${today_spend:.2f} while the last 7 days were $0.00")
    if hour_spend is not None and hour_spend > max(base, min_usd):
        return Severity.HIGH, f"${hour_spend:.2f} in the last hour, more than a normal day (${base:.2f})"
    return None, f"normal: today ${today_spend:.2f}, 7-day median ${base:.2f}/day"


# ------------------------------------------------------------------ OpenRouter

def check_openrouter(key: str, state: dict, now: datetime, opts, get=_get) -> list[Finding]:
    d = get(f"{OPENROUTER}/key", {"Authorization": f"Bearer {key}"})["data"]
    tag = _tag(key)
    st = state.setdefault("openrouter", {}).setdefault(tag, {"samples": []})
    samples = [s for s in st["samples"] if now - datetime.fromisoformat(s["t"]) <= timedelta(days=KEEP_DAYS)]
    usage = float(d.get("usage") or 0.0)
    samples.append({"t": now.isoformat(timespec="seconds"), "usage": usage})
    st["samples"] = samples
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_today = _usage_at(samples[:-1], midnight)
    out: list[Finding] = []
    label = f"OpenRouter key {d.get('label') or tag}"
    if start_today is None:
        st["status"] = "learning: first sample today"
        return out
    today = usage - start_today
    daily = []
    for back in range(7, 0, -1):
        a, b = _usage_at(samples, midnight - timedelta(days=back)), _usage_at(samples, midnight - timedelta(days=back - 1))
        if a is not None and b is not None and b >= a:
            daily.append(b - a)
    hour_ago = _usage_at(samples[:-1], now - timedelta(minutes=55))
    hour = usage - hour_ago if hour_ago is not None else None
    sev, why = judge(today, daily, hour, factor=opts.factor, min_usd=opts.min_usd, max_daily=opts.max_daily_usd)
    st["status"] = why
    if sev:
        out.append(Finding(rule="spend.spike", category="spend", severity=sev,
                           title=f"{label}: spend spike, {why}", location="openrouter.ai/api/v1/key",
                           subject=f"openrouter:{tag}:spike:{_day(now)}",
                           detail=f"Key usage is cumulative ${usage:.2f}. A jump like this is how stolen keys usually "
                                  f"show up (LLMjacking). Check which models ran at https://openrouter.ai/activity.",
                           remediation="If you didn't cause it: delete the key at https://openrouter.ai/settings/keys, "
                                       "create a new one with a credit limit, put it in your agents' .env and restart "
                                       "them. Then find where it leaked (`asca` secret findings, the dashboard's "
                                       "leaked-keys card)."))
    lim, rem = d.get("limit"), d.get("limit_remaining")
    if isinstance(lim, (int, float)) and lim > 0 and isinstance(rem, (int, float)) and rem < 0.1 * lim:
        out.append(Finding(rule="spend.limit-low", category="spend", severity=Severity.MEDIUM,
                           title=f"{label}: ${rem:.2f} of its ${lim:.2f} limit left",
                           location="openrouter.ai/api/v1/key", subject=f"openrouter:{tag}:limit",
                           detail="The key is close to its credit limit; if your agents didn't use that much, someone "
                                  "else did.", remediation="Check https://openrouter.ai/activity, then rotate the key."))
    if lim is None:
        out.append(Finding(rule="spend.no-limit", category="spend", severity=Severity.LOW,
                           title=f"{label} has no credit limit", location="openrouter.ai/api/v1/key",
                           subject=f"openrouter:{tag}:nolimit",
                           detail="A stolen key without a limit can spend your whole balance.",
                           remediation="Set a limit on the key at https://openrouter.ai/settings/keys."))
    return out


# ------------------------------------------------------------------ Anthropic (Admin key)

def _pages(url: str, headers: dict, get) -> list:
    out, page = [], None
    for _ in range(10):
        d = get(url + (f"&page={urllib.parse.quote(page)}" if page else ""), headers)
        out += d.get("data") or []
        if not d.get("has_more") or not d.get("next_page"):
            break
        page = d["next_page"]
    return out


def check_anthropic(key: str, state: dict, now: datetime, opts, get=_get) -> list[Finding]:
    h = {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = (midnight - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (midnight + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cost = _pages(f"{ANTHROPIC}/organizations/cost_report?starting_at={start}&ending_at={end}&limit=31", h, get)
    per_day: dict[str, float] = {}
    for b in cost:
        day = str(b.get("starting_at", ""))[:10]
        # amounts are decimal strings in cents (Cost API docs)
        per_day[day] = per_day.get(day, 0.0) + sum(float(r.get("amount") or 0) for r in b.get("results") or []) / 100
    today_key = _day(now)
    today = per_day.get(today_key, 0.0)
    daily = [per_day[d] for d in sorted(per_day) if d < today_key][-7:]
    out: list[Finding] = []
    st = state.setdefault("anthropic", {})
    sev, why = judge(today, daily, None, factor=opts.factor, min_usd=opts.min_usd, max_daily=opts.max_daily_usd)
    st["status"] = why
    if sev:
        out.append(Finding(rule="spend.spike", category="spend", severity=sev,
                           title=f"Anthropic organisation: spend spike, {why}", location="api.anthropic.com cost_report",
                           subject=f"anthropic:spike:{today_key}",
                           detail="Cost data can lag a few minutes. See which key and model at "
                                  "https://platform.claude.com/usage.",
                           remediation="If you didn't cause it: find the key in the Usage page (group by API key), "
                                       "disable it at https://platform.claude.com/settings/keys, create a new one for "
                                       "your agents, then find where it leaked."))
    usage = _pages(f"{ANTHROPIC}/organizations/usage_report/messages?starting_at={start}&ending_at={end}"
                   f"&bucket_width=1d&limit=31&group_by[]=api_key_id&group_by[]=model", h, get)
    seen_keys, seen_models = set(st.get("seen_keys", [])), set(st.get("seen_models", []))
    first_run = "seen_keys" not in st
    recent_keys, recent_models = set(), set()
    for b in usage:
        recent = str(b.get("starting_at", ""))[:10] == today_key
        for r in b.get("results") or []:
            tokens = sum(int(r.get(k) or 0) for k in ("uncached_input_tokens", "output_tokens", "cache_read_input_tokens"))
            if not tokens:
                continue
            k, m = r.get("api_key_id") or "console/playground", r.get("model") or "?"
            if recent:
                recent_keys.add(k)
                recent_models.add(m)
            else:
                seen_keys.add(k)
                seen_models.add(m)
    if not first_run:
        for k in sorted(recent_keys - seen_keys):
            out.append(Finding(rule="spend.new-key", category="spend", severity=Severity.HIGH,
                               title=f"Anthropic: API key {k} was used today for the first time in 8+ days",
                               location="api.anthropic.com usage_report", subject=f"anthropic:newkey:{k}",
                               detail="A key that suddenly starts working can be one an attacker just created with a "
                                      "stolen Admin key, or an old leaked key being used.",
                               remediation="Check who created the key at https://platform.claude.com/settings/keys; "
                                           "disable it if it isn't yours, and rotate your Admin key."))
        for m in sorted(recent_models - seen_models):
            out.append(Finding(rule="spend.new-model", category="spend", severity=Severity.MEDIUM,
                               title=f"Anthropic: model {m} was used today for the first time in 8+ days",
                               location="api.anthropic.com usage_report", subject=f"anthropic:newmodel:{m}",
                               detail="Key resellers often run the most expensive model. Fine if you just switched.",
                               remediation="Check which API key used it (Usage page, group by API key)."))
    st["seen_keys"] = sorted(seen_keys | recent_keys)
    st["seen_models"] = sorted(seen_models | recent_models)
    return out


# ------------------------------------------------------------------ CLI

def run(argv: list[str], get=_get, now: datetime | None = None) -> int:
    p = argparse.ArgumentParser(prog="asca spend", description=__doc__.split("\n\n")[0])
    p.add_argument("--env-file", action="append", type=Path, default=None, metavar="FILE",
                   help="agent .env to read keys from (repeatable; default: the agents' usual .env files)")
    p.add_argument("--provider", action="append", choices=["openrouter", "anthropic"], default=None)
    p.add_argument("--factor", type=float, default=3.0, help="alert when today is this many times the 7-day median "
                                                             "(default 3)")
    p.add_argument("--min-usd", type=float, default=2.0, help="ignore jumps smaller than this many dollars (default 2)")
    p.add_argument("--max-daily-usd", type=float, help="also alert when a day's spend passes this, even while learning")
    p.add_argument("--state", type=Path, default=Path("~/.local/state/asca/spend.json"))
    p.add_argument("--json", action="store_true")
    p.add_argument("--telegram", choices=["never", "always", "change"], default="never")
    p.add_argument("--telegram-chat")
    p.add_argument("--host-label", default=socket.gethostname())
    args = p.parse_args(argv)
    now = now or datetime.now(timezone.utc)
    env_files = [f.expanduser() for f in args.env_file] if args.env_file else blastradius.default_env_files()
    keys = find_keys(env_files)
    providers = args.provider or ["openrouter", "anthropic"]
    state_path = args.state.expanduser()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    findings: list[Finding] = []
    notes: list[str] = []
    errors: list[str] = []
    checks = []
    if "openrouter" in providers:
        if keys.get("OPENROUTER_API_KEY"):
            checks.append(("OpenRouter", lambda: check_openrouter(keys["OPENROUTER_API_KEY"], state, now, args, get)))
        else:
            notes.append("OpenRouter: no OPENROUTER_API_KEY found")
    if "anthropic" in providers:
        if keys.get("ANTHROPIC_ADMIN_KEY"):
            checks.append(("Anthropic", lambda: check_anthropic(keys["ANTHROPIC_ADMIN_KEY"], state, now, args, get)))
        elif keys.get("ANTHROPIC_API_KEY"):
            notes.append("Anthropic: only a normal API key found; usage needs an Admin key (ANTHROPIC_ADMIN_KEY, "
                         "sk-ant-admin01-…, created at platform.claude.com/settings/admin-keys)")
        elif args.provider:
            notes.append("Anthropic: no ANTHROPIC_ADMIN_KEY found")
    for label, fn in checks:
        try:
            findings += fn()
        except urllib.error.HTTPError as exc:
            errors.append(f"{label}: HTTP {exc.code}" + (" (key rejected or not allowed to read usage)"
                                                         if exc.code in (401, 403) else ""))
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{label}: {type(exc).__name__}")
    status = {k: (v.get("status") if k == "anthropic" else {t: s.get("status") for t, s in v.items()})
              for k, v in state.items() if k in ("openrouter", "anthropic")}
    bad = [f for f in findings if f.severity >= Severity.MEDIUM]
    headline = (f"🚨 AI spend: {len(bad)} warning(s)" if bad else
                "⚠️ AI spend: couldn't check" if errors and len(errors) == len(checks) else
                "✅ AI spend normal" if checks else "ℹ️ AI spend: no provider key to check")
    if args.json:
        print(json.dumps({"tool": "asca spend", "version": __version__, "headline": headline, "status": status,
                          "notes": notes, "errors": errors, "findings": [f.to_dict() for f in findings]}, indent=1))
    else:
        print(headline)
        for f in findings:
            print(f"  [{f.severity.name}] {f.title}\n      fix: {f.remediation[:200]}")
        for prov, s in status.items():
            print(f"  {prov}: {s if isinstance(s, str) else '; '.join(str(x) for x in s.values())}")
        for n in notes + errors:
            print(f"  note: {n}")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(".tmp")
    if args.telegram != "never":
        key = sorted(f.subject for f in bad) + sorted(e.split(":")[0] for e in errors)
        prev = state.get("last_alert_key")
        if args.telegram == "always" or (key != prev and (key or prev)):
            token, chat = report.resolve_telegram(args.telegram_chat, (args.env_file or [None])[0])
            if not token or not chat:
                print("asca spend: telegram: missing bot token or chat id", file=sys.stderr)
                return 2
            text = (f"<b>{escape(headline)}</b> ({escape(args.host_label)})\n"
                    + "\n".join(f"• {escape(f.title)}" for f in bad[:6])
                    + "".join(f"\n• {escape(e)}" for e in errors)
                    + ("" if key or not prev else "\nBack to normal."))
            sent, desc = report.send_telegram(text[:4000], token=token, chat_id=chat)
            if not sent:
                print(f"asca spend: telegram: {desc}", file=sys.stderr)
                return 2
        state["last_alert_key"] = key
    tmp.write_text(json.dumps(state, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(state_path)
    if errors and not findings and len(errors) == len(checks):
        return 2
    return 1 if bad else 0
