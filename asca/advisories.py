"""Online vulnerability feeds (OSV.dev + GitHub Advisory Database) and advisory freshness.

Why both feeds *and* the built-in table: feeds are structured and update on their own,
but they lag or miss some advisories entirely. CVE-2026-71963 (GitSpawn in Hermes Agent)
was published by NVD-based trackers on 2026-09-03 and still wasn't in OSV or GHSA a month
later. So the built-in/local tables stay authoritative, the feeds add whatever they know,
and a freshness check makes a stale local table visible instead of silently passing.

Both feeds do range matching server-side (we send the exact installed version), so no
version-range logic is duplicated here. Network use is opt-in (``--online-advisories``):
the query reveals the package name and version to osv.dev / api.github.com.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from .model import Finding, Severity

OSV_URL = "https://api.osv.dev/v1/query"
GHSA_URL = "https://api.github.com/advisories"

# date the built-in HERMES_ADVISORIES table (hermes.py) was last reviewed against public sources
BUILTIN_REVIEWED = "2026-10-06"
STALE_AFTER_DAYS = 30

# package identity per agent; extend to cover more agents
PACKAGES = {
    "hermes-agent": {"osv": ("PyPI", "hermes-agent"), "ghsa": ("pip", "hermes-agent")},
}

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class Advisory:
    ids: set[str]                 # CVE / GHSA / PYSEC aliases
    severity: Severity
    summary: str
    fixed: str = ""
    sources: set[str] = field(default_factory=set)
    url: str = ""

    @property
    def primary(self) -> str:
        cves = sorted(i for i in self.ids if i.startswith("CVE-"))
        return cves[0] if cves else sorted(self.ids)[0]


@dataclass
class FeedResult:
    advisories: list[Advisory]
    errors: list[str]


def _post_json(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "asca"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _get_json(url: str, timeout: float, headers: dict | None = None):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "asca",
                                               **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def query_osv(ecosystem: str, name: str, version: str, timeout: float = 20.0, post=_post_json) -> list[Advisory]:
    data = post(OSV_URL, {"package": {"ecosystem": ecosystem, "name": name}, "version": version}, timeout)
    out = []
    for v in data.get("vulns", []) or []:
        sev_raw = str((v.get("database_specific") or {}).get("severity") or "").lower()
        fixed = ""
        for aff in v.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    fixed = ev.get("fixed", fixed) or fixed
        out.append(Advisory(ids={v["id"], *(v.get("aliases") or [])}, severity=_SEV.get(sev_raw, Severity.MEDIUM),
                            summary=(v.get("summary") or v.get("details") or "")[:300], fixed=fixed,
                            sources={"osv"}, url=f"https://osv.dev/vulnerability/{v['id']}"))
    return out


def query_ghsa(ecosystem: str, name: str, version: str, timeout: float = 20.0, get=_get_json) -> list[Advisory]:
    qs = urllib.parse.urlencode({"ecosystem": ecosystem, "affects": f"{name}@{version}", "per_page": 100})
    headers = {}
    token = os.environ.get("ASCA_GITHUB_TOKEN")  # optional: raises the 60 req/h anonymous limit
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = get(f"{GHSA_URL}?{qs}", timeout, headers)
    out = []
    for a in data or []:
        ids = {a["ghsa_id"]} | ({a["cve_id"]} if a.get("cve_id") else set())
        fixed = ", ".join(sorted({v.get("first_patched_version") or "" for v in a.get("vulnerabilities", [])} - {""}))
        out.append(Advisory(ids=ids, severity=_SEV.get(str(a.get("severity", "")).lower(), Severity.MEDIUM),
                            summary=(a.get("summary") or "")[:300], fixed=fixed, sources={"ghsa"},
                            url=a.get("html_url", "")))
    return out


def merge(advisories: list[Advisory]) -> list[Advisory]:
    """Merge alias-overlapping advisories (GHSA-x == CVE-y == PYSEC-z); keep the highest severity."""
    merged: list[Advisory] = []
    for a in advisories:
        hit = next((m for m in merged if m.ids & a.ids), None)
        if hit is None:
            merged.append(Advisory(set(a.ids), a.severity, a.summary, a.fixed, set(a.sources), a.url))
            continue
        hit.ids |= a.ids
        hit.sources |= a.sources
        if a.severity > hit.severity:
            hit.severity = a.severity
        hit.fixed = hit.fixed or a.fixed
        hit.summary = hit.summary if len(hit.summary) >= len(a.summary) else a.summary
        hit.url = hit.url or a.url
    return merged


def fetch(package: str, version: str, *, timeout: float = 20.0, osv=query_osv, ghsa=query_ghsa) -> FeedResult:
    spec = PACKAGES[package]
    found, errors = [], []
    for label, fn, key in (("osv.dev", osv, "osv"), ("GitHub advisories", ghsa, "ghsa")):
        eco, name = spec[key]
        try:
            found += fn(eco, name, version, timeout)
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{label}: {type(exc).__name__}: {getattr(exc, 'reason', exc)}")
    return FeedResult(merge(found), errors)


def feed_findings(result: FeedResult, *, package: str, version: str, known_ids: set[str],
                  location: str) -> list[Finding]:
    out: list[Finding] = []
    for a in result.advisories:
        if a.ids & known_ids:
            continue  # already reported by the built-in/local table
        aliases = ", ".join(sorted(a.ids - {a.primary}))
        out.append(Finding(
            rule="agent.vulnerable-version", category="integrity", severity=a.severity,
            title=f"{package} {version} is affected by {a.primary}",
            location=location, subject=a.primary,
            detail=f"{a.summary} (aliases: {aliases or '—'}; source: {', '.join(sorted(a.sources))}) {a.url}".strip(),
            remediation=f"Upgrade to {a.fixed} or later." if a.fixed else
                        "No patched version listed yet; follow the advisory's mitigations.",
        ))
    for err in result.errors:
        out.append(Finding(
            rule="scanner.feed-unavailable", category="scanner", severity=Severity.LOW,
            title="Online advisory feed unavailable", location=err.split(":", 1)[0], subject=err.split(":", 1)[0],
            detail=f"{err}. Only built-in/local advisories were checked for this run.",
            remediation="Check network access to osv.dev / api.github.com; set ASCA_GITHUB_TOKEN if rate-limited.",
        ))
    return out


def freshness_findings(*, local_reviewed: str | None, local_path: str | None, today: date | None = None,
                       stale_after: int = STALE_AFTER_DAYS) -> list[Finding]:
    """Flag advisory tables that haven't been reviewed recently. The *newest* review wins:
    a recently reviewed local file covers an older built-in table."""
    today = today or datetime.now(timezone.utc).date()
    dates = [("built-in table", BUILTIN_REVIEWED)]
    if local_reviewed:
        dates.append((local_path or "advisories file", local_reviewed))
    best_label, best = None, None
    for label, d in dates:
        try:
            parsed = date.fromisoformat(d[:10])
        except ValueError:
            continue
        if best is None or parsed > best:
            best_label, best = label, parsed
    if best is None:
        return []
    age = (today - best).days
    if age <= stale_after:
        return []
    return [Finding(
        rule="advisories.stale", category="scanner", severity=Severity.LOW,
        title=f"Advisory list last reviewed {age} days ago",
        location=best_label, subject="advisories",
        detail=f"Newest review: {best.isoformat()} ({best_label}). Advisories published since then that are "
               f"missing from OSV/GitHub feeds would not be detected.",
        remediation="Review recent advisories and update your --advisories file (set its \"reviewed_at\"), "
                    "or update asca.",
    )]
