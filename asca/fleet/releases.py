"""Hermes release feed: fetch GitHub releases and extract the security fixes in each.

Release notes are prose, not structured data, so extraction is deliberately simple:

- bullets under a heading containing "Security Fix" count as **fixes**: the project's
  explicit "these were vulnerabilities" section;
- bullets under any other heading containing "Security" (e.g. "🔒 Security & Reliability")
  count as **hardening**. They're security-relevant, but often defence-in-depth rather
  than a fix for an exploitable bug;
- any bullet naming a CVE or GHSA ID is promoted to a fix, whatever section it's in.

Counts are therefore lower bounds for undisclosed issues and approximate for hardening.
The monitor reports both numbers separately rather than pretending they are the same thing.
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field

REPO = "NousResearch/hermes-agent"
API = "https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"

_VER = re.compile(r"\bv?(\d+)\.(\d+)\.(\d+)\b")
_ADV_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})\b", re.I)
_PR = re.compile(r"#(\d{3,})")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")


@dataclass
class SecurityItem:
    kind: str                  # "fix" | "hardening"
    text: str
    group: str = ""            # bold sub-heading inside the section, if any
    ids: list[str] = field(default_factory=list)   # CVE/GHSA ids
    prs: list[str] = field(default_factory=list)

    def key(self) -> str:
        """Stable identity across runs: first advisory id, else first PR, else text prefix."""
        return (self.ids[0] if self.ids else f"#{self.prs[0]}" if self.prs else self.text[:80]).upper()

    def to_dict(self) -> dict:
        return {"kind": self.kind, "text": self.text, "group": self.group, "ids": self.ids, "prs": self.prs}


@dataclass
class Release:
    version: tuple[int, int, int]
    tag: str
    name: str
    published: str
    url: str
    items: list[SecurityItem] = field(default_factory=list)

    @property
    def vstr(self) -> str:
        return ".".join(map(str, self.version))

    @property
    def fixes(self) -> list[SecurityItem]:
        return [i for i in self.items if i.kind == "fix"]

    @property
    def hardening(self) -> list[SecurityItem]:
        return [i for i in self.items if i.kind == "hardening"]

    def to_dict(self) -> dict:
        return {"version": self.vstr, "tag": self.tag, "name": self.name, "published": self.published,
                "url": self.url, "items": [i.to_dict() for i in self.items]}


def parse_version(s: str) -> tuple[int, int, int] | None:
    m = _VER.search(s or "")
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def release_version(name: str, tag: str) -> tuple[int, int, int] | None:
    """'Hermes Agent v0.21.4 (v2026.9.21)' -> (0,21,4). The calver tag is not the semver."""
    for s in (name, tag):
        v = parse_version(s)
        if v and v[0] < 1000:   # skip calver like 2026.9.21
            return v
    return None


def _clean(line: str) -> str:
    t = _LINK.sub(r"\1", line.strip().lstrip("-*").strip()).replace("**", "")
    t = re.sub(r"\s+", " ", t)
    return t if len(t) <= 220 else t[:219] + "…"


def extract_security(body: str) -> list[SecurityItem]:
    items: list[SecurityItem] = []
    section_kind: str | None = None
    group = ""
    for raw in (body or "").replace("\r", "").split("\n"):
        line = raw.rstrip()
        h = re.match(r"^(#{1,4})\s+(.*)$", line)
        if h:
            title = h.group(2).lower()
            if "security fix" in title or "security advisor" in title or "vulnerabilit" in title:
                section_kind = "fix"
            elif "security" in title:
                section_kind = "hardening"
            else:
                section_kind = None
            group = ""
            continue
        b = re.match(r"^\*\*([^*]{3,80})\*\*\s*$", line.strip())
        if b and section_kind:
            group = b.group(1).strip()
            continue
        is_bullet = re.match(r"^\s{0,3}[-*]\s+\S", line)
        ids = sorted({m.upper() for m in _ADV_ID.findall(line)})
        if is_bullet and (section_kind or ids):
            items.append(SecurityItem(kind="fix" if (section_kind == "fix" or ids) else "hardening",
                                      text=_clean(line), group=group, ids=ids,
                                      prs=sorted(set(_PR.findall(line)), key=int)))
    return items


def parse_releases(payload: list[dict]) -> list[Release]:
    out: dict[tuple, Release] = {}
    for r in payload:
        if r.get("draft") or r.get("prerelease"):
            continue
        v = release_version(r.get("name") or "", r.get("tag_name") or "")
        if not v:
            continue
        rel = Release(version=v, tag=r.get("tag_name", ""), name=r.get("name", ""),
                      published=(r.get("published_at") or "")[:10], url=r.get("html_url", ""),
                      items=extract_security(r.get("body") or ""))
        if v not in out or rel.published > out[v].published:
            out[v] = rel
    return sorted(out.values(), key=lambda x: x.version)


def fetch(repo: str = REPO, *, token: str | None = None, timeout: float = 20.0, max_pages: int = 3,
          get=None) -> list[Release]:
    """All published releases. Raises on network/API errors (the caller decides how loud to be)."""
    get = get or _get_json
    payload: list[dict] = []
    for page in range(1, max_pages + 1):
        chunk = get(API.format(repo=repo, page=page), token, timeout)
        if not isinstance(chunk, list):
            raise ValueError(f"unexpected GitHub response: {str(chunk)[:120]}")
        payload += chunk
        if len(chunk) < 100:
            break
    return parse_releases(payload)


def _get_json(url: str, token: str | None, timeout: float):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "asca-fleet"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))
