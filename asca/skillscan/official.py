"""The official list: names that look-alikes are compared against.

Sources, merged in this order (later ones add to earlier ones, nothing is removed):
1. the snapshot bundled with asca (``data/official.json``), so OpenClaw-only hosts and
   machines without Hermes still get a list;
2. a locally installed Hermes: bundled + optional skills, the in-tree plugin catalog
   (``plugin-catalog/*.yaml``, ``removed.yaml``), the MCP catalog (``optional-mcps``);
3. Hermes' cached live plugin catalog (``$HERMES_HOME/cache/plugin-catalog.json``);
4. a list refreshed with ``asca-skills update-official`` (written to the state dir).

"Official" here means *published by the project or human-reviewed into its catalog*:
Hermes builtin/trusted skills, Hermes plugin- and MCP-catalog entries, OpenClaw's bundled
skills and extensions, and the vendors' own app packages. It doesn't mean "safe": catalog
entries are third-party code too. It only means "the name you think you installed".
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .. import yamlmini

DATA = Path(__file__).parent / "data" / "official.json"
SKILLS_INDEX_URL = "https://hermes-agent.nousresearch.com/docs/api/skills-index.json"
PLUGIN_CATALOG_URL = "https://hermes-agent.nousresearch.com/docs/api/plugin-catalog.json"
OPENCLAW_CONTENTS = "https://api.github.com/repos/openclaw/openclaw/contents/{path}"

# Curated app identities: where each agent really comes from. Look-alike packages, repos
# and domains are measured against these; `brands` feed the "<brand>-core" clone rule.
APPS = [
    {"app": "Hermes Agent", "brands": ["hermes-agent", "hermes"],
     "npm": [], "pypi": ["hermes-agent"], "docker": ["nousresearch/hermes-agent"],
     "repos": ["NousResearch/hermes-agent", "NousResearch/hermes-official-plugins"],
     "domains": ["hermes-agent.nousresearch.com", "nousresearch.com", "nousresearch.github.io"]},
    {"app": "OpenClaw", "brands": ["openclaw", "clawhub", "clawdbot", "moltbot"],
     "npm": ["openclaw", "clawhub"], "pypi": [], "docker": [],
     "repos": ["openclaw/openclaw", "openclaw/clawhub"],
     "domains": ["openclaw.ai", "docs.openclaw.ai", "clawhub.ai"],
     "former_names": ["clawdbot", "moltbot"]},
    {"app": "Claude Code", "brands": ["claude-code"], "npm": ["@anthropic-ai/claude-code"], "pypi": [],
     "docker": [], "repos": ["anthropics/claude-code"], "domains": ["anthropic.com", "claude.ai"]},
    {"app": "Codex CLI", "brands": ["codex"], "npm": ["@openai/codex"], "pypi": [], "docker": [],
     "repos": ["openai/codex"], "domains": ["openai.com", "chatgpt.com"]},
    {"app": "Gemini CLI", "brands": ["gemini-cli"], "npm": ["@google/gemini-cli"], "pypi": [], "docker": [],
     "repos": ["google-gemini/gemini-cli"], "domains": ["google.com"]},
    {"app": "goose", "brands": [], "npm": [], "pypi": [], "docker": [], "repos": ["block/goose"],
     "domains": ["block.github.io"]},
]

# Official/reference MCP and SDK packages people commonly install next to an agent.
PACKAGES_NPM = [
    "@modelcontextprotocol/sdk", "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/inspector", "@playwright/mcp", "@anthropic-ai/sdk", "openai", "@google/genai",
]
PACKAGES_PYPI = ["mcp", "fastmcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time", "mcp-server-sqlite",
                 "anthropic", "openai", "google-genai", "hermes-agent"]


@dataclass
class Official:
    skills: dict[str, str] = field(default_factory=dict)          # name -> provenance ("hermes:builtin", …)
    plugins: dict[str, dict] = field(default_factory=dict)         # hermes plugin name -> {repo, tier}
    removed_plugins: dict[str, str] = field(default_factory=dict)  # name -> reason
    openclaw_extensions: set[str] = field(default_factory=set)
    mcp: set[str] = field(default_factory=set)                     # Hermes MCP-catalog entry names
    mcp_hosts: set[str] = field(default_factory=set)
    npm: set[str] = field(default_factory=set)
    pypi: set[str] = field(default_factory=set)
    apps: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def brands(self) -> list[str]:
        return sorted({b for a in self.apps for b in a.get("brands", [])})

    @property
    def domains(self) -> set[str]:
        return {d for a in self.apps for d in a.get("domains", [])} | self.mcp_hosts

    @property
    def repos(self) -> set[str]:
        out = {r.lower() for a in self.apps for r in a.get("repos", [])}
        out |= {_repo_slug(p.get("repo", "")) for p in self.plugins.values() if p.get("repo")}
        return out - {""}

    def to_json(self) -> dict:
        return {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "skills": dict(sorted(self.skills.items())),
                "plugins": dict(sorted(self.plugins.items())), "removed_plugins": self.removed_plugins,
                "openclaw_extensions": sorted(self.openclaw_extensions), "mcp": sorted(self.mcp),
                "mcp_hosts": sorted(self.mcp_hosts), "npm": sorted(self.npm), "pypi": sorted(self.pypi)}

    def merge_json(self, d: dict, label: str) -> None:
        for k, v in (d.get("skills") or {}).items():
            self.skills.setdefault(k, v)
        for k, v in (d.get("plugins") or {}).items():
            self.plugins.setdefault(k, v)
        self.removed_plugins.update(d.get("removed_plugins") or {})
        self.openclaw_extensions |= set(d.get("openclaw_extensions") or [])
        self.mcp |= set(d.get("mcp") or [])
        self.mcp_hosts |= set(d.get("mcp_hosts") or [])
        self.npm |= set(d.get("npm") or [])
        self.pypi |= set(d.get("pypi") or [])
        self.sources.append(label)


def _repo_slug(url: str) -> str:
    m = re.search(r"github\.com[/:]([^/\s]+/[^/\s#?]+?)(?:\.git)?/?$", url or "")
    return m.group(1).lower() if m else (url or "").strip().lower()


def _front_matter_name(skill_md: Path) -> str | None:
    try:
        text = skill_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    try:
        fm = yamlmini.load(text[3:end])
    except Exception:
        return None
    n = fm.get("name") if isinstance(fm, dict) else None
    return str(n).strip() if n else None


def _from_hermes_install(o: Official, install: Path) -> None:
    for sub, prov in (("skills", "hermes:builtin"), ("optional-skills", "hermes:optional")):
        root = install / sub
        if not root.is_dir():
            continue
        for md in root.rglob("SKILL.md"):
            o.skills.setdefault(md.parent.name, prov)
            n = _front_matter_name(md)
            if n:
                o.skills.setdefault(n, prov)
    cat = install / "plugin-catalog"
    if cat.is_dir():
        for y in cat.glob("*.yaml"):
            try:
                d = yamlmini.load(y.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            if y.name == "removed.yaml":
                for r in d.get("removed") or []:
                    if isinstance(r, dict) and r.get("name"):
                        o.removed_plugins[str(r["name"])] = str(r.get("reason", "removed from catalog"))
            elif d.get("name"):
                o.plugins.setdefault(str(d["name"]), {"repo": d.get("repo", ""), "tier": d.get("tier", "")})
    mcps = install / "optional-mcps"
    if mcps.is_dir():
        for m in mcps.glob("*/manifest.yaml"):
            o.mcp.add(m.parent.name)
            try:
                text = m.read_text(encoding="utf-8")
            except OSError:
                continue
            for url in re.findall(r"^\s*url:\s*(\S+)", text, re.M):
                h = urlparse(url).hostname
                if h:
                    o.mcp_hosts.add(h.lower())
    o.sources.append(f"hermes-install:{install}")


def _from_plugin_catalog_json(o: Official, d: dict, label: str) -> None:
    for e in d.get("entries") or d.get("plugins") or []:
        if isinstance(e, dict) and e.get("name"):
            o.plugins.setdefault(str(e["name"]), {"repo": e.get("repo", ""), "tier": e.get("tier", "")})
    for r in d.get("removed") or []:
        if isinstance(r, dict) and r.get("name"):
            o.removed_plugins.setdefault(str(r["name"]), str(r.get("reason", "removed from catalog")))
    o.sources.append(label)


def load(*, hermes_install: Path | None = None, hermes_home: Path | None = None,
         refreshed: Path | None = None, bundled: Path = DATA) -> Official:
    o = Official(apps=APPS, npm=set(PACKAGES_NPM) | {p for a in APPS for p in a["npm"]},
                 pypi=set(PACKAGES_PYPI) | {p for a in APPS for p in a["pypi"]})
    try:
        o.merge_json(json.loads(bundled.read_text(encoding="utf-8")), "bundled-snapshot")
    except (OSError, ValueError):
        pass
    if hermes_install and hermes_install.is_dir():
        _from_hermes_install(o, hermes_install)
    if hermes_home:
        cache = hermes_home / "cache" / "plugin-catalog.json"
        try:
            _from_plugin_catalog_json(o, json.loads(cache.read_text(encoding="utf-8")), f"hermes-cache:{cache}")
        except (OSError, ValueError):
            pass
    if refreshed and refreshed.is_file():
        try:
            o.merge_json(json.loads(refreshed.read_text(encoding="utf-8")), f"refreshed:{refreshed}")
        except (OSError, ValueError):
            pass
    return o


# ------------------------------------------------------------------ refresh from the network

def _get(url: str, timeout: float, token: str | None = None):
    headers = {"User-Agent": "asca-skills", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def refresh(*, timeout: float = 120.0, github_token: str | None = None, get=_get) -> tuple[Official, list[str]]:
    """Build a fresh list from the live sources. Returns (list, errors); partial lists are fine."""
    o = Official()
    errors: list[str] = []
    try:
        idx = get(SKILLS_INDEX_URL, timeout)
        for s in idx.get("skills", []):
            if s.get("trust_level") in ("builtin", "trusted") and s.get("name"):
                o.skills.setdefault(s["name"], f"hermes-index:{s.get('trust_level')}:{s.get('repo', '')}")
    except Exception as exc:
        errors.append(f"skills index: {type(exc).__name__}: {exc}"[:200])
    try:
        _from_plugin_catalog_json(o, get(PLUGIN_CATALOG_URL, timeout), "live-plugin-catalog")
    except Exception as exc:
        errors.append(f"plugin catalog: {type(exc).__name__}: {exc}"[:200])
    for path, kind in (("skills", "skill"), ("extensions", "ext")):
        try:
            for e in get(OPENCLAW_CONTENTS.format(path=path), timeout, github_token):
                if e.get("type") == "dir" and not e["name"].startswith("."):
                    if kind == "skill":
                        o.skills.setdefault(e["name"], "openclaw:bundled")
                    else:
                        o.openclaw_extensions.add(e["name"])
        except Exception as exc:
            errors.append(f"openclaw {path}: {type(exc).__name__}: {exc}"[:200])
    return o, errors
