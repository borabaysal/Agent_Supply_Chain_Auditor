"""Known vulnerabilities in the coding agents you have installed, not just Hermes
(``agent.vulnerable-version``; ``--no-agent-versions`` to skip).

Installed versions are read from files only; no agent binary is ever run:

| Agent | Where the version comes from |
|---|---|
| Claude Code | ``@anthropic-ai/claude-code/package.json`` in global npm/pnpm/bun/volta/nvm folders and ``~/.claude/local``; the native installer's ``~/.local/share/claude/versions/<version>`` (the one ``~/.local/bin/claude`` links to) |
| Codex | ``@openai/codex/package.json``; Homebrew ``Cellar``/``Caskroom`` ``codex/<version>`` |
| Gemini CLI | ``@google/gemini-cli/package.json``; Homebrew ``gemini-cli/<version>`` |
| goose | Homebrew ``block-goose-cli/<version>`` (the curl installer leaves no version on disk) |
| Claude Desktop | ``Claude.app/Contents/Info.plist`` (macOS) |

Versions are matched against a bundled table (``asca/agentadv_data.py``) built from the GitHub
Advisory Database **and the vendors' own repository advisories**, which don't always reach the
global database or OSV (GHSA-5j29-h97v-84ch for Claude Code and GHSA-r5pp-p5r8-466r for goose
exist only there). With ``--online-advisories`` the same three sources are queried live:
OSV.dev, the GitHub Advisory Database and the vendor's repository advisories.

One finding per installed agent and version, listing every advisory that affects it.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import urllib.error
from pathlib import Path

from . import advisories as adv
from .model import Finding, Severity

AGENTS: dict[str, dict] = {
    "claude-code": {"label": "Claude Code", "npm": "@anthropic-ai/claude-code", "repos": ("anthropics/claude-code",),
                    "repo_packages": {"@anthropic-ai/claude-code", "claude-code"}, "brew": ("claude-code",),
                    "upgrade": "`claude update` (native installer) or `npm install -g @anthropic-ai/claude-code@latest`"},
    "codex": {"label": "Codex CLI", "npm": "@openai/codex", "repos": ("openai/codex",),
              "repo_packages": {"@openai/codex", "codex", "codex-cli"}, "brew": ("codex",),
              "upgrade": "`npm install -g @openai/codex@latest` or `brew upgrade codex`"},
    "gemini-cli": {"label": "Gemini CLI", "npm": "@google/gemini-cli", "repos": ("google-gemini/gemini-cli",),
                   "repo_packages": {"@google/gemini-cli", "gemini-cli"}, "brew": ("gemini-cli",),
                   "upgrade": "`npm install -g @google/gemini-cli@latest` or `brew upgrade gemini-cli`"},
    "goose": {"label": "goose", "npm": None, "repos": ("block/goose",), "repo_packages": {"goose", "goose-cli"},
              "brew": ("block-goose-cli",), "upgrade": "`goose update` or `brew upgrade block-goose-cli`"},
    "claude-desktop": {"label": "Claude Desktop", "npm": None, "repos": ("anthropics/claude-code",),
                       "repo_packages": {"Claude Desktop"}, "brew": (),
                       "upgrade": "Claude menu → Check for Updates, or download it again from claude.ai/download"},
}
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM,
        "low": Severity.LOW}
_VER = re.compile(r"^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


# ------------------------------------------------------------------ versions and ranges

def parse(v: str):
    """Comparable key for semver-ish versions; prereleases sort before the release. None if not a version."""
    m = _VER.match(str(v).strip())
    if not m:
        return None
    core = tuple(int(x) for x in m.group(1).split("."))
    core += (0,) * (4 - len(core))
    pre = m.group(2)
    if not pre:
        return core, (1,)
    return core, (0, *[(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")])


def in_range(version: str, rng: str) -> bool:
    """GitHub-style range: comparators joined by ',' (all must hold), e.g. '>= 2.0.68, < 2.1.260' or '= 0.40.0-preview.2'."""
    v = parse(version)
    if v is None:
        return False
    for part in [p.strip() for p in str(rng).split(",") if p.strip()]:
        m = re.match(r"^(>=|<=|>|<|=)?\s*(\S+)$", part)
        if not m:
            return False
        op, w = m.group(1) or "=", parse(m.group(2))
        if w is None:
            return False
        if not {">=": v >= w, "<=": v <= w, ">": v > w, "<": v < w, "=": v == w}[op]:
            return False
    return True


def _first_version(text: str) -> str:
    m = re.search(r"\d+(?:\.\d+)+(?:-[0-9A-Za-z.-]+)?", str(text))
    return m.group(0) if m else ""


# ------------------------------------------------------------------ installed versions (files only)

def _npm_roots(home: Path, env: dict) -> list[Path]:
    roots = []
    for var in ("NPM_CONFIG_PREFIX", "npm_config_prefix", "PREFIX"):
        if env.get(var):
            roots += [Path(env[var]) / "lib" / "node_modules", Path(env[var]) / "node_modules"]
    roots += [home / ".npm-global" / "lib" / "node_modules", home / ".local" / "lib" / "node_modules",
              Path("/usr/local/lib/node_modules"), Path("/opt/homebrew/lib/node_modules"), Path("/usr/lib/node_modules"),
              home / ".bun" / "install" / "global" / "node_modules", home / ".claude" / "local" / "node_modules"]
    roots += sorted((home / ".nvm" / "versions" / "node").glob("*/lib/node_modules"))
    roots += sorted((home / ".local" / "share" / "pnpm" / "global").glob("*/node_modules"))
    roots += sorted((home / "Library" / "pnpm" / "global").glob("*/node_modules"))
    roots += sorted((home / ".volta" / "tools" / "image" / "packages").glob("*/lib/node_modules"))
    roots += sorted((home / ".local" / "share" / "fnm" / "node-versions").glob("*/installation/lib/node_modules"))
    if env.get("APPDATA"):
        roots.append(Path(env["APPDATA"]) / "npm" / "node_modules")
    return roots


def _brew_dirs() -> list[Path]:
    return [Path(p) for p in ("/opt/homebrew/Cellar", "/opt/homebrew/Caskroom", "/usr/local/Cellar", "/usr/local/Caskroom",
                              "/home/linuxbrew/.linuxbrew/Cellar")]


def _pkg_version(p: Path) -> str | None:
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    v = d.get("version") if isinstance(d, dict) else None
    return v if isinstance(v, str) and parse(v) else None


def installed(home: Path | None = None, env: dict | None = None, brew_dirs: list[Path] | None = None,
              app_dirs: list[Path] | None = None) -> list[dict]:
    """[{agent, version, where}], one per distinct install. Reads files and symlink targets only."""
    home = home or Path.home()
    env = dict(os.environ) if env is None else env
    found: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(agent: str, version: str | None, where: Path) -> None:
        if not version or not parse(version):
            return
        try:
            key = (agent, version, str(where.resolve()))
        except OSError:
            key = (agent, version, str(where))
        if key not in seen:
            seen.add(key)
            found.append({"agent": agent, "version": version, "where": str(where)})

    for root in _npm_roots(home, env):
        for agent, spec in AGENTS.items():
            if spec["npm"]:
                pj = root / spec["npm"] / "package.json"
                if pj.is_file():
                    add(agent, _pkg_version(pj), pj)
    # Claude Code native installer: versions/<version>; the active one is what ~/.local/bin/claude points to
    vdir = home / ".local" / "share" / "claude" / "versions"
    if vdir.is_dir():
        active = None
        link = home / ".local" / "bin" / "claude"
        if link.is_symlink():
            active = Path(os.readlink(link)).name
        names = sorted((p.name for p in vdir.iterdir() if parse(p.name)), key=parse)
        pick = active if active in names else (names[-1] if names else None)
        if pick:
            add("claude-code", pick, vdir / pick)
    for base in (brew_dirs if brew_dirs is not None else _brew_dirs()):
        for agent, spec in AGENTS.items():
            for formula in spec["brew"]:
                d = base / formula
                if d.is_dir():
                    vers = sorted((p.name for p in d.iterdir() if p.is_dir() and parse(p.name.split("_")[0])),
                                  key=lambda n: parse(n.split("_")[0]))
                    if vers:
                        add(agent, vers[-1].split("_")[0], d / vers[-1])
    for apps in (app_dirs if app_dirs is not None else [Path("/Applications"), home / "Applications"]):
        plist = apps / "Claude.app" / "Contents" / "Info.plist"
        try:
            with plist.open("rb") as fh:
                info = plistlib.load(fh)
        except (OSError, plistlib.InvalidFileException, ValueError):
            continue
        if info.get("CFBundleIdentifier", "").startswith("com.anthropic"):
            add("claude-desktop", str(info.get("CFBundleShortVersionString") or ""), plist)
    return found


# ------------------------------------------------------------------ matching

def bundled() -> tuple[str, dict]:
    from . import agentadv_data
    return agentadv_data.REVIEWED_AT, agentadv_data.ADVISORIES


def match(version: str, table: list[dict]) -> list[dict]:
    return [a for a in table if any(in_range(version, r) for r in a.get("ranges") or [])]


def query_repo(repo: str, packages: set[str], version: str, timeout: float = 20.0, get=adv._get_json) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("ASCA_GITHUB_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    data = get(f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published", timeout, headers)
    out = []
    for a in data or []:
        vulns = [v for v in a.get("vulnerabilities") or [] if (v.get("package") or {}).get("name") in packages]
        rngs = [v.get("vulnerable_version_range") for v in vulns if v.get("vulnerable_version_range")]
        if rngs and any(in_range(version, r) for r in rngs):
            out.append({"id": a["ghsa_id"], "cve": a.get("cve_id") or "", "severity": a.get("severity") or "medium",
                        "summary": (a.get("summary") or "")[:200], "ranges": rngs,
                        "fixed": ", ".join(sorted({str(v.get("patched_versions") or "").strip() for v in vulns} - {""})),
                        "source": f"{repo} repository advisory", "url": a.get("html_url", "")})
    return out


def online(agent: str, version: str, *, osv=adv.query_osv, ghsa=adv.query_ghsa, repo=query_repo,
           timeout: float = 20.0) -> tuple[list[dict], list[str]]:
    spec = AGENTS[agent]
    rows, errors = [], []
    calls = []
    if spec["npm"]:
        calls += [("osv.dev", lambda: osv("npm", spec["npm"], version, timeout)),
                  ("GitHub advisories", lambda: ghsa("npm", spec["npm"], version, timeout))]
    for r in spec["repos"]:
        calls.append((f"{r} advisories", lambda r=r: repo(r, spec["repo_packages"], version, timeout)))
    for label, fn in calls:
        try:
            res = fn()
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{label}: {type(exc).__name__}: {getattr(exc, 'reason', exc)}")
            continue
        for a in res:
            if isinstance(a, adv.Advisory):   # OSV / global GHSA results are already filtered by version
                ids = sorted(a.ids)
                ghsa_id = next((i for i in ids if i.startswith("GHSA-")), a.primary)
                cve = next((i for i in ids if i.startswith("CVE-")), "")
                rows.append({"id": ghsa_id, "cve": cve, "aliases": ids, "severity": a.severity.name.lower(),
                             "summary": a.summary[:200], "fixed": a.fixed, "source": ", ".join(sorted(a.sources)),
                             "url": a.url})
            else:
                rows.append(a)
    return rows, errors


def _merge(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for r in rows:
        ids = {r["id"], *(x for x in [r.get("cve")] if x), *r.get("aliases", [])}
        hit = next((o for o in out if o["_ids"] & ids), None)
        if hit is None:
            out.append({**r, "_ids": ids, "sources": {r.get("source", "")}})
            continue
        hit["_ids"] |= ids
        hit["sources"].add(r.get("source", ""))
        if _SEV.get(r.get("severity"), Severity.MEDIUM) > _SEV.get(hit.get("severity"), Severity.MEDIUM):
            hit["severity"] = r["severity"]
        for k in ("cve", "fixed", "url", "summary"):
            hit[k] = hit.get(k) or r.get(k, "")
        if r["id"].startswith("GHSA-") and not hit["id"].startswith("GHSA-"):
            hit["id"] = r["id"]
    return out


def finding(inst: dict, rows: list[dict], reviewed: str) -> Finding:
    spec = AGENTS[inst["agent"]]
    rows = sorted(_merge(rows), key=lambda r: (-int(_SEV.get(r["severity"], Severity.MEDIUM)), r["id"]))
    worst = max(_SEV.get(r["severity"], Severity.MEDIUM) for r in rows)
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    fixes = [f for f in (_first_version(r.get("fixed", "")) for r in rows) if f]
    target = max(fixes, key=parse) if fixes else ""
    unfixed = [r["id"] for r in rows if not _first_version(r.get("fixed", ""))]
    no_cve = sum(1 for r in rows if not r.get("cve"))
    lines = "; ".join(f"{r['id']}{' (' + r['cve'] + ')' if r.get('cve') else ' (no CVE)'} {r['severity']}: "
                      f"{r['summary'][:90]}" for r in rows[:8])
    more = f"; … {len(rows) - 8} more" if len(rows) > 8 else ""
    repo_only = sorted(r["id"] for r in rows if all("repository advisory" in s for s in r["sources"] if s))
    ids_key = hashlib.sha256(",".join(sorted(r["id"] for r in rows)).encode()).hexdigest()[:8]
    return Finding(
        rule="agent.vulnerable-version", category="integrity", severity=worst,
        title=f"{spec['label']} {inst['version']} is affected by {len(rows)} known "
              f"vulnerabilit{'y' if len(rows) == 1 else 'ies'} ("
              + ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda x: -int(_SEV.get(x[0], 0)))) + ")",
        location=inst["where"], subject=f"{inst['agent']}@{inst['version']}:{ids_key}",
        detail=(f"{lines}{more}."
                + (f" {no_cve} of them have no CVE ID." if no_cve else "")
                + (f" Only in the vendor's repository advisories, not in OSV or the global database: "
                   f"{', '.join(repo_only)}." if repo_only else "")
                + f" Version read from {inst['where']} (nothing was run). Table reviewed {reviewed}."),
        remediation=(f"Upgrade {spec['label']} to {target} or later: {spec['upgrade']}." if target else
                     f"Upgrade {spec['label']}: {spec['upgrade']}.")
                    + (f" No fixed version is listed for {', '.join(unfixed[:4])}; follow those advisories' "
                       f"mitigations." if unfixed else ""))


def audit(stats: dict, *, use_online: bool = False, home: Path | None = None, installs: list[dict] | None = None,
          online_fn=online) -> list[Finding]:
    installs = installed(home) if installs is None else installs
    stats["agent_versions"] = {f"{i['agent']}": i["version"] for i in installs}
    reviewed, table = bundled()
    out: list[Finding] = []
    for inst in installs:
        rows = match(inst["version"], table.get(inst["agent"], []))
        if use_online:
            live, errors = online_fn(inst["agent"], inst["version"])
            rows += live
            for err in errors:
                out.append(Finding(rule="scanner.feed-unavailable", category="scanner", severity=Severity.LOW,
                                   title="Online advisory feed unavailable", location=err.split(":", 1)[0],
                                   subject=f"{inst['agent']}:{err.split(':', 1)[0]}",
                                   detail=f"{err}. Only the bundled table (reviewed {reviewed}) was used for "
                                          f"{AGENTS[inst['agent']]['label']}.",
                                   remediation="Check network access to osv.dev / api.github.com; set "
                                               "ASCA_GITHUB_TOKEN if rate-limited."))
        if rows:
            out.append(finding(inst, rows, reviewed))
    return out
