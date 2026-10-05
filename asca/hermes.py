"""Hermes Agent home-directory checks (HERMES_HOME, usually ~/.hermes or /opt/data).

Covered
- Skills Hub installs (``skills/.hub/lock.json``): source pinning, trust level,
  scanner verdict, and on-disk drift against the recorded content hash.
- Taps (``skills/.hub/taps.json``): third-party catalogs tracked by branch.
- Plugins (``plugins/*``): git checkouts on a moving branch, repo-config sinks.
- Hermes version vs known advisories (CVE-2026-71963 GitSpawn).
- Secrets pasted into config/cron/skills/memories, and credential-file permissions.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import gitconfig, mcp, secrets, yamlmini
from .model import Finding, Severity

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".archive", ".curator_backups",
             "index-cache", ".scan-cache", "quarantine", ".locks"}

# (advisory id, first affected, last affected, fixed-in note, severity, summary)
HERMES_ADVISORIES = [
    ("CVE-2026-71963", (0, 18, 2), (0, 21, 0), "commit f6234d0 / >0.21.0", Severity.CRITICAL,
     "GitSpawn: a repository's .git/config core.fsmonitor runs attacker code when Hermes refreshes git "
     "status — before the workspace-trust prompt, with provider API keys in the environment."),
]


def content_digest(path: Path) -> str:
    """Mirror of Hermes ``tools.skills_guard._content_digest``: SHA-256 over
    (posix relative path + NUL + bytes) for every file, ordered by path string."""
    if not path.is_dir():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    h = hashlib.sha256()
    for rel, p in sorted((p.relative_to(path).as_posix(), p) for p in path.rglob("*") if p.is_file()):
        h.update(rel.encode("utf-8") + b"\x00")
        h.update(p.read_bytes())
    return h.hexdigest()


def _commit_pinned(entry: dict) -> str | None:
    """Return the pinned ref if the lock entry records an immutable commit."""
    candidates = [entry.get(k) for k in ("commit", "sha", "ref", "revision", "resolved_ref")]
    meta = entry.get("metadata") or {}
    candidates += [meta.get(k) for k in ("commit", "sha", "ref", "revision")]
    ident = str(entry.get("identifier", ""))
    if "@" in ident:
        candidates.append(ident.rsplit("@", 1)[1])
    for c in candidates:
        if isinstance(c, str) and re.fullmatch(r"[0-9a-f]{40}", c):
            return c
    return None


def audit_hub(home: Path, stats: dict) -> list[Finding]:
    out: list[Finding] = []
    skills = home / "skills"
    lock = skills / ".hub" / "lock.json"
    if not lock.exists():
        stats["hub_skills"] = 0
        return out
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
        installed = data.get("installed", {})
        if not isinstance(installed, dict):
            raise ValueError("'installed' is not an object")
    except (OSError, ValueError) as exc:
        return [Finding("scanner.parse-error", "scanner", Severity.HIGH, "Skills Hub lock file unreadable",
                        str(lock), detail=f"{exc}. Installed skills could not be audited (fail closed).",
                        remediation="Inspect/repair the lock file.")]
    stats["hub_skills"] = len(installed)
    for name, entry in sorted(installed.items()):
        loc = f"{lock}#installed.{name}"
        source = entry.get("source", "?")
        ident = entry.get("identifier", "")
        trust = entry.get("trust_level", "?")
        pinned = _commit_pinned(entry)
        if source in ("official", "builtin") or trust == "builtin":
            pass  # ships with Hermes; pinned by the Hermes release itself
        elif not pinned:
            sev = Severity.HIGH if trust == "community" else Severity.MEDIUM
            out.append(Finding(
                rule="pin.hub-skill", category="pinning", severity=sev,
                title=f"Hub skill `{name}` is not pinned to a commit",
                location=loc, subject=name,
                detail=f"Installed from `{ident}` (source {source}, trust {trust}). The lock records only a content "
                       f"hash, not an upstream commit, so `hermes skills update` pulls whatever the upstream branch "
                       f"holds at that moment. Community skills can include runnable scripts.",
                remediation="Review the upstream diff before every update; vendor the reviewed copy into a repo you "
                            "control (or a tap pinned to a commit) and install from there.",
            ))
        verdict = str(entry.get("scan_verdict", "")).lower()
        if verdict and verdict not in ("safe", "clean", "pass"):
            out.append(Finding(
                rule="hub.scan-verdict", category="integrity",
                severity=Severity.HIGH if verdict in ("dangerous", "malicious", "block") else Severity.MEDIUM,
                title=f"Hub skill `{name}` was installed despite scanner verdict `{verdict}`",
                location=loc, subject=name, detail="The Skills Guard scan flagged this skill at install time.",
                remediation=f"Re-run the scan and review findings; uninstall `{name}` if unexplained.",
            ))
        install_dir = skills / entry.get("install_path", name)
        recorded = str(entry.get("content_hash", ""))
        if not install_dir.exists():
            out.append(Finding("hub.missing", "integrity", Severity.LOW, f"Hub skill `{name}` missing on disk",
                               loc, name, detail=f"Expected at {install_dir}.",
                               remediation="Reinstall or remove the lock entry."))
        elif recorded.startswith("sha256:"):
            want = recorded.split(":", 1)[1]
            got = content_digest(install_dir)
            if not got.startswith(want):
                out.append(Finding(
                    rule="hub.drift", category="integrity", severity=Severity.MEDIUM,
                    title=f"Hub skill `{name}` changed on disk since install",
                    location=str(install_dir), subject=name,
                    detail=f"Recorded sha256:{want[:16]}, now sha256:{got[:16]}. Either you edited it locally (e.g. "
                           f"skill self-improvement) or something else rewrote it.",
                    remediation="Diff against the upstream copy; if the change is yours, re-record it (reinstall or "
                                "baseline this finding).",
                ))
        elif recorded:
            out.append(Finding("hub.weak-hash", "integrity", Severity.LOW,
                               f"Hub skill `{name}` has an unrecognised content hash", loc, name,
                               detail=f"`{recorded}`", remediation="Reinstall to record a sha256 hash."))
        else:
            out.append(Finding("hub.no-hash", "integrity", Severity.MEDIUM,
                               f"Hub skill `{name}` has no recorded content hash", loc, name,
                               detail="Tampering cannot be detected.", remediation="Reinstall the skill."))
    return out


def audit_taps(home: Path) -> list[Finding]:
    taps_file = home / "skills" / ".hub" / "taps.json"
    if not taps_file.exists():
        return []
    try:
        taps = json.loads(taps_file.read_text(encoding="utf-8")).get("taps", [])
    except (OSError, ValueError, AttributeError) as exc:
        return [Finding("scanner.parse-error", "scanner", Severity.MEDIUM, "taps.json unreadable", str(taps_file),
                        detail=str(exc), remediation="Inspect/repair the file.")]
    out = []
    for t in taps:
        repo = t.get("repo", "?") if isinstance(t, dict) else str(t)
        ref = t.get("ref") if isinstance(t, dict) else None
        if not (isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{40}", ref)):
            out.append(Finding(
                rule="pin.tap", category="pinning", severity=Severity.MEDIUM,
                title=f"Skill tap `{repo}` tracks a moving branch",
                location=str(taps_file), subject=repo,
                detail="Every skill search/install from this tap reads the repo's current default branch.",
                remediation="Only tap repos you control, or fork and tap a reviewed fork.",
            ))
    return out


def audit_plugins(home: Path, stats: dict) -> list[Finding]:
    plugins = home / "plugins"
    out: list[Finding] = []
    count = 0
    if not plugins.is_dir():
        stats["plugins"] = 0
        return out
    for p in sorted(plugins.iterdir()):
        if not p.is_dir() or not ((p / "plugin.yaml").exists() or (p / "__init__.py").exists()):
            continue
        count += 1
        git_dir = p / ".git"
        if git_dir.is_dir():
            head = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip() \
                if (git_dir / "HEAD").exists() else ""
            if head.startswith("ref:"):
                out.append(Finding(
                    rule="pin.plugin-branch", category="pinning", severity=Severity.MEDIUM,
                    title=f"Plugin `{p.name}` is a git checkout on a moving branch",
                    location=str(git_dir / "HEAD"), subject=p.name,
                    detail=f"HEAD → `{head[4:].strip()}`. A `git pull`/update installs whatever upstream pushed; "
                           f"plugins run in-process with full agent privileges.",
                    remediation="Check out a reviewed commit or tag (detached HEAD) and update deliberately.",
                ))
            out.extend(audit_git_dir(git_dir, p))
        else:
            out.append(Finding(
                rule="pin.plugin-untracked", category="pinning", severity=Severity.LOW,
                title=f"Plugin `{p.name}` has no version-control provenance",
                location=str(p), subject=p.name,
                detail="Not a git checkout, so its origin and version cannot be verified.",
                remediation="Install from a pinned commit so provenance is recorded.",
            ))
    stats["plugins"] = count
    return out


def audit_git_dir(git_dir: Path, worktree: Path) -> list[Finding]:
    out: list[Finding] = []
    cfg = git_dir / "config"
    if cfg.exists():
        entries = gitconfig.parse(cfg.read_text(encoding="utf-8", errors="replace"), str(cfg))
        out.extend(gitconfig.audit_entries(entries, scope="repo", repo=worktree))
        out.extend(gitconfig.audit_remote_credentials(entries))
    out.extend(gitconfig.audit_hooks(git_dir))
    return out


def _parse_version(s: str) -> tuple[int, ...] | None:
    m = re.match(r"^\s*v?(\d+)\.(\d+)\.(\d+)", s)
    return tuple(int(x) for x in m.groups()) if m else None


def load_advisories(path: Path) -> list[tuple]:
    """Extra advisories from JSON so users can track new CVEs without a code release:
    [{"id": "CVE-…", "first": "0.18.2", "last": "0.21.0", "fixed": "…", "severity": "critical", "summary": "…"}]"""
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for a in data:
        lo, hi = _parse_version(a["first"]), _parse_version(a["last"])
        if not lo or not hi:
            raise ValueError(f"advisory {a.get('id')}: bad version range")
        out.append((a["id"], lo, hi, a.get("fixed", "see advisory"), Severity.parse(a.get("severity", "high")),
                    a.get("summary", "")))
    return out


def detect_hermes_version(install: Path | None) -> tuple[str | None, str]:
    candidates = []
    if install:
        candidates += [install / "hermes_cli" / "__init__.py", install / "pyproject.toml"]
    for c in candidates:
        try:
            text = c.read_text(encoding="utf-8")
        except OSError:
            continue
        m = re.search(r'^(?:__version__|version)\s*=\s*["\']([^"\']+)["\']', text, re.M)
        if m:
            return m.group(1), str(c)
    return None, ""


def audit_version(install: Path | None, stats: dict, extra_advisories: list[tuple] = ()) -> list[Finding]:
    version, where = detect_hermes_version(install)
    stats["hermes_version"] = version or "unknown"
    if not version:
        return []
    v = _parse_version(version)
    if not v:
        return []
    out = []
    for adv, lo, hi, fixed, sev, summary in [*HERMES_ADVISORIES, *extra_advisories]:
        if lo <= v <= hi:
            out.append(Finding(
                rule="agent.vulnerable-version", category="integrity", severity=sev,
                title=f"Hermes Agent {version} is affected by {adv}",
                location=where, subject=adv, detail=summary,
                remediation=f"Upgrade to a release containing the fix ({fixed}). Until then, do not open "
                            f"repositories you did not clone yourself.",
            ))
    return out


def audit_mcp_config(home: Path, stats: dict) -> list[Finding]:
    cfg = home / "config.yaml"
    if not cfg.exists():
        return []
    try:
        doc = yamlmini.load(cfg.read_text(encoding="utf-8"))
    except (OSError, yamlmini.YamlError) as exc:
        return [Finding("scanner.parse-error", "scanner", Severity.HIGH, "Hermes config.yaml could not be parsed",
                        str(cfg), detail=f"{exc}. MCP servers in it were NOT audited (fail closed).",
                        remediation="Install PyYAML in the auditor's environment or simplify the YAML.")]
    servers = mcp.iter_servers(doc, origin=str(cfg))
    stats["mcp_servers"] = stats.get("mcp_servers", 0) + len(servers)
    out: list[Finding] = []
    for loc, name, spec in servers:
        out.extend(mcp.audit_server(loc, name, spec))
    return out


# text files that should never contain a literal credential
def _secret_scan_targets(home: Path) -> list[tuple[Path, str]]:
    targets: list[tuple[Path, str]] = []
    for name, ctx in (("config.yaml", "Hermes config"), ("SOUL.md", "persona file"),
                      ("cron/jobs.json", "cron job definitions")):
        p = home / name
        if p.is_file():
            targets.append((p, ctx))
    for sub, ctx in (("memories", "agent memory"), ("skills", "skill files"), ("plugins", "plugin files"),
                     ("hooks", "hooks"), ("scripts", "scripts")):
        root = home / sub
        if root.is_dir():
            targets.extend((p, ctx) for p in _walk(root))
    return targets


def _walk(root: Path, limit: int = 20000):
    n = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_symlink():
                continue
            if e.is_dir():
                if e.name not in SKIP_DIRS:
                    stack.append(e)
            elif e.is_file():
                n += 1
                if n > limit:
                    return
                yield e


def audit_secrets(home: Path, stats: dict) -> list[Finding]:
    out: list[Finding] = []
    targets = _secret_scan_targets(home)
    stats["files_scanned_for_secrets"] = stats.get("files_scanned_for_secrets", 0) + len(targets)
    for path, ctx in targets:
        if path.name.startswith(".env") or path.name in secrets.SENSITIVE_FILES:
            continue  # credential stores are expected to hold secrets; checked via permissions
        out.extend(secrets.scan_file(path, context=ctx))
    for name in (".env", "auth.json", "config.yaml", "home/.git-credentials", "home/.netrc", "mcp-tokens"):
        p = home / name
        if p.is_dir():
            for f in _walk(p, 500):
                out.extend(secrets.audit_permissions(f, label=f"{name}/{f.name}"))
        else:
            out.extend(secrets.audit_permissions(p, label=name))
    return out


def audit_skill_install_commands(home: Path) -> list[Finding]:
    """Skill docs/scripts that tell the agent to pipe a remote script into a shell."""
    rx = re.compile(r"\b(?:curl|wget)\b[^\n|]*https?://[^\s|]+[^\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
    out: list[Finding] = []
    root = home / "skills"
    if not root.is_dir():
        return out
    for p in _walk(root):
        if p.suffix.lower() not in (".md", ".sh", ".py", ".txt", ".yaml", ".yml", ""):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                out.append(Finding(
                    rule="pin.skill-curl-pipe-shell", category="pinning", severity=Severity.LOW,
                    title="Skill instructs piping a remote script into a shell",
                    location=f"{p}:{lineno}", subject=p.parent.name,
                    detail="The agent may run this verbatim; the script is fetched unpinned at run time.",
                    remediation="Replace with a pinned release download plus checksum verification.",
                ))
                break
    return out


def audit(home: Path, install: Path | None, stats: dict, extra_advisories: list[tuple] = ()) -> list[Finding]:
    findings: list[Finding] = []
    findings += audit_hub(home, stats)
    findings += audit_taps(home)
    findings += audit_plugins(home, stats)
    findings += audit_version(install, stats, extra_advisories)
    findings += audit_mcp_config(home, stats)
    findings += audit_secrets(home, stats)
    findings += audit_skill_install_commands(home)
    return findings
