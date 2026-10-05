"""Repository and generic MCP-client config discovery."""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import gitconfig, hermes, mcp, secrets
from .model import Finding, Severity

MAX_DEPTH = 4


def resolve_git_dir(worktree: Path) -> Path | None:
    dot = worktree / ".git"
    if dot.is_dir():
        return dot
    if dot.is_file():  # worktree / submodule: "gitdir: <path>"
        try:
            line = dot.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        if line.startswith("gitdir:"):
            p = Path(line[7:].strip())
            p = p if p.is_absolute() else (worktree / p)
            return p.resolve() if p.exists() else None
    return None


def find_repos(roots: list[Path]) -> list[Path]:
    """Worktrees under each root (root included), without following symlinks."""
    found: list[Path] = []
    for root in roots:
        root = root.expanduser()
        if not root.is_dir():
            continue
        stack = [(root, 0)]
        while stack:
            d, depth = stack.pop()
            if resolve_git_dir(d):
                found.append(d)
            if depth >= MAX_DEPTH:
                continue
            try:
                children = sorted(d.iterdir())
            except OSError:
                continue
            for c in children:
                if c.is_dir() and not c.is_symlink() and c.name not in hermes.SKIP_DIRS and not c.name.startswith("."):
                    stack.append((c, depth + 1))
    # stable + unique
    seen, uniq = set(), []
    for r in found:
        k = str(r.resolve())
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def audit_repo(worktree: Path) -> list[Finding]:
    git_dir = resolve_git_dir(worktree)
    if not git_dir:
        return []
    out = hermes.audit_git_dir(git_dir, worktree)
    common = git_dir / "commondir"
    if common.is_file():  # linked worktree: shared config lives in the common dir
        try:
            cdir = (git_dir / common.read_text(encoding="utf-8").strip()).resolve()
            out += hermes.audit_git_dir(cdir, worktree)
        except OSError:
            pass
    # project-level MCP configs travel with the repo, so they are attacker-influenced too
    for name in (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"):
        p = worktree / name
        if p.is_file():
            out += audit_json_mcp(p)
    return out


def global_git_configs(env: dict | None = None) -> list[Path]:
    env = env if env is not None else dict(os.environ)
    home = Path(env.get("HOME", str(Path.home())))
    xdg = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    paths = [Path(env["GIT_CONFIG_GLOBAL"])] if env.get("GIT_CONFIG_GLOBAL") else [home / ".gitconfig",
                                                                                   xdg / "git" / "config"]
    if not env.get("GIT_CONFIG_NOSYSTEM"):
        paths.append(Path(env.get("GIT_CONFIG_SYSTEM") or "/etc/gitconfig"))
    return [p for p in paths if p.is_file()]


def audit_global_git(env: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    configs = global_git_configs(env)
    fsmonitor_disabled = False
    for p in configs:
        entries = gitconfig.parse(p.read_text(encoding="utf-8", errors="replace"), str(p))
        out += gitconfig.audit_entries(entries, scope="global")
        out += gitconfig.audit_remote_credentials(entries)
        if any(e.key == "core.fsmonitor" and e.value.strip().lower() in ("false", "0", "no", "off") for e in entries):
            fsmonitor_disabled = True
    if not fsmonitor_disabled:
        out.append(Finding(
            rule="git.global-fsmonitor-default", category="repo-config", severity=Severity.LOW,
            title="Global git config does not disable core.fsmonitor",
            location=str(configs[0]) if configs else "~/.gitconfig", subject="core.fsmonitor",
            detail="Defence in depth only: a repo-local value still overrides the global one, so this does NOT "
                   "protect against GitSpawn by itself — but it removes accidental inheritance.",
            remediation="git config --global core.fsmonitor false",
        ))
    return out


def audit_json_mcp(path: Path) -> list[Finding]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [Finding("scanner.parse-error", "scanner", Severity.MEDIUM, f"MCP config {path.name} unreadable",
                        str(path), detail=f"{exc}. Not audited (fail closed).",
                        remediation="Fix the JSON so it can be audited.")]
    out: list[Finding] = []
    for loc, name, spec in mcp.iter_servers(doc, origin=str(path)):
        out += mcp.audit_server(loc, name, spec)
    return out


def default_client_configs(home: Path) -> list[Path]:
    cands = [home / ".claude.json", home / ".claude" / "settings.json", home / ".cursor" / "mcp.json",
             home / ".codeium" / "windsurf" / "mcp_config.json",
             home / ".config" / "Claude" / "claude_desktop_config.json",
             home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"]
    return [p for p in cands if p.is_file()]


def audit_client_configs(paths: list[Path], stats: dict) -> list[Finding]:
    out: list[Finding] = []
    for p in paths:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        n = len(mcp.iter_servers(doc, origin=str(p))) if doc is not None else 0
        stats["mcp_servers"] = stats.get("mcp_servers", 0) + n
        out += audit_json_mcp(p)
        out += secrets.audit_permissions(p, label=p.name)
    return out
