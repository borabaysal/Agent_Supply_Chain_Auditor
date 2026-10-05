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


def load_mcp_doc(path: Path):
    """Parse an MCP client config: JSON (most clients), JSONC (VS Code), or TOML (Codex CLI)."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        from . import yamlmini
        doc = yamlmini.load(text)
        if isinstance(doc, dict) and isinstance(doc.get("extensions"), dict):
            # goose: extensions.<name>.{cmd,args,envs,uri}
            return {"mcp_servers": {k: {"command": v.get("cmd"), "args": v.get("args"), "env": v.get("envs"),
                                        "url": v.get("uri"), "enabled": v.get("enabled", True)}
                                    for k, v in doc["extensions"].items() if isinstance(v, dict)}}
        return doc
    if path.suffix == ".toml":
        import tomllib
        doc = tomllib.loads(text)
        # Codex: [mcp_servers.<name>] -> same shape as Hermes, iter_servers handles it
        return doc
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_strip_jsonc(text))


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings (VS Code settings files)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    import re
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def audit_json_mcp(path: Path) -> list[Finding]:
    try:
        doc = load_mcp_doc(path)
    except (OSError, ValueError) as exc:
        return [Finding("scanner.parse-error", "scanner", Severity.MEDIUM, f"MCP config {path.name} unreadable",
                        str(path), detail=f"{exc}. Not audited (fail closed).",
                        remediation="Fix the file so it can be audited.")]
    out: list[Finding] = []
    for loc, name, spec in mcp.iter_servers(doc, origin=str(path)):
        out += mcp.audit_server(loc, name, spec)
    return out


# Well-known MCP client config locations (user-level). Project-level files are found
# per repo by audit_repo. Missing files are simply skipped.
CLIENT_CONFIGS = [
    ".claude.json",                                                    # Claude Code
    ".claude/settings.json",
    ".cursor/mcp.json",                                                # Cursor
    ".codeium/windsurf/mcp_config.json",                               # Windsurf
    ".gemini/settings.json",                                           # Gemini CLI
    ".codex/config.toml",                                              # OpenAI Codex CLI
    ".config/goose/config.yaml",                                       # goose (YAML: parsed via yamlmini)
    ".config/Claude/claude_desktop_config.json",                       # Claude Desktop (Linux)
    "Library/Application Support/Claude/claude_desktop_config.json",   # Claude Desktop (macOS)
    "AppData/Roaming/Claude/claude_desktop_config.json",               # Claude Desktop (Windows)
    ".config/Code/User/mcp.json",                                      # VS Code (Linux)
    "Library/Application Support/Code/User/mcp.json",                  # VS Code (macOS)
    "AppData/Roaming/Code/User/mcp.json",                              # VS Code (Windows)
]


def default_client_configs(home: Path) -> list[Path]:
    return [home / c for c in CLIENT_CONFIGS if (home / c).is_file()]


def audit_client_configs(paths: list[Path], stats: dict) -> list[Finding]:
    out: list[Finding] = []
    for p in paths:
        try:
            doc = load_mcp_doc(p)
        except (OSError, ValueError):
            doc = None
        n = len(mcp.iter_servers(doc, origin=str(p))) if doc is not None else 0
        stats["mcp_servers"] = stats.get("mcp_servers", 0) + n
        out += audit_json_mcp(p)
        out += secrets.audit_permissions(p, label=p.name)
    return out
