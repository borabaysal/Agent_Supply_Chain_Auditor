"""Secrets saved in coding-agent allow lists ("Yes, and don't ask again").

When you approve a command with "don't ask again", Claude Code saves the *literal* command as a
permission rule, e.g. ``Bash(PGPASSWORD=… psql -h db.prod…)``, in
``<project>/.claude/settings.local.json``. Claude Code lists that file in your *global* git
excludes only, never in the repo's ``.gitignore``, so it's easy to commit. Apiiro (Nov 2026)
found 104,185 public copies, 1,122 with a real secret, and many that neither gitleaks nor
TruffleHog flagged, because DB passwords and bearer tokens have no recognisable prefix.

What this reads (as text; nothing is executed, ``git`` is never run):
- Claude Code ``permissions.allow`` / ``ask`` / ``deny`` rules in ``~/.claude/settings*.json``,
  managed settings, every repo's ``.claude/settings*.json``, and older Claude Code's
  per-project ``allowedTools`` in ``~/.claude.json``;
- VS Code (and Insiders, Cursor, Windsurf, VSCodium) agent auto-approve settings, in user
  settings and every repo's ``.vscode/settings.json``: ``chat.tools.terminal.autoApprove`` and
  ``chat.tools.urls.autoApprove`` (https://code.visualstudio.com/docs/agents/run/approvals),
  plus the older ``chat.agent.terminal.allowList`` / ``denyList`` names;
- whether a repo's ``.claude/settings.local.json`` is committed (``.git/index``) or not
  excluded by the repo's own ``.gitignore``, and committed ``.specstory/`` transcripts.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import repohooks, secrets
from .model import Finding, Severity, redact

RULE = "secret.agent-allowlist"
LOCAL_SETTINGS = ".claude/settings.local.json"
VSCODE_APPS = ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium")
TERMINAL_KEYS = ("chat.tools.terminal.autoApprove", "chat.agent.terminal.allowList", "chat.agent.terminal.denyList",
                 "github.copilot.chat.agent.terminal.allowList", "github.copilot.chat.agent.terminal.denyList")
URL_KEYS = ("chat.tools.urls.autoApprove",)
MAX_READ = 2 * 1024 * 1024
MAX_SPECSTORY_FILES = 200

REMEDIATION = (
    "1) Rotate the credential first: removing it doesn't clear git history, forks or clones. "
    "2) If the file is committed: `git rm --cached .claude/settings.local.json` and add `.claude/settings.local.json` "
    "to the repo's .gitignore. "
    "3) Delete the rule (or the auto-approve entry). "
    "4) Keep secrets in environment variables and use `$VAR` in commands, so the saved rule holds no secret. "
    "5) Approve patterns like `Bash(npm run:*)` instead of literal commands.")


def _redacted_rule(text: str, values: list[str]) -> str:
    for v in sorted(values, key=len, reverse=True):
        text = text.replace(v, redact(v))
    return text[:160] + ("…" if len(text) > 160 else "")


def _secrets_in(text: str) -> list[tuple[str, Severity, str, str]]:
    return [(r, sev, label, v) for r, sev, label, v, _ in secrets.iter_line_secrets(text, set())]


def _severity(rule: str) -> Severity:
    if rule == "secret.command-password-private":
        return Severity.MEDIUM         # still a working credential saved in a shareable file
    if rule == "secret.generic-assignment":
        return Severity.MEDIUM
    return Severity.HIGH


def _rule_findings(path: Path, entries: list[tuple[str, str]], client: str, committed: bool) -> list[Finding]:
    """entries: (keypath, rule text)."""
    out: list[Finding] = []
    for keypath, text in entries:
        hits = _secrets_in(text)
        if not hits:
            continue
        shown = _redacted_rule(text, [h[3] for h in hits])
        for rule, _sev, label, value in hits:
            sev = _severity(rule)
            out.append(Finding(
                rule=RULE, category="secrets", severity=sev,
                title=f"{label} saved in a {client} allow rule" + (" (committed to git)" if committed else ""),
                location=f"{path}#{keypath}", subject=f"{label}:{redact(value)}",
                detail=f"`{shown}`. {client} saved this command verbatim when it was approved, and it's re-sent "
                       f"to the model in every session that loads these settings."
                       + (" This file is committed, so everyone with the repo (and every fork) has the secret."
                          if committed else "")
                       + (" The host looks local or private, but the password still works for anyone on that "
                          "network." if rule == "secret.command-password-private" else ""),
                remediation=REMEDIATION))
    return out


def _load(path: Path, jsonc: bool) -> tuple[object | None, Finding | None]:
    try:
        if path.stat().st_size > MAX_READ:
            return None, None
        text = path.read_text(encoding="utf-8", errors="replace")
        return (repohooks._jsonc(text) if jsonc else json.loads(text)), None
    except OSError:
        return None, None
    except ValueError as exc:
        return None, Finding(rule="scanner.parse-error", category="scanner", severity=Severity.HIGH,
                             title=f"Couldn't parse {path.name}", location=str(path), subject=str(path),
                             detail=f"{type(exc).__name__}: {str(exc)[:160]}",
                             remediation="Fix the file; until then its allow rules aren't checked for secrets.")


def claude_entries(doc) -> list[tuple[str, str]]:
    perms = doc.get("permissions") if isinstance(doc, dict) else None
    out = []
    if isinstance(perms, dict):
        for kind in ("allow", "ask", "deny"):
            for i, r in enumerate(perms.get(kind) or []):
                if isinstance(r, str):
                    out.append((f"permissions.{kind}[{i}]", r))
    return out


def vscode_entries(doc) -> list[tuple[str, str]]:
    out = []
    if not isinstance(doc, dict):
        return out
    for key in TERMINAL_KEYS + URL_KEYS:
        val = doc.get(key)
        if isinstance(val, dict):
            for k, v in val.items():
                out.append((f"{key}[{json.dumps(k)[:60]}]", str(k)))
                if isinstance(v, str):
                    out.append((f"{key}[{json.dumps(k)[:60]}].value", v))
        elif isinstance(val, list):
            out += [(f"{key}[{i}]", x) for i, x in enumerate(val) if isinstance(x, str)]
    return out


def audit_settings_file(path: Path, *, kind: str, committed: bool = False) -> list[Finding]:
    doc, err = _load(path, jsonc=(kind == "vscode"))
    if err:
        return [err]
    if doc is None:
        return []
    if kind == "vscode":
        return _rule_findings(path, vscode_entries(doc), "VS Code agent", committed)
    return _rule_findings(path, claude_entries(doc), "Claude Code", committed)


def home_files(home: Path) -> list[tuple[Path, str]]:
    files = [(home / ".claude" / "settings.json", "claude"), (home / ".claude" / "settings.local.json", "claude"),
             (Path("/Library/Application Support/ClaudeCode/managed-settings.json"), "claude"),
             (Path("/etc/claude-code/managed-settings.json"), "claude")]
    for app in VSCODE_APPS:
        for base in (home / "Library" / "Application Support", home / ".config", home / "AppData" / "Roaming"):
            files.append((base / app / "User" / "settings.json", "vscode"))
    for server in (".vscode-server", ".cursor-server", ".windsurf-server"):
        files.append((home / server / "data" / "Machine" / "settings.json", "vscode"))
    return [(p, k) for p, k in files if p.is_file()]


def audit_home(home: Path, stats: dict) -> list[Finding]:
    out: list[Finding] = []
    files = home_files(home)
    for p, kind in files:
        out += audit_settings_file(p, kind=kind)
    legacy = home / ".claude.json"            # older Claude Code: projects.<path>.allowedTools
    if legacy.is_file():
        doc, err = _load(legacy, jsonc=False)
        if err:
            out.append(err)
        elif isinstance(doc, dict) and isinstance(doc.get("projects"), dict):
            entries = []
            for proj, cfg in doc["projects"].items():
                for i, r in enumerate((cfg or {}).get("allowedTools") or [] if isinstance(cfg, dict) else []):
                    if isinstance(r, str):
                        entries.append((f"projects[{json.dumps(proj)[:80]}].allowedTools[{i}]", r))
            out += _rule_findings(legacy, entries, "Claude Code", False)
            files.append((legacy, "claude"))
    stats["agent_allowlist_files"] = stats.get("agent_allowlist_files", 0) + len(files)
    return out


# ------------------------------------------------------------------ .gitignore (subset of git's rules)

def _gi_regex(pat: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out += "/.*"
            i += 3
        elif pat[i] == "*":
            out += "[^/]*"
            i += 1
        elif pat[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pat[i])
            i += 1
    return re.compile(out + r"\Z")


def gitignored(worktree: Path, rel: str) -> bool:
    """Is ``rel`` excluded by the repo's own .gitignore files (root and along the path)?

    Implements the common subset of gitignore: comments, negation, anchoring, directory-only
    patterns, ``*``, ``?`` and ``**``. Global excludes and .git/info/exclude are deliberately
    ignored: they protect only this machine, not the next person who commits.
    """
    parts = rel.split("/")
    ignored = False
    for depth in range(len(parts)):
        base = "/".join(parts[:depth])
        gi = worktree / base / ".gitignore" if base else worktree / ".gitignore"
        try:
            lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        sub = parts[depth:]                         # path relative to this .gitignore
        for raw in lines:
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            if neg:
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.strip("/") if dir_only else line
            anchored = line.startswith("/") or "/" in line
            line = line.lstrip("/")
            rx = _gi_regex(line)
            for k in range(1, len(sub) + 1):        # the item itself or any parent directory
                is_dir = k < len(sub)
                if dir_only and not is_dir:
                    continue
                cand = "/".join(sub[:k]) if anchored else sub[k - 1]
                if rx.match(cand):
                    ignored = not neg
                    break
    return ignored


def audit_repo(worktree: Path, git_dir: Path | None, stats: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    rels = [r for r in (".claude/settings.json", LOCAL_SETTINGS, ".vscode/settings.json") if (worktree / r).is_file()]
    spec_files = []
    spec = worktree / ".specstory"
    if spec.is_dir():
        spec_files = sorted(p for p in spec.rglob("*") if p.is_file())[:MAX_SPECSTORY_FILES]
    spec_rels = [p.relative_to(worktree).as_posix() for p in spec_files]
    tracked = repohooks.tracked_paths(git_dir, rels + spec_rels)
    for rel in rels:
        out += audit_settings_file(worktree / rel, kind="vscode" if rel.startswith(".vscode") else "claude",
                                   committed=rel in tracked)
    local = worktree / LOCAL_SETTINGS
    if LOCAL_SETTINGS in tracked:
        has_secret = any(f.rule == RULE and f.location.startswith(str(local) + "#") for f in out)
        out.append(Finding(
            rule="repo.claude-local-settings-committed", category="secrets",
            severity=Severity.HIGH if has_secret else Severity.MEDIUM,
            title=".claude/settings.local.json is committed to git" + (" and holds a secret" if has_secret else ""),
            location=str(local), subject=LOCAL_SETTINGS,
            detail="This is Claude Code's personal settings file: every \"don't ask again\" approval lands here as "
                   "the literal command. Claude Code adds it to your global git excludes only, so it gets committed "
                   "from machines without that, and every clone and fork gets your approvals"
                   + (", including the secret above." if has_secret else "."),
            remediation=REMEDIATION if has_secret else
            "`git rm --cached .claude/settings.local.json`, add `.claude/settings.local.json` to the repo's "
            ".gitignore, and approve patterns like `Bash(npm run:*)` rather than literal commands."))
    elif (worktree / ".claude").is_dir() and not gitignored(worktree, LOCAL_SETTINGS):
        out.append(Finding(
            rule="repo.claude-local-settings-not-ignored", category="secrets", severity=Severity.LOW,
            title="Repo's .gitignore doesn't exclude .claude/settings.local.json", location=str(worktree / ".gitignore"),
            subject=LOCAL_SETTINGS,
            detail="Claude Code keeps \"don't ask again\" approvals (literal commands, sometimes with passwords) in "
                   ".claude/settings.local.json and excludes it only in your global git config. Anyone whose machine "
                   "lacks that exclude can commit it.",
            remediation="echo '.claude/settings.local.json' >> .gitignore"))
    committed_spec = [r for r in spec_rels if r in tracked]
    if committed_spec:
        out.append(Finding(
            rule="repo.agent-transcripts-committed", category="secrets", severity=Severity.MEDIUM,
            title=f"{len(committed_spec)} agent transcript file(s) committed under .specstory/",
            location=str(spec), subject=f".specstory:{len(committed_spec)}",
            detail="SpecStory saves full agent conversations, including every command and its output. Committed, "
                   f"they're readable by everyone with the repo. Examples: {', '.join(committed_spec[:3])}.",
            remediation="`git rm -r --cached .specstory` and add `.specstory/` to .gitignore; rotate anything the "
                        "secret findings below point at."))
        for p in spec_files:
            if p.relative_to(worktree).as_posix() in tracked:
                out += secrets.scan_file(p, context="a committed agent transcript (.specstory)")
    if stats is not None:
        stats["agent_allowlist_files"] = stats.get("agent_allowlist_files", 0) + len(rels)
    return out
