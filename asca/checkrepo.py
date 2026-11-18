"""``asca check-repo PATH``: is this downloaded repo safe to open in an IDE or coding agent?

For take-home tests, interview repos and anything else a stranger asked you to clone. Fake
recruiters have sent developers (crypto and fintech especially) repos that run code the moment
they're opened in an IDE or installed. This runs asca's repo checks on one folder, offline, before
you open it, and prints one verdict.

What runs (all static; nothing in the repo is executed, git is never run):
- git config that runs programs (``core.fsmonitor``, hooks, filters …) and project MCP configs
- IDE / agent hooks that run on open (``.vscode/tasks.json`` folderOpen, ``.claude/settings.json``,
  ``.cursor/hooks.json``, ``.gemini/settings.json``) and saved allow rules
- agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, .github/copilot-instructions.md,
  .claude/ commands and skills …) against the skill-content rules (hidden text, payloads,
  "run this curl", credential access)
- coding agents in ``.github/workflows`` that strangers can trigger
- symlinks that lead out of the repo
- npm lifecycle scripts (``preinstall``/``install``/``postinstall``/``prepare``) that run on
  ``npm install`` (see asca.installhooks), and workflow steps that hand out every secret or the
  Actions runtime token (asca.wfsecrets); wfx stealer indicators are critical

A folder without ``.git`` (a zip) is treated as if every file were committed.
Exit codes: 0 no finding at or above ``--fail-on`` (default medium), 1 there are, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from html import escape
from pathlib import Path

from . import __version__, ciagent, discover, installhooks, repohooks, report, symlinks, wfsecrets
from .model import Finding, Severity

INSTRUCTION_FILES = ["AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
                     ".clinerules", ".github/copilot-instructions.md"]
INSTRUCTION_DIRS = [".cursor/rules", ".windsurf/rules", ".clinerules", ".claude/commands", ".claude/skills",
                    ".claude/agents", ".agents", ".codex", ".gemini/commands"]
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
MAX_FILES = 400


def _instruction_files(root: Path) -> list[Path]:
    out = [root / f for f in INSTRUCTION_FILES if (root / f).is_file()]
    for d in INSTRUCTION_DIRS:
        base = root / d
        if base.is_dir() and not base.is_symlink():
            for p in sorted(base.rglob("*")):
                if p.is_file() and not p.is_symlink() and len(out) < MAX_FILES:
                    out.append(p)
    # nested instruction files in subfolders (monorepos), two levels down
    for name in ("AGENTS.md", "CLAUDE.md", "GEMINI.md"):
        for p in list(root.glob(f"*/{name}")) + list(root.glob(f"*/*/{name}")):
            if not (set(p.relative_to(root).parts) & SKIP) and p not in out:
                out.append(p)
    return out[:MAX_FILES]


def audit_package_scripts(root: Path, git_dir: Path | None = None, assume_committed: bool = False) -> list[Finding]:
    """Every npm lifecycle script, graded (see asca.installhooks)."""
    return installhooks.audit(root, git_dir=git_dir, assume_committed=assume_committed, strict=True)


def audit_instructions(root: Path) -> list[Finding]:
    from .skillscan import official as O, scan as skillscan
    off = O.load()
    out = []
    for p in _instruction_files(root):
        rel = str(p.relative_to(root))
        for h in skillscan.scan_file(p, off):
            out.append(Finding(
                rule=f"repo.instructions.{h.rule}", category=h.category, severity=h.severity,
                title=f"{h.title}: {rel}", location=f"{p}:{h.line}", subject=f"{rel}:{h.rule}:{h.text[:60]}",
                detail=(f"line {h.line}: `{h.text}`. {h.explain} Coding agents load this file automatically when you "
                        f"open the repo with them."),
                remediation="Don't let an agent read this repo until you've checked this line."))
    return out


def check(root: Path, stats: dict | None = None) -> list[Finding]:
    stats = stats if stats is not None else {}
    git_dir = discover.resolve_git_dir(root)
    archive = git_dir is None
    findings: list[Finding] = []
    if git_dir:
        findings += discover.audit_repo(root)
    else:
        for name in (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json"):
            if (root / name).is_file():
                findings += discover.audit_json_mcp(root / name)
    findings += repohooks.audit_repo(root, git_dir, assume_committed=archive)
    findings += ciagent.audit_repo(root, git_dir, stats)
    from . import allowlist
    findings += allowlist.audit_repo(root, git_dir, stats)
    findings += symlinks.audit_tree(root, git_dir=git_dir, stats=stats, assume_committed=archive)
    findings += audit_instructions(root)
    findings += audit_package_scripts(root, git_dir, assume_committed=archive)
    findings += wfsecrets.audit_repo(root, git_dir, assume_committed=archive)
    uniq: dict[str, Finding] = {}
    for f in findings:
        uniq.setdefault(f.fingerprint, f)
    return sorted(uniq.values(), key=lambda f: (-int(f.severity), f.rule, f.location))


def verdict(findings: list[Finding], fail_on: Severity) -> tuple[bool, str]:
    """ok = nothing at or above fail_on. The message has three levels whatever fail_on is."""
    ok = not any(f.severity >= fail_on for f in findings)
    high = [f for f in findings if f.severity >= Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    if high:
        return ok, f"⛔ Don't open this repo in an IDE or coding agent yet: {len(high)} high-risk finding(s)"
    if medium:
        return ok, f"⚠️ Check {len(medium)} item(s) below before you open it or run npm install"
    return ok, "✅ No red flags found by asca's static checks" + (
        f" ({len(findings)} low-risk note(s))" if findings else "")


def run(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="asca check-repo", description=__doc__.split("\n\n")[0])
    p.add_argument("path", type=Path)
    p.add_argument("--fail-on", default="medium", help="severity that makes the verdict 'don't open' (default medium)")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    p.add_argument("--telegram", choices=["never", "always"], default="never", help="send the verdict to Telegram")
    p.add_argument("--telegram-chat")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--host-label", default=socket.gethostname())
    args = p.parse_args(argv)
    root = args.path.expanduser()
    if not root.is_dir():
        print(f"asca check-repo: {root} is not a folder", file=sys.stderr)
        return 2
    try:
        fail_on = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"asca check-repo: {exc}", file=sys.stderr)
        return 2
    findings = check(root.resolve())
    ok, line = verdict(findings, fail_on)
    if args.json:
        print(json.dumps({"tool": "asca check-repo", "version": __version__, "path": str(root), "ok": ok,
                          "verdict": line, "findings": [f.to_dict() for f in findings]}, indent=1))
    else:
        print(line)
        for f in findings[:30]:
            print(f"  [{f.severity.name}] {f.title}\n      {f.location}\n      fix: {f.remediation[:220]}")
        if len(findings) > 30:
            print(f"  … {len(findings) - 30} more (use --json)")
    if args.telegram == "always":
        token, chat = report.resolve_telegram(args.telegram_chat, args.env_file)
        if not token or not chat:
            print("asca check-repo: telegram: missing bot token or chat id", file=sys.stderr)
            return 2
        text = (f"<b>{escape(line)}</b>\n<code>{escape(str(root))}</code> on {escape(args.host_label)}\n"
                + "\n".join(f"• [{f.severity.name}] {escape(f.title)}" for f in findings[:8]))
        sent, desc = report.send_telegram(text[:4000], token=token, chat_id=chat)
        if not sent:
            print(f"asca check-repo: telegram: {desc}", file=sys.stderr)
            return 2
    return 0 if ok else 1
