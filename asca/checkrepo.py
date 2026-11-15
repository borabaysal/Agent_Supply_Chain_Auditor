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
  ``npm install``; high when they fetch or decode something

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

from . import __version__, ciagent, discover, repohooks, report, symlinks
from .model import Finding, Severity

INSTRUCTION_FILES = ["AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
                     ".clinerules", ".github/copilot-instructions.md"]
INSTRUCTION_DIRS = [".cursor/rules", ".windsurf/rules", ".clinerules", ".claude/commands", ".claude/skills",
                    ".claude/agents", ".agents", ".codex", ".gemini/commands"]
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
MAX_FILES = 400
# a script that runs a file from the repo: `node scripts/x.js`, `sh ./setup.sh`, `python tools/y.py`, `./run`
_LOCAL_FILE = re.compile(r"(?:^|[;&|]\s*|\s)(?:(?:node|bun|deno\s+run|tsx|ts-node|sh|bash|zsh|python3?|ruby|perl)\s+)?"
                         r"((?:\./|[\w.-]+/)[\w./-]+\.(?:c?js|mjs|cjs|ts|mts|sh|py|rb|pl)|\./[\w./-]+)(?=\s|$|[;&|])")
# in that file: runs commands *and* talks to the network, or decodes and evaluates code
_FILE_EXEC = re.compile(r"child_process|\bexecSync\(|\bspawn\(|\bexec\(|subprocess|os\.system", re.I)
_FILE_NET = re.compile(r"https?://|\bfetch\(|\baxios\b|\brequire\(['\"]https?['\"]\)|\burllib|\brequests\.", re.I)
# fetches or pipes to a shell (`node -e`/`python -c` alone are fine: `node -e 'process.exit(0)'`)
_CMD_RISKY = re.compile(r"\b(?:curl|wget|nc|ncat|socat|telnet|scp|osascript|base64|certutil|powershell|iex)\b|"
                        r"/dev/tcp|https?://|\|\s*(?:ba|z|da)?sh\b", re.I)
_INLINE = re.compile(r"\b(?:node|bun)\s+-(?:e|p)\b|\bpython3?\s+-c\b|\b(?:ba|z)?sh\s+-c\b|\bperl\s+-e\b", re.I)
OBFUSCATED = re.compile(r"\b(?:eval|Function)\s*\(|\bBuffer\.from\([^)]*['\"]base64|\batob\(|\\x[0-9a-f]{2}", re.I)


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


def _package_jsons(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP and not d.startswith(".")]
        if Path(dirpath).relative_to(root).parts.__len__() > 3:
            dirnames[:] = []
        if "package.json" in filenames:
            out.append(Path(dirpath) / "package.json")
        if len(out) >= 50:
            break
    return out


def audit_package_scripts(root: Path) -> list[Finding]:
    out = []
    for p in _package_jsons(root):
        try:
            doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        scripts = doc.get("scripts") if isinstance(doc, dict) else None
        if not isinstance(scripts, dict):
            continue
        rel = str(p.relative_to(root))
        for name in LIFECYCLE:
            cmd = scripts.get(name)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            risky = bool(_CMD_RISKY.search(cmd) or OBFUSCATED.search(cmd)
                         or (_INLINE.search(cmd) and (_FILE_EXEC.search(cmd) or _FILE_NET.search(cmd))))
            local = _LOCAL_FILE.search(cmd)
            file_note = ""
            if local and not risky:
                target = (p.parent / local.group(1)).resolve()
                try:
                    inside = target.is_relative_to(root.resolve()) and target.is_file()
                    body = target.read_bytes()[:512 * 1024].decode("utf-8", "replace") if inside else ""
                except OSError:
                    body = ""
                if (_FILE_EXEC.search(body) and _FILE_NET.search(body)) or OBFUSCATED.search(body):
                    risky = True
                    file_note = (f" `{local.group(1)}` both runs commands and reaches the network, or decodes and "
                                 f"evaluates code.")
            sev = Severity.HIGH if risky else Severity.MEDIUM if local else Severity.LOW
            out.append(Finding(
                rule="repo.install-script", category="repo", severity=sev,
                title=f"`npm install` runs a `{name}` script from {rel}",
                location=f"{p}#scripts.{name}", subject=f"{rel}:{name}:{cmd[:80]}",
                detail=(f"`{cmd[:200]}`. npm runs this automatically on install, with your user's access to keys, "
                        f"wallets and browser data."
                        + file_note
                        + (" It fetches, decodes or evaluates something, which is how fake take-home tests have "
                           "delivered malware." if risky else
                           f" It runs `{local.group(1)}` from the repo: read that file before installing."
                           if local else " It looks like a build tool; low risk, listed so you know it runs.")),
                remediation=("Read what the script runs before installing. To install without running scripts: "
                             "`npm install --ignore-scripts`. Better, open and run untrusted repos in a throwaway "
                             "VM or container with no keys in it.")))
    return out


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
    findings += audit_package_scripts(root)
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
