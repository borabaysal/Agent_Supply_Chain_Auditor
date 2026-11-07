"""Repo-supplied agent hooks: commands a cloned repo can make your agent or editor run.

A repository can ship settings that execute commands without anyone typing them:
- Claude Code ``.claude/settings.json``: ``hooks`` (SessionStart, PreToolUse, …),
  ``statusLine``, ``apiKeyHelper``, plus ``env`` (e.g. ``ANTHROPIC_BASE_URL``),
  ``permissions`` and ``enableAllProjectMcpServers``;
- Cursor ``.cursor/hooks.json`` (beforeShellExecution, afterFileEdit, …);
- VS Code / Cursor / Windsurf ``.vscode/tasks.json`` tasks with ``"runOn": "folderOpen"``.

A file committed to the repo travels with every clone, so the same command is worse there
than in your own uncommitted ``settings.local.json``. Whether a file is committed is read
from ``.git/index`` as bytes; ``git`` is never run, and neither is any hook.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import agentcfg
from .model import Finding, Severity

MAX_READ = 1024 * 1024
SUSPICIOUS = re.compile(
    r"(\b(curl|wget|nc|ncat|socat|telnet|ssh|scp|osascript|base64|eval|xattr|certutil|powershell|iex)\b|/dev/tcp|"
    r"https?://|\|\s*(ba|z|da)?sh\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\bperl\s+-e\b|\bbash\s+-c\b|\bsh\s+-c\b)", re.I)
FILES = (".claude/settings.json", ".claude/settings.local.json", ".cursor/hooks.json", ".vscode/tasks.json")


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:12]


def _jsonc(text: str):
    """JSON with comments and trailing commas (VS Code tasks.json)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def tracked_paths(git_dir: Path | None, rels) -> set[str]:
    """Which of ``rels`` are in the git index (committed or staged). Reads the index as bytes; no git.

    v2/v3 entries end with a 2-byte flags field (low 12 bits = path length; v3 may add 2 more
    bytes of extended flags) followed by the NUL-terminated path. v4 prefix-compresses paths,
    so there we can't tell and assume "committed", which errs towards the higher severity.
    """
    if not git_dir:
        return set()
    try:
        data = (git_dir / "index").read_bytes()
    except OSError:
        return set()
    if data[:4] != b"DIRC":
        return set()
    if int.from_bytes(data[4:8], "big") >= 4:
        return set(rels)
    return {r for r in rels if _in_index(data, r)}


def _in_index(data: bytes, rel: str) -> bool:
    needle = rel.encode() + b"\x00"
    want = min(len(rel.encode()), 0x0FFF)
    start = 12
    while True:
        i = data.find(needle, start)
        if i < 0:
            return False
        for back in (2, 4):               # flags directly before the path, or flags + extended flags
            if i >= back and int.from_bytes(data[i - back:i - back + 2], "big") & 0x0FFF == want:
                return True
        start = i + 1


def _cmd_finding(rel_loc: str, path: Path, what: str, cmd: str, committed: bool, client: str) -> Finding:
    sus = SUSPICIOUS.search(cmd)
    sev = Severity.HIGH if sus else (Severity.MEDIUM if committed else Severity.LOW)
    where = "committed to the repo, so every clone runs it" if committed else "local to this checkout (not committed)"
    return Finding(
        rule="repo.agent-hook", category="repo", severity=sev,
        title=f"{client} {what} runs a command ({where.split(',')[0]})", location=f"{path}#{rel_loc}",
        subject=f"{rel_loc}:{_h(cmd)}",
        detail=f"`{cmd[:160]}`{'…' if len(cmd) > 160 else ''}. This file is {where}."
               + (f" It uses `{sus.group(0).strip()}`, which is how hooks fetch or send data." if sus else ""),
        remediation="Read the command (and any script it calls) before opening this repo with the agent. Remove "
                    "the hook if you don't need it. Hooks you wrote yourself can be accepted in the baseline; a "
                    "changed command gets a new fingerprint and is reported again.")


def _claude(path: Path, doc: dict, committed: bool) -> list[Finding]:
    out: list[Finding] = []
    hooks = doc.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for gi, g in enumerate(groups if isinstance(groups, list) else []):
                for hi, h in enumerate((g.get("hooks") if isinstance(g, dict) else None) or []):
                    if isinstance(h, dict) and isinstance(h.get("command"), str) and h["command"].strip():
                        out.append(_cmd_finding(f"hooks.{event}[{gi}].hooks[{hi}]", path, f"{event} hook",
                                                h["command"], committed, "Claude Code"))
    sl = doc.get("statusLine")
    if isinstance(sl, dict) and isinstance(sl.get("command"), str) and sl["command"].strip():
        out.append(_cmd_finding("statusLine", path, "status line", sl["command"], committed, "Claude Code"))
    helper = doc.get("apiKeyHelper")
    if isinstance(helper, str) and helper.strip():
        out.append(Finding(
            rule="repo.agent-api-key-helper", category="repo", severity=Severity.HIGH if committed else Severity.MEDIUM,
            title="Repo settings set Claude Code's apiKeyHelper", location=f"{path}#apiKeyHelper",
            subject=f"apiKeyHelper:{_h(helper)}",
            detail=f"`{helper[:120]}` runs to produce the API key Claude Code uses in this repo, so the repo "
                   f"decides which credentials (and account) the agent uses.",
            remediation="Remove it unless your team set this up; credential helpers belong in your user settings."))
    env = doc.get("env")
    if isinstance(env, dict):
        for k in agentcfg.ENDPOINT_ENV:
            v = env.get(k)
            if not isinstance(v, str) or not v.strip():
                continue
            kind = agentcfg.classify_endpoint(v)
            sev = {"relay": Severity.CRITICAL, "unknown": Severity.HIGH if committed else Severity.MEDIUM,
                   "provider": Severity.MEDIUM if committed else Severity.INFO}.get(kind)
            if sev is None:
                continue          # official, local or private endpoints
            out.append(Finding(
                rule="repo.agent-endpoint", category="repo", severity=sev,
                title=f"Repo settings send Claude Code's traffic to {agentcfg._host(v)}", location=f"{path}#env.{k}",
                subject=f"{k}:{agentcfg._host(v)}",
                detail=f"`{k}` in this repo's settings overrides the model endpoint for anyone who opens it. "
                       f"Whoever runs that endpoint sees the code and prompts and controls the replies."
                       + (" The host is on Symantec's list of unauthorized relays." if kind == "relay" else ""),
                remediation="Remove the override from the repo; endpoint choices belong in your user settings."))
    perms = doc.get("permissions")
    if isinstance(perms, dict):
        if perms.get("defaultMode") == "bypassPermissions":
            out.append(Finding(
                rule="repo.agent-permissions", category="repo", severity=Severity.HIGH if committed else Severity.MEDIUM,
                title="Repo settings switch Claude Code to bypassPermissions", location=f"{path}#permissions.defaultMode",
                subject="defaultMode:bypassPermissions",
                detail="Every tool call in this repo runs without asking, including ones a prompt injection asks for.",
                remediation="Remove it; choose permission modes per session instead."))
        allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
        broad = [a for a in allow if isinstance(a, str) and re.fullmatch(r"Bash(\((\*|:\*|\s*)\))?", a.strip())]
        if broad:
            out.append(Finding(
                rule="repo.agent-permissions", category="repo", severity=Severity.MEDIUM if committed else Severity.LOW,
                title="Repo settings pre-approve every shell command", location=f"{path}#permissions.allow",
                subject=f"allow:{','.join(broad)}",
                detail=f"`{broad[0]}` lets the agent run any shell command in this repo without asking.",
                remediation="Allow specific commands instead (e.g. `Bash(npm test)`)."))
    if doc.get("enableAllProjectMcpServers") is True:
        out.append(Finding(
            rule="repo.agent-mcp-autoenable", category="repo", severity=Severity.MEDIUM if committed else Severity.LOW,
            title="Repo settings auto-enable every MCP server in .mcp.json", location=f"{path}#enableAllProjectMcpServers",
            subject="enableAllProjectMcpServers",
            detail="MCP servers defined by the repo start without the usual approval prompt.",
            remediation="Remove it and approve servers one by one."))
    return out


def _cursor_hooks(path: Path, doc: dict, committed: bool) -> list[Finding]:
    out = []
    hooks = doc.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            for i, e in enumerate(entries if isinstance(entries, list) else []):
                cmd = e.get("command") if isinstance(e, dict) else None
                if isinstance(cmd, str) and cmd.strip():
                    out.append(_cmd_finding(f"hooks.{event}[{i}]", path, f"{event} hook", cmd, committed, "Cursor"))
    return out


def _vscode_tasks(path: Path, doc: dict, committed: bool) -> list[Finding]:
    out = []
    tasks = doc.get("tasks")
    for i, t in enumerate(tasks if isinstance(tasks, list) else []):
        if not isinstance(t, dict) or (t.get("runOptions") or {}).get("runOn") != "folderOpen":
            continue
        parts = []
        for scope in (t, t.get("osx"), t.get("linux"), t.get("windows")):
            if isinstance(scope, dict):
                c = scope.get("command")
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, dict) and isinstance(c.get("value"), str):
                    parts.append(c["value"])
                parts += [a if isinstance(a, str) else str((a or {}).get("value", "")) for a in scope.get("args") or []
                          if isinstance(a, (str, dict))]
        cmd = " ".join(p for p in parts if p) or "(no command)"
        out.append(_cmd_finding(f"tasks[{i}]", path, f"task \"{t.get('label', i)}\" on folder open", cmd, committed,
                                "VS Code/Cursor"))
    return out


def audit_repo(worktree: Path, git_dir: Path | None) -> list[Finding]:
    present = [r for r in FILES if (worktree / r).is_file()]
    if not present:
        return []
    tracked = tracked_paths(git_dir, present)
    out: list[Finding] = []
    for rel in present:
        p = worktree / rel
        try:
            if p.stat().st_size > MAX_READ:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            doc = _jsonc(text) if rel.endswith("tasks.json") else json.loads(text)
        except (OSError, ValueError) as exc:
            out.append(Finding(rule="scanner.parse-error", category="scanner", severity=Severity.HIGH,
                               title=f"Couldn't parse {rel}", location=str(p), subject=rel,
                               detail=f"{type(exc).__name__}: {str(exc)[:160]}",
                               remediation="Fix the file; until then its hooks aren't checked."))
            continue
        if not isinstance(doc, dict):
            continue
        committed = rel in tracked
        if rel.startswith(".claude/"):
            out += _claude(p, doc, committed)
        elif rel == ".cursor/hooks.json":
            out += _cursor_hooks(p, doc, committed)
        else:
            out += _vscode_tasks(p, doc, committed)
    return out
