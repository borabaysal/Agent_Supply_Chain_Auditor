"""Agent hooks set outside any repo: user-level and managed (admin) settings.

Repo-supplied hooks are covered by ``repohooks``. The same hook fields in the user's own settings run in
*every* project, so they're a persistence spot after a workstation compromise (or a ClickFix "fix" script):

| file | fields |
|---|---|
| ``~/.claude/settings.json``, ``settings.local.json`` (``$CLAUDE_CONFIG_DIR``) | ``hooks``, ``statusLine`` |
| Claude Code managed settings (``/Library/Application Support/ClaudeCode/``, ``/etc/claude-code/``, ``C:\\Program Files\\ClaudeCode\\``, ``C:\\ProgramData\\ClaudeCode\\``) | ``hooks``, ``statusLine`` |
| ``~/.cursor/hooks.json`` | ``hooks`` |
| ``~/.gemini/settings.json``, ``/etc/gemini-cli/settings.json`` | ``hooks`` |

People write their own hooks (formatters, notifications), so grading is by what runs (``hookgrade``): HIGH
when the command downloads and runs code, decodes base64 into a shell or opens a raw socket; MEDIUM when it
otherwise talks to a non-local host (a chat webhook, a telemetry POST); INFO for everything else, listed so
you know it exists. On 4,234 hooks from public settings files, that left 0 HIGH (the first draft, which
treated any curl or URL as HIGH, flagged 22, all benign). Downloading and running at start-up is the
SOMBERMEME pattern (a SessionStart hook that downloads a backdoor);
GTIG saw it in committed repo settings, which ``repohooks`` covers, and this covers the same trick at user level.
``apiKeyHelper`` with a network command is already flagged by ``agentcfg``. The inventory keeps a hash of each
hook command (never the text), so a new or changed hook is reported as a change.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import fsutil, hookgrade
from .model import Finding, Severity



def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def targets(home: Path, env: dict | None = None) -> list[tuple[str, Path, str]]:
    """[(client, path, scope)] of user-level and managed settings files that can hold hooks."""
    env = dict(os.environ) if env is None else env
    claude = Path(env["CLAUDE_CONFIG_DIR"]) if env.get("CLAUDE_CONFIG_DIR") else home / ".claude"
    out = [("Claude Code", claude / "settings.json", "user"), ("Claude Code", claude / "settings.local.json", "user"),
           *fsutil.system(("Claude Code", Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
                           "managed"), ("Claude Code", Path("/etc/claude-code/managed-settings.json"), "managed")),
           ("Cursor", home / ".cursor" / "hooks.json", "user"),
           ("Gemini CLI", home / ".gemini" / "settings.json", "user"),
           *fsutil.system(("Gemini CLI", Path("/etc/gemini-cli/settings.json"), "managed"))]
    for var in ("ProgramFiles", "ProgramData"):
        if env.get(var) and not fsutil.HOME_ONLY:
            out.append(("Claude Code", Path(env[var]) / "ClaudeCode" / "managed-settings.json", "managed"))
    return out


def hooks_in(client: str, doc) -> list[tuple[str, str, str]]:
    """[(location-in-file, what, command)] for one parsed settings file."""
    out: list[tuple[str, str, str]] = []
    if not isinstance(doc, dict):
        return out
    hooks = doc.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for gi, g in enumerate(groups if isinstance(groups, list) else []):
                if client == "Cursor":           # hooks.<event>[].command
                    cmd = g.get("command") if isinstance(g, dict) else None
                    if isinstance(cmd, str) and cmd.strip():
                        out.append((f"hooks.{event}[{gi}]", f"{event} hook", cmd))
                    continue
                for hi, h in enumerate((g.get("hooks") if isinstance(g, dict) else None) or []):
                    if isinstance(h, dict) and isinstance(h.get("command"), str) and h["command"].strip():
                        out.append((f"hooks.{event}[{gi}].hooks[{hi}]", f"{event} hook", h["command"]))
    sl = doc.get("statusLine")
    if client == "Claude Code" and isinstance(sl, dict) and isinstance(sl.get("command"), str) and sl["command"].strip():
        out.append(("statusLine", "status line", sl["command"]))
    return out


def collect(home: Path, env: dict | None = None) -> tuple[list[dict], list[Finding]]:
    """All user-level/managed hooks as dicts {client, path, scope, loc, what, cmd}, plus parse errors."""
    found, errors = [], []
    seen: set[str] = set()
    for client, path, scope in targets(home, env):
        key = os.path.normcase(str(path))
        if key in seen or not fsutil.is_file(path):
            continue
        seen.add(key)
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            if client != "Claude Code":          # Claude settings parse errors are reported by agentcfg
                errors.append(Finding(
                    rule="scanner.parse-error", category="scanner", severity=Severity.MEDIUM,
                    title=f"{client} settings unreadable: {path.name}", location=str(path), subject="hooks",
                    detail=f"{type(exc).__name__}: {exc}"[:200] + ". Hooks in it weren't checked (fail closed).",
                    remediation="Fix the file so it can be audited."))
            continue
        for loc, what, cmd in hooks_in(client, doc):
            found.append({"client": client, "path": str(path), "scope": scope, "loc": loc, "what": what, "cmd": cmd})
    return found, errors


def audit(home: Path, stats: dict, env: dict | None = None) -> list[Finding]:
    hooks, out = collect(home, env)
    stats["user_hooks"] = len(hooks)
    for h in hooks:
        sev, why = hookgrade.grade(h["cmd"])
        where = "managed (admin) settings, applied to every user" if h["scope"] == "managed" else "your user settings"
        cmd = h["cmd"]
        out.append(Finding(
            rule="agent.user-hook", category="agent-config", severity=sev,
            title=f"{h['client']} {h['what']} in {'managed' if h['scope'] == 'managed' else 'user'} settings "
                  + {Severity.HIGH: "downloads or runs remote code", Severity.MEDIUM: "talks to the network"}
                  .get(sev, "runs a command"),
            location=f"{h['path']}#{h['loc']}", subject=f"{h['loc']}:{_h(cmd)[:12]}",
            detail=f"`{cmd[:160]}`{'…' if len(cmd) > 160 else ''}. It's in {where}, so it runs in every project, "
                   f"not just one repo."
                   + {Severity.HIGH: f" It {why}: a start-up hook that downloads and runs code is how SOMBERMEME "
                                     f"was delivered (GTIG, Nov 2026).",
                      Severity.MEDIUM: f" It {why}. Fine for a notification you set up; check where the data goes."}
                   .get(sev, " Listed so you know it exists; hooks you wrote yourself are normal."),
            remediation=("If you didn't add it, remove it, then treat the machine as compromised: check what the "
                         "command downloaded and rotate the credentials the agent can reach. If you did add it, "
                         "accept it in the baseline; a changed command is reported again." if sev >= Severity.MEDIUM
                         else
                         "Nothing to do if you added it. The inventory reports it if it changes.")))
    return out
