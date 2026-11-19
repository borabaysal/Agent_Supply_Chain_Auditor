"""macOS privacy grants that hand your whole Mac to agents (``host.tcc-*``). Read-only; macOS only.

Apple says misusing Full Disk Access "puts all of the data on their Mac at risk" and is tightening the
prompt in macOS 27.3. Grants already given stay. And a grant to a **terminal or IDE** is inherited
by every CLI agent started inside it (Claude Code, Codex, Gemini CLI, Hermes …), plus any
``node``/``python`` they run.

asca reads the privacy database (TCC.db, system and user) with sqlite in read-only mode, and the
MDM-pushed grants (``MDMOverrides.plist``), which aren't in TCC.db:

| Finding | Severity |
|---|---|
| ``host.tcc-full-disk``: Full Disk Access for a terminal, IDE, agent app, or a raw ``node``/``python``/agent binary | high |
| ``host.tcc-app-control``: Accessibility (control any app's UI) or Automation of Terminal / System Events for one of those | medium |
| ``host.tcc-unreadable``: the database can't be read | low, never a silent pass |

TCC.db is itself protected: only a process with Full Disk Access can read it. So "unreadable" is the
normal result from a scheduled job, and if asca *can* read it, whatever launched asca has Full Disk
Access (reported in the stats). asca never asks for or changes a permission.
"""
from __future__ import annotations

import plistlib
import sqlite3
import sys
from pathlib import Path

from .model import Finding, Severity

SYSTEM_DB = Path("/Library/Application Support/com.apple.TCC/TCC.db")
MDM_PLIST = Path("/Library/Application Support/com.apple.TCC/MDMOverrides.plist")
FDA = "kTCCServiceSystemPolicyAllFiles"
ACCESSIBILITY = "kTCCServiceAccessibility"
APPLE_EVENTS = "kTCCServiceAppleEvents"
CONTROL_TARGETS = {"com.apple.Terminal", "com.apple.systemevents", "com.googlecode.iterm2", "com.apple.finder"}

TERMINALS = {"com.apple.Terminal": "Terminal", "com.googlecode.iterm2": "iTerm2", "dev.warp.Warp-Stable": "Warp",
             "dev.warp.Warp": "Warp", "com.mitchellh.ghostty": "Ghostty", "net.kovidgoyal.kitty": "kitty",
             "org.alacritty": "Alacritty", "io.alacritty": "Alacritty", "com.github.wez.wezterm": "WezTerm",
             "co.zeit.hyper": "Hyper", "org.tabby": "Tabby", "com.raphaelamorim.rio": "Rio"}
IDES = {"com.microsoft.VSCode": "VS Code", "com.microsoft.VSCodeInsiders": "VS Code Insiders",
        "com.todesktop.230313mzl4w4u92": "Cursor", "com.exafunction.windsurf": "Windsurf", "dev.zed.Zed": "Zed",
        "com.vscodium": "VSCodium", "com.google.antigravity": "Antigravity", "com.trae.app": "Trae"}
AGENT_APPS = {"com.anthropic.claudefordesktop": "Claude Desktop", "com.openai.chat": "ChatGPT",
              "com.openai.codex": "Codex app"}
RAW_BINARIES = ("node", "python", "python3", "bun", "deno", "claude", "codex", "gemini", "goose", "hermes", "uv", "npx")


def classify(client: str, client_type: int) -> tuple[str, str] | None:
    """(kind, display name) for clients that launch or are agents; None for everything else."""
    if client_type == 1 or client.startswith("/"):
        name = Path(client).name
        if name in RAW_BINARIES or name.startswith("python3."):
            return "binary", client
        return None
    for table, kind in ((TERMINALS, "terminal"), (IDES, "IDE"), (AGENT_APPS, "agent app")):
        if client in table:
            return kind, table[client]
    if client.startswith("com.jetbrains."):
        return "IDE", client.split(".")[-1]
    if "hermes" in client.lower():
        return "agent app", client
    return None


def read_db(path: Path) -> tuple[list[dict] | None, str]:
    """(allowed rows or None, error). Read-only URI; immutable fallback when the WAL can't be created."""
    if not path.exists():
        return [], ""
    last = ""
    for q in ("?mode=ro", "?mode=ro&immutable=1"):
        try:
            con = sqlite3.connect(f"file:{path}{q}", uri=True, timeout=1.0)
            try:
                cols = {r[1] for r in con.execute("PRAGMA table_info(access)")}
                if not cols:
                    return None, "no access table"
                auth = "auth_value" if "auth_value" in cols else "allowed"
                ind = "indirect_object_identifier" if "indirect_object_identifier" in cols else "''"
                rows = con.execute(f"SELECT service, client, client_type, {auth}, {ind} FROM access").fetchall()
            finally:
                con.close()
            # auth_value: 0 denied, 2 allowed, 3 limited; legacy `allowed`: 1
            return [{"service": s, "client": c, "client_type": int(t or 0), "target": i or ""}
                    for s, c, t, a, i in rows if (a == 2 if auth == "auth_value" else a == 1)], ""
        except sqlite3.Error as exc:
            last = f"{type(exc).__name__}: {exc}"
        except OSError as exc:
            last = f"{type(exc).__name__}: {exc}"
    return None, last


def read_mdm(path: Path) -> list[dict]:
    try:
        with path.open("rb") as fh:
            doc = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return []
    out = []
    for client, services in (doc.items() if isinstance(doc, dict) else []):
        for svc, val in (services.items() if isinstance(services, dict) else []):
            entries = val if isinstance(val, list) else [val]
            for v in entries:
                if isinstance(v, dict) and v.get("Allowed") in (True, 1):
                    out.append({"service": svc, "client": str(client), "client_type": 1 if str(client).startswith("/")
                                else 0, "target": str(v.get("AEReceiverIdentifier") or ""), "mdm": True})
    return out


def audit(stats: dict, *, home: Path | None = None, system_db: Path = SYSTEM_DB, mdm_plist: Path = MDM_PLIST,
          force: bool = False) -> list[Finding]:
    if sys.platform != "darwin" and not force:
        return []
    home = home or Path.home()
    user_db = home / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    out: list[Finding] = []
    grants: list[dict] = []
    unreadable = []
    for label, db in (("system", system_db), ("user", user_db)):
        rows, err = read_db(db)
        if rows is None:
            unreadable.append((label, db, err))
        else:
            grants += [{**r, "db": label} for r in rows]
    grants += [{**r, "db": "MDM profile"} for r in read_mdm(mdm_plist)]
    stats["tcc_read"] = [lbl for lbl, db in (("system", system_db), ("user", user_db))
                         if lbl not in {u[0] for u in unreadable} and db.exists()]
    if stats["tcc_read"]:
        stats["tcc_note"] = "asca could read TCC.db, so the app that launched it has Full Disk Access"
    for label, db, err in unreadable:
        out.append(Finding(
            rule="host.tcc-unreadable", category="host", severity=Severity.LOW,
            title=f"Couldn't read the {label} privacy database, so Full Disk Access grants weren't checked",
            location=str(db), subject=f"tcc:{label}",
            detail=f"{err}. TCC.db is protected: only a process with Full Disk Access can read it, which is the "
                   f"normal state for a scheduled job. This is reported so the check never passes silently.",
            remediation="Check by hand: System Settings → Privacy & Security → Full Disk Access, and Accessibility. "
                        "Remove terminals, IDEs and agent apps you don't need there. (Granting Full Disk Access to "
                        "asca's runner just to read this would itself be the risk this check is about.)"))
    fda, control = {}, {}
    for g in grants:
        cls = classify(g["client"], g["client_type"])
        if not cls:
            continue
        if g["service"] == FDA:
            fda.setdefault((cls, g["client"]), set()).add(g["db"])
        elif g["service"] == ACCESSIBILITY or (g["service"] == APPLE_EVENTS and g["target"] in CONTROL_TARGETS):
            what = "Accessibility" if g["service"] == ACCESSIBILITY else f"Automation of {g['target']}"
            control.setdefault((cls, g["client"]), set()).add(f"{what} ({g['db']})")
    stats["tcc_agent_grants"] = len(fda) + len(control)
    for ((kind, name), client), dbs in sorted(fda.items()):
        inherit = (" Every agent you start in it (Claude Code, Codex, Gemini CLI, Hermes …) and every node/python "
                   "script they run inherits that access." if kind in ("terminal", "IDE") else
                   " Anything this binary runs, including agent code and its tools, reads everything." if kind == "binary"
                   else " The agent can read your whole disk whenever it decides to.")
        out.append(Finding(
            rule="host.tcc-full-disk", category="host", severity=Severity.HIGH,
            title=f"{name} ({kind}) has Full Disk Access",
            location=f"TCC {', '.join(sorted(dbs))}", subject=f"tcc:fda:{client}",
            detail=f"Full Disk Access covers Mail, Messages, Safari history, other apps' data, keychains' "
                   f"files and backups.{inherit}" + (" Granted by an MDM profile." if "MDM profile" in dbs else ""),
            remediation=(f"System Settings → Privacy & Security → Full Disk Access: turn off {name}. Give agents "
                         f"access to project folders instead; macOS asks per folder (Documents, Desktop, Downloads)."
                         + (" This grant comes from an MDM profile: ask your IT admin." if "MDM profile" in dbs else ""))))
    for ((kind, name), client), what in sorted(control.items()):
        out.append(Finding(
            rule="host.tcc-app-control", category="host", severity=Severity.MEDIUM,
            title=f"{name} ({kind}) can control other apps",
            location="TCC", subject=f"tcc:control:{client}",
            detail=f"{'; '.join(sorted(what))}. An agent running inside it can click, type and script other apps, "
                   f"including approving its own prompts or running commands in another terminal.",
            remediation=f"System Settings → Privacy & Security → Accessibility / Automation: turn off {name} unless "
                        f"you need it."))
    return out
