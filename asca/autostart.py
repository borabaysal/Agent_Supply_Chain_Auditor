"""User-level autostart entries, and "delete on revoke" switches (``host.user-autostart``, ``host.revoke-switch``).

Grounding: Socket (Nov 6 2026) on ``strutil-core``, a build of the testmetest worm (Miasma family). It
installs a Python backdoor as a systemd user service or a LaunchAgent, and on the GitHub-token path a monitor
that stores the stolen token in plain text, keeps running after logout (``loginctl enable-linger``), checks
the token against the GitHub API every 45 seconds and runs a home-deleting handler when it gets 401/403.
Revoking the token, the first thing a responder does, is what triggers the wipe. Socket's advice: remove the
persistence first, then revoke and rotate from a clean device.

asca matches the structure, not the worm's names or hashes. It reads (never runs or loads):

- ``~/Library/LaunchAgents/*.plist`` (``Program``/``ProgramArguments``, ``RunAtLoad``, ``KeepAlive``,
  ``StartInterval``),
- ``~/.config/systemd/user/*.service`` (``ExecStart``/``ExecStartPre``/``ExecStartPost``, ``Environment``),
- ``~/.config/autostart/*.desktop`` (``Exec``),
- ``/var/lib/systemd/linger/<user>`` (the user's services keep running after logout).

For each entry that starts an interpreter (python, node, bun, deno, sh/bash/zsh, ruby, perl, osascript) on a
script, or runs a script directly, or passes inline code (``bash -c``), the script text is read:

| Finding | When | Severity |
|---|---|---|
| ``host.revoke-switch`` | the script checks an HTTP 401/403 answer **and** deletes the home folder or ``eval``s a handler | critical |
| ``host.user-autostart`` | script in a hidden folder, ``~/Library`` or a temp folder that calls the GitHub API, downloads and runs code (``curl … | sh``, fetch + exec/subprocess) or deletes the home folder; any entry that deletes the home folder | high |
| ``host.user-autostart`` | those signals from a script elsewhere in your home or inline in the entry; or a hidden-folder script that only talks to a remote host | medium |
| ``host.user-autostart`` | a script elsewhere in your home that only talks to a remote host | low |
| ``host.user-autostart`` | an interpreter script from a hidden or temp folder with none of those signals | info (so you know it starts) |

A switch's token file is located through the paths the script or unit mentions (and ``~/.config/<name>/token``)
and shown redacted. When a switch is found, every finding that tells you to rotate or revoke a credential gets
a warning put in front of its fix: remove the persistence first, then rotate from a clean device.
"""
from __future__ import annotations

import os
import plistlib
import re
import shlex
from pathlib import Path

from . import fsutil
from .model import Finding, Severity, redact

SOCKET = "https://socket.dev/blog/shai-hulud-descendant-malicious-ruby-gem"
MAX_SCRIPT = 1024 * 1024

_INTERP = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|pythonw|node|nodejs|bun|deno|sh|bash|zsh|dash|ksh|fish|ruby|perl"
                     r"|osascript|pwsh)$")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
GITHUB_API = re.compile(r"api\.github\.com")
DOWNLOAD = re.compile(r"\bcurl\b|\bwget\b|urlopen|urllib\.request|\brequests\.(?:get|post)|\bfetch\s*\(|"
                      r"Invoke-WebRequest|http\.client|\bhttpx\.|\baiohttp\b|https?\.get\s*\(")
_HOME_T = r"""["']?(?:~|\$\{?HOME\}?)/?(?:\*|Documents)?["']?(?=\s|;|&|\||$|["'])"""
WIPE = re.compile(r"\brm\s+(?=(?:-\S+\s+)*(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)\s)(?:-\S+\s+)+" + _HOME_T
                  + r"|rmtree\s*\([^)]*(?:expanduser\(\s*[\"']~|Path\.home\(\)|os\.environ\[?[\"']HOME|getenv\([\"']HOME)"
                  r"|rmSync\s*\([^)]*homedir\s*\(", re.M)
_URL_HOST = re.compile(r"\bhttps?://\[?([^/\s:'\"\]]+)")
_LOCAL = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)$", re.I)
PIPE_RUN = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n|;]*\|\s*"
                      r"(?:python\d*|node|bun|perl|ruby)\b|\beval\s+\"?\$\((?:curl|wget)\b")
# runs a code string (the fetched payload), not just any subprocess
RUNNER = re.compile(r"\bexec\s*\(|\beval\s*\(|[\"']-c[\"']\s*,\s*[A-Za-z_]|\bnew Function\(|\bvm\.run|"
                    r"\bbase64\b[^\n]*\|\s*(?:ba|z)?sh\b")
AUTH_FAIL = re.compile(r"40\[13\]|\b40[13]\b")
EVAL_VAR = re.compile(r"\beval\s+[\"']?\$|\bexec\s*\(\s*(?:handler|HANDLER|cmd)\b|subprocess\.\w+\(\s*handler")
_GH_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")
_PATHS = re.compile(r"""(?:~|\$\{?HOME\}?|%h)/[^\s"'`;|&)]+|/(?:home|Users)/[^\s"'`;|&)]+""")
_TMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/")


# ------------------------------------------------------------------ reading entries
def _expand(s: str, home: Path) -> str:
    h = home.as_posix()                        # forward slashes: shlex would eat Windows backslashes
    return s.replace("%h", h).replace("${HOME}", h).replace("$HOME", h).replace("%u", home.name)


def _split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def _systemd(p: Path, home: Path) -> list[tuple[list[str], str]]:
    """[(argv, extra text)] for a unit; extra text = the whole unit (Environment= lines may hold the handler)."""
    out, text = [], p.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = re.match(r"\s*Exec(?:Start|StartPre|StartPost|Reload)\s*=\s*(.+)$", line)
        if m:
            cmd = m.group(1).strip().lstrip("-@+!:")
            out.append((_split(_expand(cmd, home)), text))
    return out


def _launchd(p: Path, home: Path) -> list[tuple[list[str], str]]:
    doc = plistlib.loads(p.read_bytes())
    if not isinstance(doc, dict):
        return []
    argv = [str(a) for a in doc.get("ProgramArguments") or [] if isinstance(a, (str, int))]
    if not argv and isinstance(doc.get("Program"), str):
        argv = [doc["Program"]]
    env = doc.get("EnvironmentVariables") if isinstance(doc.get("EnvironmentVariables"), dict) else {}
    extra = " ".join(f"{k}={v}" for k, v in env.items())
    return [([_expand(a, home) for a in argv], extra)] if argv else []


def _desktop(p: Path, home: Path) -> list[tuple[list[str], str]]:
    text = p.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^Exec\s*=\s*(.+)$", text, re.M)
    return [(_split(_expand(re.sub(r"%[fFuUick]", "", m.group(1)).strip(), home)), "")] if m else []


def entries(home: Path) -> list[tuple[str, Path, list[str], str]]:
    """(kind, file, argv, extra text) for every user autostart entry."""
    out = []
    for kind, d, glob, reader in (("LaunchAgent", home / "Library" / "LaunchAgents", "*.plist", _launchd),
                                  ("systemd user service", home / ".config" / "systemd" / "user", "*.service", _systemd),
                                  ("XDG autostart", home / ".config" / "autostart", "*.desktop", _desktop)):
        if not fsutil.is_dir(d):
            continue
        try:
            files = sorted(d.glob(glob))
        except OSError:
            continue
        for p in files:
            if not fsutil.is_file(p):
                continue
            try:
                for argv, extra in reader(p, home):
                    out.append((kind, p, argv, extra))
            except Exception:              # noqa: BLE001 - one malformed plist/unit must not stop the audit
                continue
    return out


def script_of(argv: list[str]) -> tuple[Path | None, str, str]:
    """(script file, inline code, interpreter) for a command line, or (None, '', '')."""
    if not argv:
        return None, "", ""
    args = list(argv)
    if Path(args[0]).name == "env":                       # /usr/bin/env [-S] [VAR=x] python3 script
        args = [a for a in args[1:] if not a.startswith("-") and "=" not in a]
        if not args:
            return None, "", ""
    exe = Path(args[0]).name.lower()
    if not _INTERP.match(exe):
        p = Path(args[0])
        return (p, "", "") if p.is_absolute() else (None, "", "")       # a script run directly (shebang)
    rest = args[1:]
    if exe in _SHELLS and "-c" in rest:
        i = rest.index("-c")
        return None, rest[i + 1] if i + 1 < len(rest) else "", exe
    if exe.startswith("python") and "-c" in rest:
        i = rest.index("-c")
        return None, rest[i + 1] if i + 1 < len(rest) else "", exe
    if exe.startswith("python") and "-m" in rest:
        return None, "", exe                                              # module from site-packages: pystartup
    if exe in ("bun", "deno") and rest[:1] in (["run"],):
        rest = rest[1:]
    if exe == "osascript" and "-e" in rest:
        i = rest.index("-e")
        return None, rest[i + 1] if i + 1 < len(rest) else "", exe
    for a in rest:
        if a.startswith("-"):
            continue
        return Path(a), "", exe
    return None, "", exe


def place(p: Path, home: Path) -> str:
    """'hidden' (dot-folder, ~/Library or a temp folder), 'home' (elsewhere in home) or 'system'.
    Inside home is judged first: a home that itself lives under /tmp (CI runners) isn't "hidden"."""
    try:
        rel = p.relative_to(home)
    except ValueError:
        return "hidden" if p.as_posix().startswith(_TMP) else "system"
    parts = rel.parts[:-1]
    if any(x.startswith(".") for x in parts) or parts[:1] == ("Library",):
        return "hidden"
    return "home"


def _token_files(texts: list[str], home: Path, names: list[str]) -> list[tuple[Path, str]]:
    cands: list[Path] = []
    for t in texts:
        for m in _PATHS.finditer(t):
            raw = m.group(0).rstrip(".,")
            cands.append(Path(_expand(raw.replace("~", str(home), 1) if raw.startswith("~") else raw, home)))
    cands += [home / ".config" / n / "token" for n in names if n]
    out, seen = [], set()
    for p in cands:
        if p in seen or not fsutil.is_file(p):
            continue
        seen.add(p)
        try:
            if p.stat().st_size > 4096:
                continue
            v = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        m = _GH_TOKEN.search(v)
        if m or (p.name.lower() in ("token", ".token") and 20 <= len(v) <= 255 and " " not in v):
            out.append((p, m.group(0) if m else v))
    return out


def remote(text: str) -> bool:
    """A download/HTTP call that leaves the machine: a non-loopback URL, or a fetch with no URL in the text."""
    if not DOWNLOAD.search(text):
        return False
    hosts = _URL_HOST.findall(text)
    return not hosts or any(not _LOCAL.match(h) for h in hosts)


def signals(text: str) -> list[str]:
    """What the script does, strongest first."""
    sig = []
    gh, rem = bool(GITHUB_API.search(text)), remote(text)
    if gh:
        sig.append("calls the GitHub API")
    if PIPE_RUN.search(text) or (rem and RUNNER.search(text)):
        sig.append("downloads and runs code")
    elif rem and not gh:
        sig.append("talks to a remote host")
    if WIPE.search(text):
        sig.append("deletes your home folder")
    return sig


STRONG = {"calls the GitHub API", "downloads and runs code", "deletes your home folder"}


def _linger(home: Path, root: Path, user: str | None) -> bool:
    user = user or home.name
    return fsutil.exists(root / "var" / "lib" / "systemd" / "linger" / user)


def _label(p: Path, home: Path) -> str:
    try:
        return "~/" + p.relative_to(home).as_posix()
    except ValueError:
        return str(p)


# ------------------------------------------------------------------ the check
FIX_ORDER = ("Don't revoke or rotate anything yet: the switch fires when its token stops working. 1) Disconnect "
             "the machine from the network. 2) Stop and remove the entry: `systemctl --user disable --now <name>` "
             "and delete the unit file, or `launchctl bootout gui/$(id -u) <plist>` and delete the plist; delete "
             "the script; `loginctl disable-linger` if you didn't turn it on. 3) Only then revoke the token, and "
             "rotate every credential this account could read, from a clean device. 4) Rebuild the machine.")


def audit(home: Path, stats: dict, *, root: Path = Path("/"), user: str | None = None) -> list[Finding]:
    home = Path(home)
    out: list[Finding] = []
    ents = entries(home)
    stats["user_autostart_entries"] = len(ents)
    linger = _linger(home, root, user or os.environ.get("USER") or os.environ.get("LOGNAME"))
    for kind, unit, argv, extra in ents:
        script, inline, interp = script_of(argv)
        text, where = "", None
        if script is not None:
            spot = place(script, home)
            if spot == "system" or not fsutil.is_file(script):
                continue
            try:
                if script.stat().st_size > MAX_SCRIPT:
                    continue
                text = script.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not interp and not text.startswith("#!"):
                continue                                   # a binary or app bundle, not a script
            where = _label(script, home)
        elif inline:
            spot, text, where = "inline", inline, f"inline `{interp} -c`"
        else:
            continue
        both = text + "\n" + extra
        sig = signals(text)                       # the unit text only adds a stored handler (wipe) below
        if WIPE.search(extra) and "deletes your home folder" not in sig:
            sig.append("deletes your home folder")
        switch = bool(AUTH_FAIL.search(text)) and bool(WIPE.search(both) or EVAL_VAR.search(text)) \
            and (bool(GITHUB_API.search(both)) or remote(text))
        ulabel = _label(unit, home)
        survives = " It keeps running after you log out (linger is on for your user)." \
            if linger and kind.startswith("systemd") else ""
        subj = f"{unit.name}:{where}"
        if switch:
            names = [unit.stem.split(".")[-1], unit.stem, Path(where).stem if script else ""]
            toks = _token_files([text, extra], home, names)
            tok = ("; token file " + ", ".join(f"{_label(p, home)} ({redact(v)})" for p, v in toks)) if toks else ""
            out.append(Finding(
                rule="host.revoke-switch", category="host", severity=Severity.CRITICAL,
                title=f"Delete-on-revoke switch: {kind} `{unit.name}` runs {where}",
                location=str(unit), subject=subj,
                detail=f"The script checks for an HTTP 401/403 answer and then "
                       f"{'deletes your home folder' if WIPE.search(both) else 'runs a stored handler (eval)'}"
                       f"{tok}. That is the testmetest/Miasma worm's monitor: revoking the stolen token makes it "
                       f"wipe the machine ({SOCKET}).{survives}",
                remediation=FIX_ORDER))
            stats["revoke_switches"] = stats.get("revoke_switches", 0) + 1
            continue
        if sig:
            strong = bool(STRONG & set(sig))
            sev = Severity.HIGH if (strong and spot == "hidden") or "deletes your home folder" in sig \
                else Severity.MEDIUM if strong or spot == "hidden" else Severity.LOW
            out.append(Finding(
                rule="host.user-autostart", category="host", severity=sev,
                title=f"{kind} `{unit.name}` starts {where} at login, which {' and '.join(sig)}",
                location=str(unit), subject=subj,
                detail=f"Defined in {ulabel}. "
                       + {"hidden": "A script in a hidden or temporary folder", "inline": "Code written into the entry",
                          "home": "A script in your home folder"}[spot] + " "
                       + f"that {' and '.join(sig)} at every login. That is how the testmetest/Miasma worm keeps "
                         f"its backdoor (`~/.local/share/runtimes/sync.py`, polling GitHub hourly) ({SOCKET}).{survives}",
                remediation="If you don't recognise it: disconnect the machine, remove the entry and the script "
                            "before revoking any token (a companion monitor may wipe the machine when its token "
                            "stops working), then rotate credentials from a clean device. If it's yours, accept it "
                            "in the baseline."))
        elif spot == "hidden" and interp:
            out.append(Finding(
                rule="host.user-autostart", category="host", severity=Severity.INFO,
                title=f"{kind} `{unit.name}` starts {interp} on {where} at login",
                location=str(unit), subject=subj,
                detail=f"Defined in {ulabel}. Listed so you know what starts with your account; the script shows "
                       f"no network or delete calls.{survives}",
                remediation="Nothing to do if you recognise it."))
    return out


# ------------------------------------------------------------------ "rotate first" is unsafe on this host
WARNING = ("⚠️ A delete-on-revoke switch is installed on this machine ({where}). Remove that persistence first "
           "(see the host.revoke-switch finding), then rotate from a clean device. ")
_ROTATE = re.compile(r"\b(?:rotate|revoke|regenerate|roll|invalidate|deactivate)\b", re.I)


def guard_remediation(findings: list[Finding]) -> int:
    """Put the switch warning in front of every rotate/revoke fix. Text only; fingerprints don't change.
    Returns how many findings were changed."""
    switches = [f for f in findings if f.rule == "host.revoke-switch" and not f.suppressed]
    if not switches:
        return 0
    warn = WARNING.format(where=", ".join(sorted({Path(f.location).name for f in switches})))
    n = 0
    for f in findings:
        if f.rule == "host.revoke-switch" or f.remediation.startswith("⚠️ A delete-on-revoke"):
            continue
        if f.category == "secrets" or _ROTATE.search(f.remediation):
            f.remediation = warn + f.remediation
            n += 1
    return n
