"""Autostart entries, and "delete on revoke" switches (``host.user-autostart``, ``host.system-autostart``,
``host.revoke-switch``).

Grounding: Socket (Nov 6 2026) on ``strutil-core``, a build of the testmetest worm (Miasma family). It
installs a Python backdoor as a systemd user service or a LaunchAgent, and on the GitHub-token path a monitor
that stores the stolen token in plain text, keeps running after logout (``loginctl enable-linger``), checks
the token against the GitHub API every 45 seconds and runs a home-deleting handler when it gets 401/403.
Revoking the token, the first thing a responder does, is what triggers the wipe. Socket's advice: remove the
persistence first, then revoke and rotate from a clean device.

asca matches the structure, not the worm's names or hashes. It reads (never runs, loads or unloads):

| Where | Scope |
|---|---|
| ``~/Library/LaunchAgents/*.plist``, ``~/.config/systemd/user/*.service``, ``~/.config/autostart/*.desktop``, ``/var/lib/systemd/linger/<user>`` | user |
| the Windows Startup folder (``%APPDATA%\\...\\Startup``: scripts and ``.lnk`` shortcuts) and ``HKCU\\...\\Run``/``RunOnce`` | user |
| ``/Library/LaunchDaemons``, ``/Library/LaunchAgents``, ``/etc/systemd/system``, ``/etc/systemd/user``, ``/etc/xdg/autostart`` | system |
| ``/etc/crontab``, ``/etc/cron.d/*`` and the per-user crontab spools (readable when asca runs as root) | system (your own crontab: user) |
| the all-users Startup folder (``%ProgramData%``) and ``HKLM\\...\\Run``/``RunOnce`` (also ``WOW6432Node``) | system |

For each entry that starts an interpreter (python, node, bun, deno, sh/bash/zsh, ruby, perl, osascript,
PowerShell, cmd, wscript/cscript, mshta) on a script, runs a script directly, or passes inline code
(``bash -c``, ``cmd /c``, ``powershell -Command``/``-EncodedCommand``, a cron command line), the code is read.
Calls that only reach the machine itself (``localhost``, ``127.0.0.1``) don't count as network:

| Finding | When | Severity |
|---|---|---|
| ``host.revoke-switch`` | the code checks an HTTP 401/403 answer **and** deletes the home folder or ``eval``s a handler | critical |
| ``host.user-autostart`` / ``host.system-autostart`` | code in a hidden folder (dot-folder, ``~/Library``, ``AppData``, ``ProgramData``) or a temp folder that calls the GitHub API, downloads and runs code (``curl … | sh``, ``iwr … | iex``, fetch + exec) or deletes the home folder; any entry that deletes the home folder | high |
| same | those signals from elsewhere or inline in the entry; or a hidden-folder script that only talks to a remote host | medium |
| same | a script elsewhere that only talks to a remote host | low |
| same | an interpreter script from a hidden or temp folder with none of those signals | info (so you know it starts) |

A switch's token file is located through the paths the code or entry mentions (and ``~/.config/<name>/token``)
and shown redacted. When a switch is found, every finding that tells you to rotate or revoke a credential gets
a warning put in front of its fix: remove the persistence first, then rotate from a clean device.
"""
from __future__ import annotations

import base64
import os
import plistlib
import re
import shlex
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import fsutil
from .model import Finding, Severity, redact

SOCKET = "https://socket.dev/blog/shai-hulud-descendant-malicious-ruby-gem"
MAX_SCRIPT = 1024 * 1024

_INTERP = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|pythonw|node|nodejs|bun|deno|sh|bash|zsh|dash|ksh|fish|ruby|perl"
                     r"|osascript|pwsh|powershell|cmd|wscript|cscript|mshta)$")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".rb", ".pl", ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
               ".jse", ".wsf", ".hta")
GITHUB_API = re.compile(r"api\.github\.com")
DOWNLOAD = re.compile(r"\bcurl\b|\bwget\b|urlopen|urllib\.request|\brequests\.(?:get|post)|\bfetch\s*\(|"
                      r"Invoke-WebRequest|http\.client|\bhttpx\.|\baiohttp\b|https?\.get\s*\(")
PS_DOWNLOAD = re.compile(r"DownloadString|DownloadFile|DownloadData|Invoke-RestMethod|\birm\b|\biwr\b|"
                         r"Start-BitsTransfer|\bbitsadmin\b|certutil[^\n]*-urlcache|Net\.WebClient|XMLHTTP|WinHttp|"
                         r"\bmshta\s+https?:", re.I)
_HOME_T = r"""["']?(?:~|\$\{?HOME\}?)/?(?:\*|Documents)?["']?(?=\s|;|&|\||$|["'])"""
WIPE = re.compile(r"\brm\s+(?=(?:-\S+\s+)*(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)\s)(?:-\S+\s+)+" + _HOME_T
                  + r"|rmtree\s*\([^)]*(?:expanduser\(\s*[\"']~|Path\.home\(\)|os\.environ\[?[\"']HOME|getenv\([\"']HOME)"
                  r"|rmSync\s*\([^)]*homedir\s*\(", re.M)
WIPE_WIN = re.compile(r"Remove-Item\b(?=[^\n]*-Recurse)[^\n]*?(?:\$env:USERPROFILE|\$HOME|~)(?:[\\/]\*?)?[\"']?(?=\s|$|;)"
                      r"|\b(?:rd|rmdir)\s+(?:/[sq]\s+){1,2}\"?%USERPROFILE%\\?\"?(?=\s|$|&)", re.I | re.M)
_URL_HOST = re.compile(r"\bhttps?://\[?([^/\s:'\"\]]+)")
_LOCAL = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0)$", re.I)
PIPE_RUN = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n|;]*\|\s*"
                      r"(?:python\d*|node|bun|perl|ruby)\b|\beval\s+\"?\$\((?:curl|wget)\b")
# runs a code string (the fetched payload), not just any subprocess
# exec/eval of a variable (a fetched payload), not of a literal or f-string template
RUNNER = re.compile(r"\b(?:exec|eval)\s*\(\s*(?![fFrRbBuU]{0,2}['\"])|[\"']-c[\"']\s*,\s*[A-Za-z_]|\bnew Function\(|\bvm\.run|"
                    r"\bbase64\b[^\n]*\|\s*(?:ba|z)?sh\b")
PS_RUN = re.compile(r"\|\s*iex\b|\biex\s*[\(\$]|Invoke-Expression|\bmshta\s+https?:|\[ScriptBlock\]::Create", re.I)
AUTH_FAIL = re.compile(r"40\[13\]|\b40[13]\b")
EVAL_VAR = re.compile(r"\beval\s+[\"']?\$|\bexec\s*\(\s*(?:handler|HANDLER|cmd)\b|subprocess\.\w+\(\s*handler|"
                      r"Invoke-Expression\s+\$|\biex\s+\$", re.I)
_GH_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")
_PATHS = re.compile(r"""(?:~|\$\{?HOME\}?|%h)/[^\s"'`;|&)]+|/(?:home|Users)/[^\s"'`;|&)]+""")
_TMP = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/")
_HIDDEN_PARTS = {"library", "appdata", "programdata", "temp", "tmp"}
_SHELL_OPS = re.compile(r"[|;&`]|\$\(")
_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|/)")

RUN_KEYS = [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]
STARTUP = Path("Microsoft") / "Windows" / "Start Menu" / "Programs" / "Startup"


@dataclass
class Entry:
    kind: str                    # "LaunchAgent", "cron job", "Run key" …
    location: str                # file path, or registry key + value name
    name: str                    # unit file name, value name, "crontab line 3"
    scope: str                   # "user" | "system"
    when: str = "at login"       # "at login" | "at boot" | "on a schedule"
    argv: list[str] = field(default_factory=list)
    extra: str = ""              # environment text that may hold a handler
    shell: str = ""              # a raw shell command line (cron, Run value with operators)


# ------------------------------------------------------------------ reading entries
def _expand(s: str, home: Path) -> str:
    h = home.as_posix()                        # forward slashes: shlex would eat Windows backslashes
    return s.replace("%h", h).replace("${HOME}", h).replace("$HOME", h).replace("%u", home.name)


def _expand_win(s: str, home: Path, programdata: Path) -> str:
    env = {"USERPROFILE": home, "HOMEPATH": home, "APPDATA": home / "AppData" / "Roaming",
           "LOCALAPPDATA": home / "AppData" / "Local", "TEMP": home / "AppData" / "Local" / "Temp",
           "TMP": home / "AppData" / "Local" / "Temp", "PROGRAMDATA": programdata, "ALLUSERSPROFILE": programdata}
    return re.sub(r"%(\w+)%", lambda m: env[m.group(1).upper()].as_posix() if m.group(1).upper() in env else m.group(0),
                  s)


def _split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def _split_win(cmd: str) -> list[str]:
    """Windows command line: double quotes group, backslashes are path separators (kept)."""
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in re.findall(r'"[^"]*"|\S+', cmd)]


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


def cron_lines(text: str, system: bool) -> list[tuple[int, str, bool]]:
    """(line number, command, @reboot) from a crontab. System crontabs (/etc/crontab, cron.d) have a user field."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Za-z_]\w*\s*=", line):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2 if system else 1)
            need, reboot = (3 if system else 2), parts[0] == "@reboot"
        else:
            parts = line.split(None, 6 if system else 5)
            need, reboot = (7 if system else 6), False
        if len(parts) >= need:
            out.append((n, parts[-1], reboot))
    return out


def parse_lnk(data: bytes) -> tuple[str, str]:
    """(target path, arguments) from a Windows shell link (.lnk), best effort; ('', '') if it can't be read."""
    try:
        if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
            return "", ""
        flags = struct.unpack_from("<I", data, 0x14)[0]
        off, target = 0x4C, ""
        if flags & 0x01:                                        # HasLinkTargetIDList
            off += 2 + struct.unpack_from("<H", data, off)[0]
        if flags & 0x02:                                        # HasLinkInfo
            size, hsize, _lflags, _vol, base = struct.unpack_from("<IIIII", data, off)
            if hsize >= 0x24:
                ubase = struct.unpack_from("<I", data, off + 28)[0]
                end = data.find(b"\x00\x00", off + ubase)
                while end != -1 and (end - (off + ubase)) % 2:
                    end = data.find(b"\x00\x00", end + 1)
                target = data[off + ubase:end].decode("utf-16-le", "replace")
            if not target and base:
                target = data[off + base:data.find(b"\x00", off + base)].decode("latin-1")
            off += size
        uni = bool(flags & 0x80)
        strings = {}
        for bit, key in ((0x04, "name"), (0x08, "rel"), (0x10, "wd"), (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                n = struct.unpack_from("<H", data, off)[0]
                w = n * (2 if uni else 1)
                strings[key] = data[off + 2:off + 2 + w].decode("utf-16-le" if uni else "latin-1", "replace")
                off += 2 + w
        return target or strings.get("rel", ""), strings.get("args", "")
    except (struct.error, ValueError, IndexError):
        return "", ""


def read_run_keys() -> list[tuple[str, str, str]]:
    """(hive, key path, name, command) from the Windows Run/RunOnce keys. Reading only; [] elsewhere."""
    try:
        import winreg  # type: ignore
    except ImportError:
        return []
    out = []
    for hive, path in RUN_KEYS:
        root = winreg.HKEY_CURRENT_USER if hive == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(root, path) as k:
                i = 0
                while True:
                    try:
                        name, val, typ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(val, str):
                        out.append((f"{hive}\\{path}", name or "(Default)", val))
        except OSError:
            continue
    return out


def _files(d: Path, glob: str) -> list[Path]:
    if not fsutil.is_dir(d):
        return []
    try:
        return [p for p in sorted(d.glob(glob)) if fsutil.is_file(p)]
    except OSError:
        return []


def entries(home: Path, *, root: Path = Path("/"), user: str | None = None, run_keys=None,
            programdata: Path | None = None, stats: dict | None = None) -> list[Entry]:
    stats = {} if stats is None else stats
    user = user or home.name
    out: list[Entry] = []
    file_sources = [
        ("LaunchAgent", home / "Library" / "LaunchAgents", "*.plist", _launchd, "user", "at login"),
        ("systemd user service", home / ".config" / "systemd" / "user", "*.service", _systemd, "user", "at login"),
        ("XDG autostart", home / ".config" / "autostart", "*.desktop", _desktop, "user", "at login"),
        ("LaunchDaemon", root / "Library" / "LaunchDaemons", "*.plist", _launchd, "system", "at boot"),
        ("system LaunchAgent", root / "Library" / "LaunchAgents", "*.plist", _launchd, "system", "at login"),
        ("systemd system service", root / "etc" / "systemd" / "system", "*.service", _systemd, "system", "at boot"),
        ("systemd user service (all users)", root / "etc" / "systemd" / "user", "*.service", _systemd, "system",
         "at login"),
        ("XDG autostart (all users)", root / "etc" / "xdg" / "autostart", "*.desktop", _desktop, "system", "at login"),
    ]
    for kind, d, glob, reader, scope, when in file_sources:
        for p in _files(d, glob):
            try:
                for argv, extra in reader(p, home):
                    out.append(Entry(kind, str(p), p.name, scope, when, argv, extra))
            except Exception:              # noqa: BLE001 - one malformed plist/unit must not stop the audit
                continue
    # cron: system crontabs have a user field; spools are per user and usually readable only by root
    crons = [(root / "etc" / "crontab", True, "system")] + [(p, True, "system") for p in _files(root / "etc" / "cron.d", "*")]
    for spool in (root / "var" / "spool" / "cron" / "crontabs", root / "var" / "spool" / "cron",
                  root / "usr" / "lib" / "cron" / "tabs", root / "var" / "at" / "tabs"):
        crons += [(p, False, "user" if p.name == user else "system") for p in _files(spool, "*")]
    for p, system, scope in crons:
        if not fsutil.is_file(p):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:                    # someone else's crontab: skip, never abort
            stats["autostart_unreadable"] = stats.get("autostart_unreadable", 0) + 1
            continue
        kind = "cron job" if p.parent.name not in ("crontabs", "cron", "tabs") else \
            ("cron job" if p.name == user else f"cron job (user {p.name})")
        for n, cmd, reboot in cron_lines(text, system):
            out.append(Entry(kind, f"{p}:{n}", f"{p.name} line {n}", scope, "at boot" if reboot else "on a schedule",
                             shell=_expand(cmd, home)))
    # Windows Startup folders and Run keys (read on any OS when present; tests plant them)
    pd = programdata if programdata is not None else (
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) if os.name == "nt" and root == Path("/")
        else root / "ProgramData")
    for d, scope, kind in ((home / "AppData" / "Roaming" / STARTUP, "user", "Startup folder item"),
                           (pd / STARTUP, "system", "Startup folder item (all users)")):
        for p in _files(d, "*"):
            if p.name.lower() == "desktop.ini" or p.suffix.lower() == ".url":
                continue
            if p.suffix.lower() == ".lnk":
                try:
                    target, args = parse_lnk(p.read_bytes())
                except OSError:
                    continue
                if not target:
                    continue
                argv = [_expand_win(target, home, pd)] + _split_win(_expand_win(args, home, pd))
                out.append(Entry(kind, str(p), p.name, scope, "at login", argv))
            else:
                out.append(Entry(kind, str(p), p.name, scope, "at login", [p.as_posix()]))
    for key, name, cmd in (read_run_keys() if run_keys is None else run_keys):
        scope = "user" if key.upper().startswith("HKCU") else "system"
        val = _expand_win(cmd, home, pd)
        kind = "Run key" if scope == "user" else "Run key (all users)"
        e = Entry(kind, f"{key}\\{name}", name, scope, "at login")
        if _SHELL_OPS.search(re.sub(r'"[^"]*"', "", val)) and not re.match(r'^"?[^"]*\b(?:cmd|powershell|pwsh)', val, re.I):
            e.shell = val
        else:
            e.argv = _split_win(val)
        out.append(e)
    return out


def _exe(arg: str) -> str:
    name = re.split(r"[\\/]", arg)[-1].lower()
    return name[:-4] if name.endswith((".exe", ".com")) else name


def _p(arg: str) -> Path:
    return Path(arg.replace("\\", "/"))


def script_of(argv: list[str]) -> tuple[Path | None, str, str]:
    """(script file, inline code, interpreter) for a command line, or (None, '', '')."""
    if not argv:
        return None, "", ""
    args = list(argv)
    if _exe(args[0]) == "env":                            # /usr/bin/env [-S] [VAR=x] python3 script
        args = [a for a in args[1:] if not a.startswith("-") and "=" not in a]
        if not args:
            return None, "", ""
    exe = _exe(args[0])
    if not _INTERP.match(exe):
        return (_p(args[0]), "", "") if _ABS.match(args[0]) else (None, "", "")   # a script run directly
    rest = args[1:]
    low = [a.lower() for a in rest]
    if exe in _SHELLS and "-c" in rest:
        i = rest.index("-c")
        return None, rest[i + 1] if i + 1 < len(rest) else "", exe
    if exe == "cmd":
        for flag in ("/c", "/k", "/r"):
            if flag in low:
                return None, " ".join(rest[low.index(flag) + 1:]), exe
        return None, "", exe
    if exe in ("powershell", "pwsh"):
        i = 0
        while i < len(rest):
            a = low[i]
            if a in ("-encodedcommand", "-enc", "-e", "-ec") and i + 1 < len(rest):
                try:
                    return None, base64.b64decode(rest[i + 1]).decode("utf-16-le", "replace"), exe
                except ValueError:
                    return None, rest[i + 1], exe
            if a in ("-command", "-c"):
                return None, " ".join(rest[i + 1:]), exe
            if a in ("-file", "-f") and i + 1 < len(rest):
                return _p(rest[i + 1]), "", exe
            if a in ("-executionpolicy", "-ep", "-windowstyle", "-w", "-configurationname", "-version"):
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            return (_p(rest[i]), "", exe) if a.endswith(".ps1") else (None, " ".join(rest[i:]), exe)
        return None, "", exe
    if exe == "mshta":
        return None, "mshta " + " ".join(rest), exe
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
        if a.startswith("-") or (exe in ("wscript", "cscript") and a.startswith("/")):
            continue
        return _p(a), "", exe
    return None, "", exe


def place(p: Path, home: Path, scope: str = "user", root: Path = Path("/")) -> str:
    """'hidden' (dot-folder, ~/Library, AppData, ProgramData or a temp folder), 'home' (elsewhere in home),
    'elsewhere' (outside home, system entries) or 'system' (outside home, user entries: not judged).
    Inside home is judged first: a home that itself lives under /tmp (CI runners) isn't "hidden"."""
    try:
        rel = p.relative_to(home)
    except ValueError:
        try:                                   # judge relative to the scanned root (tests use a fake root)
            p = Path("/") / p.relative_to(root)
        except ValueError:
            pass
        parts = [x.lower() for x in p.parts[:-1]]
        if p.as_posix().startswith(_TMP) or any(x.startswith(".") and x not in (".", "..") for x in parts) \
                or any(x in ("programdata", "temp", "tmp") for x in parts):
            return "hidden"
        return "elsewhere" if scope == "system" else "system"
    parts = [x.lower() for x in rel.parts[:-1]]
    if any(x.startswith(".") for x in parts) or (parts[:1] and parts[0] in _HIDDEN_PARTS):
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


def wipes(text: str) -> bool:
    return bool(WIPE.search(text) or WIPE_WIN.search(text))


def remote(text: str) -> bool:
    """A download/HTTP call that leaves the machine: a non-loopback URL, or a fetch with no URL in the text."""
    if not (DOWNLOAD.search(text) or PS_DOWNLOAD.search(text)):
        return False
    hosts = _URL_HOST.findall(text)
    return not hosts or any(not _LOCAL.match(h) for h in hosts)


def signals(text: str) -> list[str]:
    """What the script does, strongest first."""
    sig = []
    gh, rem = bool(GITHUB_API.search(text)), remote(text)
    if gh:
        sig.append("calls the GitHub API")
    if PIPE_RUN.search(text) or (rem and (RUNNER.search(text) or PS_RUN.search(text))):
        sig.append("downloads and runs code")
    elif rem and not gh:
        sig.append("talks to a remote host")
    if wipes(text):
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
        return p.as_posix() if ":" in p.parts[0] else str(p)


# ------------------------------------------------------------------ the check
FIX_ORDER = ("Don't revoke or rotate anything yet: the switch fires when its token stops working. 1) Disconnect "
             "the machine from the network. 2) Stop and remove the entry: `systemctl --user disable --now <name>` "
             "(or `sudo systemctl disable --now <name>`) and delete the unit file, or `launchctl bootout "
             "gui/$(id -u) <plist>` (`sudo launchctl bootout system <plist>`) and delete the plist, or delete the "
             "crontab line, Run value or Startup item; delete the script; `loginctl disable-linger` if you didn't "
             "turn it on. 3) Only then revoke the token, and rotate every credential this account could read, from a "
             "clean device. 4) Rebuild the machine.")
_SPOT_TEXT = {"hidden": "A script in a hidden or temporary folder", "inline": "Code written into the entry",
              "home": "A script in your home folder", "elsewhere": "A script outside your home folder"}


def audit(home: Path, stats: dict, *, root: Path = Path("/"), user: str | None = None, run_keys=None,
          programdata: Path | None = None) -> list[Finding]:
    home = Path(home)
    out: list[Finding] = []
    user = user or os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME")
    ents = entries(home, root=root, user=user, run_keys=run_keys, programdata=programdata, stats=stats)
    stats["user_autostart_entries"] = sum(1 for e in ents if e.scope == "user")
    stats["system_autostart_entries"] = sum(1 for e in ents if e.scope == "system")
    linger = _linger(home, root, user)
    for e in ents:
        if e.shell:
            toks = _split(e.shell)
            while toks and re.match(r"^[A-Za-z_]\w*=", toks[0]):
                toks = toks[1:]
            if _SHELL_OPS.search(e.shell) or not toks:
                script, inline, interp = None, e.shell, "sh"
            else:
                script, inline, interp = script_of(toks)
                if script is None and not inline:
                    inline, interp = e.shell, "sh"
        else:
            script, inline, interp = script_of(e.argv)
        text, where = "", None
        if script is not None:
            spot = place(script, home, e.scope, root)
            if spot == "system" or not fsutil.is_file(script):
                continue
            try:
                if script.stat().st_size > MAX_SCRIPT:
                    continue
                text = script.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not interp and not text.startswith("#!") and not script.suffix.lower() in _SCRIPT_EXT:
                continue                                   # a binary or app bundle, not a script
            where = _label(script, home)
        elif inline:
            spot, text = "inline", inline
            where = "a cron command" if e.kind.startswith("cron") else f"inline `{interp}` code"
        else:
            continue
        both = text + "\n" + e.extra
        sig = signals(text)                       # the unit text only adds a stored handler (wipe) below
        if wipes(e.extra) and "deletes your home folder" not in sig:
            sig.append("deletes your home folder")
        switch = bool(AUTH_FAIL.search(text)) and (wipes(both) or bool(EVAL_VAR.search(text))) \
            and (bool(GITHUB_API.search(both)) or remote(text))
        loc = Path(e.location) if not e.location.startswith("HK") else None
        elabel = _label(loc, home) if loc else e.location
        survives = " It keeps running after you log out (linger is on for your user)." \
            if linger and e.kind == "systemd user service" else ""
        subj = f"{e.name}:{where}"
        if switch:
            stem = Path(e.name).stem
            names = [stem.split(".")[-1], stem, Path(where).stem if script else ""]
            toks = _token_files([text, e.extra], home, names)
            tok = ("; token file " + ", ".join(f"{_label(p, home)} ({redact(v)})" for p, v in toks)) if toks else ""
            out.append(Finding(
                rule="host.revoke-switch", category="host", severity=Severity.CRITICAL,
                title=f"Delete-on-revoke switch: {e.kind} `{e.name}` runs {where}",
                location=e.location, subject=subj,
                detail=f"The script checks for an HTTP 401/403 answer and then "
                       f"{'deletes your home folder' if wipes(both) else 'runs a stored handler (eval)'}"
                       f"{tok}. That is the testmetest/Miasma worm's monitor: revoking the stolen token makes it "
                       f"wipe the machine ({SOCKET}).{survives}",
                remediation=FIX_ORDER))
            stats["revoke_switches"] = stats.get("revoke_switches", 0) + 1
            continue
        rule = "host.user-autostart" if e.scope == "user" else "host.system-autostart"
        if sig:
            strong = bool(STRONG & set(sig))
            sev = Severity.HIGH if (strong and spot == "hidden") or "deletes your home folder" in sig \
                else Severity.MEDIUM if strong or spot == "hidden" else Severity.LOW
            out.append(Finding(
                rule=rule, category="host", severity=sev,
                title=f"{e.kind} `{e.name}` starts {where} {e.when}, which {' and '.join(sig)}",
                location=e.location, subject=subj,
                detail=f"Defined in {elabel}. {_SPOT_TEXT[spot]} that {' and '.join(sig)} {e.when}. That is how "
                       f"the testmetest/Miasma worm keeps its backdoor (`~/.local/share/runtimes/sync.py`, polling "
                       f"GitHub hourly) ({SOCKET}).{survives}",
                remediation="If you don't recognise it: disconnect the machine, remove the entry and the script "
                            "before revoking any token (a companion monitor may wipe the machine when its token "
                            "stops working), then rotate credentials from a clean device. If it's yours, accept it "
                            "in the baseline."))
        elif spot == "hidden" and interp:
            out.append(Finding(
                rule=rule, category="host", severity=Severity.INFO,
                title=f"{e.kind} `{e.name}` starts {interp} on {where} {e.when}",
                location=e.location, subject=subj,
                detail=f"Defined in {elabel}. Listed so you know what starts on this machine; the script shows "
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
    warn = WARNING.format(where=", ".join(sorted({re.split(r"[\\/]", f.location)[-1] for f in switches})))
    n = 0
    for f in findings:
        if f.rule == "host.revoke-switch" or f.remediation.startswith("⚠️ A delete-on-revoke"):
            continue
        if f.category == "secrets" or _ROTATE.search(f.remediation):
            f.remediation = warn + f.remediation
            n += 1
    return n
