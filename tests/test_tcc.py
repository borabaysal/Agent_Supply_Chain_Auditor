"""macOS privacy grants (asca.tcc), against TCC.db files built with Apple's schema. Runs on any OS (force=True)."""
import plistlib
import sqlite3
from pathlib import Path

from asca import tcc
from asca.model import Severity

SCHEMA = """CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL,
auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB,
policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED',
indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT 0, pid INTEGER,
pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminded INTEGER NOT NULL DEFAULT 0,
PRIMARY KEY (service, client, client_type, indirect_object_identifier))"""
LEGACY = """CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL,
allowed INTEGER NOT NULL, prompt_count INTEGER NOT NULL, csreq BLOB, policy_id INTEGER,
indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT, indirect_object_code_identity BLOB,
flags INTEGER, last_modified INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (service, client, client_type, indirect_object_identifier))"""


def db(path: Path, rows, legacy=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute(LEGACY if legacy else SCHEMA)
    for svc, client, ctype, auth, target in rows:
        if legacy:
            con.execute("INSERT INTO access (service, client, client_type, allowed, prompt_count, "
                        "indirect_object_identifier) VALUES (?,?,?,?,0,?)", (svc, client, ctype, auth, target))
        else:
            con.execute("INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, "
                        "indirect_object_identifier) VALUES (?,?,?,?,2,1,?)", (svc, client, ctype, auth, target))
    con.commit()
    con.close()
    return path


def run(tmp_path, system_rows=(), user_rows=(), mdm=None, legacy=False):
    sysdb = db(tmp_path / "sys/TCC.db", system_rows, legacy)
    home = tmp_path / "home"
    db(home / "Library/Application Support/com.apple.TCC/TCC.db", user_rows, legacy)
    plist = tmp_path / "MDMOverrides.plist"
    if mdm is not None:
        with plist.open("wb") as fh:
            plistlib.dump(mdm, fh)
    stats = {}
    fs = tcc.audit(stats, home=home, system_db=sysdb, mdm_plist=plist, force=True)
    return fs, stats


def test_full_disk_for_terminal_ide_binary_and_agent_app(tmp_path):
    fs, stats = run(tmp_path, system_rows=[
        (tcc.FDA, "com.googlecode.iterm2", 0, 2, "UNUSED"),
        (tcc.FDA, "com.todesktop.230313mzl4w4u92", 0, 2, "UNUSED"),
        (tcc.FDA, "/opt/homebrew/bin/node", 1, 2, "UNUSED"),
        (tcc.FDA, "com.anthropic.claudefordesktop", 0, 2, "UNUSED"),
        (tcc.FDA, "com.backblaze.bzbmenu", 0, 2, "UNUSED"),            # a backup app: expected, not reported
        (tcc.FDA, "com.apple.Terminal", 0, 0, "UNUSED"),               # denied
    ])
    got = sorted((f.rule, f.severity, f.title.split(" (")[0]) for f in fs)
    assert got == [("host.tcc-full-disk", Severity.HIGH, n) for n in ("/opt/homebrew/bin/node", "Claude Desktop",
                                                                      "Cursor", "iTerm2")]
    iterm = next(f for f in fs if "iTerm2" in f.title)
    assert "inherits" in iterm.detail and "turn off iTerm2" in iterm.remediation
    assert stats["tcc_read"] == ["system", "user"] and "launched it has Full Disk Access" in stats["tcc_note"]


def test_app_control_accessibility_and_automation(tmp_path):
    fs, _ = run(tmp_path, system_rows=[(tcc.ACCESSIBILITY, "com.microsoft.VSCode", 0, 2, "UNUSED")],
                user_rows=[(tcc.APPLE_EVENTS, "com.mitchellh.ghostty", 0, 2, "com.apple.systemevents"),
                           (tcc.APPLE_EVENTS, "com.microsoft.VSCode", 0, 2, "com.spotify.client")])   # harmless target
    got = sorted((f.rule, f.severity, f.title) for f in fs)
    assert got == [("host.tcc-app-control", Severity.MEDIUM, "Ghostty (terminal) can control other apps"),
                   ("host.tcc-app-control", Severity.MEDIUM, "VS Code (IDE) can control other apps")]


def test_legacy_schema(tmp_path):
    fs, _ = run(tmp_path, system_rows=[(tcc.FDA, "com.apple.Terminal", 0, 1, None)], legacy=True)
    assert [f.title for f in fs] == ["Terminal (terminal) has Full Disk Access"]


def test_mdm_profile_grants(tmp_path):
    fs, _ = run(tmp_path, mdm={"com.microsoft.VSCode": {tcc.FDA: {"Allowed": True}},
                               "com.apple.Safari": {tcc.FDA: {"Allowed": True}}})
    assert [f.title for f in fs] == ["VS Code (IDE) has Full Disk Access"]
    assert "MDM profile" in fs[0].detail and "IT admin" in fs[0].remediation


def test_unreadable_is_low_never_silent(tmp_path):
    bad = tmp_path / "sys/TCC.db"
    bad.parent.mkdir()
    bad.write_bytes(b"not a database at all" * 100)
    stats = {}
    fs = tcc.audit(stats, home=tmp_path / "nohome", system_db=bad, mdm_plist=tmp_path / "none", force=True)
    assert [(f.rule, f.severity) for f in fs] == [("host.tcc-unreadable", Severity.LOW)]
    assert "never passes silently" in fs[0].detail and stats["tcc_read"] == []


def test_db_is_opened_read_only(tmp_path):
    p = db(tmp_path / "sys/TCC.db", [(tcc.FDA, "com.apple.Terminal", 0, 2, "UNUSED")])
    p.chmod(0o444)
    p.parent.chmod(0o555)                                  # no -wal/-shm can be created next to it
    try:
        rows, err = tcc.read_db(p)
        assert err == "" and rows and rows[0]["client"] == "com.apple.Terminal"
    finally:
        p.parent.chmod(0o755)


def test_not_macos_is_a_noop(monkeypatch, tmp_path):
    monkeypatch.setattr(tcc.sys, "platform", "linux")
    assert tcc.audit({}, home=tmp_path) == []


def test_classify():
    assert tcc.classify("/usr/local/bin/python3.12", 1) == ("binary", "/usr/local/bin/python3.12")
    assert tcc.classify("com.jetbrains.pycharm", 0) == ("IDE", "pycharm")
    assert tcc.classify("/usr/libexec/sshd-keygen-wrapper", 1) is None
    assert tcc.classify("com.apple.Safari", 0) is None
