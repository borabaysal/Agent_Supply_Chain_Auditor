"""Windows-specific behaviour that can be exercised on any OS."""
import json

from asca import cli, secrets
from asca.model import Severity

QUIET = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-stray-instructions",
         "--no-agent-config", "--no-python-startup", "--no-docker-daemon", "--no-agent-versions", "--no-tcc",
         "--no-plugin-pins", "--format", "none"]


def test_permissions_note_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "permissions_checked", lambda: False)
    out = tmp_path / "r"
    cli.run(QUIET + ["-o", str(out)])
    notes = [f for f in json.loads(out.with_suffix(".json").read_text())["findings"]
             if f["rule"] == "scanner.permissions-not-checked"]
    assert len(notes) == 1 and notes[0]["severity"] == "low" and "icacls" in notes[0]["remediation"]


def test_no_note_on_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "permissions_checked", lambda: True)
    out = tmp_path / "r"
    cli.run(QUIET + ["-o", str(out)])
    assert not [f for f in json.loads(out.with_suffix(".json").read_text())["findings"]
                if f["rule"] == "scanner.permissions-not-checked"]


def test_note_is_low_and_never_fails_the_audit():
    assert secrets.permissions_note().severity == Severity.LOW
