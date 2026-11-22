"""asca export intune: Intune custom-compliance output (asca.intune) and the sample discovery script."""
import pytest
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asca import cli, intune

NOW = datetime(2026, 11, 19, 8, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parent.parent


def report(state: Path, counts: dict, when=NOW - timedelta(hours=3), result="FAIL"):
    state.mkdir(parents=True, exist_ok=True)
    (state / "latest.json").write_text(json.dumps({"tool": "agent-supply-chain-auditor", "version": "0.8.0",
                                                   "generated_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                   "result": result, "counts": counts, "findings": []}))
    return state


def test_result_from_report(tmp_path):
    st = report(tmp_path / "s", {"critical": 1, "high": 2, "medium": 3, "suppressed": 9})
    assert intune.result(st, now=NOW) == {"AscaReportFound": True, "AscaReportAgeHours": 3, "AscaCritical": 1,
                                          "AscaHigh": 2, "AscaMedium": 3, "AscaResult": "FAIL", "AscaVersion": "0.8.0"}


def test_missing_or_garbage_fails_closed(tmp_path):
    for st in (tmp_path / "none", report(tmp_path / "bad", {})):
        (st / "latest.json").write_text("{not json") if st.exists() else None
        r = intune.result(st, now=NOW)
        assert r["AscaReportFound"] is False and r["AscaReportAgeHours"] == intune.NEVER


def test_rules_evaluate_like_intune(tmp_path):
    """Apply the rules the way Intune does, to clean, failing, stale and missing devices."""
    ops = {"IsEquals": lambda a, b: a == b, "LessEquals": lambda a, b: a <= b}

    def compliant(res, rules):
        return all(ops[r["Operator"]](res[r["SettingName"]], r["Operand"]) for r in rules["Rules"])
    rules = intune.rules()
    ok = intune.result(report(tmp_path / "a", {"medium": 4, "low": 9}, result="FAIL"), now=NOW)
    assert compliant(ok, rules)                                            # mediums don't block by default
    assert not compliant(ok, intune.rules(max_medium=0))
    assert not compliant(intune.result(report(tmp_path / "b", {"high": 1}), now=NOW), rules)
    assert not compliant(intune.result(report(tmp_path / "c", {}, when=NOW - timedelta(hours=60)), now=NOW), rules)
    assert not compliant(intune.result(tmp_path / "missing", now=NOW), rules)


def test_rules_file_matches_and_is_valid():
    shipped = json.loads((ROOT / "examples/intune/rules.json").read_text())
    assert shipped == intune.rules()
    for r in shipped["Rules"]:
        assert r["Operator"] in {"IsEquals", "NotEquals", "GreaterThan", "GreaterEquals", "LessThan", "LessEquals"}
        assert r["DataType"] in {"Boolean", "Int64", "Double", "String", "DateTime", "Version"}
        assert any(s["Language"] == "en_US" for s in r["RemediationStrings"])
    assert len(json.dumps(shipped)) < 100_000 and len(shipped["Rules"]) <= 100


def test_cli_prints_one_line(tmp_path, capsys):
    st = report(tmp_path / "s", {"high": 1})
    assert cli.run(["export", "intune", "--state-dir", str(st)]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and json.loads(out)["AscaHigh"] == 1
    assert cli.run(["export", "nope"]) == 2


@pytest.mark.skipif(os.name == "nt", reason="bash on Windows is WSL's, with Linux paths")
def test_linux_discovery_script(tmp_path):
    st = report(tmp_path / "s", {"critical": 2})
    env = {**os.environ, "ASCA_DIR": str(ROOT), "ASCA_STATE": str(st)}
    p = subprocess.run(["bash", str(ROOT / "examples/intune/discovery-linux.sh")], env=env, capture_output=True,
                       text=True)
    assert p.returncode == 0 and json.loads(p.stdout)["AscaCritical"] == 2 and p.stdout.count("\n") == 1
    p = subprocess.run(["bash", str(ROOT / "examples/intune/discovery-linux.sh")],
                       env={**env, "ASCA_DIR": str(tmp_path / "nope")}, capture_output=True, text=True)
    assert p.returncode == 0 and json.loads(p.stdout)["AscaReportFound"] is False


# ------------------------------------------------------------------ Windows discovery script (PowerShell)

WIN_SCRIPT = ROOT / "examples" / "intune" / "discovery-windows.ps1"
PS_NOW = "2026-11-22T15:30:00Z"


def _powershell():
    """Windows PowerShell 5.1 on Windows (what Intune runs), else PowerShell 7 if installed (CI images have it)."""
    import shutil
    return (shutil.which("powershell") if os.name == "nt" else None) or shutil.which("pwsh")


def _run_ps(*args, env=None):
    exe = _powershell()
    cmd = [exe, "-NoProfile", "-NonInteractive"] + (["-ExecutionPolicy", "Bypass"] if os.name == "nt" else [])
    p = subprocess.run(cmd + ["-File", str(WIN_SCRIPT), *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120, env=env)
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    return p.returncode, lines


GOOD = {"tool": "agent-supply-chain-auditor", "version": "0.5.0", "generated_at": "2026-11-22T10:00:00Z",
        "result": "FAIL", "counts": {"critical": 1, "high": 2, "medium": 3, "low": 4}}
CASES = {
    "normal": json.dumps(GOOD),
    "pass-zero-counts": json.dumps({**GOOD, "result": "PASS", "counts": {"critical": 0, "high": 0, "medium": 0}}),
    "missing-count-keys": json.dumps({**GOOD, "counts": {"high": 5}}),
    "null-counts-values": json.dumps({**GOOD, "counts": {"critical": None, "high": None, "medium": 2}}),
    "string-numbers": json.dumps({**GOOD, "counts": {"critical": "0", "high": "2", "medium": "1"}}),
    "no-result-no-version": json.dumps({k: v for k, v in GOOD.items() if k not in ("result", "version")}),
    "other-time-format": json.dumps({**GOOD, "generated_at": "2026-11-22T10:00:00+00:00"}),
    "no-generated-at": json.dumps({k: v for k, v in GOOD.items() if k != "generated_at"}),
    "future-timestamp": json.dumps({**GOOD, "generated_at": "2026-11-22T16:00:00Z"}),
    "old-report": json.dumps({**GOOD, "generated_at": "2026-11-01T00:00:00Z"}),
    "utf8-bom": "\ufeff" + json.dumps(GOOD),
    "no-counts": json.dumps({k: v for k, v in GOOD.items() if k != "counts"}),
    "counts-not-object": json.dumps({**GOOD, "counts": [1, 2]}),
    "root-is-list": json.dumps([GOOD]),
    "invalid-json": '{"counts": {',
    "empty-file": "",
}


@pytest.mark.skipif(not _powershell(), reason="needs PowerShell (powershell.exe on Windows, or pwsh)")
@pytest.mark.parametrize("case", sorted(CASES))
def test_windows_discovery_script_matches_exporter(tmp_path, case):
    rep = tmp_path / "latest.json"
    rep.write_text(CASES[case], encoding="utf-8")
    rc, lines = _run_ps("-Report", str(rep), "-NowUtc", PS_NOW)
    assert rc == 0 and len(lines) == 1, (rc, lines)                       # one line of JSON, as Intune requires
    want = intune.result(report=rep, now=datetime(2026, 11, 22, 15, 30, tzinfo=timezone.utc))
    assert json.loads(lines[0]) == want


@pytest.mark.skipif(not _powershell(), reason="needs PowerShell")
def test_windows_discovery_script_missing_report_fails_closed(tmp_path):
    rc, lines = _run_ps("-Report", str(tmp_path / "nope.json"))
    assert rc == 0 and json.loads(lines[0]) == intune.result(report=tmp_path / "nope.json")
    assert json.loads(lines[0])["AscaReportFound"] is False


@pytest.mark.skipif(os.name != "nt" or not _powershell(), reason="the per-user default path is Windows-only")
def test_windows_discovery_script_reads_the_daily_task_report(tmp_path):
    """No -Report: as a normal user it reads %LOCALAPPDATA%\\asca\\latest.json, where asca-daily.ps1 writes."""
    (tmp_path / "asca").mkdir()
    (tmp_path / "asca" / "latest.json").write_text(json.dumps({**GOOD, "result": "PASS"}), encoding="utf-8")
    rc, lines = _run_ps("-NowUtc", PS_NOW, env={**os.environ, "LOCALAPPDATA": str(tmp_path)})
    got = json.loads(lines[0])
    assert rc == 0 and got["AscaReportFound"] is True and got["AscaResult"] == "PASS" and got["AscaReportAgeHours"] == 5


def test_windows_script_is_ascii_and_ends_with_the_intune_return_line():
    text = WIN_SCRIPT.read_text(encoding="utf-8")
    assert text.isascii()                                   # Windows PowerShell 5.1 reads BOM-less files as ANSI
    assert text.rstrip().splitlines()[-1] == "return $hash | ConvertTo-Json -Compress"
