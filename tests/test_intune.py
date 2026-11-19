"""asca export intune: Intune custom-compliance output (asca.intune) and the sample discovery script."""
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


def test_linux_discovery_script(tmp_path):
    st = report(tmp_path / "s", {"critical": 2})
    env = {**os.environ, "ASCA_DIR": str(ROOT), "ASCA_STATE": str(st)}
    p = subprocess.run(["bash", str(ROOT / "examples/intune/discovery-linux.sh")], env=env, capture_output=True,
                       text=True)
    assert p.returncode == 0 and json.loads(p.stdout)["AscaCritical"] == 2 and p.stdout.count("\n") == 1
    p = subprocess.run(["bash", str(ROOT / "examples/intune/discovery-linux.sh")],
                       env={**env, "ASCA_DIR": str(tmp_path / "nope")}, capture_output=True, text=True)
    assert p.returncode == 0 and json.loads(p.stdout)["AscaReportFound"] is False
