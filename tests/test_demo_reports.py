"""examples/demo-report*.json (for the website) must match what asca reports today."""
import json
import sys
from pathlib import Path

import pytest

from asca import demo

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux") or sys.version_info < (3, 11),
                                reason="generated on Linux with Python 3.11+ (client-config paths differ per OS; "
                                       "Codex needs tomllib)")


@pytest.mark.parametrize("name,fixed", [("demo-report.json", False), ("demo-report-fixed.json", True)])
def test_committed_demo_reports_are_current(name, fixed):
    committed = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
    assert demo.report(fixed) == committed, (
        f"examples/{name} is stale: run `python3 -m asca demo --write-reports examples` and commit the result")


def test_demo_reports_tell_the_story():
    before = json.loads((EXAMPLES / "demo-report.json").read_text(encoding="utf-8"))
    after = json.loads((EXAMPLES / "demo-report-fixed.json").read_text(encoding="utf-8"))
    assert before["result"] == "FAIL" and after["result"] == "PASS"
    assert before["demo"]["asca_version"] == before["version"] and after["demo"]["fixed"] is True
    planted = {rule for _, rule, _, _ in demo.EXPECTED}
    assert planted <= {f["rule"] for f in before["findings"]}
    text = json.dumps(before) + json.dumps(after)
    assert "/home/demo/" in text and "/tmp/" not in text.replace("/tmp/asca-demo", "")
    assert "sk-ant-asca-demo-" not in text                       # the fake key appears only redacted
    assert {f["severity"] for f in after["findings"]} <= {"info", "low"}
