"""``asca export intune``: turn asca's latest report into an Intune custom-compliance result.

Microsoft Intune's custom compliance (Windows, Linux and, since July 2026, macOS) runs a discovery
script on the device that prints one line of JSON keyed by setting names; a rules JSON in the
compliance policy decides compliant or not, and Conditional Access can act on it.

This command is the discovery script's payload. It reads the **last** asca report (it doesn't run
an audit, which wouldn't fit Intune's script time limit) and prints::

    {"AscaReportFound":true,"AscaReportAgeHours":5,"AscaCritical":0,"AscaHigh":1,"AscaMedium":2,
     "AscaResult":"FAIL","AscaVersion":"0.8.0"}

Fail closed: no report, an unreadable one, or one older than the rule's limit makes the device
non-compliant, so a stopped asca job doesn't leave a Mac "compliant" forever. Baseline-accepted
findings aren't counted (asca already excludes them). ``--rules`` prints a matching rules JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, dashboard

NEVER = 999999


def result(state_dir: Path | None = None, report: Path | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if report is None:
        report = dashboard.discover((state_dir or dashboard.default_state_dir()).expanduser()).get("audit")
    out = {"AscaReportFound": False, "AscaReportAgeHours": NEVER, "AscaCritical": 0, "AscaHigh": 0, "AscaMedium": 0,
           "AscaResult": "MISSING", "AscaVersion": "0.0.0"}
    try:
        d = json.loads(Path(report).read_text(encoding="utf-8")) if report else None
    except (OSError, ValueError):
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("counts"), dict):
        return out
    gen = dashboard._parse_time(d.get("generated_at"))
    c = d["counts"]
    out.update(AscaReportFound=True,
               AscaReportAgeHours=int((now - gen).total_seconds() // 3600) if gen else NEVER,
               AscaCritical=int(c.get("critical") or 0), AscaHigh=int(c.get("high") or 0),
               AscaMedium=int(c.get("medium") or 0), AscaResult=str(d.get("result") or "UNKNOWN"),
               AscaVersion=str(d.get("version") or "0.0.0"))
    return out


def _rule(name, op, dtype, operand, title, desc, url):
    return {"SettingName": name, "Operator": op, "DataType": dtype, "Operand": operand, "MoreInfoUrl": url,
            "RemediationStrings": [{"Language": "en_US", "Title": title, "Description": desc}]}


def rules(max_high: int = 0, max_medium: int | None = None, max_age_hours: int = 48,
          url: str = "https://github.com/borabaysal/Agent_Supply_Chain_Auditor#readme") -> dict:
    r = [
        _rule("AscaReportFound", "IsEquals", "Boolean", True, "asca hasn't produced a report on this device",
              "The daily asca audit isn't installed or hasn't run. Ask IT to (re)install the scheduled asca job.", url),
        _rule("AscaReportAgeHours", "LessEquals", "Int64", max_age_hours,
              "The last asca audit is {ActualValue} hours old",
              f"The scheduled asca job stopped running (limit: {max_age_hours} hours). Make sure the Mac has been on "
              f"and logged in, or ask IT to check the job.", url),
        _rule("AscaCritical", "IsEquals", "Int64", 0, "asca found {ActualValue} critical issue(s) on this device",
              "Open the asca report or dashboard on this device and follow each fix, or contact IT.", url),
        _rule("AscaHigh", "LessEquals", "Int64", max_high, "asca found {ActualValue} high-severity issue(s)",
              "Open the asca report or dashboard on this device and follow each fix, or contact IT. Accepted risks "
              "go in asca's baseline file and stop counting.", url),
    ]
    if max_medium is not None:
        r.append(_rule("AscaMedium", "LessEquals", "Int64", max_medium,
                       "asca found {ActualValue} medium-severity issue(s)", "Follow the fixes in the asca report.", url))
    return {"Rules": r}


def run(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="asca export intune", description=__doc__.split("\n\n")[0])
    p.add_argument("--state-dir", type=Path, help="where the asca jobs write reports (default $ASCA_STATE or "
                                                  "~/.local/state/asca)")
    p.add_argument("--report", type=Path, help="a specific audit report JSON instead")
    p.add_argument("--rules", action="store_true", help="print the matching Intune rules JSON instead")
    p.add_argument("--max-high", type=int, default=0)
    p.add_argument("--max-medium", type=int, default=None, help="also require at most this many medium findings")
    p.add_argument("--max-age-hours", type=int, default=48)
    args = p.parse_args(argv)
    if args.rules:
        print(json.dumps(rules(args.max_high, args.max_medium, args.max_age_hours), indent=2))
        return 0
    print(json.dumps(result(args.state_dir, args.report), separators=(",", ":")))
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] != ["intune"]:
        print("usage: asca export intune [--state-dir DIR | --report FILE] [--rules]", file=sys.stderr)
        return 2
    return run(argv[1:])
