"""Tests for the per-host dashboard, the report footer (ASCA_DASHBOARD) and the fleet headline/reminder."""
from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from asca import cli as asca_cli
from asca import dashboard, report
from asca.fleet import cli as fleet_cli
from asca.fleet import monitor
from asca.fleet.releases import Release
from asca.fleet.targets import Observation

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def finding(title, sev="high", fp="aa", **kw):
    d = {"rule": kw.pop("rule", "secret.x"), "category": "secrets", "severity": sev, "title": title,
         "location": kw.pop("location", "/home/u/.env"), "subject": "s", "detail": kw.pop("detail", "why it matters"),
         "remediation": kw.pop("remediation", "Run `chmod 600 /home/u/.env` now."), "suppressed": False,
         "suppress_reason": "", "fingerprint": fp}
    d.update(kw)
    return d


def audit_report(findings, when=NOW, result=None, tool="agent-supply-chain-auditor", stats=None):
    counts = {s: sum(1 for f in findings if f["severity"] == s and not f["suppressed"])
              for s in ("critical", "high", "medium", "low", "info")}
    counts["suppressed"] = sum(1 for f in findings if f["suppressed"])
    fail = counts["critical"] + counts["high"] > 0
    return {"tool": tool, "version": "0.3.0", "generated_at": ts(when), "result": result or ("FAIL" if fail else "PASS"),
            "fail_on": "high", "targets": {}, "stats": stats or {"git_repos": 1}, "counts": counts, "findings": findings}


def write(p: Path, data) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return p


def mac_layout(root: Path, audit_findings, skills_findings=(), when=NOW):
    write(root / "audit" / "latest.json", audit_report(list(audit_findings), when))
    write(root / "skills" / "skills-latest.json",
          audit_report(list(skills_findings), when, stats={"skills_scanned": 3}))
    write(root / "inventory" / "inventory-latest.json",
          {"tool": "asca-inventory", "version": "0.3.0", "generated_at": ts(when), "result": "PASS",
           "first_run": False, "counts": {"skill": 3}, "findings": [], "items": []})
    return root


# ================================================================== discovery + statuses

def test_discovers_mac_and_hermes_layouts(tmp_path):
    mac = mac_layout(tmp_path / "mac", [finding("Key in transcript")])
    assert set(dashboard.discover(mac)) == {"audit", "skills", "inventory"}
    herm = tmp_path / "herm"
    write(herm / "latest.json", audit_report([]))
    write(herm / "skills" / "skills-latest.json", audit_report([], stats={"skills_scanned": 1}))
    write(herm / "fleet" / "fleet-latest.json", {"generated_at": ts(NOW), "ok": True, "latest": {"version": "0.23.1"},
                                                 "instances": [{"name": "h", "version": "0.23.0",
                                                                "releases_behind": ["0.23.1"], "security_fixes_behind": 0}]})
    write(herm / "egress" / "summary-latest.md", "# Agent egress\n\nconnections: 5\n\nNo new destinations. ✅\n")
    found = dashboard.discover(herm)
    assert found["audit"] == herm / "latest.json" and set(found) == {"audit", "skills", "fleet", "egress"}
    jobs = {k: dashboard.load(k, p) for k, p in found.items()}
    assert jobs["fleet"].status == "warn" and "no security fixes" in jobs["fleet"].summary
    assert jobs["egress"].status == "pass" and jobs["audit"].status == "pass"


def test_skills_report_at_root_is_not_mistaken_for_audit(tmp_path):
    write(tmp_path / "latest.json", audit_report([], stats={"skills_scanned": 2}))
    assert "audit" not in dashboard.discover(tmp_path)


def test_unreadable_report_is_an_error_not_a_pass(tmp_path):
    write(tmp_path / "audit" / "latest.json", "{not json")
    out = tmp_path / "d.html"
    res = dashboard.build(tmp_path, out, host="h", now=NOW)
    assert res["jobs"]["audit"] == "error" and "report unreadable" in out.read_text()


def test_stale_job_is_flagged(tmp_path):
    mac_layout(tmp_path, [], when=NOW - timedelta(hours=30))
    out = tmp_path / "d.html"
    res = dashboard.build(tmp_path, out, host="h", now=NOW)
    page = out.read_text()
    assert set(res["stale"]) == {"audit", "skills", "inventory"} and "STALE" in page and "No new report for over 26 h" in page


# ================================================================== page content + safety

def test_findings_fixes_and_order(tmp_path):
    mac_layout(tmp_path, [finding("Medium thing", "medium", "m1"), finding("High thing", "high", "h1"),
                          finding("Low thing", "low", "l1"),
                          finding("Accepted", "high", "s1", suppressed=True, suppress_reason="revoked, 401")])
    out = tmp_path / "d.html"
    dashboard.build(tmp_path, out, host="mac", now=NOW)
    page = out.read_text()
    act = page.split("<h2>Act on these</h2>")[1].split("Lower-priority findings")[0]
    assert act.index("High thing") < act.index("Medium thing") and "Low thing" not in act
    assert "Lower-priority findings (1)" in page and "Accepted in a baseline (1)" in page and "revoked, 401" in page
    assert '<pre class="cmd" title="click to select">chmod 600 /home/u/.env</pre>' in page
    assert "Something needs your attention" in page


def test_hostile_content_is_escaped_and_page_runs_nothing(tmp_path):
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    mac_layout(tmp_path, [finding(evil, "high", "x1", location=f"/tmp/{evil}", detail=evil,
                                  remediation=f"Run `{evil}` and see <a href=javascript:alert(3)>")])
    write(tmp_path / "fleet" / "fleet-latest.json",
          {"generated_at": ts(NOW), "latest": {"version": "1", "url": "javascript:alert(4)"}, "instances": []})
    out = tmp_path / "d.html"
    dashboard.build(tmp_path, out, host=evil, now=NOW)
    page = out.read_text()
    assert "<script" not in page.lower() and "onerror=" not in page.replace("onerror=alert(2)&gt;", "")
    assert "javascript:" not in page.replace("javascript:alert(3)&gt;", "")      # only as escaped text
    assert not re.search(r"<a [^>]*href=\"javascript", page)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page and "Content-Security-Policy" in page
    # no external resources, ever
    assert not re.search(r"(src|href)=[\"']?(https?:)?//", page.replace('href="https://github.com/', ""))


def test_output_is_private_and_atomic(tmp_path):
    mac_layout(tmp_path, [])
    out = tmp_path / "d.html"
    out.write_text("old")
    os.chmod(out, 0o644)
    dashboard.build(tmp_path, out, host="h", now=NOW)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "dashboard-state.json").stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.tmp"))


# ================================================================== new / fixed-recently memory

def test_new_badge_and_fixed_recently(tmp_path):
    mac_layout(tmp_path, [finding("Old one", "high", "o1")])
    out = tmp_path / "d.html"
    dashboard.build(tmp_path, out, host="h", now=NOW)
    assert "pill new" not in out.read_text()            # first build = baseline, nothing is "new"
    mac_layout(tmp_path, [finding("Old one", "high", "o1"), finding("Fresh one", "medium", "f1")])
    dashboard.build(tmp_path, out, host="h", now=NOW + timedelta(hours=2))
    page = out.read_text()
    fresh = page.split("Fresh one")[0].rsplit('<div class="f">', 1)[1]
    old = page.split("Old one")[0].rsplit('<div class="f">', 1)[1]
    assert "pill new" in fresh and "pill new" not in old and "1 new since yesterday" in page
    mac_layout(tmp_path, [finding("Fresh one", "medium", "f1")])               # "Old one" fixed
    dashboard.build(tmp_path, out, host="h", now=NOW + timedelta(days=1))
    page = out.read_text()
    assert "<h2>Fixed recently</h2>" in page and "Old one" in page.split("<h2>Fixed recently</h2>")[1]
    dashboard.build(tmp_path, out, host="h", now=NOW + timedelta(days=9))      # older than a week: drops off
    assert "Fixed recently" not in out.read_text()


def test_missing_report_never_claims_a_fix(tmp_path):
    mac_layout(tmp_path, [finding("Still there", "high", "k1")])
    out = tmp_path / "d.html"
    dashboard.build(tmp_path, out, host="h", now=NOW)
    (tmp_path / "audit" / "latest.json").write_text("{broken")
    dashboard.build(tmp_path, out, host="h", now=NOW + timedelta(hours=1))
    assert "Fixed recently" not in out.read_text()


def test_audit_trend_from_history(tmp_path):
    mac_layout(tmp_path, [])
    for d in range(5):
        write(tmp_path / "audit" / f"history-202611{d + 1:02d}T080000Z.json",
              audit_report([finding("x", "high", f"t{d}")] * (d + 1), NOW - timedelta(days=5 - d)))
    out = tmp_path / "d.html"
    dashboard.build(tmp_path, out, host="h", now=NOW)
    page = out.read_text()
    assert "<h2>Audit trend</h2>" in page and page.count('class="bar"') == 5


def test_cli_entrypoint(tmp_path, capsys):
    mac_layout(tmp_path, [finding("A", "high", "a1")])
    assert asca_cli.run(["dashboard", "--state-dir", str(tmp_path), "--host-label", "laptop"]) == 0
    assert "wrote" in capsys.readouterr().out and "asca dashboard · laptop" in (tmp_path / "dashboard.html").read_text()
    assert asca_cli.run(["dashboard", "--state-dir", str(tmp_path / "nope")]) == 2


# ================================================================== report footer

def test_footer_in_every_report_and_alert(monkeypatch, tmp_path):
    from asca.egress import summary as esum
    from asca.inventory import cli as inv
    from asca.model import Finding, Report, Severity
    monkeypatch.setenv("ASCA_DASHBOARD", "homelab:~/.hermes/state/asca/dashboard.html")
    r = Report(targets={}, findings=[Finding(rule="r.x", category="c", severity=Severity.HIGH, title="t",
                                             location="l")], version="0.3.0", generated_at=ts(NOW))
    want = "homelab:~/.hermes/state/asca/dashboard.html"
    assert report.to_markdown(r).rstrip().endswith(f"Dashboard: `{want}`")
    assert report.telegram_text(r, host="h", report_path="/r.md").endswith(f"Dashboard: <code>{want}</code>")
    assert inv.to_markdown([], [], first_run=False, generated="x", host="h", errors=[]).rstrip().endswith(f"`{want}`")
    assert inv.to_telegram([], host="h", alert_on=Severity.LOW, items=0, report_path="/r").endswith(f"{want}</code>")
    d = esum.Diff(window=(NOW.timestamp() - 86400, NOW.timestamp()))
    assert esum.to_markdown(d, "h").rstrip().endswith(f"`{want}`")
    assert esum.to_telegram(d, "h", "/r.md").endswith(f"{want}</code>")
    st = monitor.evaluate([Observation(name="h", spec="local:/x", version="0.23.0", source="t")], [_rel("0.23.0"), _rel("0.23.1")])
    assert monitor.to_markdown(st).rstrip().endswith(f"`{want}`")
    assert monitor.to_telegram(st, what_changed=[]).endswith(f"{want}</code>")
    monkeypatch.delenv("ASCA_DASHBOARD")
    assert "Dashboard" not in report.to_markdown(r) and "Dashboard" not in monitor.to_telegram(st, what_changed=[])


def test_footer_survives_telegram_truncation(monkeypatch):
    monkeypatch.setenv("ASCA_DASHBOARD", "~/x/dashboard.html")
    t = report.with_dashboard_tg("y" * 5000)
    assert len(t) <= 4096 and t.endswith("Dashboard: <code>~/x/dashboard.html</code>") and "…(truncated)" in t


def test_footer_value_is_escaped(monkeypatch):
    monkeypatch.setenv("ASCA_DASHBOARD", "<b>x</b>\n\nevil")
    assert report.with_dashboard_tg("hi").endswith("Dashboard: <code>&lt;b&gt;x&lt;/b&gt; evil</code>")


# ================================================================== fleet headline + reminder

def _rel(v):
    return Release(version=tuple(int(x) for x in v.split(".")), tag=f"v{v}", name=f"Hermes Agent v{v}",
                   published="2026-11-10", url=f"https://github.com/NousResearch/hermes-agent/releases/tag/v{v}")


def test_headline_says_behind_not_patched():
    st = monitor.evaluate([Observation(name="homelab/hermes", spec="local:/x", version="0.23.0", source="t")],
                          [_rel("0.23.0"), _rel("0.23.1")], now=datetime(2026, 11, 13, 7, 20, tzinfo=timezone.utc))
    t = monitor.to_telegram(st, what_changed=["new release v0.23.1"])
    assert t.startswith("🟨 <b>homelab/hermes: 1 release behind for 3 days</b> (v0.23.1 released 10 Nov, no security fixes)")
    assert "patched" not in t and "docker pull" in t and "Changed: new release v0.23.1" in t
    md = monitor.to_markdown(st)
    assert "## homelab/hermes" in md and "Upgrade when convenient" in md and "[v0.23.1](" in md


def _fleet_run(tmp_path, monkeypatch, version, now, remind=3):
    inst = tmp_path / "inst"
    inst.mkdir(exist_ok=True)
    (inst / "install-stamp.json").write_text(json.dumps({"baseVersion": version}))
    monkeypatch.setattr(fleet_cli.releases, "fetch", lambda *a, **k: [_rel("0.23.0"), _rel("0.23.1")])

    class FakeDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return now
    monkeypatch.setattr(fleet_cli, "datetime", FakeDT)
    return fleet_cli.run(["--dir", str(tmp_path / "st"), "check", "--target", f"h=local:{inst}", "--format", "none",
                          "--telegram", "change", "--telegram-chat", "1", "--remind-days", str(remind)])


def test_remind_days(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(fleet_cli.asca_report, "resolve_telegram", lambda *a: ("tok", "1"))
    monkeypatch.setattr(fleet_cli.asca_report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    _fleet_run(tmp_path, monkeypatch, "0.23.1", NOW)                       # first run, current: silent
    assert sent == []
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=1))   # change: v0.23.1 -> v0.23.0 (alert)
    assert len(sent) == 1 and "1 release behind" in sent[0] and "Reminder" not in sent[0]
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=2))
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=3))
    assert len(sent) == 1                                                  # 2 days since the alert: quiet
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=4, minutes=-30))   # 2 d 23.5 h: within slack
    assert len(sent) == 2 and sent[1].startswith("⏰ Reminder · 🟨") and "every 3 days" in sent[1]
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=5))
    assert len(sent) == 2                                                  # clock restarted at the reminder
    _fleet_run(tmp_path, monkeypatch, "0.23.1", NOW + timedelta(days=6))   # upgraded: change alert, then quiet
    assert len(sent) == 3 and "up to date" in sent[2]
    _fleet_run(tmp_path, monkeypatch, "0.23.1", NOW + timedelta(days=12))
    assert len(sent) == 3


def test_reminder_off_by_default_and_old_state_starts_clock(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(fleet_cli.asca_report, "resolve_telegram", lambda *a: ("tok", "1"))
    monkeypatch.setattr(fleet_cli.asca_report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW, remind=0)
    for d in range(1, 10):
        _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=d), remind=0)
    assert sent == []          # first run behind w/o security fixes = ok status: silent, and no reminders when off
    st = json.loads((tmp_path / "st" / "state.json").read_text())
    st.pop("last_alert_at", None)                                          # state written by an older asca
    (tmp_path / "st" / "state.json").write_text(json.dumps(st))
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=20))
    assert sent == []          # starts the clock instead of alerting immediately
    _fleet_run(tmp_path, monkeypatch, "0.23.0", NOW + timedelta(days=23))
    assert len(sent) == 1 and "Reminder" in sent[0]


# ================================================================== fleet: how long behind

def _rel_on(v, published):
    return Release(version=tuple(int(x) for x in v.split(".")), tag=f"v{v}", name=f"Hermes Agent v{v}",
                   published=published, url=f"https://github.com/NousResearch/hermes-agent/releases/tag/v{v}")


def _inst(version="0.23.0"):
    return [Observation(name="homelab/hermes", spec="local:/x", version=version, source="t")]


AT_0720 = lambda day: datetime(2026, 11, day, 7, 20, tzinfo=timezone.utc)   # noqa: E731


@pytest.mark.parametrize("day,phrase", [(10, "since today"), (11, "for 1 day"), (13, "for 3 days")])
def test_days_behind_0_1_3(day, phrase):
    st = monitor.evaluate(_inst(), [_rel_on("0.23.0", "2026-11-01"), _rel_on("0.23.1", "2026-11-10")], now=AT_0720(day))
    i = st.instances[0]
    assert i.behind_since == "2026-11-10" and i.days_behind == day - 10
    t = monitor.to_telegram(st, what_changed=[], reminder_days=3)
    assert t.startswith(f"⏰ Reminder · 🟨 <b>homelab/hermes: 1 release behind {phrase}</b> "
                        "(v0.23.1 released 10 Nov, no security fixes)")
    assert f"homelab/hermes (v0.23.0) is 1 release behind {phrase}, no listed security fixes" in t
    assert f"1 release behind {phrase}" in monitor.to_markdown(st)
    assert st.to_dict()["instances"][0]["days_behind"] == day - 10


def test_several_releases_behind_counts_from_the_oldest_missing():
    rels = [_rel_on("0.23.0", "2026-11-01"), _rel_on("0.23.2", "2026-11-12"), _rel_on("0.23.1", "2026-11-05")]
    st = monitor.evaluate(_inst(), rels, now=AT_0720(13))
    i = st.instances[0]
    assert i.oldest_missing.vstr == "0.23.1" and i.days_behind == 8
    t = monitor.to_telegram(st, what_changed=[])
    assert t.startswith("🟨 <b>homelab/hermes: 2 releases behind for 8 days</b> "
                        "(oldest missing: v0.23.1, released 5 Nov, no security fixes)")


def test_missing_publish_date_leaves_the_count_out():
    for bad in ("", "not-a-date", "2026-12-01"):           # empty, garbage, in the future
        st = monitor.evaluate(_inst(), [_rel_on("0.23.0", "2026-11-01"), _rel_on("0.23.1", bad)], now=AT_0720(13))
        i = st.instances[0]
        assert i.days_behind is None and i.behind_since is None
        t = monitor.to_telegram(st, what_changed=[])
        assert t.startswith("🟨 <b>homelab/hermes: 1 release behind</b> (no security fixes)")
        assert " day" not in t.split("\n")[0] and "since today" not in t
        assert "is 1 release behind, no listed security fixes" in monitor.headline(i)


def test_security_case_shows_days_too():
    from asca.fleet.releases import SecurityItem
    fixed = _rel_on("0.23.1", "2026-11-08")
    fixed.items.append(SecurityItem(kind="fix", text="Sandbox escape via crafted skill", ids=["GHSA-xxxx-yyyy-zzzz"]))
    st = monitor.evaluate(_inst(), [_rel_on("0.23.0", "2026-11-01"), fixed], now=AT_0720(13))
    t = monitor.to_telegram(st, what_changed=[])
    assert t.startswith("🛡️ <b>homelab/hermes: 1 security fix behind for 5 days</b> (v0.23.1 released 8 Nov)")
    assert "across 1 release for 5 days" in monitor.headline(st.instances[0])


def test_day_count_does_not_change_the_alert_signature():
    rels = [_rel_on("0.23.0", "2026-11-01"), _rel_on("0.23.1", "2026-11-10")]
    a = monitor.evaluate(_inst(), rels, now=AT_0720(11))
    b = monitor.evaluate(_inst(), rels, now=AT_0720(13))
    assert a.signature() == b.signature()          # a growing count must not make `change` alert daily


def test_dashboard_patch_card_recounts_days_at_build_time(tmp_path):
    st = monitor.evaluate(_inst(), [_rel_on("0.23.0", "2026-11-01"), _rel_on("0.23.1", "2026-11-10")], now=AT_0720(13))
    (tmp_path / "fleet").mkdir()
    (tmp_path / "fleet" / "fleet-latest.json").write_text(json.dumps(st.to_dict()))
    out = tmp_path / "dashboard.html"
    dashboard.build(tmp_path, out, host="h", now=datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc))
    page = out.read_text()
    assert "<th>behind for</th>" in page and "4 days (since 10 Nov)" in page
    assert "1 release behind for 4 days, no security fixes" in page
    # report from an older asca without behind_since: no count, no crash
    d = st.to_dict()
    d["instances"][0].pop("behind_since")
    (tmp_path / "fleet" / "fleet-latest.json").write_text(json.dumps(d))
    dashboard.build(tmp_path, out, host="h", now=datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc))
    page = out.read_text()
    assert "1 release behind, no security fixes" in page and "since 10 Nov" not in page
