"""Tests for asca.fleet: release-note extraction, target probing, evaluation, alerting."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from asca.fleet import cli, monitor, releases, targets
from asca.model import Severity

BODY_FIXES = """# Hermes Agent v0.21.6

## Security Fixes

**Dashboard authentication hardening**

- Spoofed `X-Forwarded-For` headers could reset the rate limit (#133367)
- Native sign-in could send login codes to a non-loopback redirect (#130685)

**Repository git filter hardening**

- Automatic git calls could run filter programs from an untrusted repo config (#130661)

Thanks to someone for reporting.

## Upgrading

- `docker pull nousresearch/hermes-agent:stable`
"""

BODY_HARDENING = """## ✨ Highlights
- New desktop app

## 🔒 Security & Reliability
- **Redaction sweep** closes gaps ([#80965](https://github.com/x/pull/80965))
- **CVE-2026-48710 (Starlette BadHost)**: pin Starlette ([#35118](https://github.com/x/pull/35118))

## 🐛 Bug fixes
- Fixed a GHSA-abcd-efgh-ijkl issue in the parser (#999)
- Unrelated fix (#1000)
"""


def _rel(name, tag, body, date="2026-10-08", **kw):
    return {"name": name, "tag_name": tag, "body": body, "published_at": f"{date}T00:00:00Z",
            "html_url": f"https://example/{tag}", **kw}


FEED = [
    _rel("Hermes Agent v0.21.6", "v0.21.6", BODY_FIXES, "2026-10-08"),
    _rel("Hermes Agent v0.21.5 (v2026.9.24)", "v2026.9.24", "## Notes\n- perf", "2026-09-24"),
    _rel("Hermes Agent v0.21.4 (v2026.9.21)", "v2026.9.21", "", "2026-09-21"),
    _rel("Hermes Agent v0.21.0 (v2026.8.31)", "v2026.8.31", BODY_HARDENING, "2026-08-31"),
    _rel("Hermes Agent v0.22.0-rc1", "v0.22.0-rc1", BODY_FIXES, "2026-10-09", prerelease=True),
    _rel("draft", "v9.9.9", BODY_FIXES, draft=True),
]


# ------------------------------------------------------------------ releases

def test_release_version_prefers_semver_over_calver():
    assert releases.release_version("Hermes Agent v0.21.4 (v2026.9.21)", "v2026.9.21") == (0, 21, 4)
    assert releases.release_version("", "v2026.9.21") is None
    assert releases.release_version("", "v0.21.6") == (0, 21, 6)


def test_extract_security_fix_section_with_groups():
    items = releases.extract_security(BODY_FIXES)
    assert [i.kind for i in items] == ["fix"] * 3
    assert [i.prs for i in items] == [["133367"], ["130685"], ["130661"]]
    assert items[0].group == "Dashboard authentication hardening"
    assert items[2].group == "Repository git filter hardening"
    assert all("docker pull" not in i.text for i in items)    # "Upgrading" section is not security


def test_extract_hardening_and_id_promotion():
    items = releases.extract_security(BODY_HARDENING)
    kinds = {i.key(): i.kind for i in items}
    assert kinds["#80965"] == "hardening"
    assert kinds["CVE-2026-48710"] == "fix"                   # advisory id promotes to fix
    assert kinds["GHSA-ABCD-EFGH-IJKL"] == "fix"              # even outside a security section
    assert "#1000" not in kinds and "New desktop app" not in json.dumps([i.to_dict() for i in items])
    assert all("](" not in i.text and "**" not in i.text for i in items)   # markdown flattened


def test_parse_releases_skips_drafts_prereleases_and_sorts():
    rels = releases.parse_releases(FEED)
    assert [r.vstr for r in rels] == ["0.21.0", "0.21.4", "0.21.5", "0.21.6"]
    assert len(rels[-1].fixes) == 3 and len(rels[0].hardening) == 1 and len(rels[0].fixes) == 2   # CVE + GHSA


def test_fetch_paginates_and_rejects_bad_payload():
    pages = {1: [_rel(f"Hermes Agent v0.1.{i}", f"v0.1.{i}", "") for i in range(100)],
             2: [_rel("Hermes Agent v0.2.0", "v0.2.0", "")]}
    calls = []

    def get(url, token, timeout):
        n = int(url.rsplit("page=", 1)[1])
        calls.append(n)
        return pages.get(n, [])

    assert len(releases.fetch(get=get)) == 101 and calls == [1, 2]
    with pytest.raises(ValueError):
        releases.fetch(get=lambda *a: {"message": "API rate limit exceeded"})


# ------------------------------------------------------------------ targets

def test_target_parsing_and_fleet_file(tmp_path):
    assert targets.parse_target("nas=http://nas:9119") == targets.Target("nas", "http://nas:9119")
    assert targets.parse_target("local:/opt/hermes").name == "local:/opt/hermes"
    f = tmp_path / "fleet.json"
    f.write_text(json.dumps({"targets": [{"name": "a", "spec": "docker:hermes"}, "b=ssh:box"]}))
    assert [t.name for t in targets.load_fleet(f)] == ["a", "b"]


def test_observe_local_http_docker_ssh(tmp_path):
    (tmp_path / "hermes_cli").mkdir()
    (tmp_path / "hermes_cli" / "__init__.py").write_text('__version__ = "0.21.4"\n')
    assert targets.observe(targets.Target("l", f"local:{tmp_path}")).version == "0.21.4"
    assert targets.observe(targets.Target("h", "http://x:9119"),
                           http_get=lambda url, t: {"version": "0.21.5"}).version == "0.21.5"
    seen = []

    def run(cmd, timeout):
        seen.append(cmd)
        return '__version__ = "0.20.1"\n'

    d = targets.observe(targets.Target("d", "docker:hermes-2"), run=run)
    s = targets.observe(targets.Target("s", "ssh:pi@box:/srv/hermes"), run=run)
    assert d.version == s.version == "0.20.1"
    # The stamp is tried first; this fake returns no JSON, so each falls back to __init__.py.
    assert ["docker", "exec", "hermes-2", "cat", "/opt/hermes/install-stamp.json"] in seen
    assert ["docker", "exec", "hermes-2", "cat", "/opt/hermes/hermes_cli/__init__.py"] in seen
    ssh_cmds = [c for c in seen if c[0] == "ssh"]
    assert all(c[:2] == ["ssh", "-o"] for c in ssh_cmds)
    assert ssh_cmds[-1][-3:] == ["pi@box", "cat", "/srv/hermes/hermes_cli/__init__.py"]


# Hermes >= 0.21.7 serves __version__ lazily; the literal assignment is gone and
# install-stamp.json is authoritative. Before this fix every such instance
# reported "version unknown (unreadable)".
NEW_STYLE_INIT = '__release_date__ = "2026.9.24"\n__version__: str\n\ndef __getattr__(name):\n    ...\n'


def test_local_reads_install_stamp_when_init_has_no_literal(tmp_path):
    (tmp_path / "hermes_cli").mkdir()
    (tmp_path / "hermes_cli" / "__init__.py").write_text(NEW_STYLE_INIT)
    (tmp_path / "install-stamp.json").write_text(json.dumps({"baseVersion": "0.21.7", "displayVersion": "0.21.7"}))
    o = targets.observe(targets.Target("l", f"local:{tmp_path}"))
    assert o.version == "0.21.7" and o.source.endswith("install-stamp.json") and o.error is None


def test_stamp_placeholder_or_garbage_falls_back_to_init(tmp_path):
    (tmp_path / "hermes_cli").mkdir()
    (tmp_path / "hermes_cli" / "__init__.py").write_text('__version__ = "0.21.4"\n')
    for bad in ('{"baseVersion": "0.0.0"}', "not json", "{}"):
        (tmp_path / "install-stamp.json").write_text(bad)
        assert targets.observe(targets.Target("l", f"local:{tmp_path}")).version == "0.21.4"


def test_new_style_init_without_stamp_is_still_unknown(tmp_path):
    (tmp_path / "hermes_cli").mkdir()
    (tmp_path / "hermes_cli" / "__init__.py").write_text(NEW_STYLE_INIT)
    assert targets.observe(targets.Target("l", f"local:{tmp_path}")).version is None


def test_remote_prefers_stamp():
    def run(cmd, timeout):
        if cmd[-1].endswith("install-stamp.json"):
            return '{"baseVersion": "0.21.7"}'
        return NEW_STYLE_INIT
    o = targets.observe(targets.Target("d", "docker:hermes"), run=run)
    assert o.version == "0.21.7" and o.source == "docker:hermes:/opt/hermes/install-stamp.json"


@pytest.mark.parametrize("spec", ["docker:x;rm -rf /", "ssh:-oProxyCommand=evil", "docker:ok:/opt/../etc",
                                  "docker:ok:relative", "ftp://x", "docker:$(id)"])
def test_observe_rejects_unsafe_specs_without_running(spec):
    ran = []
    o = targets.observe(targets.Target("x", spec), run=lambda c, t: ran.append(c) or "")
    assert o.version is None and o.error and ran == []


def test_observe_errors_are_contained():
    def boom(url, t):
        raise OSError("connection refused")

    o = targets.observe(targets.Target("h", "http://x"), http_get=boom)
    assert o.version is None and "connection refused" in o.error


# ------------------------------------------------------------------ monitor

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
RELS = releases.parse_releases(FEED)


def _obs(name, v):
    return targets.Observation(name, "local:/x", v, "x", None if v else "unreachable")


def test_evaluate_counts_fixes_behind_and_advisories():
    adv = [("CVE-2026-82021", (0, 18, 2), (0, 18, 999), "0.19.0", Severity.CRITICAL, "s"),
           ("CVE-2026-48710", (0, 0, 0), (0, 21, 0), "0.16.0", Severity.HIGH, "dup of release-note id")]
    s = monitor.evaluate([_obs("old", "0.18.5"), _obs("mid", "0.21.4"), _obs("new", "0.21.6"),
                          _obs("dev", "0.22.1"), _obs("gone", None)], RELS, advisories=adv, now=NOW)
    old, mid, new, dev, gone = s.instances
    assert len(mid.fix_keys) == 3 and [r.vstr for r in mid.behind] == ["0.21.5", "0.21.6"] and mid.needs_patch
    assert "CVE-2026-82021" in old.fix_keys and old.fix_keys.count("CVE-2026-48710") == 1   # deduped
    assert not new.needs_patch and not new.behind
    assert dev.ahead and not dev.needs_patch
    assert gone.unknown_version and not s.ok
    assert "3 security fixes behind across 2 releases" in monitor.headline(mid)
    assert "up to date" in monitor.headline(new)


def test_behind_without_security_fixes_is_ok():
    s = monitor.evaluate([_obs("a", "0.21.4")], RELS[:3], now=NOW)    # latest = 0.21.5, no fixes
    assert s.ok and s.instances[0].behind and "no listed security fixes" in monitor.headline(s.instances[0])


def test_change_detection(tmp_path):
    p = tmp_path / "state.json"
    s1 = monitor.evaluate([_obs("a", "0.21.4")], RELS[:3], now=NOW)
    assert monitor.changes({}, s1) == ["first run"]
    monitor.save_state(p, s1)
    assert monitor.changes(monitor.load_state(p), monitor.evaluate([_obs("a", "0.21.4")], RELS[:3])) == []
    s2 = monitor.evaluate([_obs("a", "0.21.4")], RELS, now=NOW)        # new release w/ fixes
    assert any("new release v0.21.6 with 3 security fixes" in m for m in monitor.changes(monitor.load_state(p), s2))
    monitor.save_state(p, s2)
    s3 = monitor.evaluate([_obs("a", "0.21.6")], RELS, now=NOW)        # upgraded
    assert monitor.changes(monitor.load_state(p), s3) == ["a: v0.21.4 → v0.21.6"]
    s4 = monitor.evaluate([_obs("a", None)], RELS, now=NOW, feed_error="HTTP 503")
    msgs = monitor.changes(monitor.load_state(p), s4)
    assert "a: version unreadable" in msgs and "release feed failing" in msgs
    assert (p.stat().st_mode & 0o077) == 0


def test_telegram_message():
    s = monitor.evaluate([_obs("apollonia<x>", "0.21.4"), _obs("nas", "0.21.6")], RELS, now=NOW)
    t = monitor.to_telegram(s, what_changed=["new release v0.21.6"])
    assert "apollonia&lt;x&gt;: 3 security fixes behind" in t and "<x>" not in t
    assert "✅ nas (v0.21.6) is up to date" in t and "Latest: <b>v0.21.6</b>" in t
    assert "Dashboard authentication hardening: Spoofed" in t and "docker pull" in t
    assert len(t) <= 4096
    ok = monitor.to_telegram(monitor.evaluate([_obs("a", "0.21.6")], RELS, now=NOW), what_changed=["a: v0.21.4 → v0.21.6"])
    assert ok.startswith("✅ <b>Hermes fleet is patched</b>") and "docker pull" not in ok


# ------------------------------------------------------------------ CLI

def test_cli_alerts_on_change_only(tmp_path, monkeypatch):
    from asca import report
    sent = []
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    feed = {"rels": RELS[:3]}
    monkeypatch.setattr(releases, "fetch", lambda *a, **k: feed["rels"])
    inst = tmp_path / "inst"
    (inst / "hermes_cli").mkdir(parents=True)
    ver = inst / "hermes_cli" / "__init__.py"
    ver.write_text('__version__ = "0.21.4"\n')
    env = tmp_path / "e.env"
    env.write_text("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=5\n")
    args = ["--dir", str(tmp_path / "st"), "check", "--target", f"box=local:{inst}", "--format", "none",
            "--telegram", "change", "--env-file", str(env)]
    assert cli.run(args) == 0 and sent == []          # first run, all OK -> silent
    assert cli.run(args) == 0 and sent == []          # nothing changed
    feed["rels"] = RELS                               # 0.21.6 with security fixes is released
    assert cli.run(args) == 1 and len(sent) == 1 and "3 security fixes behind" in sent[0]
    assert cli.run(args) == 1 and len(sent) == 1      # still behind, but no change -> silent
    ver.write_text('__version__ = "0.21.6"\n')        # upgraded
    assert cli.run(args) == 0 and len(sent) == 2 and "patched" in sent[1]
    assert (tmp_path / "st" / "fleet-latest.md").exists()


def test_cli_first_run_alerts_when_already_behind(tmp_path, monkeypatch):
    from asca import report
    sent = []
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    monkeypatch.setattr(releases, "fetch", lambda *a, **k: RELS)
    env = tmp_path / "e.env"
    env.write_text("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=5\n")
    inst = tmp_path / "i"
    (inst / "hermes_cli").mkdir(parents=True)
    (inst / "hermes_cli" / "__init__.py").write_text('__version__ = "0.21.4"\n')
    assert cli.run(["--dir", str(tmp_path / "s"), "check", "--target", f"x=local:{inst}", "--format", "none",
                    "--telegram", "change", "--env-file", str(env)]) == 1
    assert len(sent) == 1


def test_cli_feed_failure_and_alert_failure(tmp_path, monkeypatch):
    from asca import report

    def broken(*a, **k):
        raise OSError("timed out")

    monkeypatch.setattr(releases, "fetch", broken)
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (False, "HTTP 401"))
    env = tmp_path / "e.env"
    env.write_text("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=5\n")
    st = tmp_path / "s"
    args = ["--dir", str(st), "check", "--target", "x=local:/nonexistent", "--format", "none",
            "--telegram", "change", "--env-file", str(env)]
    assert cli.run(args) == 2                     # alert could not be delivered
    assert not (st / "state.json").exists()       # state not saved -> alert retried next run
    assert cli.run(["--dir", str(st), "check", "--target", "a=local:/x", "--target", "a=local:/y"]) == 2
