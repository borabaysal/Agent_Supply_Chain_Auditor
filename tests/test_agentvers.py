"""Version advisories for installed coding agents (asca.agentvers). Installs are fake folders; nothing runs."""
import json
import os
import plistlib
from pathlib import Path

import pytest

from asca import advisories, agentvers as A, cli
from asca.model import Severity


def pkg(root: Path, name: str, version: str) -> Path:
    p = root / name / "package.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"name": name, "version": version, "bin": {"x": "cli.js"}}))
    return p


@pytest.mark.parametrize("v,rng,ok", [
    ("2.1.128", "< 2.1.129", True), ("2.1.129", "< 2.1.129", False),
    ("2.1.100", ">= 2.0.68, < 2.1.260", True), ("2.0.67", ">= 2.0.68, < 2.1.260", False),
    ("0.23.0", "<= 0.23.0", True), ("0.40.0-preview.2", "= 0.40.0-preview.2", True),
    ("0.40.0-preview.3", "= 0.40.0-preview.2", False), ("0.39.1-preview.1", "< 0.39.1", True),
    ("1.15961.9", ">= 1.1.3918, < 1.15962.0", True), ("garbage", "< 1.0", False), ("1.0.0", "~1.0", False),
])
def test_ranges(v, rng, ok):
    assert A.in_range(v, rng) is ok


def test_detects_npm_nvm_native_brew_and_desktop(tmp_path):
    home = tmp_path / "home"
    pkg(home / ".npm-global/lib/node_modules", "@anthropic-ai/claude-code", "2.1.50")
    pkg(home / ".nvm/versions/node/v22.1.0/lib/node_modules", "@openai/codex", "0.23.0")
    pkg(home / ".bun/install/global/node_modules", "@google/gemini-cli", "0.40.0-preview.2")
    vdir = home / ".local/share/claude/versions"
    vdir.mkdir(parents=True)
    for v in ("2.1.120", "2.1.140"):
        (vdir / v).write_text("binary")
    (home / ".local/bin").mkdir(parents=True)
    os.symlink(vdir / "2.1.120", home / ".local/bin/claude")         # active is the older one
    brew = tmp_path / "Cellar"
    (brew / "block-goose-cli" / "1.43.0").mkdir(parents=True)
    (brew / "goose" / "3.20.0").mkdir(parents=True)                  # pressly/goose, a different tool
    apps = tmp_path / "Applications"
    (apps / "Claude.app/Contents").mkdir(parents=True)
    with (apps / "Claude.app/Contents/Info.plist").open("wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "com.anthropic.claudefordesktop", "CFBundleShortVersionString": "1.3000.0"}, fh)
    got = {(i["agent"], i["version"]) for i in A.installed(home, env={}, brew_dirs=[brew], app_dirs=[apps])}
    assert got == {("claude-code", "2.1.50"), ("claude-code", "2.1.120"), ("codex", "0.23.0"),
                   ("gemini-cli", "0.40.0-preview.2"), ("goose", "1.43.0"), ("claude-desktop", "1.3000.0")}


def test_native_without_link_uses_newest_and_placeholders_ignored(tmp_path):
    home = tmp_path
    vdir = home / ".local/share/claude/versions"
    vdir.mkdir(parents=True)
    for v in ("2.1.9", "2.1.10", "latest"):
        (vdir / v).write_text("")
    pkg(home / ".npm-global/lib/node_modules", "@openai/codex", "not-a-version")
    assert A.installed(home, env={}, brew_dirs=[], app_dirs=[]) == [
        {"agent": "claude-code", "version": "2.1.10", "where": str(vdir / "2.1.10")}]


def test_finding_groups_advisories_and_names_repo_only_ones(tmp_path):
    inst = [{"agent": "claude-code", "version": "2.1.128", "where": "/x/package.json"}]
    fs = A.audit({}, installs=inst)
    assert len(fs) == 1
    f = fs[0]
    assert f.rule == "agent.vulnerable-version" and f.severity >= Severity.HIGH
    assert "Claude Code 2.1.128 is affected by" in f.title
    assert "GHSA-5j29-h97v-84ch" in f.detail and "Only in the vendor's repository advisories" in f.detail
    assert "nothing was run" in f.detail
    assert "Upgrade Claude Code to" in f.remediation and "claude update" in f.remediation


def test_patched_versions_are_clean():
    inst = [{"agent": "claude-code", "version": "2.99.0", "where": "/x"}, {"agent": "codex", "version": "0.60.0", "where": "/y"},
            {"agent": "goose", "version": "1.44.0", "where": "/z"}]
    assert A.audit({}, installs=inst) == []


def test_codex_unfixed_advisory_says_so():
    f = A.audit({}, installs=[{"agent": "codex", "version": "0.23.0", "where": "/c"}])[0]
    assert f.severity == Severity.CRITICAL and "No fixed version is listed for GHSA-xrxf-jgv3-qmrm" in f.remediation


def test_online_merges_aliases_and_adds_new(tmp_path):
    def osv(eco, name, version, timeout):
        assert (eco, name) == ("npm", "@openai/codex")
        return [advisories.Advisory(ids={"GHSA-w5fx-fh39-j5rw", "CVE-2025-59532"}, severity=Severity.HIGH, summary="dup",
                                    fixed="0.39.0", sources={"osv"}),
                advisories.Advisory(ids={"GHSA-new0-0000-0000"}, severity=Severity.CRITICAL, summary="brand new, no CVE",
                                    fixed="", sources={"osv"})]

    def repo(r, packages, version, timeout):
        assert r == "openai/codex" and "@openai/codex" in packages
        return []
    inst = [{"agent": "codex", "version": "0.23.0", "where": "/c"}]
    f = A.audit({}, installs=inst, use_online=True,
                online_fn=lambda a, v: A.online(a, v, osv=osv, ghsa=lambda *x: [], repo=repo))[0]
    assert "3 known vulnerabilities" in f.title                                   # 2 bundled + 1 new; dup merged
    assert "GHSA-new0-0000-0000 (no CVE)" in f.detail and "have no CVE ID" in f.detail


def test_new_advisory_changes_the_subject_so_change_alerts_fire():
    inst = [{"agent": "codex", "version": "0.23.0", "where": "/c"}]
    s1 = A.audit({}, installs=inst)[0].subject
    extra = advisories.Advisory(ids={"GHSA-zzzz-zzzz-zzzz"}, severity=Severity.LOW, summary="x", sources={"osv"})
    s2 = A.audit({}, installs=inst, use_online=True,
                 online_fn=lambda a, v: A.online(a, v, osv=lambda *x: [extra], ghsa=lambda *x: [],
                                                 repo=lambda *x: []))[0].subject
    assert s1 != s2 and s1.startswith("codex@0.23.0:")


def test_feed_error_is_low_and_bundled_still_used():
    def boom(*a):
        raise OSError("offline")
    fs = A.audit({}, installs=[{"agent": "goose", "version": "1.40.0", "where": "/g"}], use_online=True,
                 online_fn=lambda a, v: A.online(a, v, osv=boom, ghsa=boom, repo=boom))
    rules = sorted(f.rule for f in fs)
    assert rules == ["agent.vulnerable-version", "scanner.feed-unavailable"]


def test_query_repo_filters_package_and_range():
    data = [{"ghsa_id": "GHSA-a", "cve_id": None, "severity": "high", "summary": "s", "html_url": "u",
             "vulnerabilities": [{"package": {"name": "@anthropic-ai/claude-code"}, "vulnerable_version_range": "< 2.1.129",
                                  "patched_versions": "2.1.129"}]},
            {"ghsa_id": "GHSA-b", "severity": "high", "summary": "desktop",
             "vulnerabilities": [{"package": {"name": "Claude Desktop"}, "vulnerable_version_range": "< 9.0.0"}]}]
    rows = A.query_repo("anthropics/claude-code", {"@anthropic-ai/claude-code"}, "2.1.100", get=lambda *a: data)
    assert [r["id"] for r in rows] == ["GHSA-a"] and rows[0]["fixed"] == "2.1.129"


def test_bundled_table_is_well_formed():
    reviewed, table = A.bundled()
    assert set(table) == set(A.AGENTS) and reviewed
    for agent, rows in table.items():
        for r in rows:
            assert r["id"].startswith("GHSA-") and r["ranges"] and r["severity"] in A._SEV
            assert all(A.parse(w) for rng in r["ranges"] for w in [x.strip().split()[-1] for x in rng.split(",")])


def test_cli_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "installed", lambda home=None: [{"agent": "codex", "version": "0.23.0", "where": "/c"}])
    base = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-stray-instructions",
            "--no-agent-config", "--no-python-startup", "--no-docker-daemon", "--format", "none"]
    out = tmp_path / "a.json"
    assert cli.run(base + ["-o", str(out)]) == 1
    assert any(f["rule"] == "agent.vulnerable-version" for f in json.loads(out.read_text())["findings"])
    assert cli.run(base + ["--no-agent-versions", "-o", str(out)]) == 0
