"""`asca demo` (feat-asca-demo) and the --home-only mode it runs the audit with."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from asca import cli, demo, dockerd, fsutil, tcc


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """A 'real' home with its own secret, and a temp root, so leaks and stray writes are visible."""
    real = tmp_path / "real-home"
    (real / ".claude" / "projects" / "p").mkdir(parents=True)
    secret = "sk-ant-api03-" + "Rq7" + "Zt2Vx9" * 12           # built here, shape only
    (real / ".claude" / "projects" / "p" / "s.jsonl").write_text(
        json.dumps({"content": f"ANTHROPIC_API_KEY={secret}"}) + "\n", encoding="utf-8")
    (real / ".claude" / "settings.json").write_text('{"permissions": {"allow": ["Bash(rm -rf /:*)"]}}',
                                                     encoding="utf-8")
    temp = tmp_path / "temp"
    temp.mkdir()
    for k in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(k, str(real))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(real / ".claude"))
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return {"real": real, "secret": secret, "temp": temp, "cwd": cwd}


def _tree(p: Path) -> dict:
    return {str(f.relative_to(p)): f.stat().st_mtime_ns for f in p.rglob("*") if f.is_file()}


def test_every_planted_item_is_found_with_its_severity(sandbox, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    r = demo.run_demo(work)
    rows = demo.check(r["findings"])
    assert all(ok for _, ok, _ in rows), [row for row in rows if not row[1]]
    assert any("chang" in x or "tamper" in x for x in r["inventory_rules"]), r["inventory_rules"]
    assert r["check_repo"][0] == 1


def test_only_planted_problems_show(sandbox, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    rules = {f["rule"] for f in demo.run_demo(work)["findings"]}
    planted = {rule for _, rule, _, _ in demo.EXPECTED}
    side_effects = {"agent.sandbox-disabled", "agent.endpoint-override", "python.pth-import-target",
                    "mcp.launcher-dep-drift"}                  # the same planted items, seen by a second rule
    assert rules <= planted | side_effects, rules - planted - side_effects
    assert "secret.file-permissions" not in rules and "git.global-fsmonitor-default" not in rules


def test_main_prints_banner_and_never_touches_the_real_home(sandbox, capsys):
    before_home, before_cwd = _tree(sandbox["real"]), _tree(sandbox["cwd"])
    env_before = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE", "CLAUDE_CONFIG_DIR", "APPDATA")}
    assert cli.run(["demo"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("=" * 72) and "asca DEMO" in out and "FAKE home folder" in out
    assert "❌" not in out and out.count("✅") == len(demo.EXPECTED) + 2
    assert sandbox["secret"] not in out and str(sandbox["real"]) not in out and "rm -rf" not in out
    assert "<demo>" not in out or "asca-demo-" not in out.split("<demo>")[0]        # temp paths are hidden
    assert _tree(sandbox["real"]) == before_home and _tree(sandbox["cwd"]) == before_cwd   # no writes there
    assert list(sandbox["temp"].iterdir()) == []                                       # temp folder deleted
    assert {k: os.environ.get(k) for k in env_before} == env_before and fsutil.HOME_ONLY is False


def test_planted_secrets_are_generated_and_marked(sandbox, tmp_path):
    (tmp_path / "h").mkdir()
    (tmp_path / "h2").mkdir()
    a, b = demo.plant(tmp_path / "h", seed=1), demo.plant(tmp_path / "h2", seed=2)
    assert a["key"].startswith("sk-ant-asca-demo-") and a["password"].startswith("asca-demo-")
    assert a["key"] != b["key"]
    src = Path(demo.__file__).read_text(encoding="utf-8")
    assert "sk-ant-asca-demo-" in src and a["key"] not in src                          # only the prefix is stored


def test_json_format_and_keep(sandbox, capsys):
    assert cli.run(["demo", "--format", "json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["demo"] is True and d["check_repo_exit"] == 1 and len(d["findings"]) >= len(demo.EXPECTED)
    assert cli.run(["demo", "--keep"]) == 0
    kept = [p for p in sandbox["temp"].iterdir()]
    assert len(kept) == 1 and "Demo files kept in" in capsys.readouterr().out


# ---------------------------------------------------------------- --home-only
def test_home_only_skips_host_checks_and_managed_settings(sandbox, monkeypatch, tmp_path):
    def boom(*a, **k):
        raise AssertionError("host-wide check ran in --home-only mode")
    monkeypatch.setattr(dockerd, "audit", boom)
    monkeypatch.setattr(tcc, "audit", boom)
    seen = []
    real_system = fsutil.system
    monkeypatch.setattr(fsutil, "system", lambda *p: seen.append(fsutil.HOME_ONLY) or real_system(*p))
    out = tmp_path / "r"
    rc = cli.run(["--home-only", "--no-hermes", "--format", "none", "-o", str(out)])
    assert rc in (0, 1) and seen and all(seen) and fsutil.system(Path("/etc/x")) == []
    rules = {f["rule"] for f in json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]}
    assert "secret.session-history" in rules                  # the home folder is still scanned
    assert cli.run(["--no-hermes", "--no-docker-daemon", "--no-tcc", "--format", "none", "-o", str(out)]) in (0, 1)
    assert fsutil.HOME_ONLY is False                          # reset by a normal run


def test_home_only_ignores_environment_overrides(sandbox, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "projects" / "q").mkdir(parents=True)
    (elsewhere / "projects" / "q" / "s.jsonl").write_text(
        json.dumps({"content": "ANTHROPIC_API_KEY=" + sandbox["secret"]}) + "\n", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(elsewhere))
    out = tmp_path / "r"
    cli.run(["--home-only", "--no-hermes", "--format", "none", "-o", str(out)])
    locs = [f["location"] for f in json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]]
    assert not any(str(elsewhere) in loc for loc in locs)
