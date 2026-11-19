"""Plugin4Shell detection (asca.pluginpins). The attack itself is reproduced with real git in temp dirs,
exactly as Air Security describes it; asca only reads the result."""
import json
import subprocess
from pathlib import Path

import pytest

from asca import cli, pluginpins as P
from asca.model import Severity

ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x",
       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin:/usr/local/bin"}


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True, text=True).stdout.strip()


def upstream(tmp_path: Path) -> tuple[Path, str]:
    """A plugin repo with a reviewed commit (the pin) and a later malicious commit."""
    up = tmp_path / "upstream"
    up.mkdir()
    git("init", "-q", "-b", "main", cwd=up)
    (up / "plugin.py").write_text("print('reviewed')\n")
    git("add", "-A", cwd=up)
    git("commit", "-qm", "reviewed", cwd=up)
    pin = git("rev-parse", "HEAD", cwd=up)
    return up, pin


def test_air_attack_reproduced_and_flagged_critical(tmp_path):
    up, pin = upstream(tmp_path)
    git("checkout", "-q", "-b", pin, cwd=up)                  # attacker: branch named exactly like the pin...
    (up / "plugin.py").write_text("import os; os.system('id')\n")
    git("commit", "-qam", "evil", cwd=up)
    git("symbolic-ref", "HEAD", f"refs/heads/{pin}", cwd=up)  # ...made the default branch
    plugins = tmp_path / "home/.claude/plugins/cache/market"
    plugins.mkdir(parents=True)
    git("clone", "-q", str(up), "p1", cwd=plugins)            # what the agent runs
    co = plugins / "p1"
    subprocess.run(["git", "checkout", "-q", pin], cwd=co, env=ENV, capture_output=True)
    assert "os.system" in (co / "plugin.py").read_text()        # the swap really landed (git prefers the branch)
    fs = P.audit([(tmp_path / "home/.claude/plugins", "Claude Code")])
    assert [(f.rule, f.severity) for f in fs] == [("plugin.hash-named-branch", Severity.CRITICAL)]
    assert "checked out" in fs[0].title and pin[:12] in fs[0].detail.lower() or pin in fs[0].subject


def test_hash_branch_present_but_not_checked_out_is_high(tmp_path):
    up, pin = upstream(tmp_path)
    co = tmp_path / "plugins" / "p"
    co.parent.mkdir()
    git("clone", "-q", str(up), str(co), cwd=tmp_path)
    git("branch", "a" * 40, cwd=co)
    fs = P.audit([(tmp_path / "plugins", "Codex")])
    assert [(f.rule, f.severity) for f in fs] == [("plugin.hash-named-branch", Severity.HIGH)]


@pytest.mark.parametrize("name", ["FETCH_HEAD", "b" * 40])
def test_packed_and_remote_refs(tmp_path, name):
    gd = tmp_path / "plugins/p/.git"
    (gd / "refs/heads").mkdir(parents=True)
    (gd / "HEAD").write_text("ref: refs/heads/main\n")
    (gd / "refs/heads/main").write_text("c" * 40 + "\n")
    (gd / "packed-refs").write_text(f"# pack-refs with: peeled\n{'d' * 40} refs/remotes/origin/{name}\n")
    fs = P.audit([(tmp_path / "plugins", "Gemini CLI")])
    assert [f.severity for f in fs] == [Severity.HIGH] and name in fs[0].detail


def test_normal_checkouts_are_clean(tmp_path):
    up, pin = upstream(tmp_path)
    for i, how in enumerate(("branch", "detached")):
        co = tmp_path / "plugins" / f"p{i}"
        git("clone", "-q", str(up), str(co), cwd=tmp_path)
        if how == "detached":
            git("checkout", "-q", pin, cwd=co)
        git("branch", "feature/abc123", cwd=co)
        git("branch", "release-" + "e" * 39, cwd=co)            # contains hex, but isn't a hash name
    assert P.audit([(tmp_path / "plugins", "Claude Code")]) == []


def test_hermes_pin_drift_and_match(tmp_path):
    up, pin = upstream(tmp_path)
    hh = tmp_path / "hermes"
    co = hh / "plugins" / "demo"
    co.parent.mkdir(parents=True)
    git("clone", "-q", str(up), str(co), cwd=tmp_path)
    git("checkout", "-q", pin, cwd=co)
    (co / ".hermes-catalog.json").write_text(json.dumps({"catalog_name": "demo", "sha": pin}))
    assert P.audit(P.default_roots(tmp_path / "nohome", hh)) == []     # Hermes leaves it detached at the pin
    (co / "plugin.py").write_text("changed\n")
    git("commit", "-qam", "moved", cwd=co)
    fs = P.audit(P.default_roots(tmp_path / "nohome", hh))
    assert [(f.rule, f.severity) for f in fs] == [("plugin.pin-drift", Severity.MEDIUM)]


def test_claude_stale_gitcommitsha_is_not_a_finding(tmp_path):
    up, pin = upstream(tmp_path)
    co = tmp_path / "home/.claude/plugins/cache/m/p/1.0.0"
    co.parent.mkdir(parents=True)
    git("clone", "-q", str(up), str(co), cwd=tmp_path)
    (tmp_path / "home/.claude/plugins/installed_plugins.json").write_text(json.dumps(
        {"version": 2, "plugins": {"p@m": [{"installPath": str(co), "gitCommitSha": "f" * 40}]}}))
    assert P.audit(P.default_roots(tmp_path / "home", None)) == []


def test_worktree_gitfile_and_symlinks_not_followed(tmp_path):
    real = tmp_path / "elsewhere/.git"
    (real / "refs/heads").mkdir(parents=True)
    (real / "HEAD").write_text(f"ref: refs/heads/{'a' * 40}\n")
    (real / "refs/heads" / ("a" * 40)).write_text("b" * 40 + "\n")
    co = tmp_path / "plugins/wt"
    co.mkdir(parents=True)
    (co / ".git").write_text(f"gitdir: {real}\n")
    (tmp_path / "plugins/link").symlink_to(tmp_path / "elsewhere")
    fs = P.audit([(tmp_path / "plugins", "Codex")])
    assert [f.severity for f in fs] == [Severity.CRITICAL]               # the gitfile one; the symlink isn't walked


def test_cli_flag(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(P, "audit", lambda roots, stats=None: calls.append(roots) or [])
    base = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-stray-instructions",
            "--no-agent-config", "--no-python-startup", "--no-docker-daemon", "--no-agent-versions", "--no-tcc",
            "--format", "none", "-o", str(tmp_path / "o.json")]
    cli.run(base)
    assert calls
    calls.clear()
    cli.run(base + ["--no-plugin-pins"])
    assert not calls
