"""Tests for `asca inventory`: discovery, hashing budgets, every change type, alerting, safety."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from asca import cli as asca_cli
from asca import report
from asca.inventory import cli, collect, diff
from asca.inventory.hashing import MiB, Budget, Limits, tree_hash
from asca.model import Severity


# ------------------------------------------------------------------ fixtures

def _ext(home: Path, ide_dir: str, publisher: str, name: str, version: str, *, code: str = "exports.a=1;\n",
         publisher_id: str = "", source: str = "gallery", extra: dict | None = None, listed: bool = True) -> Path:
    root = home / ide_dir
    d = root / f"{publisher}.{name}-{version}"
    (d / "dist").mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"publisher": publisher, "name": name, "version": version}))
    (d / "dist" / "extension.js").write_text(code)
    (d / "README.md").write_text("docs are not code\n")
    for rel, content in (extra or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(content) if isinstance(content, bytes) else (d / rel).write_text(content)
    if listed:
        mf = root / "extensions.json"
        entries = [e for e in (json.loads(mf.read_text()) if mf.exists() else [])
                   if e["identifier"]["id"] != f"{publisher}.{name}".lower()]
        entries.append({"identifier": {"id": f"{publisher}.{name}".lower()}, "version": version,
                        "relativeLocation": d.name,
                        "metadata": {"publisherId": publisher_id or f"uuid-{publisher}",
                                     "publisherDisplayName": publisher.title(), "source": source}})
        mf.write_text(json.dumps(entries))
    return d


def _remove_ext(home: Path, ide_dir: str, eid: str) -> None:
    mf = home / ide_dir / "extensions.json"
    mf.write_text(json.dumps([e for e in json.loads(mf.read_text()) if e["identifier"]["id"] != eid]))


def _hermes(home: Path) -> Path:
    h = home / "hermes"
    sk = h / "skills"
    (sk / "notes" / "my-notes").mkdir(parents=True)
    (sk / "notes" / "my-notes" / "SKILL.md").write_text("---\nname: my-notes\n---\nTake notes.\n")
    (sk / "dev" / "github").mkdir(parents=True)
    (sk / "dev" / "github" / "SKILL.md").write_text("---\nname: github\n---\nUse gh.\n")
    (sk / ".bundled_manifest").write_text("github:aaaa1111\n")
    (sk / "trader").mkdir()
    (sk / "trader" / "SKILL.md").write_text("---\nname: trader\n---\nTrade.\n")
    (sk / ".hub").mkdir()
    (sk / ".hub" / "lock.json").write_text(json.dumps({"installed": {"trader": {
        "source": "skills.sh", "identifier": "skills-sh/SomeOrg/repo/skills/trader", "trust_level": "community",
        "content_hash": "sha256:1111"}}}))
    pl = h / "plugins" / "homeassistant"
    pl.mkdir(parents=True)
    (pl / "plugin.yaml").write_text("name: homeassistant\nversion: 2.0.1\nauthor: NousResearch\n")
    (pl / "__init__.py").write_text("X = 1\n")
    (pl / ".hermes-catalog.json").write_text(json.dumps(
        {"catalog_name": "homeassistant", "repo": "https://github.com/NousResearch/hermes-official-plugins",
         "sha": "682b22d019a1109421faa62efe43e16b23c2ebef"}))
    (h / "plugins" / "achievements-data").mkdir()                      # state only: not a plugin
    (h / "plugins" / "achievements-data" / "state.json").write_text("{}")
    (h / "config.yaml").write_text("mcp_servers:\n  fs:\n    command: npx\n    args:\n      - -y\n"
                                   "      - '@modelcontextprotocol/server-filesystem@1.0.0'\n"
                                   "      - /tmp\n    env:\n      TOKEN: sk-not-read\n")
    return h


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    h = _hermes(home)
    sent: list[str] = []
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (sent.append(text), (True, "sent"))[1])
    envf = tmp_path / "tg.env"
    envf.write_text("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=5\n")
    state = tmp_path / "state"

    def run(*extra, telegram="change", check=None):
        argv = ["--dir", str(state), "--home", str(home), "--hermes-home", str(h), "--format", "none",
                "--telegram", telegram, "--env-file", str(envf), *extra]
        rc = cli.run(argv)
        rep = json.loads((state / "inventory-latest.json").read_text())
        return rc, rep

    return type("E", (), {"home": home, "hermes": h, "sent": sent, "state": state, "run": staticmethod(run)})


def _rules(rep, min_sev="info"):
    order = ["info", "low", "medium", "high", "critical"]
    return {(f["rule"], f["severity"]) for f in rep["findings"]
            if order.index(f["severity"]) >= order.index(min_sev) and not f["suppressed"]}


# ------------------------------------------------------------------ discovery

def test_discovers_every_source(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    _ext(env.home, ".vscode/extensions", "ms-python", "python", "2026.1.0")
    (env.home / ".claude" / "plugins" / "cache" / "x").mkdir(parents=True)
    (env.home / ".claude" / "plugins" / "cache" / "x" / "plugin.json").write_text("{}")
    (env.home / ".claude" / "plugins" / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": {
        "attention@claude-community": [{"scope": "user", "version": "1.1.0",
                                        "installPath": str(env.home / ".claude" / "plugins" / "cache" / "x")}]}}))
    oc = env.home / ".openclaw" / "extensions" / "matrix"
    oc.mkdir(parents=True)
    (oc / "package.json").write_text(json.dumps({"name": "@openclaw/matrix", "version": "1.0.0"}))
    (oc / "index.js").write_text("1")
    rc, rep = env.run()
    assert rc == 0 and rep["first_run"] and env.sent == []                      # first run learns silently
    kinds = {i["kind"]: i for i in rep["items"]}
    assert rep["counts"] == {"ide-extension": 2, "claude-plugin": 1, "openclaw-extension": 1, "mcp-server": 1,
                             "hermes-plugin": 1, "skill": 3}
    ext = next(i for i in rep["items"] if i["id"] == "anthropic.claude-code")
    assert (ext["source"], ext["publisher"], ext["publisher_id"], ext["version"], ext["files"]) == \
        ("cursor", "anthropic", "uuid-anthropic", "2.1.300", 2)                  # package.json + dist js, not README
    mcp = kinds["mcp-server"]
    assert (mcp["publisher"], mcp["version"]) == ("@modelcontextprotocol", "1.0.0")
    assert "sk-not-read" not in json.dumps(rep) and "sk-not-read" not in (env.state / "state.json").read_text()
    pol = {i["id"]: (i["policy"], i["publisher"], i["version"]) for i in rep["items"] if i["kind"] == "skill"}
    assert pol == {"notes/my-notes": ("local", "local", ""), "dev/github": ("bundled", "builtin", "bundled:aaaa1111"),
                   "trader": ("managed", "someorg", "sha256:1111")}
    assert kinds["hermes-plugin"]["version"] == "2.0.1@682b22d019a1" and kinds["hermes-plugin"]["publisher"] == "nousresearch"
    assert kinds["openclaw-extension"]["publisher"] == "@openclaw"
    for p in (env.state, env.state / "state.json", env.state / "inventory-latest.md"):
        assert p.stat().st_mode & 0o077 == 0


def test_folder_fallback_skips_obsolete_and_keeps_newest(tmp_path):
    root = tmp_path / ".vscode" / "extensions"
    _ext(tmp_path, ".vscode/extensions", "pub", "tool", "1.0.0", listed=False)
    _ext(tmp_path, ".vscode/extensions", "pub", "tool", "1.2.0", listed=False)
    _ext(tmp_path, ".vscode/extensions", "pub", "gone", "1.0.0", listed=False)
    (root / ".obsolete").write_text(json.dumps({"pub.gone-1.0.0": True}))
    out = collect.Collected()
    collect.ide_extensions(tmp_path, Budget(Limits()), out)
    assert [(i.id, i.version) for i in out.items] == [("pub.tool", "1.2.0")]


def test_corrupt_extensions_json_fails_closed(env):
    _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    (env.home / ".cursor" / "extensions" / "extensions.json").write_text("{not json")
    rc, rep = env.run()
    assert rc == 1 and ("scanner.parse-error", "high") in _rules(rep)
    assert any(i["id"] == "pub.tool" for i in rep["items"])                    # still inventoried via folders


@pytest.mark.parametrize("spec,expect", [
    ({"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]}, ("@scope", "1.2.3")),
    ({"command": "npx", "args": ["-y", "left-pad@2"]}, ("left-pad", "2")),
    ({"command": "uvx", "args": ["mcp-server-git==0.6.2"]}, ("mcp-server-git", "0.6.2")),
    ({"command": "uvx", "args": ["--from", "git+https://x/y@abc", "tool"]}, ("git+https://x/y", "abc")),
    ({"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/org/img:1.4"]}, ("ghcr.io/org", "1.4")),
    ({"command": "docker", "args": ["run", "ghcr.io/org/img@sha256:abc"]}, ("ghcr.io/org", "sha256:abc")),
    ({"url": "https://mcp.notion.com/mcp"}, ("mcp.notion.com", "")),
])
def test_mcp_identity(spec, expect):
    assert collect.mcp_identity(spec)[:2] == expect


def test_mcp_hash_ignores_env_values_but_not_names():
    a = collect.mcp_identity({"command": "npx", "args": ["x@1"], "env": {"K": "one"}})[2]
    assert a == collect.mcp_identity({"command": "npx", "args": ["x@1"], "env": {"K": "two"}})[2]
    assert a != collect.mcp_identity({"command": "npx", "args": ["x@1"], "env": {"K2": "one"}})[2]


# ------------------------------------------------------------------ hashing budgets

def test_hash_is_deterministic_and_budgeted(tmp_path):
    d = tmp_path / "ext"
    (d / "node_modules" / "dep").mkdir(parents=True)
    (d / "a.js").write_bytes(b"a" * 1000)
    (d / "b.js").write_bytes(b"b" * 3000)
    (d / "node_modules" / "dep" / "index.js").write_bytes(b"n" * 2000)
    (d / "logo.png").write_bytes(b"\x89PNG" * 100)
    lim = Limits(item_cap=2500, node_modules_cap=1000, total=10_000)
    one, two = tree_hash(d, budget=Budget(lim)), tree_hash(d, budget=Budget(lim))
    assert one.digest == two.digest and one.partial and one.files == 1             # only a.js fits
    assert "node_modules cap" in one.note and "item cap" in one.note
    full = tree_hash(d, budget=Budget(Limits()))
    assert full.files == 3 and not full.partial                                     # png is not code
    skipped = tree_hash(d, budget=Budget(Limits(total=100)))
    assert skipped.digest is None and "budget" in skipped.note


def test_symlinks_are_hashed_not_followed(tmp_path):
    d = tmp_path / "ext"
    d.mkdir()
    secret = tmp_path / "outside.js"
    secret.write_text("outside")
    os.symlink(secret, d / "link.js")
    h1 = tree_hash(d, budget=Budget(Limits())).digest
    secret.write_text("changed outside")
    assert tree_hash(d, budget=Budget(Limits())).digest == h1                      # target content not read
    (d / "link.js").unlink()
    os.symlink(tmp_path / "elsewhere.js", d / "link.js")
    assert tree_hash(d, budget=Budget(Limits())).digest != h1                      # retargeting is a change


def test_budget_hit_is_low_finding(env):
    _ext(env.home, ".cursor/extensions", "big", "ext", "1.0.0", extra={"dist/huge.js": b"x" * (2 * MiB)})
    rc, rep = env.run("--item-cap-mb", "1")
    assert rc == 0 and ("inventory.hash-budget", "low") in _rules(rep)


# ------------------------------------------------------------------ change types

def test_no_change_is_quiet(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    rc, rep = env.run()
    assert rc == 0 and _rules(rep) == set() and env.sent == []


def test_tamper_same_version_is_high_and_alerts_once(env):
    d = _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    (d / "dist" / "extension.js").write_text("exports.a=1; require('child_process').exec('curl …');\n")
    rc, rep = env.run()
    assert rc == 1 and ("inventory.tamper", "high") in _rules(rep)
    assert len(env.sent) == 1 and "files changed without a version change" in env.sent[0]
    rc, rep = env.run()                                                             # learned: quiet again
    assert rc == 0 and len(env.sent) == 1


def test_non_code_change_is_not_tamper(env):
    d = _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    (d / "README.md").write_text("edited docs\n")
    rc, rep = env.run()
    assert rc == 0 and _rules(rep) == set()


def test_version_bump_is_digest_only(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.301", code="exports.a=2;\n")
    rc, rep = env.run()
    assert rc == 0 and _rules(rep) == {("inventory.version-changed", "info")} and env.sent == []
    assert "Digest (no alert)" in (env.state / "inventory-latest.md").read_text()


def test_publisher_id_change_is_high(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300", publisher_id="uuid-a")
    env.run()
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300", publisher_id="uuid-evil")
    rc, rep = env.run()
    assert rc == 1 and ("inventory.publisher-changed", "high") in _rules(rep)


def test_same_name_new_publisher_is_a_swap(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    _remove_ext(env.home, ".cursor/extensions", "anthropic.claude-code")
    _ext(env.home, ".cursor/extensions", "anthrop1c", "claude-code", "2.1.300")
    rc, rep = env.run()
    r = _rules(rep)
    assert rc == 1 and ("inventory.publisher-changed", "high") in r
    assert not any(x[0] in ("inventory.new", "inventory.removed") for x in r)       # one event, not two


def test_new_item_and_new_publisher(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    _ext(env.home, ".cursor/extensions", "anthropic", "other-tool", "1.0.0")         # known publisher
    _ext(env.home, ".cursor/extensions", "rando", "helper", "0.0.1")                  # unknown publisher
    rc, rep = env.run()
    news = [f for f in rep["findings"] if f["rule"] == "inventory.new"]
    pubs = [f for f in rep["findings"] if f["rule"] == "inventory.new-publisher"]
    assert rc == 0 and len(news) == 2 and all(f["severity"] == "medium" for f in news)
    assert [f["title"] for f in pubs] == ["First ide-extension from publisher `rando`"]
    assert len(env.sent) == 1


def test_approved_publisher_and_write_approved(env, tmp_path):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.300")
    env.run()
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps({"approved_publishers": ["Rando"]}))
    _ext(env.home, ".cursor/extensions", "rando", "helper", "0.0.1")
    rc, rep = env.run("--baseline", str(base))
    assert ("inventory.new", "medium") in _rules(rep) and not any(f["rule"] == "inventory.new-publisher"
                                                                  for f in rep["findings"])
    assert cli.run(["--dir", str(env.state), "--home", str(env.home), "--hermes-home", str(env.hermes),
                    "--write-approved", str(base)]) == 0
    assert {"anthropic", "rando", "nousresearch"} <= set(json.loads(base.read_text())["approved_publishers"])
    assert base.stat().st_mode & 0o077 == 0


def test_removed_is_info(env):
    _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    env.run()
    _remove_ext(env.home, ".cursor/extensions", "pub.tool")
    rc, rep = env.run()
    assert rc == 0 and _rules(rep) == {("inventory.removed", "info")} and env.sent == []


def test_sideload_switch_is_medium(env):
    _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    env.run()
    _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0", source="vsix")
    rc, rep = env.run()
    assert ("inventory.origin-changed", "medium") in _rules(rep)


def test_skill_policies(env):
    env.run()
    sk = env.hermes / "skills"
    (sk / "notes" / "my-notes" / "SKILL.md").write_text("---\nname: my-notes\n---\nEdited by me.\n")
    (sk / "dev" / "github" / "SKILL.md").write_text("---\nname: github\n---\nEdited bundled.\n")
    (sk / "trader" / "run.py").write_text("import os\n")
    rc, rep = env.run()
    assert _rules(rep) == {("inventory.edited", "info"), ("inventory.modified-bundled", "low"),
                           ("inventory.tamper", "high")} and rc == 1
    # Hermes updates a bundled skill: the manifest hash moves too -> version change, digest only
    (sk / ".bundled_manifest").write_text("github:bbbb2222\n")
    (sk / "dev" / "github" / "SKILL.md").write_text("---\nname: github\n---\nNew upstream.\n")
    rc, rep = env.run()
    assert _rules(rep) == {("inventory.version-changed", "info")}


def test_plugin_tamper_and_update(env):
    env.run()
    pl = env.hermes / "plugins" / "homeassistant"
    (pl / "__init__.py").write_text("import os; os.system('id')\n")
    rc, rep = env.run()
    assert ("inventory.tamper", "high") in _rules(rep)
    cat = json.loads((pl / ".hermes-catalog.json").read_text())
    cat["sha"] = "1" * 40
    (pl / ".hermes-catalog.json").write_text(json.dumps(cat))
    (pl / "__init__.py").write_text("X = 2\n")
    rc, rep = env.run()
    assert _rules(rep) == {("inventory.version-changed", "info")}


def test_mcp_definition_change_is_medium(env):
    env.run()
    cfg = env.hermes / "config.yaml"
    cfg.write_text(cfg.read_text().replace("/tmp", "/"))
    rc, rep = env.run()
    assert _rules(rep) == {("inventory.definition-changed", "medium")} and len(env.sent) == 1


def test_known_bad_build_is_critical_and_alerts_once(env):
    _ext(env.home, ".cursor/extensions", "anthropic", "claude-code", "2.1.313")
    rc, rep = env.run()                                                             # even on the first run
    assert rc == 1 and ("inventory.known-bad", "critical") in _rules(rep) and len(env.sent) == 1
    rc, rep = env.run()
    assert rc == 1 and len(env.sent) == 1                                           # still failing, no re-alert


def test_known_bad_file(env, tmp_path):
    kb = tmp_path / "kb.json"
    kb.write_text(json.dumps([{"kind": "ide-extension", "id": "pub.tool", "versions": ["1.0.0"], "summary": "x"}]))
    _ext(env.home, ".vscode/extensions", "pub", "tool", "1.0.0")
    rc, rep = env.run("--known-bad", str(kb))
    assert ("inventory.known-bad", "critical") in _rules(rep)


def test_each_new_tamper_is_a_new_finding(env, tmp_path):
    d = _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    env.run(telegram="never")
    (d / "dist" / "extension.js").write_text("changed")
    rc, rep = env.run(telegram="never")
    fp = next(f["fingerprint"] for f in rep["findings"] if f["rule"] == "inventory.tamper")
    (d / "dist" / "extension.js").write_text("changed again")
    rc, rep = env.run(telegram="never")
    fp2 = next(f["fingerprint"] for f in rep["findings"] if f["rule"] == "inventory.tamper")
    assert fp != fp2                                                                # a new tamper is a new finding


def test_baseline_suppression(env, tmp_path):
    d = _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    env.run(telegram="never")
    (d / "dist" / "extension.js").write_text("changed")
    st = json.loads((env.state / "state.json").read_text())
    rc, rep = env.run(telegram="never")
    fp = next(f["fingerprint"] for f in rep["findings"] if f["rule"] == "inventory.tamper")
    (env.state / "state.json").write_text(json.dumps(st))                          # replay the same change
    base = tmp_path / "b.json"
    base.write_text(json.dumps({"suppress": [{"fingerprint": fp, "reason": "I patched it"}]}))
    rc, rep = env.run("--baseline", str(base))
    assert rc == 0 and env.sent == [] and [f["suppressed"] for f in rep["findings"]] == [True]


def test_limits_change_does_not_cry_tamper(env):
    _ext(env.home, ".cursor/extensions", "big", "ext", "1.0.0", extra={"dist/huge.js": b"x" * (2 * MiB)})
    env.run("--item-cap-mb", "1")
    rc, rep = env.run("--item-cap-mb", "8")
    assert ("inventory.rehashed", "info") in _rules(rep) and ("inventory.tamper", "high") not in _rules(rep)


# ------------------------------------------------------------------ alerting / state / safety

def test_failed_delivery_does_not_save_state(env, monkeypatch):
    d = _ext(env.home, ".cursor/extensions", "pub", "tool", "1.0.0")
    env.run()
    (d / "dist" / "extension.js").write_text("changed")
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (False, "HTTP 401"))
    envf = env.state.parent / "tg.env"
    assert cli.run(["--dir", str(env.state), "--home", str(env.home), "--hermes-home", str(env.hermes),
                    "--format", "none", "--telegram", "change", "--env-file", str(envf)]) == 2
    monkeypatch.setattr(report, "send_telegram", lambda text, **k: (env.sent.append(text), (True, "ok"))[1])
    rc, rep = env.run()
    assert ("inventory.tamper", "high") in _rules(rep) and len(env.sent) == 1     # retried, not lost


def test_corrupt_state_is_an_error(env):
    env.run()
    (env.state / "state.json").write_text("{oops")
    assert cli.run(["--dir", str(env.state), "--home", str(env.home), "--no-hermes", "--format", "none"]) == 2


def test_telegram_text_escaped_and_bounded():
    from asca.model import Finding
    fs = [Finding("inventory.new", "inventory", Severity.MEDIUM, f"New <b>{i}</b>", "/x", str(i)) for i in range(400)]
    t = cli.to_telegram(fs, host="h<1>", alert_on=Severity.MEDIUM, items=3, report_path="/r")
    assert "<b>0</b>" not in t and "&lt;b&gt;" in t and len(t) <= 4096 and "more" in t


def test_dispatch_from_main_cli(env, capsys):
    rc = asca_cli.run(["inventory", "--dir", str(env.state), "--home", str(env.home), "--no-hermes"])
    assert rc == 0 and "asca inventory: PASS" in capsys.readouterr().out


def test_never_executes_or_runs_git(env, monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise AssertionError("inventory tried to execute something")
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    pl = env.hermes / "plugins" / "gitplug"
    (pl / ".git" / "refs" / "heads").mkdir(parents=True)
    (pl / "__init__.py").write_text("")
    (pl / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (pl / ".git" / "refs" / "heads" / "main").write_text("c" * 40 + "\n")
    (pl / ".git" / "config").write_text('[core]\n\tfsmonitor = touch /tmp/pwned\n[remote "origin"]\n'
                                        '\turl = https://github.com/SomeOne/gitplug.git\n')
    rc, rep = env.run()
    item = next(i for i in rep["items"] if i["id"] == "gitplug")
    assert item["version"] == "c" * 12 and item["publisher"] == "someone" and item["origin"] == "git"
    assert not Path("/tmp/pwned").exists()
