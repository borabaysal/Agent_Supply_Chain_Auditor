"""Tests for secrets in agent allow lists (asca.allowlist) and passwords typed into commands (asca.secrets)."""
from __future__ import annotations

import json
import secrets as pysecrets
import string
import struct
from pathlib import Path

import pytest

from asca import allowlist, cli, secrets, sessions
from asca.model import Severity


def rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(pysecrets.choice(alphabet) for _ in range(n))


def fake_password() -> str:            # mixed case + digits + symbol, never a dictionary word
    return "Q" + rnd(10) + "7!"


def fake_openrouter() -> str:
    return "sk-or-v1-" + pysecrets.token_hex(32)


def fake_github() -> str:
    return "ghp_" + rnd(36)


def _index(git: Path, paths) -> None:
    body = b""
    for p in sorted(paths):
        raw = p.encode()
        entry = b"\x00" * 60 + struct.pack(">H", min(len(raw), 0x0FFF)) + raw + b"\x00"
        body += entry + b"\x00" * (-len(entry) % 8)
    (git / "index").write_bytes(b"DIRC" + struct.pack(">II", 2, len(paths)) + body)


def make_repo(root: Path, files: dict, tracked=()) -> Path:
    wt = root / "repo"
    (wt / ".git").mkdir(parents=True)
    (wt / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (wt / ".git" / "config").write_text("[core]\n\tbare = false\n")
    for rel, content in files.items():
        p = wt / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content, indent=2))
    _index(wt / ".git", list(tracked))
    return wt


def jack_settings() -> tuple[dict, list[str]]:
    """Jack's reproduction: a committed settings.local.json with 4 secrets (DB password, OpenRouter key,
    MySQL password, GitHub token) plus one harmless rule. Values are generated per run."""
    db, orr, my, gh = fake_password(), fake_openrouter(), fake_password(), fake_github()
    allow = [f"Bash(PGPASSWORD={db} psql -h db.acme-prod.com -U admin -c 'select 1')",
             f"Bash(curl -H 'Authorization: Bearer {orr}' https://openrouter.ai/api/v1/models)",
             f"Bash(mysql -u root -p{my} -h 10.0.0.5)",
             f"Bash(git push https://x:{gh}@github.com/acme/app.git)",
             "Bash(npm test)"]
    return {"permissions": {"allow": allow}}, [db, orr, my, gh]


# ================================================================== password-in-command detector

def _hits(line: str):
    return [(r, sev, v) for r, sev, _l, v, _e in secrets.iter_line_secrets(line, set())]


@pytest.mark.parametrize("template,rule", [
    ("PGPASSWORD={v} psql -h db.acme-prod.com -U app", "secret.command-password"),
    ("MYSQL_PWD='{v}' mysql -h mysql.acme.io", "secret.command-password"),
    ("mysql -u root -p{v} -h 52.18.4.7 shop", "secret.command-password"),
    ("mysqldump --password={v} --host=db.acme.io shop", "secret.command-password"),
    ("sshpass -p '{v}' ssh deploy@51.15.20.30", "secret.command-password"),
    ("psql postgres://app:{v}@db.prod-acme.io:5432/app", "secret.command-password"),
    ("mongosh 'mongodb+srv://ops:{v}@cluster0.ab1cd.mongodb.net/x'", "secret.command-password"),
    ("amqp://svc:{v}@mq.acme.io:5672/", "secret.command-password"),
    ("curl -u admin:{v} https://api.acme.io/v1", "secret.command-password"),
    ("redis-cli -u redis://default:{v}@localhost:6379", "secret.command-password-private"),
    ("mysql -u root -p{v} -h 10.0.0.5", "secret.command-password-private"),
    ("PGPASSWORD={v} psql -U postgres", "secret.command-password-private"),          # no host: local socket
    ("PGPASSWORD={v} psql -h db.example.com", "secret.command-password-private"),     # documentation host
    ("psql postgres://u:{v}@postgres:5432/x", "secret.command-password-private"),     # compose service name
])
def test_command_password_positives(template, rule):
    v = fake_password()
    hits = _hits(template.format(v=v))
    assert [(r, val) for r, _s, val in hits] == [(rule, v)]
    assert hits[0][1] == secrets.RULE_SEVERITY[rule]


def test_bearer_token_including_jwt():
    jwt = "eyJ" + rnd(20) + "." + "eyJ" + rnd(30) + "." + rnd(43, string.ascii_letters + string.digits + "_-")
    assert [r for r, _s, _v in _hits(f"curl -H 'Authorization: Bearer {jwt}' https://api.acme.io")] == \
        ["secret.command-password"]


def test_provider_key_beats_command_rule():
    key = fake_openrouter()
    assert [r for r, _s, _v in _hits(f"curl -H 'Authorization: Bearer {key}' https://x.io")] == ["secret.openrouter-key"]
    gh = fake_github()
    assert [r for r, _s, _v in _hits(f"git push https://x:{gh}@github.com/a/b.git")] == ["secret.github-token"]


@pytest.mark.parametrize("line", [
    "PGPASSWORD=$PGPASSWORD psql -h db.acme.com", "PGPASSWORD=\"${DB_PASS}\" psql -h db.acme.com",
    "PGPASSWORD=DB_PASSWORD psql -h db.acme.com", "PGPASSWORD=password psql -h db.acme.com",
    "mysql -u root -p -h db.acme.com", "mysql -P 3306 -h db.acme.com", "mysql --password=<password> -h db.acme.com",
    "mysql --password --host db.acme.com", "--password=*** ", "postgres://user:password@db.acme.com/x",
    "postgres://user:${DB_PASS}@db.acme.com/x", "postgres://user:<password>@db.acme.com/x",
    "Authorization: Bearer $TOKEN", "Authorization: Bearer <your-token>", "Authorization: Bearer YOUR_API_TOKEN_HERE",
    "Bearer the-quick-brown-fox-jumps", "curl -u $USER:$PASS https://x.io", "curl -u user:pass https://x.io",
    "git clone https://github.com/acme/app.git", "sshpass -p \"$SSH_PASS\" ssh host", "sshpass -f ~/.pw ssh host",
    "https://user@github.com/acme/app.git", "see https://docs.acme.io/a:b@c for details",
    "psql postgresql://postgres:postgres@db:5432/x", "export PGPASSWORD=changeme",
])
def test_command_password_negatives(line):
    assert [h for h in _hits(line) if h[0].startswith("secret.command-password")] == []


@pytest.mark.parametrize("host,kind", [
    ("db.acme-prod.com", "public"), ("52.18.4.7", "public"), ("10.0.0.5", "private"), ("192.168.1.9", "private"),
    ("127.0.0.1", "private"), ("localhost", "private"), ("db", "private"), ("db.local", "private"),
    ("db.example.com", "private"), ("host.docker.internal", "private"), ("[::1]", "private"), (None, "none"),
])
def test_classify_host(host, kind):
    assert secrets.classify_host(host) == kind


def test_session_history_uses_detector_and_severity():
    v = fake_password()
    line = json.dumps({"type": "tool_use", "input": {"command": f"sshpass -p '{v}' ssh root@51.15.20.30 uptime"}})
    got = list(sessions.scan_line(line))
    assert [(r, val) for r, _l, _i, val in got] == [("secret.command-password", v)]
    assert sessions.triggered("psql postgres://app:x@db.acme.io/x")         # URL creds trigger the slow path


# ================================================================== allow rules: Jack's repo

def test_jack_four_secret_repo_end_to_end(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    settings, values = jack_settings()
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.local.json").write_text(json.dumps(settings))
    proj = tmp_path / "projects"
    proj.mkdir()
    make_repo(proj, {allowlist.LOCAL_SETTINGS: settings, "README.md": "# app\n"},
              tracked=[allowlist.LOCAL_SETTINGS, "README.md"])
    out = tmp_path / "r"
    rc = cli.run(["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history",
                  "--no-stray-instructions", "--no-python-startup", "--no-agent-config", "--repos", str(proj),
                  "-o", str(out), "--format", "none"])
    rep = json.loads(out.with_suffix(".json").read_text())
    md = out.with_suffix(".md").read_text()
    repo_hits = [f for f in rep["findings"] if f["rule"] == allowlist.RULE and "/projects/" in f["location"]]
    home_hits = [f for f in rep["findings"] if f["rule"] == allowlist.RULE and "/home/.claude/" in f["location"]]
    assert len(repo_hits) == 4 and len(home_hits) == 4
    assert sorted(f["severity"] for f in repo_hits) == ["high", "high", "high", "medium"]   # MySQL on 10.0.0.5
    assert all("committed" in f["title"] for f in repo_hits)
    committed = [f for f in rep["findings"] if f["rule"] == "repo.claude-local-settings-committed"]
    assert len(committed) == 1 and committed[0]["severity"] == "high"
    assert rc == 1
    for v in values:                                                      # never a raw secret in any report
        assert v not in json.dumps(rep) and v not in md
    assert committed[0]["remediation"].startswith("1) Rotate the credential first")


def test_ask_and_deny_rules_are_scanned_too(tmp_path):
    v = fake_password()
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"permissions": {"ask": [f"Bash(sshpass -p {v} ssh ops@51.15.20.30)"],
                                             "deny": [f"Bash(curl -u admin:{v}x https://api.acme.io)"]}}))
    f = allowlist.audit_settings_file(p, kind="claude")
    assert sorted(x.location.split("#")[1] for x in f) == ["permissions.ask[0]", "permissions.deny[0]"]


def test_clean_allow_rules_are_quiet(tmp_path):
    p = tmp_path / "settings.local.json"
    p.write_text(json.dumps({"permissions": {"allow": [
        "Bash(npm run:*)", "Bash(PGPASSWORD=$PGPASSWORD psql -h db.acme.com -c 'select 1')",
        "Bash(git push origin main)", "WebFetch(domain:docs.anthropic.com)", "Bash(mysql -u root -p -h db)"]}}))
    assert allowlist.audit_settings_file(p, kind="claude") == []


def test_committed_local_settings_without_secret_is_medium(tmp_path):
    wt = make_repo(tmp_path, {allowlist.LOCAL_SETTINGS: {"permissions": {"allow": ["Bash(npm test)"]}}},
                   tracked=[allowlist.LOCAL_SETTINGS])
    f = allowlist.audit_repo(wt, wt / ".git")
    assert [(x.rule, x.severity) for x in f] == [("repo.claude-local-settings-committed", Severity.MEDIUM)]


@pytest.mark.parametrize("gitignore,expected", [
    ("", True), ("node_modules/\n", True),
    (".claude/settings.local.json\n", False), ("/.claude/settings.local.json\n", False), (".claude/\n", False),
    ("**/settings.local.json\n", False), ("*.local.json\n", False), ("settings.local.json\n", False),
    (".claude/*\n!.claude/settings.json\n", False), (".claude/settings.local.json\n!.claude/settings.local.json\n", True),
    ("# .claude/settings.local.json\n", True), ("/settings.local.json\n", True),      # anchored to the repo root
])
def test_gitignore_check(tmp_path, gitignore, expected):
    files = {".claude/settings.json": {"permissions": {"allow": []}}}
    if gitignore:
        files[".gitignore"] = gitignore
    wt = make_repo(tmp_path, files, tracked=[".claude/settings.json"])
    f = allowlist.audit_repo(wt, wt / ".git")
    flagged = [(x.rule, x.severity) for x in f] == [("repo.claude-local-settings-not-ignored", Severity.LOW)]
    assert flagged is expected
    if expected:
        assert f[0].remediation == "echo '.claude/settings.local.json' >> .gitignore"


def test_gitignore_inside_claude_dir_counts(tmp_path):
    wt = make_repo(tmp_path, {".claude/.gitignore": "settings.local.json\n", ".claude/settings.json": "{}"})
    assert allowlist.audit_repo(wt, wt / ".git") == []


def test_repo_without_claude_dir_is_quiet(tmp_path):
    wt = make_repo(tmp_path, {"README.md": "x"}, tracked=["README.md"])
    assert allowlist.audit_repo(wt, wt / ".git") == []


# ================================================================== VS Code auto-approve + legacy stores

def test_vscode_user_and_workspace_auto_approve(tmp_path):
    home = tmp_path / "home"
    user = home / "Library" / "Application Support" / "Code" / "User"
    user.mkdir(parents=True)
    v1, v2, v3 = fake_password(), fake_password(), fake_password()
    (user / "settings.json").write_text(f"""{{
      // JSONC: comments and trailing commas
      "editor.fontSize": 13,
      "chat.tools.terminal.autoApprove": {{
        "npm test": true,
        "PGPASSWORD={v1} psql -h db.acme-prod.com": true,
        "/^sshpass -p {v2} ssh/": {{"approve": true, "matchCommandLine": true}},
      }},
      "chat.tools.urls.autoApprove": {{"https://ops:{v3}@grafana.acme.io/*": true}},
    }}""")
    cursor = home / ".config" / "Cursor" / "User"
    cursor.mkdir(parents=True)
    tok = fake_github()
    (cursor / "settings.json").write_text(json.dumps({"chat.agent.terminal.allowList": {f"gh auth login --with-token {tok}": True}}))
    f = allowlist.audit_home(home, {})
    assert len(f) == 4 and all(x.rule == allowlist.RULE and "VS Code agent" in x.title for x in f)
    keys = " ".join(x.location for x in f)
    assert "chat.tools.terminal.autoApprove" in keys and "chat.tools.urls.autoApprove" in keys
    assert "chat.agent.terminal.allowList" in keys
    wt = make_repo(tmp_path, {".vscode/settings.json": {"chat.tools.terminal.autoApprove": {
        f"curl -u admin:{v1} https://api.acme.io": True}}}, tracked=[".vscode/settings.json"])
    rf = allowlist.audit_repo(wt, wt / ".git")
    assert [(x.rule, x.severity) for x in rf] == [(allowlist.RULE, Severity.HIGH)] and "committed" in rf[0].title


def test_legacy_claude_json_allowed_tools(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    v = fake_password()
    (home / ".claude.json").write_text(json.dumps({"projects": {"/Users/me/app": {
        "allowedTools": [f"Bash(PGPASSWORD={v} psql -h db.acme-prod.com)", "Bash(ls)"]}}}))
    f = allowlist.audit_home(home, {})
    assert len(f) == 1 and "allowedTools[0]" in f[0].location and f[0].severity == Severity.HIGH


def test_committed_specstory_transcripts(tmp_path):
    v = fake_password()
    wt = make_repo(tmp_path, {".specstory/history/2026-11-01_chat.md":
                              f"ran: `PGPASSWORD={v} psql -h db.acme-prod.com -c 'select 1'`\n"},
                   tracked=[".specstory/history/2026-11-01_chat.md"])
    f = allowlist.audit_repo(wt, wt / ".git")
    assert ("repo.agent-transcripts-committed", Severity.MEDIUM) in {(x.rule, x.severity) for x in f}
    assert ("secret.command-password", Severity.HIGH) in {(x.rule, x.severity) for x in f}
    assert v not in json.dumps([x.to_dict() for x in f])


def test_unparseable_settings_fail_closed(tmp_path):
    wt = make_repo(tmp_path, {allowlist.LOCAL_SETTINGS: "{not json", ".gitignore": ".claude/settings.local.json\n"})
    assert [(x.rule, x.severity) for x in allowlist.audit_repo(wt, wt / ".git")] == [("scanner.parse-error",
                                                                                     Severity.HIGH)]


def test_cli_flag_disables(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    settings, _ = jack_settings()
    (home / ".claude" / "settings.local.json").write_text(json.dumps(settings))
    out = tmp_path / "r"
    cli.run(["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-stray-instructions",
             "--no-python-startup", "--no-agent-config", "--no-agent-allowlist", "-o", str(out), "--format", "none"])
    assert not any(f["rule"] == allowlist.RULE for f in json.loads(out.with_suffix(".json").read_text())["findings"])


@pytest.mark.parametrize("line", [   # false positives found by the benchmark (skills, httpx, pydantic)
    "sed 's|https://[^:]*:\\([^@]*\\)@.*|\\1|'",
    "Credentials embedded in remote URLs (`https://user:tok@`).",
    "https://jo%40email.com:a%20secret@www.acme.io",
    "MultiHostUrl('https://foo.com:123,foo:bar@bar.com/path')",
])
def test_benchmarked_false_positives_stay_quiet(line):
    assert [h for h in _hits(line) if h[0].startswith("secret.command-password")] == []


def test_hand_made_toy_key_is_treated_as_placeholder():
    # Jack's original reproduction used sk-or-v1- + 64 letters a-f (no digit). asca has always skipped that shape:
    # a real 64-hex key without a single digit has probability (6/16)**64 ~ 1e-27. Realistic fakes are found.
    toy = "sk-or-v1-" + "abcdef" * 10 + "abcd"
    assert _hits(f"Bash(curl -H 'Authorization: Bearer {toy}' https://openrouter.ai/api/v1/models)") == []
    real = fake_openrouter()
    assert [r for r, _s, _v in _hits(f"Bash(curl -H 'Authorization: Bearer {real}' https://openrouter.ai)")] == \
        ["secret.openrouter-key"]


# ================================================================== private-key headers vs keys; pre-signed URLs

def _pem(kind: str = "RSA ") -> tuple[str, str]:
    import base64
    body = base64.b64encode(pysecrets.token_bytes(600)).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {kind}PRIVATE KEY-----\n{lines}\n-----END {kind}PRIVATE KEY-----", body


@pytest.mark.parametrize("line", [   # Bora's Codex transcript: a secret-scanner regex, not a key
    r"rg -n '(-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})'",
    "Never commit -----BEGIN PRIVATE KEY----- blocks.", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY----- (redacted)",
])
def test_private_key_header_without_body_is_not_a_key(line):
    assert [h for h in _hits(line) if h[0] == "secret.private-key"] == []
    assert list(sessions.scan_line(json.dumps({"output": line}))) == []


def test_real_private_keys_still_found_everywhere(tmp_path):
    pem, body = _pem()
    assert [f.rule for f in secrets.scan_text(pem, "k.pem", context="t")] == ["secret.private-key"]   # file
    assert [r for r, *_ in sessions.scan_line(json.dumps({"output": pem}))] == ["secret.private-key"]  # JSONL
    c_src = 'static const char *k = "-----BEGIN RSA PRIVATE KEY-----\\n"\n  "' + body[:64] + '\\n"'
    assert [h[0] for h in _hits(c_src)] == ["secret.private-key"]                                       # C string
    enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB12\n\n" + body[:64]
    assert [f.rule for f in secrets.scan_text(enc, "e.pem", context="t")] == ["secret.private-key"]   # encrypted PEM
    plain = tmp_path / "transcript.md"                                                                   # plain-text history
    plain.write_text("user: show me the key\n" + pem + "\n")
    found: dict = {}
    sessions._scan_blob(plain.read_bytes(), 1, plain, sessions.Root("t", tmp_path), found)
    assert [s.rule for s in found.values()] == ["secret.private-key"]


def test_aws_key_id_in_presigned_url_is_not_a_secret():
    kid = "ASIA" + rnd(16, string.ascii_uppercase + string.digits)
    for line in (f"https://b.s3.amazonaws.com/preview.pdf?AWSAccessKeyId={kid}&Expires=1773421830&Signature=x",
                 f"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={kid}%2F20260313%2Fus-east-1%2Fs3"):
        assert [h for h in _hits(line) if h[0] == "secret.aws-access-key"] == []
    assert [h[0] for h in _hits(f"aws_access_key_id = {kid}")] == ["secret.aws-access-key"]
