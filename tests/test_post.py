"""`asca post` (#2): incident -> sample finding + X/LinkedIn post. Nothing is published."""
import codecs
import json

import pytest

from asca import cli, hookgrade, post
from asca.model import Severity


@pytest.mark.parametrize("inc", post.INCIDENTS, ids=lambda i: i.id)
def test_every_incident_produces_a_real_sample_that_fits_x(inc):
    f = post.demo_finding(inc)
    assert f and f["rule"] in inc.rules                        # the planted setup still trips the current rules
    p = post.build(inc, f, real=False)
    assert p["x_length"] <= post.X_LIMIT and inc.url in p["x_post"]
    assert "…" not in p["x_post"]                              # fits without cutting a sentence
    assert len(p["linkedin_post"].splitlines()) == 3 and inc.url in p["linkedin_post"]
    assert "asca-post-" not in json.dumps(p) and "/tmp" not in json.dumps(p)      # no temp-folder paths
    assert p["finding_origin"].startswith("asca run on a planted")


def test_sources_are_primary_https_links():
    assert all(i.url.startswith("https://") for i in post.INCIDENTS)
    assert len({i.id for i in post.INCIDENTS}) == len(post.INCIDENTS)


def test_sombermeme_sample_is_rot13_and_grades_high():
    cmd = codecs.decode(post._SOMBERMEME_HOOK, "rot13")
    assert hookgrade.grade(cmd)[0] == Severity.HIGH and "example.invalid" in cmd


@pytest.mark.parametrize("raw,want", [
    ("/Users/alice/Projects/AcmeClient/.env", "…/.env"),
    ("/home/bob/work/secret-app/.claude/settings.json", "…/.claude/settings.json"),
    (r"C:\Users\tester1\AppData\Roaming\Claude\claude_desktop_config.json", "…/claude_desktop_config.json"),
    ("(venv /srv/envs/cache/v1)", "(venv …/v1)"),
    ("~/.npmrc", "~/.npmrc"),
    ("`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`", "`//registry.npmjs.org/:_authToken=${NPM_TOKEN}`"),
    ("https://example.com/a/b/c.html", "https://example.com/a/b/c.html"),
    ("tcp://0.0.0.0:2375", "tcp://0.0.0.0:2375"),
    ("/etc/docker/daemon.json", "…/docker/daemon.json"),
])
def test_sanitise(raw, want):
    assert post.sanitise(raw) == want


def _report(tmp_path, findings):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"findings": findings, "host_label": "my-laptop"}), encoding="utf-8")
    return p


def test_report_finding_is_used_highest_severity_first_and_sanitised(tmp_path, capsys):
    rep = _report(tmp_path, [
        {"rule": "aistack.port-exposed", "severity": "medium", "title": "Ollama exposed",
         "location": "/home/bob/clientX/ollama/docker-compose.yml#services.ollama", "detail": "d", "remediation": "r.",
         "subject": "SECRET-SUBJECT"},
        {"rule": "aistack.litellm-default-key", "severity": "high", "title": "LiteLLM master key is the example value",
         "location": "/home/bob/clientX/litellm/.env", "detail": "LITELLM_MASTER_KEY = sk-1… (len=7, sha256:abcd1234)",
         "remediation": "Generate a long random key.", "subject": "SECRET-SUBJECT"},
        {"rule": "aistack.auth-disabled", "severity": "critical", "suppressed": True, "title": "suppressed one",
         "location": "/x", "detail": "", "remediation": ""}])
    assert cli.run(["post", "artex", "--report", str(rep), "--format", "json"]) == 0
    p = json.loads(capsys.readouterr().out)
    assert p["finding"]["rule"] == "aistack.litellm-default-key" and p["finding"]["location"] == "…/.env"
    assert p["finding_origin"].startswith("real asca report")
    out = json.dumps(p)
    assert "clientX" not in out and "bob" not in out and "SECRET-SUBJECT" not in out and "my-laptop" not in out


def test_report_without_a_match_falls_back_to_the_planted_sample(tmp_path, capsys):
    rep = _report(tmp_path, [{"rule": "git.fsmonitor", "severity": "critical", "title": "t", "location": "/x",
                              "detail": "", "remediation": ""}])
    assert cli.run(["post", "carbonato", "--report", str(rep), "--format", "json"]) == 0
    io = capsys.readouterr()
    assert json.loads(io.out)["finding"]["rule"] == "host.docker-api-exposed" and "planted sample" in io.err


def test_cli_list_markdown_unknown_and_output_file(tmp_path, capsys):
    assert cli.run(["post", "--list"]) == 0
    assert "artex" in capsys.readouterr().out
    assert cli.run(["post", "nope"]) == 2
    out = tmp_path / "p.md"
    assert cli.run(["post", "mcp-drift", "-o", str(out)]) == 0
    md = out.read_text(encoding="utf-8")
    assert md.startswith("# Pinned MCP servers") and "## X (" in md and "nothing has been published" in md
