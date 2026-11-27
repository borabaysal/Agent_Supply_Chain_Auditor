"""secret.sent-to-provider and agent.provider-routing (Dragos canary research, OpenRouter's Nov 22 list).

Fake keys are assembled at runtime so this file passes asca's own secret scan."""
from __future__ import annotations

import json
import os
import random
import string
import sys
import time
from pathlib import Path

import pytest

from asca import cli, provexpo, sessions
from asca.model import Severity


def fake(prefix: str, n: int, seed: int) -> str:
    rnd = random.Random(seed)
    return prefix + "".join(rnd.choice(string.ascii_uppercase + string.digits) for _ in range(n))


AWS = fake("AK" + "IA", 16, seed=3)


def _hermes(tmp_path: Path, config: str, when: float | None = None, profile: str | None = None) -> Path:
    h = tmp_path / "hermes"
    base = h / "profiles" / profile if profile else h
    (base / "sessions").mkdir(parents=True, exist_ok=True)
    (base / "config.yaml").write_text(config, encoding="utf-8")
    s = base / "sessions" / "s1.jsonl"
    s.write_text(json.dumps({"role": "tool", "content": f"aws_access_key_id = {AWS}\n"}) + "\n", encoding="utf-8")
    if when is not None:
        os.utime(s, (when, when))
    if profile:
        (h / "config.yaml").write_text("model:\n  provider: anthropic\n", encoding="utf-8")
    return h


def _run(tmp_path: Path, hermes: Path, home: Path | None = None, env: dict | None = None):
    home = home or tmp_path / "home"
    home.mkdir(exist_ok=True)
    collected: list = []
    sessions.audit(sessions.default_roots(home, hermes, env or {}), {}, collect=collected)
    table = provexpo.routes(home, hermes, env or {})
    return provexpo.sent_to_provider(collected, table), provexpo.routing(table)


def _ts(day: str) -> float:
    return time.mktime(time.strptime(day + " 12:00", "%Y-%m-%d %H:%M"))


def test_key_in_hermes_transcript_sent_through_openrouter_is_high_and_redacted(tmp_path):
    h = _hermes(tmp_path, "model:\n  default: x\n  provider: openrouter\n")
    sent, routing = _run(tmp_path, h)
    assert [(f.rule, f.severity) for f in sent] == [("secret.sent-to-provider", Severity.HIGH)]
    f = sent[0]
    assert "OpenRouter" in f.title and AWS not in json.dumps(f.to_dict())
    assert "provider_routing.only" in f.detail and "Dragos" in f.detail and "today's setting" in f.detail
    assert "artex-agent" in f.remediation and routing == []


def test_first_party_and_local_endpoints_add_nothing(tmp_path):
    for i, cfg in enumerate(["model:\n  provider: anthropic\n", "model:\n  base_url: https://api.anthropic.com\n",
                             "model:\n  base_url: http://localhost:11434/v1\n", "model:\n  provider: lmstudio\n",
                             "model:\n  provider: deepseek\n"]):
        sent, _ = _run(tmp_path / str(i), _hermes(tmp_path / str(i), cfg))
        assert sent == [], cfg


def test_unknown_gateway_is_medium_and_custom_provider_entry_is_followed(tmp_path):
    sent, _ = _run(tmp_path, _hermes(tmp_path, "model:\n  base_url: https://llm.corp.invalid/v1\n"))
    assert [(f.severity, "llm.corp.invalid" in f.title) for f in sent] == [(Severity.MEDIUM, True)]
    cfg = "model:\n  provider: relay\nproviders:\n  relay:\n    api: https://vip.reseller.invalid/v1\n"
    sent, _ = _run(tmp_path / "b", _hermes(tmp_path / "b", cfg))
    assert [f.severity for f in sent] == [Severity.MEDIUM]


def test_pinned_provider_with_incident_is_critical_when_transcript_overlaps_window(tmp_path):
    cfg = ("model:\n  provider: openrouter\nprovider_routing:\n  only:\n    - Phala\n    - anthropic\n"
           "  data_collection: deny\n")
    sent, routing = _run(tmp_path, _hermes(tmp_path, cfg, when=_ts("2026-10-25")))
    assert [f.severity for f in sent] == [Severity.CRITICAL]
    assert "Phala" in sent[0].title and "2026-10-21 to 2026-11-08" in sent[0].detail
    assert "data_collection: deny" in sent[0].detail
    assert [(f.rule, f.severity, f.location.endswith("provider_routing.only[0]")) for f in routing] == \
        [("agent.provider-routing", Severity.MEDIUM, True)]


def test_transcript_older_than_incident_window_stays_high(tmp_path):
    cfg = "model:\n  provider: openrouter\nprovider_routing:\n  order: [phala]\n"
    sent, _ = _run(tmp_path, _hermes(tmp_path, cfg, when=_ts("2026-09-01")))
    assert [f.severity for f in sent] == [Severity.HIGH]
    assert "last written before that window" in sent[0].detail


def test_direct_host_with_incident(tmp_path):
    sent, routing = _run(tmp_path, _hermes(tmp_path, "model:\n  provider: gmi\n", when=_ts("2026-11-01")))
    assert [f.severity for f in sent] == [Severity.CRITICAL] and "GMI Cloud" in sent[0].title
    assert [f.title.startswith("Hermes sends its prompts straight to GMI Cloud") for f in routing] == [True]
    sent, _ = _run(tmp_path / "t", _hermes(tmp_path / "t", "model:\n  base_url: https://api.together.xyz/v1\n",
                                           when=_ts("2026-11-01")))
    assert [f.severity for f in sent] == [Severity.CRITICAL]      # no start-of-window problem: Nov > Jun


def test_profile_transcripts_use_the_profile_config(tmp_path):
    h = _hermes(tmp_path, "model:\n  provider: openrouter\n", profile="work")
    sent, _ = _run(tmp_path, h)
    assert len(sent) == 1 and "profile work" in sent[0].detail


def test_claude_code_base_url_from_settings_and_env(tmp_path):
    home = tmp_path / "home"
    proj = home / ".claude" / "projects" / "p"
    proj.mkdir(parents=True)
    (proj / "s.jsonl").write_text(json.dumps({"content": f"AWS_ACCESS_KEY_ID={AWS}"}) + "\n", encoding="utf-8")
    (home / ".claude" / "settings.json").write_text(json.dumps({"env": {
        "ANTHROPIC_BASE_URL": "https://openrouter.ai/api"}}), encoding="utf-8")
    sent, _ = _run(tmp_path, None, home=home)
    assert [(f.severity, "OpenRouter" in f.title) for f in sent] == [(Severity.HIGH, True)]
    (home / ".claude" / "settings.json").unlink()
    sent, _ = _run(tmp_path, None, home=home, env={"ANTHROPIC_BASE_URL": "https://api.anthropic.com"})
    assert sent == []


@pytest.mark.skipif(sys.version_info < (3, 11), reason="Codex config.toml needs tomllib")
def test_codex_selected_model_provider(tmp_path):
    home = tmp_path / "home"
    (home / ".codex" / "sessions").mkdir(parents=True)
    (home / ".codex" / "sessions" / "r.jsonl").write_text(json.dumps({"c": f"key {AWS}"}) + "\n", encoding="utf-8")
    (home / ".codex" / "config.toml").write_text(
        'model_provider = "nov"\n[model_providers.nov]\nbase_url = "https://api.novita.ai/openai"\n', encoding="utf-8")
    sent, routing = _run(tmp_path, None, home=home)
    assert [f.severity for f in sent] == [Severity.CRITICAL] and "NovitaAI" in sent[0].title
    assert len(routing) == 1


def test_incident_lookup_by_name_and_host():
    assert provexpo.incident_for("Together").name == "Together AI"
    assert provexpo.incident_for("https://api.together.xyz/v1").name == "Together AI"
    assert provexpo.incident_for("atlas-cloud").name == "Atlas Cloud"
    assert provexpo.incident_for("anthropic") is None and provexpo.incident_for("api.openai.com") is None


def test_cli_end_to_end(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    h = _hermes(tmp_path, "model:\n  provider: openrouter\n")
    out = tmp_path / "out" / "rep"
    assert cli.run(["--hermes-home", str(h), "--no-client-configs", "--no-global-git", "--no-stray-instructions",
                    "-o", str(out), "--format", "none"]) == 1
    data = json.loads(out.with_suffix(".json").read_text())
    rules = sorted(f["rule"] for f in data["findings"])
    assert "secret.sent-to-provider" in rules and "secret.session-history" in rules
    assert AWS not in out.with_suffix(".json").read_text()
    assert data["stats"]["session_secrets_sent_to_provider"] == 1
