"""Key blast-radius card on the dashboard (asca.blastradius). Fake keys are generated at runtime."""
import hashlib
import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asca import blastradius, dashboard
from asca.model import redact

NOW = datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc)
RNG = random.Random(1117)


def fake(prefix, n):
    return prefix + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


def tag(v):
    return hashlib.sha256(v.encode()).hexdigest()[:8]


def f_key(rule, label, value, location, extra="", sev="high", suppressed=False):
    d = {"rule": rule, "category": "secrets", "severity": sev, "title": f"{label} in {Path(location).name}",
         "location": location, "subject": f"{label}:{tag(value)}0000", "detail": f"{redact(value)}{extra}",
         "remediation": "rotate"}
    if suppressed:
        d.update(suppressed=True, suppress_reason="Accepted 2026-11-01: rotated")
    return d


def write_report(state: Path, findings: list, when=NOW):
    state.mkdir(parents=True, exist_ok=True)
    doc = {"tool": "agent-supply-chain-auditor", "generated_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "result": "fail",
           "counts": {"high": len(findings)}, "findings": findings}
    (state / "latest.json").write_text(json.dumps(doc))


K1 = fake("sk-ant-api03-", 90)              # same key in 3 places
K2 = fake("sk-or-v1-", 64)                  # rotated, accepted


def setup(tmp_path, live_keys=()):
    k1, k2 = K1, K2
    findings = [
        f_key("secret.anthropic-key", "Anthropic API key", k1, "/home/u/.hermes/config.yaml"),
        f_key("secret.session-history", "Anthropic API key", k1, "/home/u/.claude/projects",
              " appears 5 time(s) in 3 transcript file(s) (Claude Code transcripts)."),
        f_key("secret.agent-allowlist", "Anthropic API key", k1, "/home/u/.codex/rules/default.rules", sev="critical"),
        f_key("secret.session-history", "OpenRouter API key", k2, "/home/u/.hermes/sessions",
              " appears 1 time(s) in 1 transcript file(s) (Hermes sessions).", suppressed=True),
    ]
    state = tmp_path / "state"
    write_report(state, findings)
    env = tmp_path / ".env"
    env.write_text("".join(f"KEY_{i}='{v}'\n" for i, v in enumerate(live_keys)) + "SHORT=abc\n")
    return state, env, k1, k2


def page(state, env, now=NOW):
    out = state / "dashboard.html"
    dashboard.build(state, out, host="h", now=now, env_files=[env])
    return out.read_text()


def test_groups_copies_of_one_key_and_never_shows_values(tmp_path):
    state, env, k1, k2 = setup(tmp_path, live_keys=[])
    h = page(state, env)
    sec = h[h.index("Leaked keys"):]
    assert sec.count("<div class='f'>") == 1                       # one card for k1, not three findings
    assert "3 places across Claude Code, Codex, Hermes" in sec
    assert "transcripts · 3 files" in sec and "allow rule" in sec
    assert "CRITICAL" in sec                                        # worst severity of the copies
    assert k1 not in h and k2 not in h and k1[4:20] not in h
    assert "Anthropic: create a new key" in sec                     # provider steps, once
    assert sec.count("Anthropic: create a new key") == 1


def test_live_key_is_flagged(tmp_path):
    state, env, k1, _ = setup(tmp_path, live_keys=[K1])
    sec = page(state, env).split("Leaked keys")[1]
    assert "still live" in sec and "KEY_0" in sec and "Rotate it first" in sec


def test_rotated_key_says_delete_copies(tmp_path):
    state, env, *_ = setup(tmp_path, live_keys=[fake("sk-ant-api03-", 90)])
    sec = page(state, env).split("Leaked keys")[1]
    assert "not in your current .env" in sec and "Delete every copy above" in sec


def test_no_env_files(tmp_path):
    state, _, *_ = setup(tmp_path)
    out = state / "d.html"
    dashboard.build(state, out, host="h", now=NOW, env_files=[])
    assert "no agent .env found to compare" in out.read_text()


def test_accepted_key_that_is_still_live_is_flagged(tmp_path):
    state, env, _, k2 = setup(tmp_path, live_keys=[K2])
    sec = page(state, env).split("Leaked keys")[1]
    assert "Accepted keys still on disk (1) · ⚠️ 1 still live" in sec
    assert "<details open>" in sec


def test_exposure_age_from_first_seen(tmp_path):
    state, env, *_ = setup(tmp_path)
    page(state, env, now=NOW - timedelta(days=9))                 # first build: memory starts (first unknown)
    page(state, env, now=NOW - timedelta(days=8))
    k = {"audit": dashboard.load("audit", state / "latest.json", NOW)}
    mem = json.loads((state / "dashboard-state.json").read_text())
    active, _ = blastradius.group(k, dashboard._fkey, mem)
    assert active and all(a["first"] is None for a in active)      # fresh memory: no invented dates
    # a key seen on a later run gets that run's date
    findings = json.loads((state / "latest.json").read_text())["findings"]
    k3 = fake("hf_", 34)
    findings.append(f_key("secret.hf-token", "Hugging Face token", k3, "/home/u/.hermes/.env.bak"))
    write_report(state, findings, when=NOW - timedelta(days=5))
    page(state, env, now=NOW - timedelta(days=5))
    write_report(state, findings, when=NOW)
    sec = page(state, env).split("Leaked keys")[1]
    assert "exposed 5 days (first seen 2026-11-12)" in sec
    assert "exposed since before the dashboard started tracking" in sec


def test_live_tags_reads_values_only_in_memory(tmp_path):
    v = fake("ghp_", 36)
    p = tmp_path / ".env"
    p.write_text(f"# comment\nexport GH_TOKEN=\"{v}\"\nEMPTY=\nX=short\n")
    live = blastradius.live_tags([p, tmp_path / "missing.env"])
    assert live == {tag(v): f"GH_TOKEN in {p}"}


def test_no_section_without_keys(tmp_path):
    state = tmp_path / "state"
    write_report(state, [{"rule": "repo.hook", "severity": "high", "title": "x", "location": "/r", "subject": "s",
                          "detail": "d", "remediation": ""}])
    out = state / "d.html"
    dashboard.build(state, out, host="h", now=NOW, env_files=[])
    assert "Leaked keys" not in out.read_text()
