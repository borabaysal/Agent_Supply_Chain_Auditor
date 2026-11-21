"""asca spend: stolen-key spend tripwire, against fake OpenRouter / Anthropic APIs (shapes from their docs)."""
import os
import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from asca import spend
from asca.model import Severity

T0 = datetime(2026, 11, 10, 0, 30, tzinfo=timezone.utc)
OPTS = SimpleNamespace(factor=3.0, min_usd=2.0, max_daily_usd=None)
FAKE_OR = "sk-or-v1-" + "a" * 64
FAKE_ADMIN = "sk-ant-admin01-" + "b" * 80


def test_judge():
    assert spend.judge(5, [1, 1], None, factor=3, min_usd=2, max_daily=None)[0] is None          # learning
    assert spend.judge(50, [1, 1], None, factor=3, min_usd=2, max_daily=20)[0] == Severity.HIGH  # ceiling while learning
    assert spend.judge(2.5, [1, 1, 1], None, factor=3, min_usd=2, max_daily=None)[0] is None     # < base + $2
    assert spend.judge(4, [1, 1, 1], None, factor=3, min_usd=2, max_daily=None)[0] == Severity.HIGH
    assert spend.judge(1, [1, 1, 1], 3.5, factor=3, min_usd=2, max_daily=None)[0] == Severity.HIGH  # hour > a day
    sev, why = spend.judge(3, [0, 0, 0], None, factor=3, min_usd=2, max_daily=None)
    assert sev == Severity.HIGH and "$0.00" in why


class OpenRouter:
    def __init__(self, limit=100.0):
        self.usage, self.limit, self.urls = 0.0, limit, []

    def __call__(self, url, headers, timeout=20):
        self.urls.append(url)
        assert url == "https://openrouter.ai/api/v1/key" and headers["Authorization"] == f"Bearer {FAKE_OR}"
        rem = None if self.limit is None else self.limit - self.usage
        return {"data": {"label": "sk-or-v1-aaa...aaa", "usage": self.usage, "limit": self.limit, "limit_remaining": rem}}


def hourly(fake, state, start, hours, per_hour):
    fs = []
    for h in range(hours):
        fake.usage += per_hour
        fs = spend.check_openrouter(FAKE_OR, state, start + timedelta(hours=h), OPTS, get=fake)
    return fs


def test_openrouter_learns_then_catches_a_spike():
    fake, state = OpenRouter(limit=1000), {}
    assert hourly(fake, state, T0, 24 * 5, 0.05) == []                 # 5 normal days at $1.20/day: silent
    tag = next(iter(state["openrouter"]))
    assert state["openrouter"][tag]["status"].startswith("normal")
    fs = hourly(fake, state, T0 + timedelta(days=5), 3, 2.0)           # someone runs the key hard
    assert [f.rule for f in fs] == ["spend.spike"] and fs[0].severity == Severity.HIGH
    assert FAKE_OR not in json.dumps(state) and FAKE_OR not in fs[0].title + fs[0].detail


def test_openrouter_limit_low_and_no_limit():
    fake, state = OpenRouter(limit=10), {}
    fake.usage = 9.5
    assert [f.rule for f in spend.check_openrouter(FAKE_OR, state, T0, OPTS, get=fake)] == []    # first sample
    fs = spend.check_openrouter(FAKE_OR, state, T0 + timedelta(days=1), OPTS, get=fake)
    assert "spend.limit-low" in [f.rule for f in fs]
    fake2 = OpenRouter(limit=None)
    spend.check_openrouter(FAKE_OR, {}, T0, OPTS, get=fake2)
    st = {}
    spend.check_openrouter(FAKE_OR, st, T0, OPTS, get=fake2)
    assert "spend.no-limit" in [f.rule for f in spend.check_openrouter(FAKE_OR, st, T0 + timedelta(days=1), OPTS,
                                                                        get=fake2)]


def test_old_samples_pruned():
    fake, state = OpenRouter(), {}
    hourly(fake, state, T0, 24 * 12, 0.01)
    samples = next(iter(state["openrouter"].values()))["samples"]
    assert len(samples) <= 24 * spend.KEEP_DAYS + 1


class Anthropic:
    """cost_report in cents; usage_report grouped by api_key_id + model."""

    def __init__(self, costs: dict, usage: dict):
        self.costs, self.usage, self.urls = costs, usage, []

    def __call__(self, url, headers, timeout=20):
        self.urls.append(url)
        assert url.startswith("https://api.anthropic.com/v1/organizations/") and headers["x-api-key"] == FAKE_ADMIN
        if "/cost_report" in url:
            return {"data": [{"starting_at": f"{d}T00:00:00Z", "results": [{"amount": str(c * 100), "currency": "USD"}]}
                             for d, c in self.costs.items()], "has_more": False}
        return {"data": [{"starting_at": f"{d}T00:00:00Z", "results": [
            {"api_key_id": k, "model": m, "uncached_input_tokens": 10, "output_tokens": 5} for k, m in rows]}
            for d, rows in self.usage.items()], "has_more": False}


NOW = datetime(2026, 11, 17, 15, 0, tzinfo=timezone.utc)
DAYS = [(NOW - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(8, 0, -1)]
TODAY = NOW.strftime("%Y-%m-%d")


def test_anthropic_spike_and_new_key_and_model():
    normal = {d: [("apikey_01mine", "claude-sonnet-5")] for d in DAYS}
    st = {}
    fake = Anthropic({**{d: 4.0 for d in DAYS}, TODAY: 3.0}, {**normal, TODAY: normal[DAYS[0]]})
    assert spend.check_anthropic(FAKE_ADMIN, st, NOW, OPTS, get=fake) == []          # first run learns keys
    fake = Anthropic({**{d: 4.0 for d in DAYS}, TODAY: 40.0},
                     {**normal, TODAY: [("apikey_01mine", "claude-sonnet-5"), ("apikey_01evil", "claude-opus-5-5")]})
    rules = sorted((f.rule, f.severity) for f in spend.check_anthropic(FAKE_ADMIN, st, NOW, OPTS, get=fake))
    assert rules == [("spend.new-key", Severity.HIGH), ("spend.new-model", Severity.MEDIUM),
                     ("spend.spike", Severity.HIGH)]
    assert any("group_by[]=api_key_id" in u for u in fake.urls)


def test_find_keys_env_wins_then_files(tmp_path):
    p = tmp_path / ".env"
    p.write_text(f"OPENROUTER_API_KEY='{FAKE_OR}'\nANTHROPIC_API_KEY=\nOTHER=x\n")
    assert spend.find_keys([p], env={}) == {"OPENROUTER_API_KEY": FAKE_OR}
    assert spend.find_keys([p], env={"OPENROUTER_API_KEY": "sk-or-v1-env"})["OPENROUTER_API_KEY"] == "sk-or-v1-env"


def test_refuses_other_hosts():
    with pytest.raises(ValueError):
        spend._get("https://evil.example/v1/key", {})


def test_cli_notes_admin_key_needed_and_telegram_change(tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(f"OPENROUTER_API_KEY={FAKE_OR}\nANTHROPIC_API_KEY=sk-ant-api03-{'c' * 90}\n")
    state = tmp_path / "s.json"
    sent = []
    monkeypatch.setattr(spend.report, "resolve_telegram", lambda *a: ("t", "c"))
    monkeypatch.setattr(spend.report, "send_telegram", lambda text, **k: (sent.append(text), (True, "ok"))[1])
    fake = OpenRouter(limit=1000)
    base = ["--env-file", str(env), "--state", str(state), "--telegram", "change"]
    t = T0
    for _ in range(24 * 4):
        fake.usage += 0.05
        assert spend.run(base, get=fake, now=t) == 0
        t += timedelta(hours=1)
    out = capsys.readouterr().out
    assert "needs an Admin key" in out and sent == []                                 # normal: silent
    fake.usage += 6
    assert spend.run(base, get=fake, now=t) == 1 and len(sent) == 1 and "spend spike" in sent[0]
    fake.usage += 0.01
    assert spend.run(base, get=fake, now=t + timedelta(minutes=5)) == 1 and len(sent) == 1   # same alert: silent
    assert FAKE_OR not in state.read_text() and FAKE_OR not in capsys.readouterr().out
    assert os.name == "nt" or state.stat().st_mode & 0o777 == 0o600


def test_cli_rejected_key_is_an_error(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(f"OPENROUTER_API_KEY={FAKE_OR}\n")

    def denied(url, headers, timeout=20):
        raise urllib.error.HTTPError(url, 401, "no", {}, io.BytesIO(b""))
    assert spend.run(["--env-file", str(env), "--state", str(tmp_path / "s.json")], get=denied) == 2
    assert "key rejected" in capsys.readouterr().out
