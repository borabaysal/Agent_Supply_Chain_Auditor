"""Developer credential files (#1): the agent-framework stealer's file list, read as text."""
import base64
import json
import os
import random
import string

import pytest

from asca import cli, devcreds, respond
from asca.model import Severity

RNG = random.Random(9031)


def _tok(prefix: str, n: int) -> str:
    return prefix + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


NPM = _tok("npm_", 36)
PYPI = _tok("pypi-", 60)
HF = _tok("hf_", 34)
GH = _tok("ghp_", 36)
PW = _tok("", 20)
DOCKER = base64.b64encode(f"me:{PW}".encode()).decode()


def _w(p, text, mode=0o600):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    os.chmod(p, mode)
    return p


def _home(tmp_path):
    h = tmp_path / "home"
    _w(h / ".npmrc", f"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={NPM}\n"
                     "//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}\n")
    _w(h / ".pypirc", f"[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = {PYPI}\n")
    _w(h / ".config" / "pip" / "pip.conf", f"[global]\nextra-index-url = https://me:{PW}@pkgs.example.invalid/simple\n")
    _w(h / ".netrc", f"machine api.example.invalid login me password {PW}\nmachine b.example.invalid login x password y2\n")
    _w(h / ".docker" / "config.json", json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": DOCKER},
                                                            "ghcr.io": {"auth": DOCKER}},
                                                  "credHelpers": {"ghcr.io": "desktop"}}))
    _w(h / ".azure" / "msal_token_cache.json", json.dumps({"AccessToken": {"x": {"secret": _tok("eyJ", 80)}}}))
    _w(h / ".cache" / "huggingface" / "token", HF + "\n")
    _w(h / ".git-credentials", f"https://me:{GH}@github.com\n")
    return h


def _audit(home, env=None):
    return devcreds.audit(home, {}, env={} if env is None else env)


def test_the_stealers_file_list_is_inventoried_without_values(tmp_path):
    h = _home(tmp_path)
    f = _audit(h)
    plain = {x.subject: x for x in f if x.rule == "devcred.plaintext"}
    assert set(plain) == {"npmrc:npm token", "pypirc:PyPI token", "pipconf:package index password",
                          "netrc:netrc password", "docker:Docker registry credentials",
                          "azure:Azure CLI token cache", "hf:Hugging Face token", "gitcreds:GitHub token"}
    assert {x.severity for x in plain.values()} == {Severity.LOW}
    assert "(2 entries)" in plain["netrc:netrc password"].title
    assert "entries" not in plain["docker:Docker registry credentials"].title      # ghcr.io uses a cred helper
    assert "entries" not in plain["npmrc:npm token"].title                          # ${GITHUB_TOKEN} isn't counted
    blob = json.dumps([x.__dict__ for x in f], default=str)
    for v in (NPM, PYPI, HF, GH, PW, DOCKER):
        assert v not in blob
    assert "sha256:" in plain["npmrc:npm token"].detail
    summary = [x for x in f if x.rule == "devcred.summary"]
    assert len(summary) == 1 and summary[0].severity == Severity.INFO and "8 developer credential" in summary[0].title


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_readable_by_others_reuses_the_permission_rule(tmp_path):
    h = tmp_path / "home"
    _w(h / ".npmrc", f"//registry.npmjs.org/:_authToken={NPM}\n", mode=0o644)
    rules = {(x.rule, x.severity) for x in _audit(h)}
    assert ("secret.file-permissions", Severity.HIGH) in rules and ("devcred.plaintext", Severity.LOW) in rules


@pytest.mark.parametrize("name,text", [
    (".npmrc", "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"),
    (".pypirc", "[pypi]\nusername = __token__\n"),
    (".netrc", "machine x login y\n"),
    (".docker/config.json", json.dumps({"auths": {"https://index.docker.io/v1/": {}}, "credsStore": "osxkeychain"})),
    (".git-credentials", ""),
    (".azure/msal_token_cache.json", "{}"),
])
def test_references_stores_and_empty_files_are_quiet(tmp_path, name, text):
    h = tmp_path / "home"
    _w(h / name, text)
    assert [x for x in _audit(h) if x.rule.startswith("devcred.")] == []


def test_env_overrides_and_bad_json(tmp_path):
    h = tmp_path / "home"
    alt = _w(tmp_path / "alt" / "npmrc", f"//r.example.invalid/:_auth={NPM}\n")
    _w(tmp_path / "dk" / "config.json", "{not json")
    f = _audit(h, env={"NPM_CONFIG_USERCONFIG": str(alt), "DOCKER_CONFIG": str(tmp_path / "dk")})
    assert {(x.rule, x.subject) for x in f} >= {("devcred.plaintext", "npmrc:npm token"),
                                                ("scanner.parse-error", "docker")}


def test_no_revoke_steps_for_stored_credentials(tmp_path):
    f = _audit(_home(tmp_path))
    respond.enrich(f, tmp_path)
    hf = next(x for x in f if x.subject == "hf:Hugging Face token")
    assert "Steps:" not in hf.remediation and "logout" in hf.remediation


def test_cli_flag(tmp_path, monkeypatch):
    h = _home(tmp_path)
    monkeypatch.setenv("HOME", str(h))
    for k in ("NPM_CONFIG_USERCONFIG", "DOCKER_CONFIG", "AZURE_CONFIG_DIR", "HF_HOME", "XDG_CONFIG_HOME",
              "XDG_CACHE_HOME", "PIP_CONFIG_FILE", "NETRC", "HF_TOKEN_PATH"):
        monkeypatch.delenv(k, raising=False)
    base = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-session-history", "--no-stray-instructions",
            "--no-agent-config", "--no-python-startup", "--no-docker-daemon", "--format", "none"]
    out = tmp_path / "r"
    cli.run(base + ["-o", str(out)])
    rules = {x["rule"] for x in json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]}
    assert "devcred.plaintext" in rules
    cli.run(base + ["--no-dev-credentials", "-o", str(out)])
    rules = {x["rule"] for x in json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))["findings"]}
    assert not any(r.startswith("devcred.") for r in rules)
