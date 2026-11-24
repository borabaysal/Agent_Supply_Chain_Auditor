"""Self-hosted AI gateways and apps (#4, the ARTEX playbook)."""
import plistlib
import textwrap
from pathlib import Path

import pytest

from asca import aistack, cli, pystartup
from asca.model import Severity

DEFAULT = "sk-" + "1234"          # LiteLLM's documented example key


def _w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def _run(home, **kw):
    kw.setdefault("root", home.parent / "root")
    kw.setdefault("env", {})
    kw.setdefault("sites", [])
    return aistack.audit(home, {}, **kw)


def _got(fs):
    return sorted((f.rule, f.severity.name) for f in fs)


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


# ---------------------------------------------------------------- LiteLLM
def test_litellm_default_key_in_env_and_published_compose_is_critical(home):
    _w(home / "litellm" / ".env", f'LITELLM_MASTER_KEY = "{DEFAULT}"\n')
    _w(home / "litellm" / "docker-compose.yml", """\
        services:
          litellm:
            image: ghcr.io/berriai/litellm:main-stable
            env_file: .env
            ports:
              - "4000:4000"
        """)
    fs = _run(home)
    assert ("aistack.litellm-default-key", "CRITICAL") in _got(fs)
    assert ("aistack.port-exposed", "MEDIUM") in _got(fs)
    key = next(f for f in fs if f.rule == "aistack.litellm-default-key")
    assert DEFAULT not in key.detail + key.title and "sha256:" in key.detail       # redacted


def test_litellm_default_key_in_config_loopback_only_is_high(home):
    _w(home / "llm" / "config.yaml", f"""\
        model_list:
          - model_name: gpt
            litellm_params:
              model: openai/gpt-4o
        general_settings:
          master_key: {DEFAULT}
        """)
    _w(home / "llm" / "compose.yaml", """\
        services:
          proxy:
            image: ghcr.io/berriai/litellm:v1.80.0
            ports:
              - "127.0.0.1:4000:4000"
        """)
    assert _got(_run(home)) == [("aistack.litellm-default-key", "HIGH")]


def test_litellm_master_key_from_env_reference(home):
    _w(home / "llm" / "litellm_config.yaml", """\
        model_list: []
        general_settings:
          master_key: os.environ/LITELLM_MASTER_KEY
        """)
    _w(home / "llm" / ".env", f"LITELLM_MASTER_KEY={DEFAULT}\n")
    assert [f.rule for f in _run(home)] == ["aistack.litellm-default-key"]          # one finding, not two
    _w(home / "llm" / ".env", "LITELLM_MASTER_KEY=sk-a8F3kq0ZpL2mW9xR7tYv\n")
    assert _run(home) == []


def test_litellm_no_master_key_low_then_high_when_published(home):
    cfg = _w(home / "llm" / "proxy_config.yaml", """\
        model_list:
          - model_name: m
            litellm_params:
              model: ollama/llama3
        litellm_settings:
          drop_params: true
        """)
    assert _got(_run(home)) == [("aistack.litellm-no-master-key", "LOW")]
    _w(cfg.parent / "docker-compose.yml", """\
        services:
          litellm:
            image: litellm/litellm:latest
            ports: ["4000:4000"]
        """)
    assert ("aistack.litellm-no-master-key", "HIGH") in _got(_run(home))


def test_litellm_source_checkout_and_examples_are_skipped(home):
    repo = home / "src" / "litellm"
    _w(repo / ".git" / "config", '[remote "origin"]\n\turl = https://github.com/BerriAI/litellm.git\n')
    _w(repo / "proxy_server_config.yaml", f"model_list: []\ngeneral_settings:\n  master_key: {DEFAULT}\n")
    _w(home / "x" / "docs" / ".env", f"LITELLM_MASTER_KEY={DEFAULT}\n")
    _w(home / "x" / ".env.example", f"LITELLM_MASTER_KEY={DEFAULT}\n")
    assert _run(home) == []


def test_non_litellm_yaml_is_ignored(home):
    _w(home / "k8s" / "config.yaml", "apiVersion: v1\nkind: Config\nmaster_key: " + DEFAULT + "\n")
    assert _run(home) == []


# ---------------------------------------------------------------- Open WebUI
def test_open_webui_auth_off_published(home):
    _w(home / "owui" / "docker-compose.yaml", """\
        services:
          open-webui:
            image: ghcr.io/open-webui/open-webui:main
            ports:
              - "3000:8080"
            environment:
              - WEBUI_AUTH=${WEBUI_AUTH:-False}
        """)
    assert _got(_run(home)) == [("aistack.auth-disabled", "CRITICAL"), ("aistack.port-exposed", "MEDIUM")]


def test_open_webui_open_signup_roles(home):
    _w(home / "owui" / ".env", "WEBUI_SECRET_KEY=abc\nDEFAULT_USER_ROLE=user\n")
    assert _got(_run(home)) == [("aistack.open-signup", "MEDIUM")]
    _w(home / "owui" / ".env", "WEBUI_SECRET_KEY=abc\nDEFAULT_USER_ROLE=admin\n")
    assert _got(_run(home)) == [("aistack.open-signup", "HIGH")]
    for safe in ("DEFAULT_USER_ROLE=pending", "DEFAULT_USER_ROLE=user\nENABLE_SIGNUP=False"):
        _w(home / "owui" / ".env", "WEBUI_SECRET_KEY=abc\n" + safe + "\n")
        assert _run(home) == []


def test_generic_default_user_role_without_webui_context_is_ignored(home):
    _w(home / "app" / ".env", "DEFAULT_USER_ROLE=admin\n")
    assert _run(home) == []


# ---------------------------------------------------------------- compose ports
@pytest.mark.parametrize("ports,exposed", [
    (['"11434:11434"'], True),
    (['"11434"'], True),                                   # random host port, still 0.0.0.0
    (['"0.0.0.0:11434:11434"'], True),
    (['"[::]:11434:11434"'], True),
    (['"127.0.0.1:11434:11434"'], False),
    (['"[::1]:11434:11434"'], False),
    (['"192.168.1.20:11434:11434"'], False),               # a chosen address, not "all interfaces"
    (['"${BIND:-127.0.0.1}:11434:11434"'], False),
    (['"${OLLAMA_PORT}:11434/tcp"'], True),
    (["\n      - target: 11434\n        published: 11434"], True),
    (["\n      - target: 11434\n        host_ip: 127.0.0.1"], False),
])
def test_ollama_compose_port_scopes(home, ports, exposed):
    lines = "".join(f"\n      - {p}" if not p.startswith("\n") else p for p in ports)
    _w(home / "ollama" / "docker-compose.yml",
       f"services:\n  ollama:\n    image: ollama/ollama:0.12.3\n    ports:{lines}\n")
    got = _got(_run(home))
    assert (got == [("aistack.port-exposed", "HIGH")]) is exposed and (got == []) is (not exposed)


def test_host_network_counts_as_published(home):
    _w(home / "o" / "compose.yml", "services:\n  ollama:\n    image: ollama/ollama\n    network_mode: host\n")
    assert _got(_run(home)) == [("aistack.port-exposed", "HIGH")]


def test_unrelated_images_on_3000_are_not_flagged(home):
    _w(home / "web" / "docker-compose.yml",
       'services:\n  web:\n    image: node:22\n    ports:\n      - "3000:3000"\n  graf:\n    image: grafana/grafana\n'
       '    ports: ["3000:3000"]\n')
    assert _run(home) == []


def test_dify_nginx_front_is_attributed_to_dify(home):
    _w(home / "dify" / "docker" / "docker-compose.yaml", """\
        services:
          api:
            image: langgenius/dify-api:1.9.1
          web:
            image: langgenius/dify-web:1.9.1
          nginx:
            image: nginx:latest
            ports:
              - "${EXPOSE_NGINX_PORT:-80}:${NGINX_PORT:-80}"
        """)
    [f] = _run(home)
    assert f.rule == "aistack.port-exposed" and f.title.startswith("Dify (`nginx`)") and "INIT_PASSWORD" in f.remediation


# ---------------------------------------------------------------- versions
def test_ragflow_image_from_dotenv_is_matched(home):
    _w(home / "ragflow" / "docker" / ".env", "RAGFLOW_IMAGE=infiniflow/ragflow:v0.24.0\nSVR_HTTP_PORT=9380\n")
    _w(home / "ragflow" / "docker" / "docker-compose.yml", """\
        services:
          ragflow:
            image: ${RAGFLOW_IMAGE}
            ports:
              - ${SVR_HTTP_PORT}:9380
        """)
    got = _got(_run(home))
    assert ("aistack.vulnerable-version", "CRITICAL") in got and ("aistack.port-exposed", "MEDIUM") in got
    _w(home / "ragflow" / "docker" / ".env", "RAGFLOW_IMAGE=infiniflow/ragflow:v0.25.0\nSVR_HTTP_PORT=9380\n")
    assert ("aistack.vulnerable-version", "CRITICAL") not in _got(_run(home))


@pytest.mark.parametrize("tag,vuln", [("1.2.0", True), ("v1.1.4", True), ("1.3.0", False), ("1.6.4", False),
                                      ("latest", False)])
def test_langflow_image_tag(home, tag, vuln):
    _w(home / "lf" / "compose.yaml", f'services:\n  langflow:\n    image: langflowai/langflow:{tag}\n'
                                     f'    ports:\n      - "127.0.0.1:7860:7860"\n')
    assert any(f.rule == "aistack.vulnerable-version" for f in _run(home)) is vuln


@pytest.mark.parametrize("name,ver,vuln", [("langflow", "1.2.0", True), ("langflow", "1.3.0", False),
                                           ("langflow_base", "0.2.9", True), ("langflow-base", "0.3.0", False),
                                           ("ragflow-sdk", "0.24.0", False)])
def test_langflow_site_packages(home, name, ver, vuln):
    site = home / "venv" / "lib" / "python3.12" / "site-packages"
    _w(site / f"{name}-{ver}.dist-info" / "METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n\n")
    fs = _run(home, sites=[pystartup.Site(site, "venv")])
    assert any(f.rule == "aistack.vulnerable-version" and f.severity == Severity.CRITICAL for f in fs) is vuln


# ---------------------------------------------------------------- Ollama host settings
@pytest.mark.parametrize("line,sev", [
    ("export OLLAMA_HOST=0.0.0.0", "HIGH"),
    ('export OLLAMA_HOST="0.0.0.0:11434"', "HIGH"),
    ("launchctl setenv OLLAMA_HOST 0.0.0.0", "HIGH"),
    ("set -gx OLLAMA_HOST http://0.0.0.0:11434", "HIGH"),
    ("OLLAMA_HOST=:11434 ollama serve", "HIGH"),
    ("export OLLAMA_HOST=100.101.102.103", "MEDIUM"),
    ("export OLLAMA_HOST=127.0.0.1:11434", None),
    ("# export OLLAMA_HOST=0.0.0.0", None),
    ("export OLLAMA_HOST=localhost", None),
])
def test_ollama_host_in_shell_profile(home, line, sev):
    _w(home / ".zshrc", line + "\n")
    got = _got(_run(home))
    assert got == ([("aistack.ollama-host", sev)] if sev else [])


def test_ollama_host_in_systemd_dropin_launchd_and_env(home, tmp_path):
    root = tmp_path / "root"
    _w(root / "etc/systemd/system/ollama.service.d/override.conf",
       '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0" "OLLAMA_ORIGINS=*"\n')
    la = home / "Library" / "LaunchAgents"
    la.mkdir(parents=True)
    (la / "com.me.ollama.plist").write_bytes(plistlib.dumps(
        {"Label": "x", "ProgramArguments": ["/bin/launchctl", "setenv", "OLLAMA_HOST", "0.0.0.0"]}))
    (la / "other.plist").write_bytes(plistlib.dumps({"Label": "y", "EnvironmentVariables": {"OLLAMA_HOST": "[::]:11434"}}))
    fs = _run(home, root=root, env={"OLLAMA_HOST": "0.0.0.0:11434"})
    locs = sorted(Path(f.location).name if f.location[0] in "/\\" or ":" in f.location[:3] else f.location for f in fs)
    assert [f.rule for f in fs] == ["aistack.ollama-host"] * 4
    assert locs == ["com.me.ollama.plist", "environment (OLLAMA_HOST)", "other.plist", "override.conf"]


# ---------------------------------------------------------------- robustness
def test_unparseable_compose_with_ai_image_is_reported_low(home):
    _w(home / "bad" / "docker-compose.yml", "services:\n  o:\n    image: ollama/ollama\n   ports: [\n")
    assert _got(_run(home)) == [("scanner.parse-error", "LOW")]


def test_walk_budget(home, monkeypatch):
    for i in range(6):
        (home / f"d{i}").mkdir()
    monkeypatch.setattr(aistack, "DIR_BUDGET", 3)
    assert [f.rule for f in _run(home)] == ["aistack.walk-budget"]


def test_repo_roots_and_system_dirs_are_searched(home, tmp_path):
    repos = tmp_path / "projects"
    _w(repos / "stack" / ".env", "WEBUI_AUTH=false\n")
    root = tmp_path / "root"
    _w(root / "srv" / "ai" / ".env", f"LITELLM_MASTER_KEY={DEFAULT}\n")
    got = _got(_run(home, repo_roots=[repos], root=root, system_dirs=["/srv"]))
    assert got == [("aistack.auth-disabled", "HIGH"), ("aistack.litellm-default-key", "HIGH")]


def test_cli_flag_and_default(tmp_path, monkeypatch):
    home = tmp_path / "home"
    _w(home / "owui" / ".env", "WEBUI_AUTH=False\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    out = tmp_path / "out" / "rep"
    base = ["--no-hermes", "--no-client-configs", "--no-global-git", "--no-stray-instructions",
            "--no-session-history", "-o", str(out), "--format", "none"]
    import json
    assert cli.run(base) == 1
    assert [f["rule"] for f in json.loads(out.with_suffix(".json").read_text())["findings"]] == ["aistack.auth-disabled"]
    assert cli.run(base + ["--no-ai-stack"]) == 0


def test_yamlmini_block_scalar_list_items_from_compose_command():
    from asca import yamlmini
    doc = yamlmini.load(textwrap.dedent("""\
        services:
          ollama:
            image: ollama/ollama
            entrypoint: ["/bin/bash", "-c"]
            command:
              - |
                ollama serve &
                sleep 5
              - >-
                folded
                text
            ports:
              - "11434:11434"
        """))
    svc = doc["services"]["ollama"]
    assert svc["command"] == ["ollama serve &\nsleep 5\n", "folded text"] and svc["ports"] == ["11434:11434"]


def test_yamlmini_merge_key_with_alias_list_and_compose_port_strings():
    from asca import yamlmini
    doc = yamlmini.load(textwrap.dedent("""\
        x-base: &base
          image: ollama/ollama:latest
          restart: always
        x-gpu: &gpu
          restart: "no"
          runtime: nvidia
        services:
          ollama-gpu:
            <<: [*base, *gpu]
            ports:
              - 11434:11434
              - 53:53
        """))
    svc = doc["services"]["ollama-gpu"]
    assert svc["image"] == "ollama/ollama:latest" and svc["restart"] == "always" and svc["runtime"] == "nvidia"
    assert svc["ports"] == ["11434:11434", "53:53"]          # YAML 1.2 like Compose: no base-60 integers
