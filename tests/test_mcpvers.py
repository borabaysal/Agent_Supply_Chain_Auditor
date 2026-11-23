"""MCP launchers (#6 dependency drift, #7 vulnerable pinned versions)."""
import json

import pytest

from asca import discover, mcp, mcpvers
from asca.advisories import Advisory
from asca.model import Severity


@pytest.fixture(autouse=True)
def _fresh():
    mcpvers.LAUNCHES.clear()
    yield
    mcpvers.LAUNCHES.clear()


def _run(command, args, env=None, name="srv"):
    spec = {"command": command, "args": args}
    if env is not None:
        spec["env"] = env
    return mcp.audit_server("cfg.json#mcpServers.srv", name, spec)


def _rules(fs):
    return sorted((f.rule, f.severity) for f in fs)


@pytest.mark.parametrize("command,args,eco,pkg,ver", [
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"], "npm",
     "@modelcontextprotocol/server-filesystem", "2025.8.21"),
    ("npx", ["-y", "mcp-remote@0.1.29", "https://x.example.invalid"], "npm", "mcp-remote", "0.1.29"),
    ("bunx", ["some-mcp@v1.2.3"], "npm", "some-mcp", "1.2.3"),
    ("npx.cmd", ["-y", "a-mcp@1.0.0"], "npm", "a-mcp", "1.0.0"),
    ("npm", ["exec", "--", "b-mcp@2.0.1"], "npm", "b-mcp", "2.0.1"),
    ("uvx", ["awslabs.document-loader-mcp-server==1.0.12"], "PyPI", "awslabs.document-loader-mcp-server", "1.0.12"),
    ("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git"], "PyPI", "mcp-server-git", "0.6.2"),
    ("uvx", ["mcp-server-fetch@2025.4.7"], "PyPI", "mcp-server-fetch", "2025.4.7"),
    ("pipx", ["run", "--spec", "c-mcp==3.1.0", "c-mcp"], "PyPI", "c-mcp", "3.1.0"),
    ("/usr/local/bin/uvx", ["d-mcp[cli]==0.9.0"], "PyPI", "d-mcp", "0.9.0"),
])
def test_pinned_launch_is_parsed_and_gets_a_drift_note(command, args, eco, pkg, ver):
    f = _run(command, args)
    drift = [x for x in f if x.rule == "mcp.launcher-dep-drift"]
    assert len(drift) == 1 and drift[0].severity == Severity.INFO
    assert drift[0].subject == f"srv:{eco}:{pkg}@{ver}" and "15 different dependency sets" in drift[0].detail
    assert not any(x.rule == "pin.mcp-package" for x in f)                 # exact pins still pass the pin check


@pytest.mark.parametrize("command,args", [
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem"]),          # unpinned: pin.mcp-package instead
    ("npx", ["-y", "x-mcp@^1.2.0"]),
    ("npx", ["./local/server.js"]),
    ("uvx", ["mcp-server-git"]),
    ("uvx", ["mcp-server-git>=0.6"]),
    ("uvx", ["--from", "git+https://github.com/o/r@" + "a" * 40, "srv"]),
    ("uvx", ["--constraints", "c.txt", "e-mcp==1.0.0"]),                 # frozen by constraints
    ("uvx", ["--with-requirements", "req.txt", "e-mcp==1.0.0"]),
    ("docker", ["run", "-i", "--rm", "ghcr.io/o/mcp@sha256:" + "b" * 64]),
    ("node", ["/opt/servers/x/index.js"]),
])
def test_no_drift_note_when_not_an_exact_registry_pin_or_already_frozen(command, args):
    assert not [x for x in _run(command, args) if x.rule == "mcp.launcher-dep-drift"]


def test_document_loader_cve_in_range_unmitigated_is_high():
    f = _run("uvx", ["awslabs.document-loader-mcp-server==1.0.15"])
    v = [x for x in f if x.rule == "mcp.vulnerable-version"]
    assert len(v) == 1 and v[0].severity == Severity.HIGH and "CVE-2026-130901" in v[0].subject
    assert "isn't set here" in v[0].detail and "==1.0.21" in v[0].remediation


def test_document_loader_mitigated_by_base_dir_is_medium():
    f = _run("uvx", ["awslabs.document-loader-mcp-server==1.0.10"], env={"DOCUMENT_BASE_DIR": "/home/me/docs"})
    v = [x for x in f if x.rule == "mcp.vulnerable-version"]
    assert [x.severity for x in v] == [Severity.MEDIUM] and "mitigation" in v[0].detail


@pytest.mark.parametrize("ver", ["1.0.9", "1.0.21", "1.1.0"])
def test_document_loader_outside_range_is_clean(ver):
    assert not [x for x in _run("uvx", [f"awslabs-document-loader-mcp-server=={ver}"])
                if x.rule == "mcp.vulnerable-version"]


@pytest.mark.parametrize("base", ["/", "C:\\", "//"])
def test_document_loader_root_base_dir_is_flagged_on_any_version(base):
    f = _run("uvx", ["awslabs.document-loader-mcp-server==1.0.25"], env={"DOCUMENT_BASE_DIR": base})
    assert ("mcp.document-loader-root", Severity.MEDIUM) in _rules(f)


def test_client_config_end_to_end(tmp_path):
    p = tmp_path / "claude_desktop_config.json"
    p.write_text(json.dumps({"mcpServers": {
        "docs": {"command": "uvx", "args": ["awslabs.document-loader-mcp-server==1.0.20"]},
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"]}}}),
        encoding="utf-8")
    got = _rules(discover.audit_json_mcp(p))
    assert got.count(("mcp.launcher-dep-drift", Severity.INFO)) == 2 and ("mcp.vulnerable-version", Severity.HIGH) in got
    assert len(mcpvers.LAUNCHES) == 2


def test_online_adds_feed_advisories_and_skips_bundled_ones():
    launches = [("cfg#fs", "fs", "npm", "@modelcontextprotocol/server-filesystem", "2025.3.28"),
                ("cfg#docs", "docs", "PyPI", "awslabs.document-loader-mcp-server", "1.0.15")]
    calls = []

    def osv(eco, pkg, ver, timeout):
        calls.append(("osv", eco, pkg))
        if pkg.startswith("@modelcontextprotocol"):
            return [Advisory(ids={"GHSA-aaaa-bbbb-cccc", "CVE-2025-53110"}, severity=Severity.HIGH,
                             summary="Path validation bypass", fixed="2025.7.1", sources={"osv"}, url="u")]
        return [Advisory(ids={"CVE-2026-130901"}, severity=Severity.HIGH, summary="dup", fixed="1.0.21")]

    def ghsa(eco, pkg, ver, timeout):
        calls.append(("ghsa", eco, pkg))
        return []

    f, errs = mcpvers.online(launches, osv=osv, ghsa=ghsa)
    assert errs == [] and [x.subject.split(":")[0] for x in f] == ["fs"]          # bundled CVE not repeated
    assert "@2025.7.1" in f[0].remediation and "osv.dev" in f[0].detail
    assert ("ghsa", "pip", "awslabs.document-loader-mcp-server") in calls          # GitHub calls PyPI "pip"


def test_online_feed_errors_are_reported_not_raised():
    def boom(*a, **k):
        raise OSError("offline")
    f, errs = mcpvers.online([("c", "s", "npm", "x-mcp", "1.0.0")], osv=boom, ghsa=boom)
    assert f == [] and len(errs) == 2
