"""Shared test setup.

- The host's real macOS privacy database is never read (CI's macOS runners have Full Disk Access grants).
- On Windows: tests point HOME at a temp dir, but Python takes the home folder from USERPROFILE there, so
  Path.home()/expanduser follow HOME while a test sets it. And the test fixtures read and write their files as
  UTF-8 (Windows defaults to cp1252). asca's own code passes encoding= explicitly; test_encoding.py enforces it,
  so this shim can't hide a bug in asca.
"""
import os
import pathlib

import pytest

from asca import agentvers, aistack, autostart, devcreds, pthtargets, pystartup, secrets, tcc, userhooks

REAL_HOME = pathlib.Path.home().resolve()     # captured before any test changes HOME


@pytest.fixture(autouse=True)
def _no_host_tcc(monkeypatch):
    monkeypatch.setattr(tcc, "ENABLED", False)


@pytest.fixture(autouse=True)
def _no_host_agent_installs(monkeypatch):
    """Agent-version detection reads PATH, APPDATA, LOCALAPPDATA, Homebrew and /Applications, so a test run on a
    machine with a real (old) Claude Code would see it. Tests get an empty host unless they pass their own."""
    real = agentvers.installed

    def isolated(home=None, env=None, brew_dirs=None, app_dirs=None):
        return real(home, env={} if env is None else env, brew_dirs=[] if brew_dirs is None else brew_dirs,
                    app_dirs=[] if app_dirs is None else app_dirs)

    monkeypatch.setattr(agentvers, "installed", isolated)


@pytest.fixture(autouse=True)
def _no_real_home_files(monkeypatch):
    """Checks that read the user's own files (credential files, agent hooks) see nothing in the real home of
    the machine running the tests; tests that point HOME at a temp dir are unaffected."""
    for mod in (devcreds, userhooks):
        real = mod.audit

        def isolated(home, stats, env=None, _real=real):
            if pathlib.Path(home).resolve() == REAL_HOME:
                return []
            return _real(home, stats, env=env)

        monkeypatch.setattr(mod, "audit", isolated)
    real_collect = userhooks.collect
    monkeypatch.setattr(userhooks, "collect", lambda home, env=None: ([], []) if pathlib.Path(home).resolve() ==
                        REAL_HOME else real_collect(home, env))


@pytest.fixture(autouse=True)
def _no_host_ai_stack(monkeypatch, tmp_path_factory):
    """The AI-stack check walks home, /opt and /srv and reads systemd units, launchd plists, OLLAMA_HOST and
    site-packages. Tests see none of the host's unless they pass their own root/env/sites."""
    real = aistack.audit
    empty = tmp_path_factory.mktemp("no-host-root")

    def isolated(home, stats, *, repo_roots=(), root=None, env=None, sites=None, system_dirs=None):
        if pathlib.Path(home).resolve() == REAL_HOME:
            return []
        return real(home, stats, repo_roots=repo_roots, root=empty if root is None else root,
                    env={} if env is None else env, sites=[] if sites is None else sites, system_dirs=system_dirs)

    monkeypatch.setattr(aistack, "audit", isolated)


@pytest.fixture(autouse=True)
def _no_host_autostart(monkeypatch, tmp_path_factory):
    """Never read the test machine's LaunchAgents, systemd user units or linger files."""
    real = autostart.audit
    empty = tmp_path_factory.mktemp("no-host-root")

    def isolated(home, stats, *, root=None, user=None):
        if pathlib.Path(home).resolve() == REAL_HOME:
            return []
        return real(home, stats, root=empty if root is None else root, user=user or "nobody")

    monkeypatch.setattr(autostart, "audit", isolated)


@pytest.fixture(autouse=True)
def _no_host_python_sites(monkeypatch, tmp_path_factory):
    """CLI runs would read the machine's system site-packages and dpkg database (CI's Ubuntu image has distro
    Python packages with startup hooks). Tests that want a system site pass it explicitly."""
    real = pystartup.discover

    def isolated(home, *, hermes_install=None, repo_roots=(), extra=(), system=False):
        return real(home, hermes_install=hermes_install, repo_roots=repo_roots, extra=extra, system=False)

    monkeypatch.setattr(pystartup, "discover", isolated)
    monkeypatch.setattr(pthtargets, "DPKG_INFO", tmp_path_factory.mktemp("no-dpkg"))


@pytest.fixture(autouse=True)
def _no_windows_permissions_note(monkeypatch):
    # The once-per-run low note on Windows would change every exact finding list; test_windows.py covers it.
    # (Only the note: the mode-bit checks themselves skip Windows on their own.)
    monkeypatch.setattr(secrets, "permissions_checked", lambda: True)


if os.name == "nt":
    _home, _expand = pathlib.Path.home, os.path.expanduser
    _read, _write = pathlib.Path.read_text, pathlib.Path.write_text

    def _home_from_env(cls=None):
        return pathlib.Path(os.environ["HOME"]) if os.environ.get("HOME") else _home()

    def _expanduser(path):
        s = os.fspath(path)
        if os.environ.get("HOME") and isinstance(s, str) and (s == "~" or s.startswith(("~/", "~\\"))):
            return os.environ["HOME"] + s[1:]
        return _expand(path)

    def _read_utf8(self, encoding=None, errors=None, *a, **k):
        return _read(self, encoding or "utf-8", errors, *a, **k)

    def _write_utf8(self, data, encoding=None, errors=None, *a, **k):
        return _write(self, data, encoding or "utf-8", errors, *a, **k)

    pathlib.Path.home = classmethod(_home_from_env)
    pathlib.Path.expanduser = lambda self: pathlib.Path(_expanduser(str(self)))
    os.path.expanduser = _expanduser
    pathlib.Path.read_text = _read_utf8
    pathlib.Path.write_text = _write_utf8
