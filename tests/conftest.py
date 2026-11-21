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

from asca import secrets, tcc


@pytest.fixture(autouse=True)
def _no_host_tcc(monkeypatch):
    monkeypatch.setattr(tcc, "ENABLED", False)


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
