"""Filesystem probes that never raise.

``Path.exists()/is_dir()/is_file()`` raise ``PermissionError`` on Python 3.10–3.13 when a parent folder
can't be entered (3.14 returns False). Walks over other people's folders (``/tmp``, shared drives,
``--repos`` roots) must skip those, not abort the whole audit.
"""
from __future__ import annotations

import stat
from pathlib import Path


def is_dir(p: Path) -> bool:
    try:
        return stat.S_ISDIR(p.stat().st_mode)
    except (OSError, ValueError):
        return False


def is_file(p: Path) -> bool:
    try:
        return stat.S_ISREG(p.stat().st_mode)
    except (OSError, ValueError):
        return False


def exists(p: Path) -> bool:
    try:
        p.stat()
        return True
    except (OSError, ValueError):
        return False


def utf8_stdio() -> None:
    """Redirected output on Windows defaults to cp1252, and printing ✅ or → would crash the run. Switch
    non-UTF-8 redirected streams to UTF-8 (a real console already handles Unicode, so it's left alone)."""
    import sys
    for s in (sys.stdout, sys.stderr):
        enc = (getattr(s, "encoding", "") or "").lower().replace("-", "")
        if enc != "utf8" and hasattr(s, "reconfigure"):
            try:
                if not s.isatty():
                    s.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
