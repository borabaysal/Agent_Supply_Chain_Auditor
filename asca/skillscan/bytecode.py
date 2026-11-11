"""Bytecode caches in skills that Python would run instead of the visible source (PyCache Trap).

A skill can ship harmless ``helper.py`` next to ``__pycache__/helper.cpython-313.pyc`` whose code
differs. Python's loader accepts a cache when its header matches the source (timestamp-based:
source mtime and size; checked hash-based: a hash of the source) or never checks at all
(unchecked hash-based), then runs the *cache*. Scanners that read only the source miss it:
PyCache Trap got past seven skill scanners in 94-100% of cases (arXiv 2610.10612, Oct 2026).

What this does, without ever executing scanned code:
- reads each ``.pyc`` header and decides what CPython would do with it;
- only for caches Python would actually use, compiles the visible source and compares code
  objects (filenames ignored) in a separate ``python -I -S`` helper process, so a malformed
  cache can't crash the auditor and no site/.pth hooks run there. ``compile()`` parses, it
  doesn't execute; ``marshal.loads`` builds a code object, it doesn't run it.

Stale caches (header doesn't match) are ignored: Python recompiles those instead of running them.
Caches for another Python version can't be compared and are reported LOW.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from ..model import Finding, Severity

TAG = re.compile(r"^(?P<name>.+?)\.(?P<tag>[a-z]+-\d+)(?:\.opt-(?P<opt>[12]))?\.pyc$")
MAX_PYC = 8 * 1024 * 1024
MAX_FILES = 2000
REF = "https://arxiv.org/abs/2610.10612"
FIX = ("Delete the cache files (`find <skill> -name __pycache__ -type d -exec rm -rf {} +` and any stray .pyc) "
       "and reinstall the skill from its source. If you didn't put bytecode there, treat the skill as malicious: "
       "remove it and check what it ran.")

# Runs in a separate interpreter: compiles the source, loads the cache body, compares code objects.
_HELPER = r'''
import json, marshal, sys, types
src_path, pyc_path, opt = sys.argv[1], sys.argv[2], int(sys.argv[3])
def norm(co):
    consts = tuple(norm(c) if isinstance(c, types.CodeType) else c for c in co.co_consts)
    return co.replace(co_filename="", co_consts=consts)
try:
    src = open(src_path, "rb").read()
    ref = compile(src, src_path, "exec", dont_inherit=True, optimize=opt)
    body = open(pyc_path, "rb").read()[16:]
    got = marshal.loads(body)
    if not isinstance(got, types.CodeType):
        print(json.dumps({"result": "not-code"}))
    else:
        print(json.dumps({"result": "same" if norm(ref) == norm(got) else "different"}))
except SyntaxError:
    print(json.dumps({"result": "source-syntax-error"}))
except Exception as e:
    print(json.dumps({"result": "error", "why": type(e).__name__}))
'''


def _header(data: bytes):
    """(magic, flags, mtime, size, hash) or None if too short to be a pyc."""
    if len(data) < 16:
        return None
    flags = int.from_bytes(data[4:8], "little")
    if flags & 1:
        return data[:4], flags, None, None, data[8:16]
    return data[:4], flags, int.from_bytes(data[8:12], "little"), int.from_bytes(data[12:16], "little"), None


def _source_for(pyc: Path) -> tuple[Path, int, bool]:
    """(expected source path, optimization level, in __pycache__?)"""
    if pyc.parent.name == "__pycache__":
        m = TAG.match(pyc.name)
        if m:
            return pyc.parent.parent / (m.group("name") + ".py"), int(m.group("opt") or 0), True
        return pyc.parent.parent / (pyc.name.split(".")[0] + ".py"), 0, True
    return pyc.with_suffix(".py"), 0, False


def _compare(src: Path, pyc: Path, opt: int, timeout: float = 20.0) -> str:
    try:
        r = subprocess.run([sys.executable, "-I", "-S", "-c", _HELPER, str(src), str(pyc), str(opt)],
                           capture_output=True, text=True, timeout=timeout, env={"PATH": os.environ.get("PATH", "")})
        return json.loads(r.stdout.strip() or "{}").get("result", "crashed" if r.returncode else "error")
    except subprocess.TimeoutExpired:
        return "timeout"
    except (OSError, ValueError):
        return "error"


def audit_dir(root: Path, owner: str, *, rule_prefix: str = "skill") -> list[Finding]:
    """Check every .pyc/.pyo under ``root`` (a skill or plugin folder)."""
    out: list[Finding] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".venv", "venv")
                       and not (Path(dirpath) / d / "SKILL.md").exists()]   # nested skills are scanned on their own
        for fn in filenames:
            if not fn.endswith((".pyc", ".pyo")):
                continue
            seen += 1
            if seen > MAX_FILES:
                return out
            pyc = Path(dirpath, fn)
            if pyc.is_symlink():
                continue
            out += _check(pyc, owner, rule_prefix)
    return out


def _f(rule_prefix, rule, sev, title, pyc, owner, detail, extra=""):
    return Finding(rule=f"{rule_prefix}.{rule}", category="hidden-content", severity=sev, title=f"{title}: `{owner}`",
                   location=str(pyc), subject=f"{owner}:{pyc.name}{extra}", detail=detail + f" ({REF})",
                   remediation=FIX)


def _check(pyc: Path, owner: str, rp: str) -> list[Finding]:
    try:
        size = pyc.stat().st_size
        if size > MAX_PYC:
            return [_f(rp, "bundled-bytecode", Severity.MEDIUM, "Oversized bytecode file in skill", pyc, owner,
                       f"{size} bytes; not inspected.")]
        data = pyc.read_bytes()
    except OSError:
        return []
    hdr = _header(data)
    src, opt, cached = _source_for(pyc)
    if hdr is None:
        return [_f(rp, "bundled-bytecode", Severity.MEDIUM, "Malformed bytecode file in skill", pyc, owner,
                   "Too short to be a valid .pyc; it isn't something Python wrote.")]
    magic, flags, mtime, srcsize, srchash = hdr
    if not src.is_file():
        if cached:
            return [_f(rp, "bundled-bytecode", Severity.LOW, "Bytecode cache without its source", pyc, owner,
                       f"No `{src.name}` next to the __pycache__ folder. Python ignores such a cache, so it can't "
                       f"run on import, but nothing in a skill should need it.")]
        return [_f(rp, "bytecode-sourceless", Severity.HIGH, "Bytecode with no readable source", pyc, owner,
                   f"`{pyc.name}` has no `{src.name}` beside it, so `import {src.stem}` runs this bytecode directly. "
                   f"There's no source to review.")]
    if not cached:
        return []      # legacy-location .pyc next to its .py: Python imports the source, not this file
    if magic != importlib.util.MAGIC_NUMBER:
        return [_f(rp, "bundled-bytecode", Severity.LOW, "Bytecode cache for another Python version", pyc, owner,
                   f"Compiled by a different Python than this one ({sys.version.split()[0]}), so asca can't compare "
                   f"it with `{src.name}`. A Python of that version would run it if its header matches.")]
    try:
        st = src.stat()
        source_bytes = src.read_bytes() if flags & 1 else b""
    except OSError:
        return []
    if flags & 1:                                   # hash-based
        unchecked = not (flags & 2)
        if not unchecked and srchash != importlib.util.source_hash(source_bytes):
            return []                               # checked hash mismatch: Python recompiles
        used = True
    else:                                           # timestamp-based
        used = (mtime == (int(st.st_mtime) & 0xFFFFFFFF)) and (srcsize == (st.st_size & 0xFFFFFFFF))
    if not used:
        return []
    verdict = _compare(src, pyc, opt)
    if verdict == "same":
        return []
    if verdict == "different":
        how = ("an unchecked hash-based cache, which Python never checks against the source" if flags & 1 and
               not flags & 2 else "a cache whose header matches the source, which Python accepts")
        return [_f(rp, "bytecode-mismatch", Severity.HIGH, "Bytecode cache runs different code than its source",
                   pyc, owner,
                   f"`{pyc.name}` is {how}, but its code is not what `{src.name}` compiles to. Python runs the cache, "
                   f"so what you reviewed isn't what executes: the PyCache Trap technique.")]
    if verdict == "source-syntax-error":
        return [_f(rp, "bytecode-mismatch", Severity.HIGH, "Bytecode cache for source that doesn't compile",
                   pyc, owner, f"`{src.name}` has a syntax error, yet Python would load this cache for it.")]
    return [_f(rp, "bundled-bytecode", Severity.MEDIUM, "Bytecode cache couldn't be verified", pyc, owner,
               f"Comparison with `{src.name}` failed ({verdict}). A cache that can't be loaded cleanly is unusual.")]
