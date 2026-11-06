"""Deterministic, budgeted content hashes for installed extensions, plugins and skills.

The hash of an item is sha256 over ``relpath NUL sha256(file) LF`` for each selected file, in
sorted posix-relpath order. Nothing is executed and symlinks are never followed (a link
contributes its target string, so retargeting it changes the hash).

Budgets keep a daily run cheap and, more importantly, deterministic:
- **per item:** files are planned in sorted order from ``stat`` sizes and cut at
  ``item_cap`` bytes (``node_modules`` has its own smaller cap). The same files are cut on
  every run, so a partial hash is still comparable from run to run;
- **total:** an item whose planned bytes don't fit the remaining run budget is not hashed at
  all (``hash=None``), rather than hashed partially in a way that depends on other items.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

MiB = 1024 * 1024
DEFAULT_ITEM_CAP = 64 * MiB
DEFAULT_NODE_MODULES_CAP = 16 * MiB
DEFAULT_TOTAL = 1024 * MiB
DEFAULT_MAX_FILES = 20_000

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
             ".in_use", ".DS_Store"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".log", ".lock", ".tmp", ".swp"}
# What "code" means for an extension or plugin: things that run, plus the manifests that say what runs.
CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".node", ".wasm", ".py", ".pyd",
                 ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".exe", ".dll", ".so", ".dylib",
                 ".jar", ".class", ".rb", ".pl", ".php", ".lua", ".applescript", ".scpt", ".vbs", ".go", ".rs",
                 ".html", ".htm"}
MANIFESTS = {"package.json", "plugin.yaml", "plugin.yml", "plugin.json", "pyproject.toml", "setup.py", "setup.cfg",
             "requirements.txt", "extension.vsixmanifest", ".mcp.json", "manifest.json", "manifest.yaml",
             "skill.md", "hooks.json", "settings.json"}


@dataclass
class Limits:
    item_cap: int = DEFAULT_ITEM_CAP
    node_modules_cap: int = DEFAULT_NODE_MODULES_CAP
    total: int = DEFAULT_TOTAL
    max_files: int = DEFAULT_MAX_FILES

    def to_dict(self) -> dict:
        return {"item_cap": self.item_cap, "node_modules_cap": self.node_modules_cap, "total": self.total,
                "max_files": self.max_files}


class Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limits.total - self.used)


@dataclass
class TreeHash:
    digest: str | None
    files: int = 0
    bytes: int = 0
    partial: bool = False
    note: str = ""      # why partial / skipped


def _selected(name: str, mode: str) -> bool:
    low = name.lower()
    suffix = os.path.splitext(low)[1]
    if suffix in SKIP_SUFFIXES:
        return False
    if mode == "all":
        return True
    return low in MANIFESTS or suffix in CODE_SUFFIXES


def plan(root: Path, mode: str, limits: Limits) -> tuple[list[tuple[str, Path, int, bool]], bool, str]:
    """Sorted (relpath, path, size, is_link) list within the per-item caps, plus (partial, note)."""
    entries: list[tuple[str, Path, int, bool]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        for f in filenames:
            if not _selected(f, mode):
                continue
            p = base / f
            rel = p.relative_to(root).as_posix()
            try:
                st = os.lstat(p)
            except OSError:
                continue
            is_link = os.path.islink(p)
            entries.append((rel, p, 0 if is_link else st.st_size, is_link))
    entries.sort(key=lambda e: e[0])
    out, total, nm_total, partial, notes = [], 0, 0, False, set()
    for rel, p, size, is_link in entries:
        in_nm = "/node_modules/" in f"/{rel}"
        if len(out) >= limits.max_files:
            partial = True
            notes.add(f"file cap {limits.max_files}")
            break
        if in_nm and nm_total + size > limits.node_modules_cap:
            partial = True
            notes.add(f"node_modules cap {limits.node_modules_cap // MiB} MiB")
            continue
        if total + size > limits.item_cap:
            partial = True
            notes.add(f"item cap {limits.item_cap // MiB} MiB")
            continue
        out.append((rel, p, size, is_link))
        total += size
        if in_nm:
            nm_total += size
    return out, partial, ", ".join(sorted(notes))


def tree_hash(root: Path, *, mode: str = "code", budget: Budget) -> TreeHash:
    files, partial, note = plan(root, mode, budget.limits)
    planned = sum(s for _, _, s, _ in files)
    if planned > budget.remaining:
        return TreeHash(None, len(files), planned, True, "run budget exhausted; not hashed")
    h = hashlib.sha256()
    read = 0
    for rel, p, _size, is_link in files:
        if is_link:
            try:
                fh = "link:" + os.readlink(p)
            except OSError:
                fh = "link:?"
        else:
            fd = hashlib.sha256()
            try:
                with open(p, "rb") as fp:
                    for chunk in iter(lambda: fp.read(1 * MiB), b""):
                        fd.update(chunk)
                        read += len(chunk)
            except OSError:
                fd.update(b"\x00unreadable")
            fh = fd.hexdigest()
        h.update(rel.encode("utf-8", "surrogateescape") + b"\0" + fh.encode() + b"\n")
    budget.used += read
    return TreeHash(h.hexdigest(), len(files), read, partial, note)


def text_hash(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8", "surrogateescape")).hexdigest()
