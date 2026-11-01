"""Agent instruction files left in web-writable folders (Downloads, Desktop, temp).

Coding agents load AGENTS.md / CLAUDE.md / .cursorrules … from the directory they start in.
A browser download or an extracted archive can drop one into ~/Downloads, and an agent
launched there obeys it (Forever Security found a malicious AGENTS.md that told the agent to
install a rogue npm package). Instruction files inside git repositories are expected and are
skipped. Files are read as text only and analysed with the asca-skills content rules.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .model import Finding, Severity

RULE = "repo.stray-agent-instructions"
MAX_DEPTH = 2                 # the folder itself, its children and grandchildren
MAX_ENTRIES_PER_DIR = 5000
MAX_READ = 512 * 1024

# Instruction files each client loads automatically from its working directory.
FILES = {
    "AGENTS.md": "Codex CLI, Cursor, Copilot, Gemini CLI and other AGENTS.md readers",
    "CLAUDE.md": "Claude Code",
    "CLAUDE.local.md": "Claude Code",
    "GEMINI.md": "Gemini CLI",
    ".cursorrules": "Cursor (legacy rules file)",
    ".windsurfrules": "Windsurf (legacy rules file)",
    ".clinerules": "Cline",
}
# (sub-path, client) — directories whose files are all rules, or single nested files
RULE_DIRS = {(".cursor", "rules"): "Cursor", (".windsurf", "rules"): "Windsurf", (".clinerules",): "Cline"}
NESTED = {(".github", "copilot-instructions.md"): "GitHub Copilot"}

SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "venv", ".cache", ".git"}


def default_dirs(home: Path) -> list[Path]:
    dirs = [home / "Downloads", home / "Desktop", Path(tempfile.gettempdir())]
    if os.name == "posix":
        dirs.append(Path("/tmp"))
    out: list[Path] = []
    seen: set[str] = set()
    for d in dirs:
        try:
            key = str(d.resolve())
        except OSError:
            key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _is_dir(p: Path) -> bool:
    try:
        return stat.S_ISDIR(p.lstat().st_mode)
    except OSError:
        return False


def _candidates(d: Path):
    """(path, client) instruction files directly in directory *d* (not following symlinked dirs)."""
    for name, client in FILES.items():
        p = d / name
        try:
            st = p.lstat()
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            yield p, client
    for parts, client in NESTED.items():
        p = d.joinpath(*parts)
        if _is_dir(d / parts[0]):
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                yield p, client
    for parts, client in RULE_DIRS.items():
        rd = d.joinpath(*parts)
        if not (_is_dir(d / parts[0]) and _is_dir(rd)):
            continue
        try:
            entries = sorted(rd.iterdir())[:200]
        except OSError:
            continue
        for p in entries:
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                yield p, client


def find(dirs: list[Path]) -> list[tuple[Path, str, Path]]:
    """(file, client, scanned root) for instruction files up to MAX_DEPTH below each dir, skipping git repos."""
    found: list[tuple[Path, str, Path]] = []
    for root in dirs:
        if not _is_dir(root):
            continue  # not present
        stack = [(root, 0)]
        while stack:
            d, depth = stack.pop()
            if (d / ".git").exists():
                continue  # repo instruction files are expected; nested repos too
            found.extend((p, client, root) for p, client in _candidates(d))
            if depth >= MAX_DEPTH:
                continue
            try:
                entries = sorted(os.scandir(d), key=lambda e: e.name)[:MAX_ENTRIES_PER_DIR]
            except OSError:
                continue
            for e in entries:
                if e.name in SKIP_DIRS or e.name in (".cursor", ".windsurf", ".github", ".clinerules"):
                    continue
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append((Path(e.path), depth + 1))
                except OSError:
                    continue
    uniq: dict[str, tuple[Path, str, Path]] = {}
    for t in found:
        uniq.setdefault(str(t[0]), t)
    return sorted(uniq.values(), key=lambda t: str(t[0]))


def _label(root: Path) -> str:
    home = Path.home()
    if root in (home / "Downloads", home / "Desktop"):
        return f"~/{root.name}"
    if root in (Path(tempfile.gettempdir()), Path("/tmp")):
        return "a temp directory"
    return str(root)


def audit(dirs: list[Path], stats: dict, official=None) -> list[Finding]:
    from .skillscan import official as off
    from .skillscan import scan as skillscan

    if official is None:
        official = off.load()
    out: list[Finding] = []
    hits_total = 0
    files = find(dirs)
    for path, client, root in files:
        note, hits = "", []
        try:
            st = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            note = " It is a symlink (target not read)."
        else:
            try:
                with open(path, "rb"):
                    pass
                hits = [h for h in skillscan.scan_file(path, official)
                        if h.severity >= Severity.MEDIUM and h.rule != "bundled-binary"]
            except OSError as exc:
                note = f" Content could not be read ({type(exc).__name__}), so it was not analysed (fail closed)."
        hits_total += len(hits)
        sev = Severity.HIGH if hits else Severity.MEDIUM
        if hits:
            shown = "; ".join(f"line {h.line}: {h.title} [{h.rule}] `{h.text}`" for h in hits[:3])
            more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
            why = f" Content rules matched: {shown}{more}."
        else:
            why = ""
        where = _label(root)
        out.append(Finding(
            rule=RULE, category="repo-config", severity=sev,
            title=f"Agent instruction file `{path.name}` in {where}" + (" with suspicious content" if hits else ""),
            location=str(path), subject=path.name,
            detail=(f"{client} loads this file automatically when started in {path.parent}. It is not inside a git "
                    f"repository, so it most likely arrived with a download, archive or another program — a "
                    f"planted AGENTS.md in ~/Downloads has been used to make a coding agent install a malicious "
                    f"npm package.{why}{note}"),
            remediation=(f"Read it. If you didn't put it there, delete it (and the archive it came with), and don't "
                         f"start coding agents in {root}. If an agent already ran there, review what it installed "
                         f"or executed."),
        ))
    stats["stray_instruction_files"] = len(files)
    return out
