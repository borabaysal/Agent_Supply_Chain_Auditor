"""Python startup hooks: code that runs every time Python starts, before any import you wrote.

Python's ``site`` module executes every line beginning with ``import`` in any ``*.pth`` file in a
site-packages directory, and imports ``sitecustomize`` / ``usercustomize`` when present. That
makes them the favourite persistence spot for poisoned packages:
- litellm 1.82.8 (Mar 2026) shipped ``litellm_init.pth``;
- litellm 1.107.0 (Oct 2026) shipped ``cook.pth`` + ``cook.py`` + ``sitecustomize.py`` in every
  wheel, a credential stealer that ran on any Python start, pip included.

Everything here is read as text: no interpreter is started, no module imported, no pip run.
Ownership comes from the ``RECORD`` files of installed distributions, so a finding can say
which package put a hook there (a hook nobody owns was dropped by something other than pip).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .model import Finding, Severity

KNOWN_BAD_DISTS = {
    "litellm": {"1.82.7": "TeamPCP backdoor in proxy_server.py (Mar 2026)",
                "1.82.8": "TeamPCP backdoor with litellm_init.pth startup hook (Mar 2026)",
                "1.107.0": "credential stealer + hourly remote loader via cook.pth / sitecustomize.py (Oct 2026)"},
}
KNOWN_BAD_FILES = {"litellm_init.pth": "litellm 1.82.8 backdoor", "cook.pth": "litellm 1.107.0 credential stealer"}
REFERENCES = {"litellm": "https://docs.litellm.ai/blog/security-incident-oct-21-2026"}

# Executable .pth files that standard tooling writes. Name *and* content must match.
BENIGN_PTH = [
    (r"^distutils-precedence\.pth$", r"^import os; var = 'SETUPTOOLS_USE_DISTUTILS'"),
    (r"^_virtualenv\.pth$", r"^import _virtualenv\s*$"),
    (r"^__editable__\..+\.pth$", r"^import __editable___[\w]+_finder; __editable___[\w]+_finder\.install\(.*\)\s*$"),
    (r"^_editable_impl_.+\.pth$", r"^import _editable_impl_\w+\s*$"),
    (r"^_.+\.pth$", r"^import _(?:pdm|hatch|editable)_?\w*\s*$"),
    (r"^.+-nspkg\.pth$", r"^import sys, types, os;"),
    (r"^pywin32\.pth$", r"^import pywin32_bootstrap\s*$"),
    (r"^(?:a1_)?coverage\.pth$|^pytest-cov\.pth$|^.*coverage.*\.pth$",
     r"^import (?:os, sys;exec\(.*COV_CORE_SOURCE.*|coverage; coverage\.process_startup\(\))"),
    (r"^_uv_ephemeral_overlay\.pth$", r"^import "),
    (r"^matplotlib-.*\.pth$", r"^import sys, types, os;"),
]
SUSPICIOUS = re.compile(r"(exec\s*\(|eval\s*\(|compile\s*\(|base64|b64decode|zlib|marshal|codecs\.decode|__import__|"
                        r"subprocess|os\.system|os\.popen|Popen|socket|urllib|requests|http\.client|urlopen|"
                        r"getattr\s*\(\s*__builtins__|bytes\.fromhex|\\x[0-9a-f]{2}|chr\s*\(\s*\d+)", re.I)
SITE_GLOBS = ["lib/python3*/site-packages", "lib/python3*/dist-packages", "Lib/site-packages"]
STARTUP_FIX = ("Don't run Python in that environment until you know where this came from (pip itself would run "
               "it). Delete the environment and rebuild it from a pinned lockfile; if the hook ran, rotate every "
               "credential the user can read (cloud, SSH, agent .env, browser).")


@dataclass
class Site:
    path: Path
    label: str


def _venvs_under(root: Path, depth: int = 4):
    root = root.expanduser()
    if not root.is_dir():
        return
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        if "pyvenv.cfg" in filenames:
            yield d
            dirnames[:] = []
            continue
        if len(d.parts) - base >= depth:
            dirnames[:] = []
            continue
        dirnames[:] = [x for x in dirnames if x not in ("node_modules", ".git", "__pycache__", "site-packages")]


def _sites_in(prefix: Path) -> list[Path]:
    out = []
    for g in SITE_GLOBS:
        out += [p for p in prefix.glob(g) if p.is_dir()]
    return out


def discover(home: Path, *, hermes_install: Path | None = None, repo_roots: list[Path] = (),
             extra: list[Path] = (), system: bool = True) -> list[Site]:
    sites: list[Site] = []
    if hermes_install:
        for venv in (hermes_install / ".venv", hermes_install / "venv"):
            sites += [Site(s, "hermes venv") for s in _sites_in(venv)]
        for py in sorted((hermes_install / "tools").glob("python-*")):
            sites += [Site(s, "hermes bundled python") for s in _sites_in(py)]
    sites += [Site(s, "user site") for s in (*_sites_in(home / ".local"),
                                             *sorted((home / "Library" / "Python").glob("3.*/lib/python/site-packages")))]
    for base, label in ((home / ".local" / "pipx" / "venvs", "pipx"), (home / ".local" / "share" / "uv" / "tools", "uv tool"),
                        (home / ".local" / "share" / "pipx" / "venvs", "pipx")):
        if base.is_dir():
            for v in sorted(base.iterdir()):
                sites += [Site(s, f"{label} {v.name}") for s in _sites_in(v)]
    for root in repo_roots:
        for v in _venvs_under(root):
            sites += [Site(s, f"venv {v}") for s in _sites_in(v)]
    if system:
        for prefix in (Path("/usr"), Path("/usr/local"), Path("/opt/homebrew")):
            sites += [Site(s, "system") for s in _sites_in(prefix)]
    sites += [Site(Path(p).expanduser(), "extra") for p in extra if Path(p).expanduser().is_dir()]
    seen, uniq = set(), []
    for s in sites:
        try:
            k = s.path.resolve()
        except OSError:
            continue
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def _dist_infos(site: Path) -> list[tuple[str, str, Path]]:
    out = []
    for d in site.glob("*.dist-info"):
        name, ver = "", ""
        try:
            with open(d / "METADATA", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("Name:"):
                        name = line[5:].strip()
                    elif line.startswith("Version:"):
                        ver = line[8:].strip()
                    elif not line.strip():
                        break
        except OSError:
            m = re.match(r"^(.+?)-([^-]+)\.dist-info$", d.name)
            name, ver = (m.group(1), m.group(2)) if m else (d.name, "")
        out.append((name, ver, d))
    return out


def _owner(site: Path, rel: str, dists) -> str | None:
    for name, ver, d in dists:
        try:
            with open(d / "RECORD", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.split(",", 1)[0] == rel:
                        return f"{name} {ver}"
        except OSError:
            continue
    return None


def _benign_pth(name: str, line: str) -> bool:
    return any(re.match(n, name) and re.match(c, line) for n, c in BENIGN_PTH)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def audit_site(site: Site, stats: dict) -> list[Finding]:
    out: list[Finding] = []
    sp = site.path
    dists = _dist_infos(sp)
    stats["python_dists"] = stats.get("python_dists", 0) + len(dists)
    for name, ver, d in dists:
        bad = KNOWN_BAD_DISTS.get(_norm(name), {}).get(ver)
        if bad:
            out.append(Finding(
                rule="python.known-bad-package", category="python-startup", severity=Severity.CRITICAL,
                title=f"Known-malicious {name} {ver} is installed ({site.label})", location=str(d),
                subject=f"{_norm(name)}=={ver}", detail=f"{bad}. Its code may already have run on every Python start "
                f"in this environment.", remediation=f"{STARTUP_FIX} Advisory: {REFERENCES.get(_norm(name), '')}"))
    for f in sorted(sp.glob("*.pth")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        exec_lines = [l for l in text.splitlines() if l.startswith(("import ", "import\t"))]
        if f.name in KNOWN_BAD_FILES:
            out.append(Finding(
                rule="python.known-bad-hook", category="python-startup", severity=Severity.CRITICAL,
                title=f"Known-malicious startup hook {f.name} ({site.label})", location=str(f),
                subject=f"{sp}:{f.name}", detail=f"{KNOWN_BAD_FILES[f.name]}; it runs on every Python start.",
                remediation=STARTUP_FIX))
            continue
        if not exec_lines:
            continue   # path-only .pth: just adds directories to sys.path
        if all(_benign_pth(f.name, l) for l in exec_lines):
            continue
        owner = _owner(sp, f.name, dists)
        sus = [l for l in exec_lines if SUSPICIOUS.search(l) or len(l) > 400]
        sev = Severity.HIGH if (sus or not owner) else Severity.MEDIUM
        out.append(Finding(
            rule="python.executable-pth", category="python-startup", severity=sev,
            title=f"{f.name} runs code at every Python start ({site.label})", location=str(f),
            subject=f"{sp}:{f.name}:{len(text)}",
            detail=(f"Installed by {owner}." if owner else "No installed package claims this file (not in any "
                    "RECORD), so pip didn't put it there.")
                   + (f" It uses {', '.join(sorted({m.group(0).strip('( ') for l in sus for m in [SUSPICIOUS.search(l)] if m}))}"
                      f", typical of droppers." if sus else "")
                   + f" First line: `{exec_lines[0][:100]}`",
            remediation=("Check the owning package is one you meant to install and is pinned. "
                         if owner else "") + "If you can't explain it: " + STARTUP_FIX))
    for mod in ("sitecustomize", "usercustomize"):
        for f in (sp / f"{mod}.py", sp / mod / "__init__.py"):
            if not f.is_file():
                continue
            rel = f.relative_to(sp).as_posix()
            owner = _owner(sp, rel, dists)
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            sus = SUSPICIOUS.search(text)
            sev = Severity.HIGH if (sus or not owner) else Severity.MEDIUM
            out.append(Finding(
                rule="python.sitecustomize", category="python-startup", severity=sev,
                title=f"{mod} in {site.label} runs at every Python start", location=str(f),
                subject=f"{sp}:{rel}:{len(text)}",
                detail=(f"Installed by {owner}." if owner else "No installed package claims it.")
                       + (f" Contains `{sus.group(0).strip('( ')}`." if sus else "")
                       + " Packages have no business shipping this file (litellm 1.107.0 did).",
                remediation=STARTUP_FIX))
    return out


def audit(sites: list[Site], stats: dict) -> list[Finding]:
    stats["python_sites"] = len(sites)
    out: list[Finding] = []
    for s in sites:
        out += audit_site(s, stats)
    return out
