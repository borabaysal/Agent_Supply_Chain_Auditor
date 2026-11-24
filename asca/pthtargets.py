"""What executable ``.pth`` lines import: the module that actually runs at every Python start
(``python.pth-import-target``).

``pystartup`` grades the ``.pth`` line itself, and lets lines that standard tooling writes pass by name and
content (``import _virtualenv``, ``__import__('_distutils_hack')``, ``import coverage`` ...). The code that runs is
the imported module, which nothing checked: a ``_virtualenv.py`` swapped for a stealer, or a compiled
``_virtualenv.*.so`` placed next to it (extension modules load before ``.py``), passed silently. And a
malicious wheel lists its own files in ``RECORD`` (litellm 1.107.0's ``cook.py`` was), so ownership alone
doesn't clear a file.

For every module an executable ``.pth`` line imports from its own site-packages folder (``import x``,
``from x import``, ``__import__('x')``, ``importlib.import_module('x')``, also inside ``exec('...')`` strings):

| Finding | Severity |
|---|---|
| the file differs from the sha256 its package's ``RECORD`` lists (changed after pip installed it) | high |
| it reaches the network or runs commands **and** decodes/evaluates code or reads credential files | high |
| a compiled module shadows it and no package installed the compiled file | high |
| no package installed it and it isn't virtualenv's own ``_virtualenv.py``; high when its ``.pth`` passed the standard-tooling allow list (impersonation) | medium / high |

Text only: nothing is imported or run, and no interpreter is started.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from .model import Finding, Severity

_IMPORTS = [re.compile(r"\bimport\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)"),
            re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)\s+import\b"),
            re.compile(r"__import__\s*\(\s*['\"]([\w.]+)['\"]"),
            re.compile(r"import_module\s*\(\s*['\"]([\w.]+)['\"]")]
NET = re.compile(r"\burllib\b|urlopen|\brequests\.|http\.client|\bsocket\.|\bsubprocess\b|os\.system|os\.popen|"
                 r"\bPopen\b|\bhttpx\b|\baiohttp\b")
RUN = re.compile(r"\bexec\s*\(|\beval\s*\(|b64decode|marshal\.loads|zlib\.decompress|\bcompile\s*\(|bytes\.fromhex")
CRED = re.compile(r"\.ssh/|\.aws/credentials|\.git-credentials|\.npmrc|\.pypirc|\.netrc|\.docker/config\.json|"
                  r"\.kube/config|id_rsa|id_ed25519|Login Data|\.config/gcloud|\.azure/")
# Files that tools (not pip) write next to their .pth: (module, marker that their own file contains)
TOOL_FILES = {"_virtualenv": "VIRTUALENV_PATCH_FILE"}
MAX_BYTES = 512 * 1024
# Distro Python packages (Debian/Ubuntu dist-packages) carry no pip RECORD; dpkg keeps an md5 per file instead.
DPKG_INFO = Path("/var/lib/dpkg/info")


def imported_modules(line: str) -> list[str]:
    """Top-level module names a .pth line imports, in order of appearance (best effort; over-matching is
    harmless because only names that resolve inside the same site-packages folder are checked)."""
    found: list[tuple[int, str]] = []
    from_clauses = list(_IMPORTS[1].finditer(line))
    for m in from_clauses:
        found.append((m.start(1), m.group(1)))
    # `from x import y`: y is a name inside x, not a module to resolve
    masked = line
    for m in re.finditer(r"\bfrom\s+[\w.]+\s+import\s+[\w\s,]+", line):
        masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    for rx in (_IMPORTS[0], _IMPORTS[2], _IMPORTS[3]):
        for m in rx.finditer(masked):
            for part in m.group(1).split(","):
                if part.strip():
                    found.append((m.start(1) + m.group(1).find(part.strip()), part.strip().split()[0]))
    out: list[str] = []
    for _, name in sorted(found):
        top = name.split(".")[0]
        if top not in out:
            out.append(top)
    return out


def path_dirs(site: Path, pth: Path) -> list[Path]:
    """Folders a .pth adds to sys.path (relative lines, e.g. pywin32's `win32\\lib`), inside the site folder."""
    out = []
    try:
        text = pth.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "import ", "import\t")):
            continue
        d = (site / line.replace("\\", "/")).resolve()
        try:
            d.relative_to(site.resolve())
        except ValueError:
            continue                                 # outside site-packages: not ours to judge
        if d.is_dir():
            out.append(d)
    return out


def resolve(site: Path, mod: str, extra: list[Path] = ()) -> tuple[Path | None, list[Path]]:
    """The file Python would load for `mod` from this folder or the .pth's own path folders, plus any compiled
    modules found. Import order per folder: package dir, extension modules, source, sourceless bytecode."""
    for d in (site, *extra):
        hit = _resolve_in(d, mod)
        if hit[0] is not None:
            return hit
    return None, []


def _resolve_in(site: Path, mod: str) -> tuple[Path | None, list[Path]]:
    pkg = site / mod
    if (pkg / "__init__.py").is_file() or any(pkg.glob("__init__.*.so")) or any(pkg.glob("__init__*.pyd")):
        exts = sorted([*pkg.glob("__init__.*.so"), *pkg.glob("__init__*.pyd")])
        return (exts[0] if exts else pkg / "__init__.py"), exts
    exts = sorted([*site.glob(f"{mod}.*.so"), *site.glob(f"{mod}.so"), *site.glob(f"{mod}.*.pyd"),
                   *site.glob(f"{mod}.pyd")])
    if exts:
        return exts[0], exts
    for p in (site / f"{mod}.py", site / f"{mod}.pyc"):
        if p.is_file():
            return p, []
    return None, []


def record_entries(dists) -> dict[str, tuple[str, str]]:
    """RECORD path -> (owner 'name version', 'sha256=...' or '')."""
    out: dict[str, tuple[str, str]] = {}
    for name, ver, d in dists:
        try:
            with open(d / "RECORD", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.rstrip("\r\n").split(",")
                    if len(parts) >= 2 and parts[0]:
                        out.setdefault(parts[0], (f"{name} {ver}", parts[1]))
        except OSError:
            continue
    return out


def dpkg_entries(info_dir: Path | None = None) -> dict[str, tuple[str, str]]:
    """Absolute path -> (deb package, md5) for Python files dpkg installed."""
    out: dict[str, tuple[str, str]] = {}
    d = DPKG_INFO if info_dir is None else info_dir
    try:
        files = sorted(d.glob("*.md5sums"))
    except OSError:
        return out
    for f in files:
        pkg = f.name[: -len(".md5sums")].split(":")[0]
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "-packages/" in line:
                        md5, _, rel = line.rstrip("\r\n").partition("  ")
                        out["/" + rel.lstrip("/")] = (pkg, md5)
        except OSError:
            continue
    return out


def top_level_owners(site: Path) -> dict[str, str]:
    """Top-level module -> 'dist version' from top_level.txt (egg-info, setuptools-built dist-info). A claim with
    no file hashes: distro packages and old installs only have this."""
    out: dict[str, str] = {}
    for meta in sorted([*site.glob("*.egg-info"), *site.glob("*.dist-info")]):
        try:
            names = (meta / "top_level.txt").read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            continue
        m = re.match(r"^(.+?)-(\d[^-]*?)(?:-py\d.*)?\.(?:egg|dist)-info$", meta.name)
        label = f"{m.group(1)} {m.group(2)}" if m else meta.name
        for n in names:
            out.setdefault(n.strip(), label)
    return out


def _md5(p: Path) -> str:
    h = hashlib.md5(usedforsecurity=False)          # integrity check against dpkg's own record, not security
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _digest(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return "sha256=" + base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")


def _signals(text: str) -> list[str]:
    net, run, cred = NET.search(text), RUN.search(text), CRED.search(text)
    if net and (run or cred):
        return [m.group(0).strip("( ") for m in (net, run, cred) if m]
    return []


def audit_site(site, dists, pth_lines: list[tuple[Path, str, bool]], stats: dict, fix: str) -> list[Finding]:
    """pth_lines: (.pth file, executable line, whether pystartup let it pass as standard tooling)."""
    out: list[Finding] = []
    sp = site.path
    records = dpkg = tops = None
    done: set[Path] = set()
    for pth, line, allowed in pth_lines:
        for mod in imported_modules(line):
            target, exts = resolve(sp, mod, path_dirs(sp, pth))
            if target is None or target in done:
                continue
            done.add(target)
            stats["python_pth_targets"] = stats.get("python_pth_targets", 0) + 1
            if records is None:
                records = record_entries(dists)
            rel = target.resolve().relative_to(sp.resolve()).as_posix()
            owner, want = records.get(rel, (None, ""))
            want_md5 = ""
            if not owner:                                   # distro package: dpkg's md5, else top_level.txt
                if dpkg is None:
                    dpkg = dpkg_entries()
                hit = dpkg.get(str(target.resolve()))
                if hit:
                    owner, want_md5 = f"{hit[0]} (dpkg)", hit[1]
                else:
                    if tops is None:
                        tops = top_level_owners(sp)
                    claim = tops.get(rel.split("/")[0].split(".")[0]) if "/" in rel else tops.get(mod)
                    owner = f"{claim} (top_level.txt, no file hashes)" if claim else None
            where = f"{pth.name} → {rel} ({site.label})"

            def add(sev, what, detail, rel=rel, owner=owner):
                out.append(Finding(
                    rule="python.pth-import-target", category="python-startup", severity=sev,
                    title=f"{what}: {where}", location=str(sp / rel), subject=f"{sp}:{rel}:{what}",
                    detail=detail + (f" Installed by {owner}." if owner else "") + f" `{pth.name}` imports it at "
                           f"every Python start, pip included.", remediation=fix))

            try:
                if target.stat().st_size > MAX_BYTES:
                    continue
                if want.startswith("sha256=") and _digest(target) != want:
                    add(Severity.HIGH, "Startup module changed after install",
                        "Its sha256 no longer matches the one in its package's RECORD, so something rewrote it "
                        "after pip installed it.")
                    continue
                if want_md5 and _md5(target) != want_md5:
                    add(Severity.HIGH, "Startup module changed after install",
                        "Its md5 no longer matches the one dpkg recorded when the distro package installed it.")
                    continue
                if target.suffix in (".so", ".pyd"):
                    if not owner:
                        add(Severity.HIGH, "Compiled startup module nobody installed",
                            f"`{target.name}` loads instead of `{mod}.py` (Python prefers extension modules) and no "
                            f"installed package lists it.")
                    continue
                if target.suffix == ".pyc":
                    if not owner:
                        add(Severity.HIGH, "Bytecode-only startup module nobody installed",
                            f"`{target.name}` has no source next to it and no installed package lists it.")
                    continue
                text = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sig = _signals(text)
            if sig:
                add(Severity.HIGH, "Startup module downloads or runs code",
                    f"It uses {', '.join(sig)}: network or command access together with decoding/evaluating code "
                    f"or reading credential files, the shape of the litellm 1.107.0 `cook.pth` stealer.")
                continue
            marker = TOOL_FILES.get(mod)
            if owner or (marker and marker in text):
                continue
            add(Severity.HIGH if allowed else Severity.MEDIUM, "Startup module nobody installed",
                "No installed package lists it in RECORD" + (
                    f", although its `.pth` looks like one that standard tooling writes, so the name may be borrowed."
                    if allowed else "."))
    return out
