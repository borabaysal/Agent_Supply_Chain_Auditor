"""Symlinks that lead out of a repo or agent workspace (``repo.symlink-escape``).

Grounding: CVE-2026-103916 (Endor Labs, Nov 2026). A sandboxed agent planted a symlink in its
granted workspace; a later ``sbx cp`` by the operator followed it and read or wrote host files
outside the sandbox. The researcher calls it the second sandbox bug of this shape found in 2026.
Any tool that later copies, zips, uploads or edits "the workspace" can be steered the same way,
so a link left behind is the trap even after the agent has gone.

asca only lists links: ``os.readlink`` gives the target text, which is resolved *lexically*
against the link's folder. Targets are never opened, stat-ed or followed.

| Link | Severity |
|---|---|
| target is a credential location (``~/.ssh``, ``~/.aws``, ``.env``, ``auth.json``, ``.git-credentials``, wallets, keychains, browser profiles) or a whole home folder / ``/`` | high |
| committed to the repo (in ``.git/index``) and pointing outside it | medium |
| any other link leaving the repo or workspace | low |

Limit: this finds links left on disk or committed. A link created and used within one run is gone
before asca looks. Links inside ``node_modules`` and virtualenvs are skipped (package managers make
them on purpose); so is ``.git``.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .model import Finding, Severity
from .repohooks import tracked_paths
from . import fsutil

RULE = "repo.symlink-escape"
MAX_ENTRIES = 200_000
SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
        "site-packages", ".pnpm-store", ".cache"}

ENDOR = ("https://www.endorlabs.com/learn/docker-sandboxes-vulnerability-lets-ai-agents-access-sensitive-files-"
         "outside-their-sandbox-cve-2026-103916")

# path fragments (posix, compared on "/"-joined components) that hold credentials
CRED_DIRS = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud", ".password-store",
             ".config/gh", ".config/solana", ".electrum", ".bitcoin", ".ethereum", ".local/share/keyrings",
             "Library/Keychains", "Library/Application Support/Exodus", "Library/Application Support/Google/Chrome",
             "Library/Application Support/BraveSoftware", ".config/google-chrome", ".config/BraveSoftware",
             ".mozilla/firefox", "Library/Cookies", ".hermes", ".codex", ".claude"]
CRED_FILES = {".env", ".netrc", ".git-credentials", "auth.json", "credentials", "credentials.json", ".npmrc",
              ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "wallet.dat", ".claude.json",
              "application_default_credentials.json", "login data", "cookies", "key4.db", "logins.json"}
# Agent-home folders that are caches or the agent's own bookkeeping, not a workspace (and slow to walk)
AGENT_HOME_SKIP = {"cache", ".cache", ".npm", "checkpoints", "lazy-packages", "logs", "sessions", "audio_cache",
                   "images", "backups", "node", ".local", "state", "cron"}
_RUNTIME = re.compile(r"^/(?:tmp|run|var/run|private/tmp|private/var/folders|var/folders)(?:/|$)")
_ENV_FILE = re.compile(r"^\.env(\..+)?$")
_HOME = re.compile(r"^/(?:Users|home)/[^/]+/?$|^/root/?$|^/$")


def _norm(link: Path, target: str) -> str:
    base = target if os.path.isabs(target) else os.path.join(os.path.dirname(str(link)), target)
    return os.path.normpath(base)


def under_runtime(path: str) -> bool:
    """True for paths in /tmp, /run, macOS per-user temp … (also after resolving /var -> /private/var)."""
    return bool(_RUNTIME.match(path) or _RUNTIME.match(os.path.realpath(path)))


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def credential_target(path: str, home: str | None = None) -> str | None:
    """Why ``path`` (already normalised) counts as a credential location, else None."""
    p = path.replace("\\", "/")
    if _HOME.match(p) or (home and os.path.normpath(p) == os.path.normpath(home)):
        return "a whole home folder (every credential in it)"
    if p in ("/etc", "/etc/shadow", "/var/run/docker.sock", "/run/docker.sock"):
        return f"`{p}`"
    parts = [x for x in p.split("/") if x]
    joined = "/" + "/".join(parts) + "/"
    for d in CRED_DIRS:
        if f"/{d}/" in joined:
            return f"`{d}`"
    name = parts[-1].lower() if parts else ""
    if name in CRED_FILES or _ENV_FILE.match(name):
        return f"`{parts[-1]}`"
    return None


def _walk_links(root: Path, limit: int, stats: dict, skip: set[str] = frozenset()):
    n = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            n += 1
            if n > limit:
                stats["symlink_scan_truncated"] = stats.get("symlink_scan_truncated", 0) + 1
                return
            if e.is_symlink():
                yield Path(e.path)
            elif e.is_dir(follow_symlinks=False) and e.name not in SKIP and e.name not in skip \
                    and not fsutil.exists(Path(e.path) / "pyvenv.cfg"):
                stack.append(Path(e.path))


def audit_tree(root: Path, *, git_dir: Path | None = None, label: str = "repo", stats: dict | None = None,
               home: str | None = None, limit: int = MAX_ENTRIES, skip: set[str] = frozenset(),
               assume_committed: bool = False) -> list[Finding]:
    stats = stats if stats is not None else {}
    home = home or str(Path.home())
    rootn = os.path.normpath(str(root))
    # Links into /tmp, /run … are usually sockets that get new names every restart, so they're ignored. Not when
    # the tree itself lives there (a repo cloned to /tmp to inspect it): then every escape is a real escape.
    runtime_ok = not under_runtime(rootn)
    escapes = []
    for link in _walk_links(root, limit, stats, skip):
        stats["symlinks_seen"] = stats.get("symlinks_seen", 0) + 1
        try:
            target = os.readlink(link)
        except OSError:
            continue
        resolved = _norm(link, target)
        if _inside(resolved, rootn):
            continue
        if runtime_ok and _RUNTIME.match(resolved) and not credential_target(resolved, home):
            continue                  # sockets and runtime dirs (PulseAudio, X11 …) get new names every restart

        escapes.append((link, target, resolved))
    if not escapes:
        return []
    rels = [os.path.relpath(str(lk), rootn).replace(os.sep, "/") for lk, _, _ in escapes]
    tracked = set(rels) if assume_committed else (tracked_paths(git_dir, rels) if git_dir else set())
    out = []
    for (link, target, resolved), rel in zip(escapes, rels):
        cred = credential_target(resolved, home)
        committed = rel in tracked
        if cred:
            sev = Severity.HIGH
            why = (f"It points at {cred}. Any tool that later copies, zips, uploads or edits this {label} can be "
                   f"made to read or overwrite those files.")
        elif committed:
            sev = Severity.MEDIUM
            why = f"It's committed, so every clone of the {label} gets a link that leads outside it."
        else:
            sev = Severity.LOW
            why = f"Tools that treat the {label} as self-contained (copy, sync, sandbox mounts) will follow it out."
        out.append(Finding(
            rule=RULE, category="repo", severity=sev,
            title=f"Symlink leads out of the {label}: `{rel}` → `{target}`",
            location=str(link), subject=f"{rel}->{target}",
            detail=(f"{why} " + ("Committed to git. " if committed and cred else "")
                    + f"A sandbox only protects the paths it knows about; a link left in the workspace is how "
                      f"CVE-2026-103916 reached host files ({ENDOR}). asca read the link only; the target was not "
                      f"opened."),
            remediation=(f"If you didn't create it, remove it (`rm '{link}'` removes the link, not the target) and "
                         f"find out what did. If you need the files, copy them in instead of linking."),
        ))
    return out
