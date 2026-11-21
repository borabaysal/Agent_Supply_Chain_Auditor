"""Plugin checkouts that aren't on their pinned commit (Plugin4Shell). Reads ``.git`` as text; never runs git.

Air Security's Plugin4Shell (Sep 2026; CVE-2026-86063 for Claude Code / Claude Desktop, fixed in
2.1.179; Codex fixed in 0.146.0; Copilot unfixed at disclosure) showed agents installing a plugin
with ``git clone`` + ``git checkout <pinned-sha>``. If the upstream repo's *default branch* is named
exactly like that 40-hex SHA, git prefers the branch, and the agent reports "installed at the pinned
commit" while the attacker's code is checked out, also on background auto-update. A Gemini CLI
variant uses a branch named ``FETCH_HEAD``.

No legitimate workflow names a branch like a commit hash or ``FETCH_HEAD``, so their presence in a
plugin checkout is the signal:

| Finding | Severity |
|---|---|
| ``plugin.hash-named-branch``: HEAD is on a branch named like a 40-hex SHA or ``FETCH_HEAD`` (the swap landed) | critical |
| the same kind of branch exists locally or as a remote-tracking ref but isn't checked out | high |
| ``plugin.pin-drift``: a Hermes catalog plugin's checkout is on a different commit than the one Hermes recorded at install | medium |

Claude Code's ``gitCommitSha`` in ``installed_plugins.json`` is not compared: it is known to keep
the install-time value after updates (anthropics/claude-code#54969, #56740, #52218), so a mismatch
there means nothing.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .model import Finding, Severity
from . import fsutil

HEX40 = re.compile(r"^[0-9a-f]{40}$")
SUSPICIOUS_NAMES = {"FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD"}
MAX_DEPTH = 4
MAX_CHECKOUTS = 400
AIR = "https://www.air.security/blog-posts/plugin4shell"


def _read(p: Path, limit: int = 1 << 20) -> str:
    try:
        with p.open("rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def git_dir(checkout: Path) -> Path | None:
    g = checkout / ".git"
    if fsutil.is_dir(g):
        return g
    if fsutil.is_file(g):                                   # worktree / submodule: "gitdir: <path>"
        m = re.match(r"gitdir:\s*(.+)", _read(g, 4096).strip())
        if m:
            p = Path(m.group(1).strip())
            p = p if p.is_absolute() else (checkout / p)
            return p if fsutil.is_dir(p) else None
    return None


def refs(gd: Path) -> dict[str, str]:
    """refname -> sha, from loose refs and packed-refs (text only)."""
    out: dict[str, str] = {}
    for line in _read(gd / "packed-refs").splitlines():
        parts = line.split()
        if len(parts) == 2 and HEX40.match(parts[0]) and parts[1].startswith("refs/"):
            out[parts[1]] = parts[0]
    base = gd / "refs"
    if base.is_dir():
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if not Path(dirpath, d).is_symlink()]
            for f in filenames:
                p = Path(dirpath, f)
                if p.is_symlink():
                    continue
                sha = _read(p, 128).strip()
                if HEX40.match(sha):
                    out[p.relative_to(gd).as_posix()] = sha
    return out


def head(gd: Path, all_refs: dict[str, str]) -> tuple[str | None, str | None]:
    """(symbolic ref or None if detached, resolved sha or None)."""
    h = _read(gd / "HEAD", 4096).strip()
    if h.startswith("ref:"):
        ref = h[4:].strip()
        return ref, all_refs.get(ref)
    return None, h if HEX40.match(h) else None


def _suspicious(refname: str) -> bool:
    for prefix in ("refs/heads/", "refs/remotes/"):
        if refname.startswith(prefix):
            name = refname[len(prefix):]
            if prefix == "refs/remotes/":
                name = name.split("/", 1)[-1]          # drop the remote name
            return bool(HEX40.match(name.lower())) or name in SUSPICIOUS_NAMES
    return False


def checkouts(roots: list[tuple[Path, str]]) -> list[tuple[Path, str]]:
    """Git checkouts under each (root, agent label), up to MAX_DEPTH levels, symlinks not followed."""
    found: list[tuple[Path, str]] = []
    for root, label in roots:
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            d = Path(dirpath)
            if ".git" in dirnames or ".git" in filenames:
                found.append((d, label))
                dirnames[:] = []                       # don't descend into a checkout
                continue
            dirnames[:] = [x for x in dirnames if not (d / x).is_symlink() and x not in ("node_modules", ".venv")]
            if len(d.parts) - base_depth >= MAX_DEPTH:
                dirnames[:] = []
            if len(found) >= MAX_CHECKOUTS:
                return found
    return found


def default_roots(home: Path, hermes_home: Path | None) -> list[tuple[Path, str]]:
    roots = [(home / ".claude" / "plugins", "Claude Code"), (home / ".codex" / "plugins", "Codex"),
             (home / ".copilot", "GitHub Copilot CLI"), (home / ".gemini" / "extensions", "Gemini CLI")]
    if hermes_home:
        roots.append((hermes_home / "plugins", "Hermes"))
    return roots


def audit(roots: list[tuple[Path, str]], stats: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    cos = checkouts(roots)
    if stats is not None:
        stats["plugin_checkouts"] = len(cos)
    for co, label in cos:
        gd = git_dir(co)
        if gd is None:
            continue
        all_refs = refs(gd)
        sym, sha = head(gd, all_refs)
        bad = sorted(r for r in all_refs if _suspicious(r))
        if sym and _suspicious(sym) and sym not in bad:
            bad.insert(0, sym)
        if bad:
            landed = bool(sym and _suspicious(sym))
            out.append(Finding(
                rule="plugin.hash-named-branch", category="pinning",
                severity=Severity.CRITICAL if landed else Severity.HIGH,
                title=f"{label} plugin `{co.name}` has a branch named like a commit hash"
                      + (" and it is checked out" if landed else ""),
                location=str(co), subject=f"{co}:{','.join(bad[:3])}",
                detail=(f"Refs: {', '.join(bad[:5])}. HEAD: {sym or 'detached'} ({(sha or '?')[:12]}). "
                        f"Plugin4Shell ({AIR}): a branch named exactly like the pinned SHA (or FETCH_HEAD) wins over "
                        f"the commit in `git checkout <sha>`, so the agent runs the attacker's code while reporting the "
                        f"pinned commit. No normal workflow creates such a branch."
                        + (" The checkout is on that branch now, so the pinned code is not what's on disk."
                           if landed else " It isn't checked out yet; the next install or auto-update may switch to it.")),
                remediation=("Disable the plugin and its marketplace's auto-update, delete this checkout, and update the "
                             "agent (Claude Code ≥ 2.1.179, Codex ≥ 0.146.0). Tell the marketplace owner: a hash-named "
                             "default branch means the upstream repo is compromised. If it ran, rotate the keys the "
                             "agent could reach.")))
        cat_p = co / ".hermes-catalog.json"
        if label == "Hermes" and cat_p.is_file():
            try:
                pin = str(json.loads(_read(cat_p)).get("sha") or "").lower()
            except ValueError:
                pin = ""
            if HEX40.match(pin) and sha and sha.lower() != pin:
                out.append(Finding(
                    rule="plugin.pin-drift", category="pinning", severity=Severity.MEDIUM,
                    title=f"Hermes plugin `{co.name}` isn't on the commit Hermes installed",
                    location=str(co), subject=f"{co}:{pin[:12]}->{sha[:12]}",
                    detail=(f"Hermes recorded {pin[:12]} (the commit it checked out and verified at install); the "
                            f"checkout is now on {sha[:12]}" + (f" via {sym}" if sym else " (detached)") + ". Someone or "
                            "something moved it after install, so the reviewed code is not what loads."),
                    remediation=("If you pulled it yourself, reinstall through `hermes plugins install` so the pin is "
                                 "recorded; otherwise inspect `git -C <dir> log` from another shell before the next "
                                 "Hermes restart.")))
    return out
