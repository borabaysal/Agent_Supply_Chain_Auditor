"""npm install-time hooks: lifecycle scripts that run code on ``npm install`` (``repo.install-hook``).

Grounding: the wfx credential stealer (SafeDep and Aikido, 12 Nov 2026) pushed, with stolen GitHub
tokens, a ``postinstall`` hook that runs a hidden ``.ci-xxxxxx.sh`` (771 repos), e.g.
``sh ./.ci-dwgd2n.sh >/dev/null 2>&1; … exit 42``. It runs on any CI runner or laptop that does
``npm install`` and sends secrets, cloud credentials and AI-tool keys out. Two repos still had the
hook live when SafeDep reported it; in the rest the attacker reverted within minutes.

Shared by the daily audit (``--repos``, only risky hooks are reported) and ``asca check-repo``
(every hook, graded). Files are read as text; npm and git are never run.

| Hook | Severity |
|---|---|
| wfx indicator: ``.ci-xxxxxx.sh`` runner, the ``exit 42`` sentinel, ``WF_CALLBACK``/``WF_CTOKEN`` or a published exfil address in the script it runs | critical |
| runs a hidden dotfile, hides its own output (``>/dev/null 2>&1``) while running a file, pipes a download to a shell / decodes / evals / opens a raw socket, or the file it runs uploads data (a shell script) or reads credential files or the whole environment and uploads | high (medium when the package.json isn't committed) |
| runs a file from the repo, or downloads something (binary installers) | medium (check-repo only) |
| a build tool (``husky``, ``only-allow`` …) | low (check-repo only) |
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .model import Finding, Severity
from .repohooks import tracked_paths

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
MAX_PACKAGES = 50
MAX_READ = 512 * 1024
SAFEDEP = "https://safedep.io/blog/github-actions-wfx-credential-stealer"

# a script that runs a file from the repo: `node scripts/x.js`, `sh ./.ci-ab12cd.sh`, `python tools/y.py`, `./run`
_LOCAL_FILE = re.compile(r"(?:^|[;&|]\s*|\s)(?:(?:node|bun|deno\s+run|tsx|ts-node|sh|bash|zsh|python3?|ruby|perl)\s+)?"
                         r"((?:\./|[\w.-]+/)?[\w./-]*\.(?:c?js|mjs|cjs|ts|mts|sh|py|rb|pl)|\./[\w./-]+)(?=\s|$|[;&|>])")
# in the command itself. Strong: runs fetched or decoded code / raw sockets. Weak: just downloads something.
_CMD_RISKY = re.compile(r"\b(?:nc|ncat|socat|telnet|osascript|base64|certutil|powershell|iex)\b|/dev/tcp|"
                        r"\|\s*(?:ba|z|da)?sh\b|\$\(\s*(?:curl|wget)\b|`\s*(?:curl|wget)\b", re.I)
_CMD_FETCH = re.compile(r"\b(?:curl|wget|scp)\b|https?://", re.I)
_INLINE = re.compile(r"\b(?:node|bun)\s+-(?:e|p)\b|\bpython3?\s+-c\b|\b(?:ba|z)?sh\s+-c\b|\bperl\s+-e\b", re.I)
OBFUSCATED = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]|"
                        r"\bBuffer\.from\([^)]*['\"]base64|\batob\(|\bexec\(\s*(?:base64|zlib)")
_SILENCED = re.compile(r">\s*/dev/null\s+2>&1|&>\s*/dev/null|2>&1\s*>\s*/dev/null")
# in the file it runs
_FILE_EXEC = re.compile(r"child_process|\bexecSync\(|\bspawn\(|\bexec\(|subprocess|os\.system", re.I)
_FILE_NET = re.compile(r"https?://|\bfetch\(|\baxios\b|\brequire\(['\"]https?['\"]\)|\burllib|\brequests\.", re.I)
# uploads (data leaving), as opposed to downloads, in a shell script or a JS/Python file
_SH_SEND = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:-X\s*POST|--data|\s-d\s|\s-F\s|--upload-file|\s-T\s|@-|--post-)|"
                      r"\b(?:nc|ncat|socat)\s+\S+\s+\d+|/dev/tcp/", re.I)
_UPLOAD = re.compile(r"""method\s*[:=]\s*['"]POST|\.post\(|requests\.post|urlopen\([^)]*data=|"""
                     r"""\.write\([^)]*(?:env|secret|token|cred)|""" + _SH_SEND.pattern, re.I)
# credential *files* and stores (not env var names: downloaders read GITHUB_TOKEN for rate limits)
_CRED_READ = re.compile(r"\.aws/credentials|\.ssh/id_|\.npmrc|\.git-credentials|\.docker/config\.json|\.kube/config|"
                        r"\.config/gcloud|\.netrc|Library/Keychains|Local Storage/leveldb|\.claude\.json|"
                        r"\.codex/auth\.json|\.hermes/\.env|wallet\.dat|Exodus|toJSON\(secrets\)|process\.env\)|"
                        r"Object\.(?:keys|entries)\(process\.env\)|os\.environ\)|printenv|\benv\s*\|", re.I)
# wfx indicators published by SafeDep and Aikido (12 Nov 2026)
WFX_FILE = re.compile(r"(?:^|/)\.ci-[a-z0-9]{6}\.sh$")
# indicators exactly as listed in SafeDep's IOC table (campaign tokens, exfil servers, env names)
WFX_TEXT = re.compile(r"\bWF_CALLBACK\b|\bWF_CTOKEN\b|\bWF_TG_CHAT\b|b42d70a7aab9140ca19e8249|e6ny5telf3pht81qk5zv|"
                      r"194\.150\.166\.244|18\.143\.168\.96")
WFX_SENTINEL = re.compile(r"-eq\s+42\b[^\n]*exit\s+42")


def package_jsons(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP and not d.startswith("."))
        if len(Path(dirpath).relative_to(root).parts) >= 3:
            dirnames[:] = []
        if "package.json" in filenames:
            out.append(Path(dirpath) / "package.json")
        if len(out) >= MAX_PACKAGES:
            break
    return out


def grade(cmd: str, pkg_dir: Path, root: Path, strict: bool = False) -> tuple[Severity, str, str]:
    """(severity, rule, why) for one lifecycle command. strict (check-repo, a stranger's repo): a hook file that runs
    commands *and* reaches the network is high, as in v0.5.0; in your own repos (daily audit) that's medium, because
    install-time binary downloaders look the same."""
    local = _LOCAL_FILE.search(cmd)
    target_rel = local.group(1) if local else ""
    body = ""
    if local:
        target = (pkg_dir / target_rel).resolve()
        try:
            if target.is_relative_to(root.resolve()) and target.is_file():
                body = target.read_bytes()[:MAX_READ].decode("utf-8", "replace")
        except OSError:
            body = ""
    # a hidden *file* (wfx: `.ci-xxxxxx.sh`); files in tool folders such as `.husky/` or `.config/` are normal
    hidden = bool(local) and Path(target_rel).name.startswith(".")
    if (local and WFX_FILE.search(target_rel)) or WFX_SENTINEL.search(cmd) or WFX_TEXT.search(cmd + "\n" + body):
        return Severity.CRITICAL, "repo.wfx-indicator", (
            f"It matches the wfx credential stealer's published indicators (a `.ci-xxxxxx.sh` runner, the `exit 42` "
            f"sentinel, or its exfil settings and servers in the script) ({SAFEDEP}).")
    reasons, weak = [], []
    if _CMD_RISKY.search(cmd) or OBFUSCATED.search(cmd) or (_INLINE.search(cmd) and (_FILE_EXEC.search(cmd)
                                                                                    or _FILE_NET.search(cmd))):
        reasons.append("it runs downloaded or decoded code, or opens a raw network connection")
    elif _CMD_FETCH.search(cmd):
        weak.append("it downloads something at install time")
    if hidden:
        reasons.append(f"it runs a hidden file (`{target_rel}`)")
    if local and _SILENCED.search(cmd):
        reasons.append("it throws away the script's output, so nothing shows during install")
    if body:
        if _CRED_READ.search(body) and _UPLOAD.search(body):
            reasons.append(f"`{target_rel}` reads credential files or the whole environment and uploads data")
        elif target_rel.endswith(".sh") and _SH_SEND.search(body):
            reasons.append(f"`{target_rel}` uploads data to the network")
        elif OBFUSCATED.search(body) and (_FILE_EXEC.search(body) or _FILE_NET.search(body)):
            reasons.append(f"`{target_rel}` decodes or evaluates code and runs commands or reaches the network")
        elif _FILE_EXEC.search(body) and _FILE_NET.search(body):
            (reasons if strict else weak).append(
                f"`{target_rel}` runs commands and reaches the network"
                + ("" if strict else " (common for downloading binaries)"))
    if reasons:
        return Severity.HIGH, "repo.install-hook", "Risky because " + "; ".join(reasons + weak) + "."
    if weak:
        return Severity.MEDIUM, "repo.install-script", "Check it: " + "; ".join(weak) + "."
    if local:
        return Severity.MEDIUM, "repo.install-script", f"It runs `{target_rel}` from the repo: read that file before installing."
    return Severity.LOW, "repo.install-script", "It looks like a build tool; low risk, listed so you know it runs."


def audit(root: Path, *, git_dir: Path | None = None, risky_only: bool = False,
          assume_committed: bool = False, strict: bool = False) -> list[Finding]:
    """risky_only: the daily audit reports only high/critical hooks (your own repos' husky hooks are expected)."""
    out = []
    pkgs = package_jsons(root)
    rels = [str(p.relative_to(root)).replace(os.sep, "/") for p in pkgs]
    tracked = set(rels) if assume_committed else (tracked_paths(git_dir, rels) if git_dir else set())
    for p, rel in zip(pkgs, rels):
        try:
            doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        scripts = doc.get("scripts") if isinstance(doc, dict) else None
        if not isinstance(scripts, dict):
            continue
        committed = rel in tracked
        for name in LIFECYCLE:
            cmd = scripts.get(name)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            sev, rule, why = grade(cmd, p.parent, root, strict)
            if risky_only and sev < Severity.HIGH:
                continue
            if sev == Severity.HIGH and not committed and git_dir is not None and not assume_committed:
                sev = Severity.MEDIUM
                why += " The package.json change isn't committed, so it only affects this checkout (for now)."
            elif committed and sev >= Severity.HIGH:
                why += " It's committed, so every clone and CI run gets it."
            out.append(Finding(
                rule=rule, category="repo", severity=sev,
                title=f"`npm install` runs a `{name}` script from {rel}"
                      + (" (wfx stealer indicators)" if rule == "repo.wfx-indicator" else ""),
                location=f"{p}#scripts.{name}", subject=f"{rel}:{name}:{cmd[:80]}",
                detail=(f"`{cmd[:200]}`. npm runs this automatically on install, with your user's access to keys, "
                        f"wallets and browser data. {why}"),
                remediation=(REMEDIATE_WFX if rule == "repo.wfx-indicator" else
                             "Read what the script runs before installing. To install without running scripts: "
                             "`npm install --ignore-scripts`. If you didn't add it, check `git log -p package.json` "
                             "for who did, and rotate the secrets of anyone who ran `npm install` since.")))
    return out


REMEDIATE_WFX = ("Don't run `npm install` here. Remove the hook and the `.ci-*.sh` file, then treat the token that pushed "
                 "it as stolen: revoke the commit author's GitHub tokens and rotate every secret, cloud role and AI key "
                 "on machines and CI runners that installed since. SafeDep's checklist covers the AWS and Azure backdoors "
                 f"wfx leaves ({SAFEDEP}).")
