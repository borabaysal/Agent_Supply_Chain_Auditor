"""Read-only git config parser + command-sink rules.

SECURITY: this module never invokes ``git``. Running ``git status`` inside an
untrusted repository is exactly how CVE-2026-71963 (Hermes Agent) and the
wider "GitSpawn" class fire: git executes whatever program the repo's own
``.git/config`` names in ``core.fsmonitor`` (and several other keys). So we
parse the config file as text instead.

Syntax handled (git-config(1)): ``[section]``, ``[section "Sub"]``, legacy
``[section.sub]``, case-insensitive section/key names, case-sensitive
subsections, bare boolean keys, quoted values with escapes, ``#``/``;``
comments outside quotes, and backslash line continuation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .model import Finding, Severity


@dataclass
class Entry:
    key: str        # canonical "section.sub.name" (section/name lower-cased, sub kept)
    value: str
    line: int
    file: str


_SECTION_RE = re.compile(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')


def parse(text: str, file: str = "") -> list[Entry]:
    entries: list[Entry] = []
    section = ""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        raw = lines[i]
        # join continuation lines (a trailing unescaped backslash)
        while raw.rstrip().endswith("\\") and not raw.rstrip().endswith("\\\\") and i + 1 < len(lines):
            raw = raw.rstrip()[:-1] + lines[i + 1]
            i += 1
        i += 1
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            m = _SECTION_RE.match(line)
            if not m:
                section = "!malformed"
                continue
            name, sub = m.group(1), m.group(2)
            if sub is not None:
                section = f"{name.lower()}.{_unescape_sub(sub)}"
            elif "." in name:  # legacy [section.sub] form: sub is lower-cased by git
                head, _, tail = name.partition(".")
                section = f"{head.lower()}.{tail.lower()}"
            else:
                section = name.lower()
            rest = line[m.end():].strip()
            if not rest or rest[0] in "#;":
                continue
            line = rest  # "[core] fsmonitor = x" on one line is legal
        name, sep, value = line.partition("=")
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name):
            continue
        val = _parse_value(value) if sep else "true"
        entries.append(Entry(f"{section}.{name.lower()}", val, start + 1, file))
    return entries


def _unescape_sub(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _parse_value(raw: str) -> str:
    out, quote, i = [], False, 0
    raw = raw.strip()
    while i < len(raw):
        ch = raw[i]
        if ch == '"':
            quote = not quote
        elif ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(nxt, nxt))
            i += 1
        elif ch in "#;" and not quote:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


# --------------------------------------------------------------------------- rules
#
# (pattern, rule id, severity, title, why). Patterns match the canonical key; the
# "*" segment stands for any subsection. Every key listed here makes git run a
# program named by the config file.

_FALSEY = {"", "false", "no", "off", "0"}
_TRUTHY = {"true", "yes", "on", "1"}

SINK_RULES: list[tuple[str, str, Severity, str, str]] = [
    ("core.fsmonitor", "git.fsmonitor", Severity.CRITICAL,
     "core.fsmonitor names a program git runs on every index refresh",
     "Any `git status`/`git diff` — including the ones agents run silently to orient "
     "themselves — executes this command with your privileges (GitSpawn; CVE-2026-71963 "
     "Hermes Agent, CVE-2026-19592 Codex, CVE-2026-72718 goose)."),
    ("core.hookspath", "git.hookspath", Severity.HIGH,
     "core.hooksPath redirects git hooks to another directory",
     "Hooks in that directory run on commit/checkout/merge — an agent committing for you triggers them."),
    ("core.sshcommand", "git.sshcommand", Severity.HIGH,
     "core.sshCommand replaces the ssh binary git uses",
     "Runs on every fetch/push over SSH."),
    ("core.askpass", "git.askpass", Severity.HIGH,
     "core.askPass names a credential-prompt program",
     "Runs whenever git needs a credential and receives the prompt text."),
    ("core.gitproxy", "git.gitproxy", Severity.HIGH,
     "core.gitProxy names a proxy command for git:// transport", "Runs on git:// fetches."),
    ("diff.external", "git.diff-external", Severity.HIGH,
     "diff.external replaces the diff program", "Runs on every `git diff`."),
    ("diff.*.textconv", "git.textconv", Severity.HIGH,
     "diff.<driver>.textconv names a conversion program", "Runs on `git diff`/`git log -p` for matching files."),
    ("diff.*.command", "git.diff-driver", Severity.HIGH,
     "diff.<driver>.command names an external diff driver", "Runs on `git diff` for matching files."),
    ("filter.*.clean", "git.filter", Severity.HIGH,
     "filter.<driver>.clean names a program", "Runs on `git add`/`git status` for matching paths."),
    ("filter.*.smudge", "git.filter", Severity.HIGH,
     "filter.<driver>.smudge names a program", "Runs on checkout for matching paths."),
    ("filter.*.process", "git.filter", Severity.HIGH,
     "filter.<driver>.process names a long-running filter program", "Runs on checkout/add/status."),
    ("merge.*.driver", "git.merge-driver", Severity.MEDIUM,
     "merge.<driver>.driver names a merge program", "Runs during merges/rebases of matching files."),
    ("uploadpack.packobjectshook", "git.packobjectshook", Severity.HIGH,
     "uploadpack.packObjectsHook names a program", "Runs on clone/fetch served from this repo."),
    ("remote.*.uploadpack", "git.remote-program", Severity.MEDIUM,
     "remote.<name>.uploadpack overrides the remote helper program", "Runs on fetch from that remote."),
    ("remote.*.receivepack", "git.remote-program", Severity.MEDIUM,
     "remote.<name>.receivepack overrides the remote helper program", "Runs on push to that remote."),
    ("core.pager", "git.pager", Severity.MEDIUM,
     "core.pager names a program", "Runs whenever git pages output in a terminal."),
    ("pager.*", "git.pager", Severity.MEDIUM,
     "pager.<cmd> sets a per-command pager program", "Runs when that command pages output."),
    ("core.editor", "git.editor", Severity.MEDIUM,
     "core.editor names a program", "Runs on commit/rebase/tag when a message is edited."),
    ("sequence.editor", "git.editor", Severity.MEDIUM,
     "sequence.editor names a program", "Runs during interactive rebase."),
    ("gpg.program", "git.gpg-program", Severity.MEDIUM,
     "gpg.program replaces the signing program", "Runs on signed commits/tags and signature checks."),
    ("gpg.*.program", "git.gpg-program", Severity.MEDIUM,
     "gpg.<format>.program replaces the signing program", "Runs on signed commits/tags and signature checks."),
    ("credential.helper", "git.credential-helper", Severity.HIGH,
     "credential.helper runs a shell command", "A `!`-prefixed or path helper runs whenever git authenticates."),
    ("credential.*.helper", "git.credential-helper", Severity.HIGH,
     "credential.<url>.helper runs a shell command", "Runs whenever git authenticates to that URL."),
    ("protocol.ext.allow", "git.protocol-ext", Severity.HIGH,
     "protocol.ext.allow enables the ext:: transport", "ext:: URLs run arbitrary commands on fetch/clone."),
    ("include.path", "git.include", Severity.MEDIUM,
     "include.path pulls in another config file", "Included files can carry any of the keys above."),
    ("includeif.*.path", "git.include", Severity.MEDIUM,
     "includeIf.<cond>.path pulls in another config file", "Included files can carry any of the keys above."),
    ("alias.*", "git.alias-shell", Severity.LOW,
     "alias runs a shell command", "`!`-prefixed aliases execute a shell command when the alias is typed."),
]

# git's built-in credential helpers (no shell, no arbitrary program)
_BUILTIN_HELPERS = {"store", "cache", "osxkeychain", "manager", "manager-core", "libsecret", "wincred"}


def _match(pattern: str, key: str) -> bool:
    p, k = pattern.split("."), key.split(".")
    if len(p) == 2 and p[1] == "*":  # e.g. "pager.*" / "alias.*": any second+ segment
        return k[0] == p[0] and len(k) >= 2
    if "*" not in p:
        return key.lower() == pattern
    # three-part with subsection wildcard: section.<anything>.name
    return len(k) >= 3 and k[0] == p[0] and k[-1] == p[-1]


def _is_safe_value(rule: str, key: str, value: str) -> bool:
    v = value.strip().lower()
    if rule == "git.fsmonitor":
        # true/false select git's built-in daemon (no external program)
        return v in _FALSEY or v in _TRUTHY
    if rule == "git.protocol-ext":
        return v in ("never", "user")
    if rule == "git.credential-helper":
        if v == "":
            return True
        first = value.strip().split()[0]
        return first in _BUILTIN_HELPERS or first.startswith("cache") or first.startswith("store")
    if rule == "git.alias-shell":
        return not value.strip().startswith("!")
    if rule in ("git.pager", "git.editor"):
        # booleans for pager.<cmd> and trivially inert programs
        return v in _FALSEY or v in _TRUTHY or v in ("less", "more", "cat", "vi", "vim", "nano", "true")
    if rule == "git.hookspath":
        return v in ("/dev/null", "nul")
    if rule == "git.diff-external":
        return v == ""
    return False


def audit_entries(entries: list[Entry], *, scope: str, repo: Path | None = None) -> list[Finding]:
    """Apply sink rules. ``scope`` is 'repo' (attacker-influenced) or 'global'/'system'
    (developer-controlled: still reported, one severity step lower, except fsmonitor)."""
    out: list[Finding] = []
    for e in entries:
        for pattern, rule, sev, title, why in SINK_RULES:
            if not _match(pattern, e.key):
                continue
            if _is_safe_value(rule, e.key, e.value):
                break
            severity = sev
            if scope != "repo" and rule != "git.fsmonitor" and severity > Severity.LOW:
                severity = Severity(severity - 1)
            if rule == "git.hookspath" and repo is not None:
                severity = max(severity, Severity.HIGH) if _outside(repo, e.value) else severity
            out.append(Finding(
                rule=rule, category="repo-config", severity=severity, title=title,
                location=f"{e.file}:{e.line}", subject=e.key,
                detail=f"{why} Value: `{_short(e.value)}` (scope: {scope}).",
                remediation=_remedy(rule, e.key, scope),
            ))
            break
    return out


def _outside(repo: Path, value: str) -> bool:
    p = Path(value).expanduser()
    if not p.is_absolute():
        return False
    try:
        p.resolve().relative_to(repo.resolve())
        return False
    except ValueError:
        return True


def _short(v: str, n: int = 120) -> str:
    v = v.replace("\n", " ")
    return v if len(v) <= n else v[: n - 1] + "…"


def _remedy(rule: str, key: str, scope: str) -> str:
    flag = "" if scope == "repo" else " --global"
    if rule == "git.fsmonitor":
        return (f"If you did not set this yourself, treat the repo as hostile: do not open it in an agent. "
                f"Remove it without running git in the repo (edit .git/config by hand) or `git config{flag} "
                f"--unset {key}` from a safe shell. Upgrade agents to patched versions.")
    return f"Verify you set `{key}` yourself; otherwise remove it (`git config{flag} --unset {key}`)."


# --------------------------------------------------------------------- hooks + creds

def audit_hooks(git_dir: Path) -> list[Finding]:
    hooks = git_dir / "hooks"
    out: list[Finding] = []
    if not hooks.is_dir():
        return out
    for h in sorted(hooks.iterdir()):
        if h.name.endswith(".sample") or not h.is_file():
            continue
        out.append(Finding(
            rule="git.active-hook", category="repo-config", severity=Severity.MEDIUM,
            title=f"Active git hook `{h.name}`", location=str(h), subject=h.name,
            detail="Hooks run automatically on git operations agents perform (commit, checkout, merge). "
                   "Hooks are not versioned, so they are invisible in code review.",
            remediation="Confirm you installed it (e.g. pre-commit); delete it otherwise.",
        ))
    return out


_URL_CRED_RE = re.compile(r"^[a-z][a-z0-9+.-]*://([^/@\s:]+):([^/@\s]+)@", re.I)


def audit_remote_credentials(entries: list[Entry]) -> list[Finding]:
    out = []
    for e in entries:
        if e.key.endswith(".url") or e.key.endswith(".pushurl"):
            m = _URL_CRED_RE.match(e.value)
            if m:
                from .model import redact
                out.append(Finding(
                    rule="secret.git-remote-url", category="secrets", severity=Severity.HIGH,
                    title="Credential embedded in git remote URL", location=f"{e.file}:{e.line}",
                    subject=e.key,
                    detail=f"The URL carries a password/token ({redact(m.group(2))}). Anything that can read "
                           f".git/config — including an agent's context window — can read it.",
                    remediation="Rotate the token, then use a credential helper instead of an inline URL.",
                ))
    return out
