"""Workflow steps that hand every secret to a script, or leak the Actions runtime tokens
(``repo.workflow-secret-dump``).

Grounding: the wfx credential stealer (SafeDep and Aikido, 12 Nov 2026) injected two steps into
existing workflows in 7,309 repos: one copies ``ACTIONS_RUNTIME_TOKEN`` (and the cache/results
URLs) into ``$GITHUB_ENV``, the next passes ``${{ toJSON(secrets) }}`` and ``${{ toJSON(vars) }}``
to the payload. It also added whole files named ``build-audit-xxxxxx.yml``.

``toJSON(secrets)`` gives one step every secret in the repository at once; legitimate workflows
name the secrets a step needs. The runtime tokens let a step write to the Actions cache and
artifacts (cache poisoning) and are meant to stay inside the runner. asca reads every workflow as
text (``.github/workflows/*.yml``), whether or not it runs a coding agent, and never runs anything.

| Finding | Severity |
|---|---|
| wfx indicators: ``WF_CALLBACK`` / ``WF_CTOKEN``, its published token or exfil servers, a ``build-audit-xxxxxx.yml`` file | critical |
| ``toJSON(secrets)`` together with the runtime-token step or a hard-coded URL; ``ACTIONS_RUNTIME_TOKEN`` / ``ACTIONS_ID_TOKEN_REQUEST_TOKEN`` persisted by name into ``$GITHUB_ENV`` / ``$GITHUB_OUTPUT``, or sent with curl/wget to a hard-coded non-GitHub URL | high (medium if the workflow isn't committed) |
| ``toJSON(secrets)`` alone (often deliberate: secrets-to-env actions) | medium (shown, doesn't fail the audit) |
| ``toJSON(vars)`` (all repository variables; not secret, but rarely needed whole) | low |

Using the runtime or OIDC token normally (``curl $ACTIONS_ID_TOKEN_REQUEST_URL``, cache tools) isn't reported.
"""
from __future__ import annotations

import re
from pathlib import Path

from .installhooks import SAFEDEP, WFX_TEXT
from .model import Finding, Severity
from .repohooks import tracked_paths

MAX_FILES = 200
MAX_READ = 1024 * 1024
WORKFLOW_DIR = ".github/workflows"

_ALL_SECRETS = re.compile(r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}", re.I)
_ALL_VARS = re.compile(r"\$\{\{\s*toJSON\(\s*vars\s*\)\s*\}\}", re.I)
_RUNTIME = re.compile(r"ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN")
# Legitimate workflows *use* these tokens (curl to $ACTIONS_ID_TOKEN_REQUEST_URL for OIDC, sccache with the
# cache token). wfx's step *persisted* the token into $GITHUB_ENV so every later step - the payload - inherits it.
_PERSIST = re.compile(r"GITHUB_ENV|GITHUB_OUTPUT")
_LITERAL_URL = re.compile(r"https?://(?![\w.-]*(?:githubusercontent\.com|github\.com|actions\.githubusercontent|"
                          r"pipelines\.actions|blob\.core\.windows\.net)\b)[\w.-]+", re.I)
_WFX_NAME = re.compile(r"^build-audit-[a-z0-9]{6}\.ya?ml$")


def _line(text: str, pos: int) -> tuple[int, str]:
    n = text.count("\n", 0, pos) + 1
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    return n, text[s:e if e != -1 else len(text)].strip()[:140]


# The token *name* written out (a quoted key list, or NAME= in an echo), as opposed to the value being used.
_NAMED = re.compile(r"""['"]ACTIONS_(?:RUNTIME_TOKEN|ID_TOKEN_REQUEST_TOKEN)['"]|"""
                    r"""(?<![${\w])ACTIONS_(?:RUNTIME_TOKEN|ID_TOKEN_REQUEST_TOKEN)=""")
_SENDER = re.compile(r"\b(?:curl|wget|nc|fetch\(|Invoke-WebRequest)", re.I)
_LOCAL = re.compile(r"https?://(?:localhost|127\.0\.0\.1|\[::1\])", re.I)
WINDOW = 3


def _step_block(lines: list[str], idx: int) -> str:
    """The text of the YAML list item (workflow step) that contains line idx: from the nearest '- ' item start
    indented less than that line, up to the next item at the same indent or anything indented less."""
    ind = lambda s: len(s) - len(s.lstrip(" "))  # noqa: E731
    cur = ind(lines[idx])
    start = idx
    for j in range(idx, -1, -1):
        st = lines[j].lstrip(" ")
        if st.startswith("- ") and (ind(lines[j]) < cur or j == idx):
            start = j
            break
    item = ind(lines[start])
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if not lines[j].strip() or lines[j].lstrip().startswith("#"):
            continue
        if ind(lines[j]) < item or (ind(lines[j]) == item and lines[j].lstrip(" ").startswith("- ")):
            end = j
            break
    return "\n".join(lines[start:end])


def _runtime_leak(text: str) -> re.Match | None:
    """wfx's step: the runtime/OIDC request token persisted into $GITHUB_ENV/$GITHUB_OUTPUT (its name written out,
    with the write within a few lines), or its value sent with curl/wget to a hard-coded non-GitHub URL."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if not _RUNTIME.search(ln):
            continue
        near = "\n".join(lines[max(0, i - WINDOW):i + WINDOW + 1])
        if _NAMED.search(ln) and _PERSIST.search(near):
            return _RUNTIME.search(text, sum(len(x) + 1 for x in lines[:i]))
        if _SENDER.search(ln) and _LITERAL_URL.search(ln) and not _LOCAL.search(ln):
            return _RUNTIME.search(text, sum(len(x) + 1 for x in lines[:i]))
    return None


def audit_repo(repo: Path, git_dir: Path | None, *, assume_committed: bool = False) -> list[Finding]:
    wf_dir = repo / WORKFLOW_DIR
    if not wf_dir.is_dir():
        return []
    files = sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file()
                   and not p.is_symlink())[:MAX_FILES]
    rels = [f"{WORKFLOW_DIR}/{p.name}" for p in files]
    tracked = set(rels) if assume_committed else tracked_paths(git_dir, rels)
    out: list[Finding] = []
    for p, rel in zip(files, rels):
        try:
            if p.stat().st_size > MAX_READ:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        committed = rel in tracked or git_dir is None
        hits: list[tuple[Severity, str, int, str, str]] = []      # sev, kind, line, snippet, why
        m = WFX_TEXT.search(text)
        if m or _WFX_NAME.match(p.name):
            n, snip = _line(text, m.start()) if m else (1, p.name)
            hits.append((Severity.CRITICAL, "wfx", n, snip,
                         f"It matches the wfx credential stealer's published indicators ({SAFEDEP})."))
        leak = _runtime_leak(text)
        m = _ALL_SECRETS.search(text)
        if m:
            n, snip = _line(text, m.start())
            near = _step_block(text.split("\n"), n - 1)
            sent = bool(_SENDER.search(near) and _LITERAL_URL.search(near) and not _LOCAL.search(near))
            if leak or sent:
                hits.append((Severity.HIGH, "all-secrets", n, snip,
                             "`toJSON(secrets)` hands every secret in the repository to one step, and "
                             + ("the same workflow persists the Actions runtime token, the pair of steps wfx injected"
                                if leak else "the step sends data to a hard-coded URL") + "."))
            else:
                # common and usually deliberate (secrets-to-env actions, reusable actions); shown, no alert
                hits.append((Severity.MEDIUM, "all-secrets", n, snip,
                             "`toJSON(secrets)` hands every secret in the repository to one step. That's often "
                             "deliberate (e.g. a secrets-to-env action), but any compromise of that step or action "
                             "gets all of them. wfx used it to steal every secret at once. Make sure you added it."))
        m = leak
        if m:
            n, snip = _line(text, m.start())
            hits.append((Severity.HIGH, "runtime-token", n, snip,
                         f"`{m.group(0)}` is written to `$GITHUB_ENV`/`$GITHUB_OUTPUT` or sent to a hard-coded URL, "
                         f"so later steps (or a server) can write to the Actions cache and artifacts or mint OIDC "
                         f"tokens. wfx's first injected step did exactly this."))
        m = _ALL_VARS.search(text)
        if m:
            n, snip = _line(text, m.start())
            hits.append((Severity.LOW, "all-vars", n, snip,
                         "`toJSON(vars)` passes every repository variable to one step."))
        for sev, kind, n, snip, why in hits:
            if not committed and sev == Severity.HIGH:
                sev = Severity(sev - 1)
                why += " The workflow isn't committed yet, so it only runs once it's pushed."
            out.append(Finding(
                rule="repo.wfx-indicator" if kind == "wfx" else "repo.workflow-secret-dump", category="repo",
                severity=sev,
                title=(f"Workflow `{p.name}` carries wfx stealer indicators" if kind == "wfx" else
                       f"Workflow `{p.name}` hands out " + {"all-secrets": "every secret (`toJSON(secrets)`)",
                                                           "runtime-token": "the Actions runtime token",
                                                           "all-vars": "every variable (`toJSON(vars)`)"}[kind]),
                location=f"{p}:{n}", subject=f"{rel}:{kind}", detail=f"line {n}: `{snip}`. {why}",
                remediation=(
                    "Treat the repository's secrets as stolen: delete the file or step, revoke the GitHub token of the "
                    "commit author, rotate every secret and cloud role the workflows can read, and check the run "
                    "history for deleted runs (gaps in run numbers). See SafeDep's cleanup list." if kind == "wfx" else
                    "If you didn't write this step, check `git log -p` on the file for who added it and rotate the "
                    "secrets. Otherwise pass only the secrets the step needs (`MY_KEY: ${{ secrets.MY_KEY }}`) and keep "
                    "runtime tokens inside the runner.")))
    return out
