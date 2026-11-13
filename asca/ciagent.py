"""Coding agents in GitHub workflows that strangers can trigger (``repo.ci-agent-untrusted-trigger``).

A workflow that runs Claude Code, Gemini CLI, Codex or another coding agent on an event anyone can
cause (opening an issue, commenting, a pull request from a fork via ``pull_request_target``) hands
untrusted text to an agent that holds the job's token and secrets. Researchers turned that into key
theft and repository takeover across vendors in 2026 ("Comment and Control"; Aikido's "PromptPwnd";
GHSA-8q5r-mmjf-575q for claude-code-action, GHSA-wpqr-6v78-jr5g for run-gemini-cli).

What this reads, statically: ``.github/workflows/*.yml|yaml`` in each repo, as text. Nothing is run.
Only files that mention a known agent are parsed at all.

Per agent step on an untrusted trigger, the finding collects reasons and takes the worst:
- HIGH: the agent can be steered and the job holds something worth stealing (a write token, an
  unrestricted token, secrets beyond the model key, or an OIDC token). Steered means one of:
  - issue / comment / PR / review / discussion text (``${{ github.event.*.title|body }}``, branch names)
    pasted into the agent's prompt or command, with no write-access gate on who starts it;
  - a ``pull_request_target`` job that checks out the PR's code before the agent runs, so the agent
    loads the attacker's CLAUDE.md / GEMINI.md / AGENTS.md / .mcp.json;
  - claude-code-action's write-access check switched off (``allowed_non_write_users``, or
    ``allowed_bots: '*'``) with no other gate.
- MEDIUM: the same with a read-only job and no secrets in reach; the write check off in the vendor's
  documented triage setup (only issues / pull-requests write and the model key); pasted text in a job
  a write-access gate starts (the gate limits who starts it, not who wrote the text); or an ungated
  agent holding a write token or secrets.
- LOW: an ungated agent in a read-only job without secrets.
``repo.ci-agent-unpinned`` (LOW): a third-party agent action referenced by tag or branch instead of a
commit SHA. Workflows not in the git index are lowered one level: they run only once pushed.

claude-code-action checks the triggering user's write access by default, so on its own an untrusted
trigger is not reported for it. Other agents count as gated when the job or step has an ``if:`` that
tests ``author_association`` / the actor, or a step checks collaborator permission before the agent.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from . import yamlmini
from .model import Finding, Severity
from .repohooks import tracked_paths

MAX_FILES = 200
MAX_READ = 1024 * 1024
WORKFLOW_DIR = ".github/workflows"

# Events that run in the base repository's context (secrets, a writable token) yet anyone with an
# account can cause on a public repo. `pull_request` from a fork gets no secrets and a read-only token.
UNTRUSTED = {"issues", "issue_comment", "pull_request_target", "discussion", "discussion_comment"}

# Agent actions (owner/repo, lower-case) and the vendor-documented gate they apply by default.
AGENT_ACTIONS = {
    "anthropics/claude-code-action": ("Claude Code", True),
    "anthropics/claude-code-base-action": ("Claude Code", False),
    "google-github-actions/run-gemini-cli": ("Gemini CLI", False),
    "google-gemini/gemini-cli-action": ("Gemini CLI", False),
    "openai/codex-action": ("Codex", False),
    "actions/ai-inference": ("GitHub AI Inference", False),
}
AGENT_CLI = re.compile(
    r"(?:^|[\s;&|(`$])(?:npx\s+(?:-y\s+|--yes\s+)?)?(?:"
    r"@anthropic-ai/claude-code(?:@\S*)?|claude|@google/gemini-cli(?:@\S*)?|gemini|@openai/codex(?:@\S*)?|codex|copilot"
    r")\s+(?:[^\n]*?\s)?(?:-p\b|--print\b|--prompt\b|exec\b|--yolo\b|--dangerously-skip-permissions\b|"
    r"--full-auto\b|--allow-all-tools\b)", re.M)
CLI_NAMES = (("@anthropic-ai/claude-code", "Claude Code"), ("claude", "Claude Code"), ("gemini", "Gemini CLI"),
             ("codex", "Codex"), ("copilot", "Copilot CLI"))
USES_AGENT = re.compile(r"^\s*-?\s*uses:\s*['\"]?(?:" + "|".join(re.escape(a) for a in AGENT_ACTIONS) + r")(?:[/@'\"\s]|$)",
                        re.I | re.M)

# Text an outsider controls, as GitHub expressions.
EVENT_TEXT = re.compile(
    r"\$\{\{\s*[^}]*?(?:github\.event\.(?:issue|comment|pull_request|review|review_comment|discussion|head_commit|"
    r"commits\[[^\]]*\])\.(?:title|body|message)|github\.event\.pull_request\.head\.(?:ref|label)|github\.head_ref|"
    r"github\.event\.(?:issue|pull_request|comment)\b\s*\}\}|toJSON\(\s*github\.event\s*\))[^}]*\}\}")
HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|"
                           r"github\.event\.pull_request\.merge_commit_sha", re.I)
# An `if:` that limits who can run the agent. Comparing two users (commenter == issue author) or checking only
# the repository name is not a gate: anyone can be either.
_WHO = r"github\.(?:triggering_)?actor|github\.event\.(?:[a-z_]+\.)?(?:user|sender)\.(?:login|id)"
GATE_IF = re.compile(
    r"author_association[^\n]*?(?:OWNER|MEMBER|COLLABORATOR)|(?:OWNER|MEMBER|COLLABORATOR)[^\n]*?author_association|"
    rf"(?:{_WHO})\s*==\s*['\d]|['\d][^'\s]*'?\s*==\s*(?:{_WHO})|"
    rf"contains\(\s*fromJSON\([^)]*\)\s*,\s*(?:{_WHO})\s*\)|"
    r"pull_request\.head\.repo\.full_name\s*==\s*github\.repository|"
    r"github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name|"
    r"pull_request\.head\.repo\.fork\s*==\s*false|!\s*github\.event\.pull_request\.head\.repo\.fork|"
    r"needs\.[\w-]+\.outputs\.[\w-]*(?:authori[sz]ed|is[_-]?member|is[_-]?maintainer|is[_-]?collaborator|"
    r"allowed|trusted|permission)[\w-]*", re.I)
GATE_STEP = re.compile(r"collaborators/[^\n]{1,80}?/permission\b|getCollaboratorPermissionLevel|"
                       r"check-user-permission|permission-check|actions-cool/check-user", re.I)
SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
# Inputs whose secret the action keeps away from the agent: codex-action serves the model API through
# its own proxy, so Codex never holds the key (openai/codex-action README).
PROXIED_INPUTS = {"openai/codex-action": {"openai-api-key", "responses-api-endpoint"}}
PROVIDER_KEYS = re.compile(r"^(?:ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|GEMINI_API_KEY|GOOGLE_API_KEY|"
                           r"OPENAI_API_KEY|AZURE_OPENAI_API_KEY|[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI)[A-Z0-9_]*_(?:API_)?KEY)$")
# Write scopes that only let a hijacked agent edit conversation, not code, releases or packages.
NARROW_WRITE = {"issues", "pull-requests", "discussions"}
SHA = re.compile(r"@[0-9a-f]{40}$")

REF = ("https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/ ; "
       "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents")
FIX = ("Run the agent only on events from people with write access: use `pull_request` instead of "
       "`pull_request_target`, gate `issues`/`issue_comment` jobs on `github.event.comment.author_association` "
       "(OWNER, MEMBER, COLLABORATOR), and keep claude-code-action's write check on (no `allowed_non_write_users`, no "
       "`allowed_bots: '*'`). Pass issue and PR text to the agent as a file or tool result, not pasted into the prompt. "
       "Set `permissions:` to read-only for the agent job and keep other secrets out of it. Never check out the PR's "
       "code in a `pull_request_target` job that runs an agent.")


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:10]


def _triggers(doc: dict) -> set[str]:
    on = None
    for k in ("on", "True", True):
        if k in doc:
            on = doc[k]
            break
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {x for x in on if isinstance(x, str)}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _perm_state(*levels) -> tuple[set[str] | None, bool]:
    """(write scopes, oidc) from workflow/job ``permissions``; the job level wins when present.
    None = unrestricted: no ``permissions`` anywhere (the repository default may be read-write) or write-all."""
    perms = next((p for p in reversed(levels) if p is not None), None)
    if perms is None:
        return None, False
    if isinstance(perms, str):
        return (None, False) if perms.strip() == "write-all" else (set(), False)
    if isinstance(perms, dict):
        oidc = str(perms.get("id-token", "")).strip() == "write"
        return {str(k) for k, v in perms.items() if k != "id-token" and str(v).strip() == "write"}, oidc
    return None, False


def _flat(v) -> str:
    if isinstance(v, dict):
        return "\n".join(f"{k}: {_flat(x)}" for k, x in v.items())
    if isinstance(v, list):
        return "\n".join(_flat(x) for x in v)
    return "" if v is None else str(v)


def _agent_of(step: dict) -> tuple[str, str, bool] | None:
    """(agent name, how referenced, gated by default) for an agent step, else None."""
    uses = step.get("uses")
    if isinstance(uses, str):
        base = uses.split("@", 1)[0].strip().lower()
        for repo, (name, gated) in AGENT_ACTIONS.items():
            if base == repo or base.startswith(repo + "/"):
                return name, uses.strip(), gated
    run = step.get("run")
    if isinstance(run, str):
        m = AGENT_CLI.search(run)
        if m:
            cmd = m.group(0)
            name = next((n for key, n in CLI_NAMES if key in cmd), "a coding agent CLI")
            return name, f"run: {cmd.strip()[:60]}", False
    return None


def audit_repo(repo: Path, git_dir: Path | None, stats: dict | None = None) -> list[Finding]:
    wf_dir = repo / WORKFLOW_DIR
    if not wf_dir.is_dir():
        return []
    files = sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file()
                   and not p.is_symlink())[:MAX_FILES]
    rels = [f"{WORKFLOW_DIR}/{p.name}" for p in files]
    tracked = tracked_paths(git_dir, rels)
    out: list[Finding] = []
    for p, rel in zip(files, rels):
        try:
            if p.stat().st_size > MAX_READ:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not (USES_AGENT.search(text) or AGENT_CLI.search(text)):
            continue                      # no agent step: not parsed at all
        if stats is not None:
            stats["agent_workflows"] = stats.get("agent_workflows", 0) + 1
        try:
            doc = yamlmini.load(text)
        except yamlmini.YamlError as exc:
            out.append(Finding(
                rule="repo.ci-agent-untrusted-trigger", category="repo", severity=Severity.LOW,
                title="Workflow mentions a coding agent but couldn't be parsed", location=str(p),
                subject=f"{rel}:parse", detail=f"{exc}. asca couldn't check its triggers and permissions.",
                remediation="Review this workflow by hand, or report the YAML construct to asca."))
            continue
        if not isinstance(doc, dict):
            continue
        out += _audit_workflow(p, rel, doc, committed=rel in tracked or git_dir is None)
    return out


def _audit_workflow(path: Path, rel: str, doc: dict, committed: bool) -> list[Finding]:
    trig = _triggers(doc)
    risky = sorted(trig & UNTRUSTED)
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    out: list[Finding] = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
        job_if = str(job.get("if") or "")
        writes, oidc = _perm_state(doc.get("permissions"), job.get("permissions"))
        job_secrets = set(SECRET.findall(_flat(job.get("env")) + _flat(doc.get("env"))))
        head_checked_out = False
        gate_step_seen = False
        for idx, step in enumerate(steps):
            flat = _flat(step)
            if isinstance(step.get("uses"), str) and step["uses"].lower().startswith("actions/checkout") \
                    and HEAD_CHECKOUT.search(_flat(step.get("with"))):
                head_checked_out = True
            if GATE_STEP.search(flat):
                gate_step_seen = True
            agent = _agent_of(step)
            if not agent:
                continue
            name, how, gated_default = agent
            loc = f"{path}#jobs.{job_id}.steps[{idx}]"
            subj = f"{rel}:{job_id}:{idx}"
            if isinstance(step.get("uses"), str) and not SHA.search(step["uses"].strip()):
                out.append(_lower(Finding(
                    rule="repo.ci-agent-unpinned", category="pinning", severity=Severity.LOW,
                    title=f"{name} action not pinned to a commit in workflow `{path.name}`", location=loc,
                    subject=f"{subj}:pin", detail=f"`uses: {step['uses']}` follows a tag or branch, so a change "
                    f"upstream reaches this workflow, with its token and secrets, without review.",
                    remediation="Pin to a full commit SHA (`owner/repo@<40-hex> # vX.Y.Z`) and update it deliberately."),
                    committed))
            if not risky:
                continue
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            prompt_text = _flat(with_.get("prompt")) + "\n" + _flat(with_.get("direct_prompt")) + "\n" + \
                (step.get("run") if isinstance(step.get("run"), str) else "")
            reasons_high, reasons, medium_reasons = [], [], []
            gated_ext = bool(GATE_IF.search(job_if + "\n" + str(step.get("if") or ""))) or gate_step_seen
            pasted = sorted(set(m.group(0) for m in EVENT_TEXT.finditer(prompt_text)))
            if pasted:
                msg = ("text from the issue, comment or pull request is pasted into the agent's prompt "
                       f"({', '.join(f'`{x}`' for x in pasted[:3])}), so whoever wrote it steers the agent")
                if gated_ext:   # the gate limits who starts it, not who wrote the text it reads
                    medium_reasons.append(msg + "; a write-access gate limits who starts the run, but the text can "
                                          "come from someone else (a maintainer labelling or answering a stranger's issue)")
                else:
                    reasons_high.append(msg)
            if "pull_request_target" in trig and head_checked_out and not gated_ext:
                reasons_high.append("this `pull_request_target` job checks out the pull request's code before the "
                                    "agent runs, so the agent reads the attacker's CLAUDE.md / GEMINI.md / AGENTS.md "
                                    "/ .mcp.json with this repo's token and secrets")
            gate_off = []
            if name == "Claude Code" and gated_default:
                anwu = str(with_.get("allowed_non_write_users") or "").strip()
                bots = str(with_.get("allowed_bots") or "").strip()
                if anwu:
                    gate_off.append(f"`allowed_non_write_users: {anwu}`")
                if bots == "*":
                    gate_off.append("`allowed_bots: '*'`")
                if gate_off and not gated_ext:
                    msg = ("the write-access check of claude-code-action is switched off "
                           f"({' and '.join(gate_off)}), so anyone who can open an issue or comment can start it")
                    other = {s for s in set(SECRET.findall(flat)) | job_secrets
                             if s != "GITHUB_TOKEN" and not PROVIDER_KEYS.match(s)}
                    # id-token: write is how claude-code-action signs in to the Claude GitHub App, so it is part
                    # of the vendor's documented setup rather than extra power here.
                    narrow = writes is not None and writes <= NARROW_WRITE and not other
                    if narrow:   # the vendor's documented triage setup: only issue/PR edits and the model key at stake
                        medium_reasons.append(msg + "; the job can only edit issues and pull requests, but an "
                                              "injected prompt can still misuse that and try to read the model key "
                                              "(the action scrubs it from subprocesses on a best-effort basis)")
                    else:
                        reasons_high.append(msg)
            gated = (gated_default and not gate_off) or gated_ext
            proxied = PROXIED_INPUTS.get(str(step.get("uses", "")).split("@", 1)[0].strip().lower(), set())
            reachable = {k: v for k, v in step.items() if k != "with"}
            reachable["with"] = {k: v for k, v in with_.items() if k not in proxied}
            step_secrets = set(SECRET.findall(_flat(reachable))) | job_secrets
            step_secrets.discard("GITHUB_TOKEN")
            if not reasons_high and not medium_reasons and gated:
                continue
            if not gated:
                reasons.append("nothing checks that the person who triggered it has write access")
            power = []
            if writes is None:
                power.append("a token the workflow doesn't restrict (the repository default may be read-write)"
                             if job.get("permissions") is None and doc.get("permissions") is None
                             else "a token with write access to everything (`write-all`)")
            elif writes:
                power.append("a token that can write " + ", ".join(f"`{w}`" for w in sorted(writes)))
            vendor_oidc = oidc and name == "Claude Code" and gated_default   # the action's own sign-in
            if oidc and not vendor_oidc:
                power.append("an OIDC token (`id-token: write`), which any cloud account that trusts this repo accepts")
            if step_secrets:
                power.append("secrets " + ", ".join(f"`{s}`" for s in sorted(step_secrets)[:4]))
            if reasons_high and power:
                sev = Severity.HIGH
            elif reasons_high:          # steerable, but a read-only job with no secrets in reach
                sev = Severity.MEDIUM
            elif medium_reasons or (power and not gated):
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            detail = (f"Runs {name} ({how}) on {', '.join(f'`{t}`' for t in risky)}, events anyone with a GitHub "
                      f"account can cause on a public repo. "
                      + " ".join(r[0].upper() + r[1:] + "." for r in reasons_high + medium_reasons + reasons)
                      + (f" The job holds {', '.join(power)}." if power else
                         " The job is read-only and has no secrets in reach, which limits the damage to what its "
                         "output (comments, artifacts, caches) can do.")
                      + (" Its `id-token: write` is the action's own sign-in." if vendor_oidc else "")
                      + f" ({REF})")
            out.append(_lower(Finding(
                rule="repo.ci-agent-untrusted-trigger", category="repo", severity=sev,
                title=f"{name} in workflow `{path.name}` can be triggered by anyone"
                      + (" and steered by their text" if pasted else ""),
                location=loc, subject=f"{subj}:{_h(','.join(risky) + how)}", detail=detail, remediation=FIX),
                committed))
    return out


def _lower(f: Finding, committed: bool) -> Finding:
    if committed:
        return f
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    f.severity = order[max(0, order.index(f.severity) - 1)]
    f.detail += " This workflow isn't committed yet, so it only runs once it's pushed."
    return f
