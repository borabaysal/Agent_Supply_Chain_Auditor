"""repo.ci-agent-untrusted-trigger / repo.ci-agent-unpinned: coding agents in GitHub workflows.

Fixtures are inline YAML modelled on real workflows (vendor examples and public repos); nothing is run.
"""
import struct
import textwrap

import pytest

from asca import ciagent, yamlmini
from asca.model import Severity

SHA = "a" * 40


def _index(git, paths):
    body = b""
    for p in paths:
        raw = p.encode()
        entry = b"\x00" * 40 + b"\x00" * 20 + struct.pack(">H", len(raw)) + raw + b"\x00"
        entry += b"\x00" * ((8 - len(entry) % 8) % 8)
        body += entry
    (git / "index").write_bytes(b"DIRC" + struct.pack(">II", 2, len(paths)) + body)


def _repo(tmp_path, files, tracked=None):
    wt = tmp_path / "wt"
    wf = wt / ".github" / "workflows"
    wf.mkdir(parents=True)
    for name, text in files.items():
        (wf / name).write_text(textwrap.dedent(text))
    git = wt / ".git"
    git.mkdir()
    _index(git, [f".github/workflows/{n}" for n in (files if tracked is None else tracked)])
    return wt, git


def _run(tmp_path, files, tracked=None, stats=None):
    wt, git = _repo(tmp_path, files, tracked)
    return ciagent.audit_repo(wt, git, stats)


def _trig(fs):
    return [f for f in fs if f.rule == "repo.ci-agent-untrusted-trigger"]


# ------------------------------------------------------------------ HIGH

PASTED = f"""
name: triage
on:
  issues:
    types: [opened]
permissions:
  contents: write
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@{SHA}
        with:
          anthropic_api_key: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
          prompt: |
            Title: ${{{{ github.event.issue.title }}}}
            Body: ${{{{ github.event.issue.body }}}}
"""


def test_issue_text_pasted_into_prompt_is_high(tmp_path):
    [f] = _trig(_run(tmp_path, {"triage.yml": PASTED}))
    assert f.severity == Severity.HIGH
    assert "pasted into the agent's prompt" in f.detail
    assert "`contents`" in f.detail and "ANTHROPIC_API_KEY" in f.detail
    assert "steered by their text" in f.title
    assert f.location.endswith("#jobs.triage.steps[1]")
    # claude-code-action's write check is on by default and pinned: no other finding
    assert [x.rule for x in _run(tmp_path / "b", {"triage.yml": PASTED})] == ["repo.ci-agent-untrusted-trigger"]


GATE_OFF = """
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  pull-requests: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          allowed_non_write_users: "*"
"""


def test_write_check_switched_off_with_contents_write_is_high(tmp_path):
    fs = _run(tmp_path, {"claude.yml": GATE_OFF})
    [f] = _trig(fs)
    assert f.severity == Severity.HIGH
    assert "allowed_non_write_users: *" in f.detail
    assert any(x.rule == "repo.ci-agent-unpinned" and x.severity == Severity.LOW for x in fs)


def test_allowed_bots_star_switches_the_check_off(tmp_path):
    text = GATE_OFF.replace('allowed_non_write_users: "*"', "allowed_bots: '*'")
    [f] = _trig(_run(tmp_path, {"claude.yml": text}))
    assert f.severity == Severity.HIGH and "allowed_bots: '*'" in f.detail


def test_extra_secret_beyond_model_key_keeps_triage_setup_high(tmp_path):
    text = GATE_OFF.replace("  contents: write\n  pull-requests: write\n", "  issues: write\n").replace(
        "allowed_non_write_users", "github_token: ${{ secrets.BOT_PAT }}\n          allowed_non_write_users")
    [f] = _trig(_run(tmp_path, {"claude.yml": text}))
    assert f.severity == Severity.HIGH and "BOT_PAT" in f.detail


PRT_HEAD = """
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    env:
      SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          prompt: Review this pull request.
"""


def test_pull_request_target_with_head_checkout_is_high(tmp_path):
    [f] = _trig(_run(tmp_path, {"review.yml": PRT_HEAD}))
    assert f.severity == Severity.HIGH
    assert "checks out the pull request's code" in f.detail
    assert "SLACK_WEBHOOK" in f.detail and "GEMINI_API_KEY" in f.detail
    assert f.title.startswith("Gemini CLI")


def test_agent_cli_in_run_step(tmp_path):
    text = """
    on: issue_comment
    jobs:
      bot:
        runs-on: ubuntu-latest
        steps:
          - run: |
              npx -y @anthropic-ai/claude-code -p "answer: ${{ github.event.comment.body }}" --dangerously-skip-permissions
            env:
              ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    """
    [f] = _trig(_run(tmp_path, {"bot.yml": text}))
    assert f.severity == Severity.HIGH
    assert "doesn't restrict" in f.detail          # no permissions block anywhere
    assert "run: " in f.detail


# ------------------------------------------------------------------ MEDIUM / LOW grading


def test_vendor_triage_example_is_medium_not_high(tmp_path):
    """claude-code-action's own examples/issue-triage.yml: write check off, but only issues:write and the
    model key in reach (id-token: write is the action's own sign-in)."""
    text = """
    on:
      issues:
        types: [opened]
    jobs:
      triage-issue:
        runs-on: ubuntu-latest
        permissions:
          contents: read
          issues: write
          id-token: write
        steps:
          - uses: actions/checkout@v6
          - uses: anthropics/claude-code-action@v1
            with:
              prompt: "/label-issue REPO: ${{ github.repository }} ISSUE_NUMBER: ${{ github.event.issue.number }}"
              anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
              allowed_non_write_users: "*"
              github_token: ${{ secrets.GITHUB_TOKEN }}
    """
    [f] = _trig(_run(tmp_path, {"triage.yml": text}))
    assert f.severity == Severity.MEDIUM
    assert "can only edit issues and pull requests" in f.detail
    assert "own sign-in" in f.detail
    assert "pasted" not in f.detail            # the issue *number* is not text an outsider controls


def test_ungated_agent_with_write_token_is_medium(tmp_path):
    text = f"""
    on:
      issues:
        types: [opened]
    permissions:
      issues: write
    jobs:
      t:
        runs-on: ubuntu-latest
        steps:
          - uses: openai/codex-action@{SHA}
            with:
              openai-api-key: ${{{{ secrets.OPENAI_API_KEY }}}}
              prompt-file: .github/codex/triage.md
    """
    [f] = _trig(_run(tmp_path, {"t.yml": text}))
    assert f.severity == Severity.MEDIUM
    assert "Nothing checks" in f.detail
    assert "OPENAI_API_KEY" not in f.detail    # codex-action keeps the key in its proxy, away from Codex


def test_read_only_no_secrets_is_low_and_head_checkout_without_power_is_medium(tmp_path):
    ro = f"""
    on: [issues]
    permissions: read-all
    jobs:
      t:
        runs-on: ubuntu-latest
        steps:
          - uses: openai/codex-action@{SHA}
            with:
              openai-api-key: ${{{{ secrets.OPENAI_API_KEY }}}}
    """
    [f] = _trig(_run(tmp_path, {"t.yml": ro}))
    assert f.severity == Severity.LOW and "read-only" in f.detail
    prt = PRT_HEAD.replace("  pull-requests: write\n", "").replace(
        "    env:\n      SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}\n", "").replace(
        "google-github-actions/run-gemini-cli@v0", f"openai/codex-action@{SHA}").replace(
        "gemini_api_key: ${{ secrets.GEMINI_API_KEY }}", "openai-api-key: ${{ secrets.OPENAI_API_KEY }}")
    [g] = _trig(_run(tmp_path / "b", {"r.yml": prt}))
    assert g.severity == Severity.MEDIUM and "checks out the pull request's code" in g.detail


def test_local_workflow_is_one_level_lower(tmp_path):
    [f] = _trig(_run(tmp_path, {"triage.yml": PASTED}, tracked=[]))
    assert f.severity == Severity.MEDIUM and "isn't committed yet" in f.detail


# ------------------------------------------------------------------ not reported


@pytest.mark.parametrize("gate", [
    "if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)",
    "if: github.event.comment.author_association == 'OWNER'",
    "if: github.actor == 'maintainer-bot'",
    "if: contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)",
    "if: needs.authorize.outputs.IS_AUTHORIZED == 'true'",
])
def test_gated_jobs_with_disabled_vendor_check_are_not_high(tmp_path, gate):
    text = GATE_OFF.replace("    runs-on: ubuntu-latest\n", f"    runs-on: ubuntu-latest\n    {gate}\n")
    assert yamlmini.load(text)["jobs"]["claude"]["if"]
    assert _trig(_run(tmp_path, {"claude.yml": text})) == []


@pytest.mark.parametrize("not_a_gate", [
    "if: github.repository == 'org/repo'",
    "if: github.event.comment.user.login == github.event.issue.user.login",   # any commenter on own issue
    "if: github.event.comment.user.type != 'Bot'",
    "if: contains(github.event.comment.body, '@claude')",
])
def test_conditions_that_do_not_limit_who_runs_it(tmp_path, not_a_gate):
    text = GATE_OFF.replace("    runs-on: ubuntu-latest\n", f"    runs-on: ubuntu-latest\n    {not_a_gate}\n")
    [f] = _trig(_run(tmp_path, {"claude.yml": text}))
    assert f.severity == Severity.HIGH


def test_gate_does_not_clear_pasted_text(tmp_path):
    """A maintainer applying a label starts it, but the issue text was written by a stranger."""
    text = PASTED.replace("    types: [opened]", "    types: [labeled]").replace(
        "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: github.event.sender.login == 'maintainer'\n")
    [f] = _trig(_run(tmp_path, {"triage.yml": text}))
    assert f.severity == Severity.MEDIUM and "can come from someone else" in f.detail


def test_permission_check_step_gates_the_agent(tmp_path):
    text = """
    on: [issues]
    permissions: {issues: write}
    jobs:
      t:
        runs-on: ubuntu-latest
        steps:
          - run: gh api repos/${{ github.repository }}/collaborators/${{ github.actor }}/permission
          - uses: google-github-actions/run-gemini-cli@v0
    """
    fs = _run(tmp_path, {"t.yml": text})
    assert _trig(fs) == [] and [f.rule for f in fs] == ["repo.ci-agent-unpinned"]


def test_trusted_triggers_and_same_repo_prs_are_silent(tmp_path):
    files = {
        "pr.yml": PRT_HEAD.replace("pull_request_target:", "pull_request:"),
        "push.yml": PASTED.replace("issues:\n    types: [opened]", "push:\n    branches: [main]"),
        "same_repo.yml": PRT_HEAD.replace("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: "
                                          "github.event.pull_request.head.repo.full_name == github.repository\n"),
    }
    assert _trig(_run(tmp_path, files)) == []


def test_files_without_agents_are_not_parsed(tmp_path):
    files = {"ci.yml": "on: [issues]\njobs:\n  a:\n    steps:\n      - run: echo gemini of claude codex\n",
             "broken.yml": "on: [issues\n  :::: {\n"}
    stats = {}
    assert _run(tmp_path, files, stats=stats) == []
    assert stats.get("agent_workflows", 0) == 0


def test_unparseable_agent_workflow_fails_closed(tmp_path):
    text = "on: [issues]\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n     bad: indent\n"
    [f] = _run(tmp_path, {"x.yml": text})
    assert f.severity == Severity.LOW and "couldn't be parsed" in f.title


def test_no_workflow_dir_and_symlinks_ignored(tmp_path):
    assert ciagent.audit_repo(tmp_path, None) == []
    wt, git = _repo(tmp_path, {})
    target = tmp_path / "evil.yml"
    target.write_text(PASTED)
    (wt / ".github" / "workflows" / "link.yml").symlink_to(target)
    assert ciagent.audit_repo(wt, git) == []


def test_anchors_and_aliases_reach_the_agent_step(tmp_path):
    """Real repos reuse steps with YAML anchors; the aliased job must be checked too."""
    text = f"""
    on: [issues]
    permissions: {{contents: write}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps: &steps
          - uses: anthropics/claude-code-action@{SHA}
            with:
              prompt: "${{{{ github.event.issue.body }}}}"
      b:
        runs-on: ubuntu-latest
        steps: *steps
    """
    fs = _trig(_run(tmp_path, {"x.yml": text}))
    assert sorted(f.location.split("#")[1] for f in fs) == ["jobs.a.steps[0]", "jobs.b.steps[0]"]


def test_cli_flag_and_stats(tmp_path):
    import json
    from asca import cli
    wt, git = _repo(tmp_path / "repos", {"triage.yml": PASTED})
    (git / "config").write_text("[core]\n\tbare = false\n")
    common = ["--repos", str(tmp_path / "repos"), "--no-hermes", "--no-client-configs", "--no-global-git",
              "--no-session-history", "--no-stray-instructions", "--format", "none"]

    def rules(*extra):
        out = tmp_path / "out" / "rep"
        rc = cli.run(common + ["-o", str(out), *extra])
        data = json.loads(out.with_suffix(".json").read_text())
        return rc, {f["rule"] for f in data["findings"]}, data["stats"]

    rc, found, stats = rules()
    assert rc == 1 and "repo.ci-agent-untrusted-trigger" in found and stats["agent_workflows"] == 1
    rc, found, _ = rules("--no-ci-agents")
    assert not any(r.startswith("repo.ci-agent") for r in found)


# ------------------------------------------------------------------ yamlmini anchors


def test_yamlmini_anchors_aliases_merge():
    t = textwrap.dedent("""
    base: &b
      x: 1
      y: [2, 3]
    derived:
      <<: *b
      y: 4
    paths: &p
      - a/**
      - b
    other: *p
    lit: &l |
      hi
    again: *l
    """)
    d = yamlmini.load(t)
    assert d["derived"] == {"x": 1, "y": 4}
    assert d["other"] == ["a/**", "b"] and d["again"] == "hi\n"
    d["other"].append("c")
    assert d["paths"] == ["a/**", "b"]                  # aliases are copies
    with pytest.raises(yamlmini.YamlError, match="unknown alias"):
        yamlmini.load("a: *nope\n")
