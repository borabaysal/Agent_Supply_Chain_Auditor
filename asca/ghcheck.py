"""``asca github-check``: were your GitHub repos probed or hit by the wfx stealer? (opt-in, online, read-only)

The wfx credential stealer (SafeDep and Aikido, 12 Nov 2026) used stolen tokens to push into the
victims' own repositories and then cleaned up within a minute, deleting the workflow run and its
logs. Its traces are on GitHub, not on disk, so the offline audit can't see them:

- **Probe pull request** ``docs: dependency audit notes`` from a ``wfx-docs`` branch (61,000+ repos,
  most still open). SafeDep: "A probe pull request on its own means the account is compromised."
- **Payload and cleanup commits**: ``ci: refresh build cache``, ``chore: add ci helper``,
  ``chore: add dependency audit workflow``, then ``ci: restore`` / ``ci: cleanup``.
- **Throwaway branches** ``chore/xxxxxxxx`` and ``ci-check-NNNN``.
- **Deleted runs**: "A missing run number on the attacker's commit is the more reliable sign that
  the payload ran" (Aikido).
- **Loot left behind**: ``wfx-loot`` artifacts and ``wfx-`` cache entries.
- **Payload still live**: the default branch's ``package.json`` and workflows, checked with the
  offline wfx rules (asca.installhooks, asca.wfsecrets).

Only HTTPS GET requests to ``api.github.com`` (or ``https://<host>/api/v3``) with a token asca finds
the same way as ``--github-token-scopes`` (gh login, ``GH_TOKEN``/``GITHUB_TOKEN``,
``.git-credentials``) or ``--token-env VAR``. Nothing is written to GitHub, nothing is cloned, the
token is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from . import __version__, ghtoken, installhooks, report, wfsecrets
from .model import Finding, Severity

SINCE = "2026-11-10"            # first probe PRs: 10 Nov 12:45 UTC (Aikido)
SAFEDEP = installhooks.SAFEDEP
AIKIDO = ("https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-"
          "of-repositories")
PROBE_TITLE = "docs: dependency audit notes"
PROBE_BRANCH = "wfx-docs"
PAYLOAD_TITLES = {"chore: add ci helper": Severity.HIGH, "chore: add dependency audit workflow": Severity.HIGH,
                  "ci: refresh build cache": Severity.MEDIUM}       # generic wording: SafeDep rates it medium
CLEANUP_TITLES = {"ci: restore", "ci: cleanup"}
BRANCH_RX = re.compile(r"^(?:chore/(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8}|ci-check-\d{4})$")
MAX_PAGES = 5
MAX_WORKFLOW_FILES = 40

ROTATE = ("Treat the account that pushed it as compromised (SafeDep): revoke its tokens, OAuth app grants, SSH keys and "
          "sessions and turn on 2FA; rotate every secret and variable the repo can read (also environment and org "
          "secrets); delete the `wfx-docs` branch and close the probe PR; pull package versions built between the "
          "payload commit and `ci: cleanup`; treat machines that ran `npm install` on those commits as compromised. "
          f"Then check AWS/Azure for the backdoors wfx leaves ({SAFEDEP}).")


class Api:
    """Read-only GitHub REST client. ``fetch(url) -> (status, json_or_bytes, headers)`` can be swapped for tests."""

    def __init__(self, token: str, host: str = "github.com", fetch=None, timeout: float = 20.0):
        self.base = ghtoken._api_base(host)
        self._token = token
        self.timeout = timeout
        self.fetch = fetch or self._fetch
        self.calls = 0

    def _fetch(self, url: str, raw: bool = False):
        if not url.startswith(self.base + "/"):          # never send the token anywhere else
            raise ValueError(f"refusing to send the token to {url}")
        req = urllib.request.Request(url, method="GET", headers={
            "Authorization": f"Bearer {self._token}", "User-Agent": f"asca/{__version__}",
            "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:     # noqa: S310 (fixed https base)
                body = r.read()
                return r.status, (body if raw else json.loads(body or b"null")), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, None, dict(e.headers or {})

    def get(self, path: str, raw: bool = False, **params):
        self.calls += 1
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        url = self.base + path + q
        return self.fetch(url, raw) if raw else self.fetch(url)

    def pages(self, path: str, key: str | None = None, **params) -> tuple[int, list]:
        out, status = [], 200
        for page in range(1, MAX_PAGES + 1):
            status, doc, _ = self.get(path, per_page=100, page=page, **params)
            if status != 200 or doc is None:
                return status, out
            items = doc.get(key, []) if key else doc
            out += items
            if len(items) < 100:
                break
        return status, out


def list_repos(api: Api, owners: list[str], repos: list[str]) -> tuple[list[str], list[str]]:
    """Full names to check, and errors. Default: every repo the token's user owns (incl. private)."""
    names, errors = list(repos), []
    if not owners and not repos:
        st, items = api.pages("/user/repos", affiliation="owner", sort="pushed")
        if st != 200 and not items:
            errors.append(f"can't list your repos (HTTP {st}); pass --repo OWNER/NAME")
        names += [r["full_name"] for r in items]
    for o in owners:
        st, items = api.pages(f"/orgs/{o}/repos", type="all")
        if st == 404:
            st, items = api.pages(f"/users/{o}/repos", type="owner")
        if st != 200 and not items:
            errors.append(f"can't list repos of {o} (HTTP {st})")
        names += [r["full_name"] for r in items]
    seen, out = set(), []
    for n in names:
        if n.lower() not in seen:
            seen.add(n.lower())
            out.append(n)
    return out, errors


def _ts(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _f(repo: str, rule: str, sev: Severity, title: str, detail: str, where: str, subject: str,
       fix: str = ROTATE) -> Finding:
    return Finding(rule=rule, category="github", severity=sev, title=f"{repo}: {title}", location=where,
                   subject=f"{repo}:{subject}", detail=detail, remediation=fix)


def check_repo(api: Api, repo: str, since: str = SINCE) -> tuple[list[Finding], list[str]]:
    """Findings and notes (things that couldn't be checked) for one repo."""
    out: list[Finding] = []
    notes: list[str] = []
    web = f"https://github.com/{repo}"
    since_dt = _ts(since + "T00:00:00Z")

    # 1) probe pull requests (any state; newest first, stop once older than the window)
    st, prs = api.pages(f"/repos/{repo}/pulls", state="all", sort="created", direction="desc")
    if st not in (200,) and not prs:
        notes.append(f"pull requests: HTTP {st}")
    for pr in prs:
        if since_dt and (_ts(pr.get("created_at")) or since_dt) < since_dt:
            continue
        head = (pr.get("head") or {}).get("ref", "")
        if head == PROBE_BRANCH or (pr.get("title") or "").strip().lower() == PROBE_TITLE:
            who = (pr.get("user") or {}).get("login", "?")
            out.append(_f(repo, "github.wfx-probe-pr", Severity.CRITICAL,
                          f"wfx probe pull request #{pr.get('number')} ({pr.get('state')}) opened by {who}",
                          f"`{pr.get('title')}` from branch `{head}`, {pr.get('created_at')}. The attacker opens this "
                          f"with a stolen token to test write access; SafeDep: a probe PR on its own means the "
                          f"account ({who}) is compromised.", pr.get("html_url") or web, f"pr:{pr.get('number')}"))

    # 2) payload and cleanup commits on the default branch since the campaign started
    st, commits = api.pages(f"/repos/{repo}/commits", since=since + "T00:00:00Z")
    if st not in (200, 409) and not commits:          # 409 = empty repository
        notes.append(f"commits: HTTP {st}")
    titles = [((c.get("commit") or {}).get("message") or "").split("\n")[0].strip() for c in commits]
    cleanup = any(t.lower() in CLEANUP_TITLES for t in titles)
    payload_times = []
    for c, t in zip(commits, titles):
        sev = PAYLOAD_TITLES.get(t.lower())
        if not sev:
            continue
        author = ((c.get("author") or {}).get("login") or ((c.get("commit") or {}).get("author") or {}).get("name", "?"))
        when = ((c.get("commit") or {}).get("committer") or {}).get("date")
        payload_times.append(_ts(when))
        if cleanup:
            sev = Severity.CRITICAL
        out.append(_f(repo, "github.wfx-payload-commit", sev,
                      f"wfx payload commit `{t}` by {author}" + (" followed by a cleanup commit" if cleanup else ""),
                      f"{c.get('sha', '')[:7]} at {when}. wfx pushes this commit, lets it run once, then reverts with "
                      f"`ci: restore` / `ci: cleanup`" + (" (also present)." if cleanup else
                                                          ". `ci: refresh build cache` is generic wording: check the diff.")
                      , c.get("html_url") or web, f"commit:{c.get('sha', '')[:12]}"))

    # 3) throwaway branches still present
    st, branches = api.pages(f"/repos/{repo}/branches")
    for b in branches:
        name = b.get("name", "")
        if name == PROBE_BRANCH or BRANCH_RX.match(name):
            out.append(_f(repo, "github.wfx-branch", Severity.CRITICAL if name == PROBE_BRANCH else Severity.MEDIUM,
                          f"branch `{name}` matches wfx's branch names",
                          "wfx used `wfx-docs` for probe PRs and short-lived `chore/xxxxxxxx` / `ci-check-NNNN` branches "
                          "for payloads. A `chore/` branch with 8 random characters can be yours: check who pushed it.",
                          f"{web}/tree/{urllib.parse.quote(name)}", f"branch:{name}"))

    # 4) deleted runs: gaps in run numbers per workflow, since the campaign started
    st, runs = api.pages(f"/repos/{repo}/actions/runs", key="workflow_runs", created=f">={since}")
    if st not in (200,) and not runs:
        notes.append(f"workflow runs: HTTP {st}")
    by_wf: dict = {}
    for r in runs:
        # group by workflow id only: with `run-name:` every run of one workflow has its own name
        by_wf.setdefault(r.get("workflow_id"), []).append(r)
    for wf_id, rs in by_wf.items():
        wf_name = (str(rs[0].get("path") or "").rsplit("/", 1)[-1].split("@")[0] or rs[0].get("name") or "?")
        nums = sorted({r.get("run_number") for r in rs if isinstance(r.get("run_number"), int)})
        missing = [n for a, b in zip(nums, nums[1:]) for n in range(a + 1, b)]
        if not missing:
            continue
        # a gap alone is common in busy repos (maintainers delete runs): note it; next to wfx traces it matters
        sev = Severity.HIGH if (payload_times or any(f.rule == "github.wfx-probe-pr" for f in out)) else Severity.LOW
        out.append(_f(repo, "github.deleted-runs", sev,
                      f"workflow `{wf_name}` is missing run number{'s' if len(missing) > 1 else ''} "
                      f"{', '.join('#' + str(n) for n in missing[:8])}{' …' if len(missing) > 8 else ''}",
                      f"Runs since {since} skip these numbers, so they were deleted. wfx deletes the run that sent "
                      f"your secrets (Aikido: the most reliable sign the payload ran). Deleting runs yourself also "
                      f"leaves gaps; check the audit log (`workflows.delete_workflow_run`) for who did it."
                      + (" A wfx payload commit is in the same window." if payload_times else ""),
                      f"{web}/actions", f"runs:{wf_id}:{','.join(map(str, missing[:20]))}"))

    # 5) loot left behind (artifacts, caches); 403 when the token lacks actions:read
    st, doc, _ = api.get(f"/repos/{repo}/actions/artifacts", name="wfx-loot", per_page=10)
    if st == 200 and doc and doc.get("total_count"):
        out.append(_f(repo, "github.wfx-loot", Severity.CRITICAL, "a `wfx-loot` artifact exists",
                      "The stealer stores collected secrets in this artifact in some configurations.", f"{web}/actions",
                      "artifact"))
    st, doc, _ = api.get(f"/repos/{repo}/actions/caches", key="wfx-", per_page=10)
    if st == 200 and doc and doc.get("total_count"):
        out.append(_f(repo, "github.wfx-loot", Severity.CRITICAL, "an Actions cache entry starting with `wfx-` exists",
                      "The stealer can stash collected secrets in the Actions cache.", f"{web}/actions/caches", "cache"))

    # 6) payload still live on the default branch: run the offline rules on the fetched text
    out += _live_files(api, repo, web)
    return out, notes


def _live_files(api: Api, repo: str, web: str) -> list[Finding]:
    found: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="asca-ghcheck-") as tmp:
        root = Path(tmp)
        st, body, _ = api.get(f"/repos/{repo}/contents/package.json", raw=True)
        if st == 200 and isinstance(body, (bytes, str)):
            (root / "package.json").write_bytes(body if isinstance(body, bytes) else body.encode())
            try:
                scripts = json.loads((root / "package.json").read_text("utf-8", "replace")).get("scripts") or {}
            except (ValueError, AttributeError):
                scripts = {}
            for k in installhooks.LIFECYCLE:          # fetch the in-repo file the hook runs, if any
                m = installhooks._LOCAL_FILE.search(str(scripts.get(k, "")))
                rel = m.group(1)[2:] if m and m.group(1).startswith("./") else (m.group(1) if m else "")
                if rel and ".." not in rel:
                    st2, b2, _ = api.get(f"/repos/{repo}/contents/{urllib.parse.quote(rel)}", raw=True)
                    if st2 == 200 and isinstance(b2, (bytes, str)):
                        (root / rel).parent.mkdir(parents=True, exist_ok=True)
                        (root / rel).write_bytes(b2 if isinstance(b2, bytes) else b2.encode())
        st, listing, _ = api.get(f"/repos/{repo}/contents/.github/workflows")
        if st == 200 and isinstance(listing, list):
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            for item in [i for i in listing if str(i.get("name", "")).endswith((".yml", ".yaml"))][:MAX_WORKFLOW_FILES]:
                st2, b2, _ = api.get(f"/repos/{repo}/contents/.github/workflows/{urllib.parse.quote(item['name'])}",
                                     raw=True)
                if st2 == 200 and isinstance(b2, (bytes, str)):
                    (wf / Path(item["name"]).name).write_bytes(b2 if isinstance(b2, bytes) else b2.encode())
        for f in installhooks.audit(root, risky_only=True, assume_committed=True) + \
                wfsecrets.audit_repo(root, None, assume_committed=True):
            rel = f.location.replace(str(root) + os.sep, "").split("#")[0].split(":")[0]
            found.append(Finding(rule=f.rule, category="github", severity=f.severity,
                                 title=f"{repo} (default branch): {f.title}", location=f"{web}/blob/HEAD/{rel}",
                                 subject=f"{repo}:live:{f.subject}", detail=f.detail.replace(str(root) + os.sep, ""),
                                 remediation=f.remediation))
    return found


def verdict(findings: list[Finding], notes: list[str] | None = None) -> str:
    rules = {f.rule for f in findings}
    if rules & {"github.wfx-loot"} or any(f.rule == "github.wfx-payload-commit" and f.severity == Severity.CRITICAL
                                           for f in findings) or "repo.wfx-indicator" in rules:
        return "🟥 payload pushed"
    if "github.wfx-probe-pr" in rules or any(f.rule == "github.wfx-branch" and f.severity == Severity.CRITICAL
                                             for f in findings):
        return "🟥 probed (account compromised)"
    if any(f.severity >= Severity.HIGH for f in findings):
        return "🟧 check"
    if any(f.severity >= Severity.MEDIUM for f in findings):
        return "🟨 check"
    if notes and len(notes) >= 2:          # couldn't read the repo: never call it clean
        return "❔ couldn't check"
    return "✅ clean"


def _pick_token(args) -> tuple[str | None, str]:
    if args.token_env:
        return os.environ.get(args.token_env), "github.com"
    hh = Path(args.hermes_home).expanduser() if args.hermes_home else None
    toks = [t for t in ghtoken.discover(Path.home(), hh) if t.host in ("github.com", "api.github.com")]
    return (toks[0].value, toks[0].host) if toks else (None, "github.com")


def run(argv: list[str], api: Api | None = None) -> int:
    p = argparse.ArgumentParser(prog="asca github-check", description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME", help="repo to check (repeatable)")
    p.add_argument("--owner", action="append", default=[], metavar="ORG_OR_USER",
                   help="check every repo of this org or user (repeatable)")
    p.add_argument("--since", default=SINCE, help=f"start of the window, YYYY-MM-DD (default {SINCE}, wfx's first probe)")
    p.add_argument("--max-repos", type=int, default=200)
    p.add_argument("--token-env", metavar="VAR", help="read the token from this environment variable")
    p.add_argument("--hermes-home", default=os.environ.get("HERMES_HOME"), help="also look for a token here")
    p.add_argument("--json", action="store_true")
    p.add_argument("--telegram", choices=["never", "always", "change"], default="never")
    p.add_argument("--state", type=Path, default=Path("~/.local/state/asca/github-check.json"),
                   help="remembers the last result for --telegram change")
    p.add_argument("--telegram-chat")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--host-label", default=socket.gethostname())
    args = p.parse_args(argv)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.since):
        print("asca github-check: --since must be YYYY-MM-DD", file=sys.stderr)
        return 2
    if api is None:
        token, host = _pick_token(args)
        if not token:
            print("asca github-check: no GitHub token found (gh login, GH_TOKEN/GITHUB_TOKEN, .git-credentials); "
                  "use --token-env VAR", file=sys.stderr)
            return 2
        api = Api(token, host)
    names, errors = list_repos(api, args.owner, args.repo)
    names = names[:args.max_repos]
    results = []
    for n in names:
        fs, notes = check_repo(api, n, args.since)
        results.append({"repo": n, "verdict": verdict(fs, notes), "findings": fs, "notes": notes})
    bad = [r for r in results if any(f.severity >= Severity.MEDIUM for f in r["findings"])]
    unchecked = [r for r in results if r["verdict"].startswith("❔")]
    headline = (f"⛔ wfx: {len(bad)} of {len(results)} repos need attention" if bad else
                f"✅ wfx: no traces in {len(results) - len(unchecked)} repos since {args.since}")
    if unchecked:
        headline += f" ({len(unchecked)} couldn't be checked)"
    if args.json:
        print(json.dumps({"tool": "asca github-check", "version": __version__, "since": args.since,
                          "headline": headline, "errors": errors, "api_calls": api.calls,
                          "repos": [{"repo": r["repo"], "verdict": r["verdict"], "notes": r["notes"],
                                     "findings": [f.to_dict() for f in r["findings"]]} for r in results]}, indent=1))
    else:
        print(headline)
        for r in results:
            if r in bad or [n for n in r["notes"] if not n.startswith("workflow runs: HTTP 403")]:
                print(f"  {r['verdict']}  {r['repo']}" + (f"   (couldn't check: {'; '.join(r['notes'])})"
                                                          if r["notes"] else ""))
                for f in r["findings"][:10]:
                    print(f"      [{f.severity.name}] {f.title.split(': ', 1)[-1]}\n        {f.location}")
        no_runs = [r for r in results if any(n.startswith("workflow runs: HTTP 403") for n in r["notes"])]
        if no_runs:
            print(f"  note: the token can't read Actions on {len(no_runs)} repo(s), so deleted runs weren't checked "
                  f"there (fine-grained token: add 'Actions: read'; classic: `repo`).")
        for e in errors:
            print(f"  ! {e}")
        if bad:
            print(f"  fix: {ROTATE}")
    if (errors and not results) or (unchecked and not bad):
        return 2
    if args.telegram != "never":
        key = sorted(f"{r['repo']}|{f.rule}|{f.subject}" for r in bad for f in r["findings"])
        state = args.state.expanduser()
        try:
            prev = json.loads(state.read_text()).get("key")
        except (OSError, ValueError):
            prev = None
        changed = prev != key
        if args.telegram == "always" or (changed and (bad or prev)):
            token, chat = report.resolve_telegram(args.telegram_chat, args.env_file)
            if not token or not chat:
                print("asca github-check: telegram: missing bot token or chat id", file=sys.stderr)
                return 2
            text = (f"<b>{escape(headline)}</b> ({escape(args.host_label)})\n" + "\n".join(
                f"{escape(r['verdict'])} <code>{escape(r['repo'])}</code>: "
                + escape("; ".join(f.title.split(': ', 1)[-1] for f in r["findings"][:2])) for r in bad[:10]))
            sent, desc = report.send_telegram(text[:4000], token=token, chat_id=chat)
            if not sent:
                print(f"asca github-check: telegram: {desc}", file=sys.stderr)
                return 2
        state.parent.mkdir(parents=True, exist_ok=True)
        tmp = state.with_suffix(".tmp")
        tmp.write_text(json.dumps({"key": key, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}))
        os.chmod(tmp, 0o600)
        tmp.replace(state)
    return 1 if bad else 0
