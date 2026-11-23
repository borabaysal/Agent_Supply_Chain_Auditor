"""asca — Agent Supply-Chain Auditor CLI.

Exit codes: 0 = PASS, 1 = FAIL (findings at/above --fail-on), 2 = usage/scanner error.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import (__version__, advisories, agentcfg, agentvers, pluginpins, tcc, allowlist, ciagent, discover, dockerd, ghtoken, hermes, installhooks,
               mcp, persona, pystartup, repohooks, report, respond, secrets, sessions, stray, symlinks, wfsecrets)
from .model import Finding, Report, Severity
from . import fsutil
from . import devcreds, mcpvers, userhooks


def _default_home() -> Path | None:
    for cand in (os.environ.get("HERMES_HOME"), str(Path.home() / ".hermes")):
        if cand and Path(cand).expanduser().is_dir():
            return Path(cand).expanduser()
    return None


def _default_install() -> Path | None:
    for cand in (os.environ.get("HERMES_INSTALL_DIR"), "/opt/hermes", str(Path.home() / ".hermes" / "hermes-agent")):
        if cand and (Path(cand) / "hermes_cli").is_dir():
            return Path(cand)
    try:  # an importable hermes_cli (pipx/venv install)
        import importlib.util
        spec = importlib.util.find_spec("hermes_cli")
        if spec and spec.origin:
            return Path(spec.origin).parent.parent
    except (ImportError, ValueError):
        pass
    return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asca", description="Audit a self-hosted agent (Hermes / MCP clients) for supply-chain risk: "
                                 "unpinned skills & MCP servers, command-executing git config (GitSpawn / "
                                 "core.fsmonitor), and exposed keys.")
    p.add_argument("--hermes-home", type=Path, help="Hermes data dir (default: $HERMES_HOME or ~/.hermes)")
    p.add_argument("--hermes-install", type=Path, help="Hermes source/install dir, for version advisories")
    p.add_argument("--no-hermes", action="store_true", help="skip Hermes checks")
    p.add_argument("--repos", type=Path, action="append", default=[], metavar="DIR",
                   help="scan git repos under DIR (repeatable; searches 4 levels deep)")
    p.add_argument("--mcp-config", type=Path, action="append", default=[], metavar="FILE",
                   help="extra MCP client config JSON (repeatable)")
    p.add_argument("--no-client-configs", action="store_true",
                   help="don't auto-discover ~/.claude.json, Cursor, Claude Desktop, Windsurf configs")
    p.add_argument("--no-global-git", action="store_true", help="skip ~/.gitconfig and /etc/gitconfig")
    p.add_argument("--no-agent-allowlist", action="store_true",
                   help="skip secret scanning of agent allow rules (Claude Code permissions, VS Code auto-approve) and "
                        "the committed .claude/settings.local.json check")
    p.add_argument("--no-plugin-pins", action="store_true",
                   help="skip Plugin4Shell checks: plugin checkouts with commit-hash-named branches or off their pin")
    p.add_argument("--no-tcc", action="store_true",
                   help="skip macOS Full Disk Access / Accessibility grants for terminals, IDEs and agents")
    p.add_argument("--no-agent-versions", action="store_true",
                   help="skip known-vulnerability checks for installed Claude Code, Codex, Gemini CLI, goose and "
                        "Claude Desktop (versions are read from files, nothing is run)")
    p.add_argument("--no-install-hooks", action="store_true",
                   help="skip risky npm install hooks and secret-dumping workflow steps in repos (wfx)")
    p.add_argument("--no-symlinks", action="store_true",
                   help="skip listing symlinks that lead out of repos and the agent home")
    p.add_argument("--no-docker-daemon", action="store_true",
                   help="skip checking whether the Docker API is exposed over TCP without client certificates")
    p.add_argument("--no-persona", action="store_true",
                   help="skip checking Hermes SOUL.md / memories and gateway access settings for tampering")
    p.add_argument("--known-archived", type=Path, metavar="FILE",
                   help="extra MCP server packages to treat as archived/unmaintained (one per line)")
    p.add_argument("--no-ci-agents", action="store_true",
                   help="skip checking .github/workflows for coding agents that anyone can trigger")
    p.add_argument("--no-repo-hooks", action="store_true",
                   help="skip repo-supplied agent hooks (.claude/settings.json, .cursor/hooks.json, folder-open tasks)")
    p.add_argument("--github-token-scopes", action="store_true",
                   help="ONLINE: look up the scopes of GitHub tokens found locally (one HTTPS request per token, "
                        "sent only to that token's own GitHub host)")
    p.add_argument("--no-dev-credentials", action="store_true",
                   help="skip developer credential files (.npmrc, .pypirc, pip.conf, .netrc, Docker, Azure CLI, "
                        "Hugging Face, .git-credentials)")
    p.add_argument("--no-user-hooks", action="store_true",
                   help="skip hooks/statusLine in user-level and managed agent settings (Claude Code, Cursor, Gemini)")
    p.add_argument("--no-agent-config", action="store_true",
                   help="skip agent config tamper checks (Codex sandbox, endpoint overrides, approvals, telemetry)")
    p.add_argument("--claude-settings", type=Path, action="append", default=[], metavar="FILE",
                   help="extra Claude Code settings.json to check (repeatable)")
    p.add_argument("--no-python-startup", action="store_true",
                   help="skip Python startup-hook checks (.pth, sitecustomize) in agent/system environments")
    p.add_argument("--python-site", type=Path, action="append", default=[], metavar="DIR",
                   help="extra site-packages dir to check for startup hooks (repeatable)")
    p.add_argument("--no-session-history", action="store_true",
                   help="don't scan agent session/transcript history (Hermes sessions + cron output, Claude Code, "
                        "Codex, Cursor) for saved secrets")
    p.add_argument("--session-budget-mb", type=int, default=sessions.DEFAULT_BUDGET // sessions.MiB, metavar="MB",
                   help="max MiB of history read per run, newest files first (default: %(default)s)")
    p.add_argument("--session-file-cap-mb", type=int, default=sessions.DEFAULT_FILE_CAP // sessions.MiB,
                   metavar="MB", help="max MiB read from any one history file (default: %(default)s)")
    p.add_argument("--session-max-files", type=int, default=sessions.DEFAULT_MAX_FILES, metavar="N",
                   help="max history files read per run (default: %(default)s)")
    p.add_argument("--no-stray-instructions", action="store_true",
                   help="don't look for AGENTS.md / CLAUDE.md / .cursorrules … in ~/Downloads, ~/Desktop and temp")
    p.add_argument("--instructions-dir", type=Path, action="append", default=[], metavar="DIR",
                   help="extra folder to check for stray agent instruction files (repeatable)")
    p.add_argument("--advisories", type=Path, metavar="FILE",
                   help="extra Hermes version advisories (JSON list; see README)")
    p.add_argument("--online-advisories", action="store_true",
                   help="also query OSV.dev and the GitHub Advisory Database for the detected Hermes version "
                        "(sends package name + version to those services)")
    p.add_argument("--fail-on", default="high", help="minimum severity that fails the audit (default: high)")
    p.add_argument("--baseline", type=Path, help="JSON file of accepted fingerprints to suppress")
    p.add_argument("--write-baseline", type=Path, metavar="FILE",
                   help="write all current findings to FILE as a baseline, then exit 0")
    p.add_argument("-o", "--output", type=Path, default=Path("asca-report"),
                   help="output path prefix; writes PREFIX.md and PREFIX.json (default: ./asca-report)")
    p.add_argument("--format", choices=("text", "json", "none"), default="text", help="stdout format")
    p.add_argument("--telegram", choices=("never", "fail", "always", "change"), default="never",
                   help="send a Telegram alert: never | fail (only on FAIL) | always | change (when result or "
                        "failing set differs from the previous run)")
    p.add_argument("--telegram-chat", help="chat id (default: $ASCA_TELEGRAM_CHAT_ID / $TELEGRAM_CHAT_ID / "
                                           "$TELEGRAM_HOME_CHANNEL)")
    p.add_argument("--env-file", type=Path, help="read TELEGRAM_* settings from a dotenv file")
    p.add_argument("--host-label", default=socket.gethostname(), help="name shown in alerts")
    p.add_argument("--version", action="version", version=f"asca {__version__}")
    return p


def apply_baseline(findings: list[Finding], path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    accepted = {}
    for item in data.get("suppress", []):
        if isinstance(item, dict) and item.get("fingerprint"):
            accepted[item["fingerprint"]] = item.get("reason", "accepted")
    for f in findings:
        if f.fingerprint in accepted:
            f.suppressed, f.suppress_reason = True, accepted[f.fingerprint]


def run(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["dashboard"]:   # `asca dashboard …`: static HTML status page from the reports
        from .dashboard import run as dashboard_run
        return dashboard_run(argv[1:])
    if argv[:1] == ["export"]:   # `asca export intune`: last report as an Intune custom-compliance result
        from . import intune
        return intune.main(argv[1:])
    if argv[:1] == ["spend"]:   # `asca spend`: tripwire for stolen AI keys (online, read-only)
        from . import spend
        return spend.run(argv[1:])
    if argv[:1] == ["github-check"]:   # `asca github-check`: wfx traces in your GitHub repos (online, read-only)
        from . import ghcheck
        return ghcheck.run(argv[1:])
    if argv[:1] == ["check-repo"]:   # `asca check-repo PATH`: is a downloaded repo safe to open?
        from .checkrepo import run as checkrepo_run
        return checkrepo_run(argv[1:])
    if argv[:1] == ["inventory"]:   # `asca inventory …`: IDE/agent inventory + drift (own options)
        from .inventory.cli import run as inventory_run
        return inventory_run(argv[1:])
    args = build_parser().parse_args(argv)
    mcpvers.LAUNCHES.clear()                  # pinned MCP launches seen in this run (online lookup)
    try:
        fail_on = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"asca: {exc}", file=sys.stderr)
        return 2

    stats: dict = {}
    findings: list[Finding] = []
    targets: dict = {}
    if args.known_archived:
        try:
            mcp.EXTRA_ARCHIVED |= mcp.load_known_archived(args.known_archived)
        except OSError as exc:
            print(f"asca: cannot read --known-archived: {exc}", file=sys.stderr)
            return 2

    home = None if args.no_hermes else (args.hermes_home or _default_home())
    if home is not None:
        if not home.is_dir():
            print(f"asca: hermes home {home} not found", file=sys.stderr)
            return 2
        install = args.hermes_install or _default_install()
        targets["hermes_home"] = str(home)
        targets["hermes_install"] = str(install) if install else ""
        extra = []
        if args.advisories:
            try:
                extra = hermes.load_advisories(args.advisories)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                print(f"asca: cannot read advisories: {exc}", file=sys.stderr)
                return 2
        findings += hermes.audit(home, install, stats, extra)
        version = stats.get("hermes_version")
        if args.online_advisories and version and version != "unknown":
            known = {a[0] for a in [*hermes.HERMES_ADVISORIES, *extra]}
            result = advisories.fetch("hermes-agent", version)
            stats["online_advisories"] = len(result.advisories)
            findings += advisories.feed_findings(result, package="hermes-agent", version=version, known_ids=known,
                                                 location="osv.dev+github-advisories")
        if not args.no_persona:
            from .skillscan import official as _official
            off = _official.load(hermes_home=home)
            for path, label in persona.targets(home):
                findings += persona.audit_file(path, label, off)
            findings += persona.audit_env(home)
        if not args.no_symlinks:
            findings += symlinks.audit_tree(home, label="agent workspace", stats=stats,
                                            skip=symlinks.AGENT_HOME_SKIP)
        findings += advisories.freshness_findings(
            local_reviewed=hermes.advisories_reviewed_at(args.advisories) if args.advisories else None,
            local_path=str(args.advisories) if args.advisories else None)

    if not args.no_agent_versions:
        findings += agentvers.audit(stats, use_online=args.online_advisories)
    if not args.no_plugin_pins:
        findings += pluginpins.audit(pluginpins.default_roots(Path.home(), home), stats)
    if not args.no_tcc:
        findings += tcc.audit(stats)

    client_cfgs = list(args.mcp_config)
    if not args.no_client_configs:
        client_cfgs += [p for p in discover.default_client_configs(Path.home()) if p not in client_cfgs]
    targets["mcp_client_configs"] = [str(p) for p in client_cfgs]
    findings += discover.audit_client_configs(client_cfgs, stats)

    repos = discover.find_repos(args.repos)
    targets["repo_roots"] = [str(p) for p in args.repos]
    stats["git_repos"] = len(repos)
    for r in repos:
        findings += discover.audit_repo(r)
        if not args.no_repo_hooks:
            findings += repohooks.audit_repo(r, discover.resolve_git_dir(r))
        if not args.no_ci_agents:
            findings += ciagent.audit_repo(r, discover.resolve_git_dir(r), stats)
        if not args.no_agent_allowlist:
            findings += allowlist.audit_repo(r, discover.resolve_git_dir(r), stats)
        if not args.no_symlinks:
            findings += symlinks.audit_tree(r, git_dir=discover.resolve_git_dir(r), stats=stats)
        if not args.no_install_hooks:   # only risky hooks here: your own repos' husky hooks are expected
            findings += installhooks.audit(r, git_dir=discover.resolve_git_dir(r), risky_only=True)
            findings += wfsecrets.audit_repo(r, discover.resolve_git_dir(r))

    if not args.no_session_history:
        if min(args.session_budget_mb, args.session_file_cap_mb, args.session_max_files) < 1:
            print("asca: session budgets must be >= 1", file=sys.stderr)
            return 2
        roots = sessions.default_roots(Path.home(), home)
        targets["session_history"] = [str(r.path) for r in roots if r.path.exists()]
        findings += sessions.audit(roots, stats, sessions.Budget(
            total_bytes=args.session_budget_mb * sessions.MiB, file_bytes=args.session_file_cap_mb * sessions.MiB,
            max_files=args.session_max_files))

    if not args.no_stray_instructions or args.instructions_dir:
        dirs = [] if args.no_stray_instructions else stray.default_dirs(Path.home())
        dirs += [d for d in args.instructions_dir if d not in dirs]
        targets["instruction_dirs"] = [str(d) for d in dirs]
        findings += stray.audit(dirs, stats)

    if not args.no_agent_allowlist:
        findings += allowlist.audit_home(Path.home(), stats)

    if args.github_token_scopes:
        tokens = ghtoken.discover(Path.home(), home)
        targets["github_token_sources"] = sorted({s for t in tokens for s in t.sources})
        findings += ghtoken.audit(tokens, stats)

    if not args.no_agent_config:
        findings += agentcfg.audit(Path.home(), home, stats, extra_claude=args.claude_settings)

    if not args.no_user_hooks:
        findings += userhooks.audit(Path.home(), stats)

    if not args.no_python_startup:
        sites = pystartup.discover(Path.home(), hermes_install=args.hermes_install or _default_install(),
                                   repo_roots=list(args.repos), extra=list(args.python_site))
        targets["python_sites"] = [str(s.path) for s in sites]
        findings += pystartup.audit(sites, stats)

    if not args.no_docker_daemon:
        findings += dockerd.audit(home=Path.home(), stats=stats)

    if not args.no_dev_credentials:
        findings += devcreds.audit(Path.home(), stats)

    # cloud credential files hold keys by design: check who can read them, not what's in them
    findings += secrets.audit_permissions(Path.home() / ".aws" / "credentials", label="~/.aws/credentials")

    if not args.no_global_git:
        targets["global_git_configs"] = [str(p) for p in discover.global_git_configs()]
        findings += discover.audit_global_git()

    if args.online_advisories and mcpvers.LAUNCHES:
        more, errs = mcpvers.online()
        stats["mcp_online_advisories"] = len(more)
        findings += more
        if errs:
            findings.append(Finding(
                rule="scanner.feed-unavailable", category="scanner", severity=Severity.LOW,
                title="Some MCP server advisory lookups failed", location="osv.dev+github-advisories",
                subject="mcp-online", detail="; ".join(sorted(set(errs)))[:400] + ". The bundled table was still used.",
                remediation="Retry later; set ASCA_GITHUB_TOKEN to raise GitHub's rate limit."))

    # dedupe (the same file can be reached via two roots)
    uniq: dict[str, Finding] = {}
    for f in findings:
        uniq.setdefault(f.fingerprint, f)
    findings = list(uniq.values())
    if not secrets.permissions_checked():     # Windows: say so instead of silently skipping (fail closed)
        findings.append(secrets.permissions_note())
    respond.enrich(findings, Path.home())     # provider-specific steps + AWS blast-radius card (text only)

    if args.write_baseline:
        args.write_baseline.write_text(json.dumps({"suppress": [
            {"fingerprint": f.fingerprint, "rule": f.rule, "title": f.title, "reason": "accepted at baseline"}
            for f in sorted(findings, key=lambda x: x.fingerprint)]}, indent=2) + "\n", encoding="utf-8")
        print(f"asca: wrote {len(findings)} fingerprints to {args.write_baseline}")
        return 0
    if args.baseline:
        try:
            apply_baseline(findings, args.baseline)
        except (OSError, ValueError) as exc:
            print(f"asca: cannot read baseline: {exc}", file=sys.stderr)
            return 2

    rep = Report(targets=targets, findings=findings, stats=stats, fail_on=fail_on,
                 generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), version=__version__)

    md_path = args.output.with_suffix(".md") if args.output.suffix != ".md" else args.output
    json_path = md_path.with_suffix(".json")
    prev = _previous_state(json_path)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(report.to_markdown(rep), encoding="utf-8")
    json_path.write_text(report.to_json(rep), encoding="utf-8")
    for p in (md_path, json_path):  # reports describe your weak spots: keep them private
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    if args.format == "json":
        sys.stdout.write(report.to_json(rep))
    elif args.format == "text":
        _print_summary(rep, md_path, json_path)

    alert_rc = _maybe_alert(args, rep, md_path, prev)
    if alert_rc:
        return alert_rc
    return 0 if rep.passed else 1


def _previous_state(json_path: Path) -> tuple[str, frozenset] | None:
    try:
        d = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    sev = Severity.parse(d.get("fail_on", "high"))
    failing = frozenset(f["fingerprint"] for f in d.get("findings", [])
                        if not f.get("suppressed") and Severity.parse(f["severity"]) >= sev)
    return d.get("result", ""), failing


def _maybe_alert(args, rep: Report, md_path: Path, prev) -> int:
    mode = args.telegram
    if mode == "never" or (mode == "fail" and rep.passed):
        return 0
    if mode == "change":
        now = ("PASS" if rep.passed else "FAIL", frozenset(f.fingerprint for f in rep.failing))
        if prev == now:
            print("asca: telegram: result unchanged since last run; no alert")
            return 0
    token, chat = report.resolve_telegram(args.telegram_chat, args.env_file)
    if not token or not chat:
        print("asca: telegram: missing bot token or chat id (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, or use "
              "--env-file / --telegram-chat)", file=sys.stderr)
        return 2
    text = report.telegram_text(rep, host=args.host_label, report_path=str(md_path.resolve()))
    ok, desc = report.send_telegram(text, token=token, chat_id=chat)
    print(f"asca: telegram: {desc}", file=sys.stderr if not ok else sys.stdout)
    return 0 if ok else 2


def _print_summary(rep: Report, md: Path, js: Path) -> None:
    c = rep.counts()
    print(f"asca {rep.version}: {'PASS' if rep.passed else 'FAIL'} (fail-on {rep.fail_on.name.lower()})")
    print("  " + "  ".join(f"{k}={v}" for k, v in c.items()))
    for f in rep.failing[:15]:
        print(f"  [{f.severity.name}] {f.title}\n      {f.location}")
    if len(rep.failing) > 15:
        print(f"  … {len(rep.failing) - 15} more")
    print(f"  report: {md}  ({js})")


def main() -> None:
    fsutil.utf8_stdio()
    sys.exit(run())


if __name__ == "__main__":
    main()
