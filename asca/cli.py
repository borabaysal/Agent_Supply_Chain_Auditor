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

from . import __version__, discover, hermes, report
from .model import Finding, Report, Severity


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
    args = build_parser().parse_args(argv)
    try:
        fail_on = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"asca: {exc}", file=sys.stderr)
        return 2

    stats: dict = {}
    findings: list[Finding] = []
    targets: dict = {}

    home = None if args.no_hermes else (args.hermes_home or _default_home())
    if home is not None:
        if not home.is_dir():
            print(f"asca: hermes home {home} not found", file=sys.stderr)
            return 2
        install = args.hermes_install or _default_install()
        targets["hermes_home"] = str(home)
        targets["hermes_install"] = str(install) if install else ""
        findings += hermes.audit(home, install, stats)

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

    if not args.no_global_git:
        targets["global_git_configs"] = [str(p) for p in discover.global_git_configs()]
        findings += discover.audit_global_git()

    # dedupe (the same file can be reached via two roots)
    uniq: dict[str, Finding] = {}
    for f in findings:
        uniq.setdefault(f.fingerprint, f)
    findings = list(uniq.values())

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
    sys.exit(run())


if __name__ == "__main__":
    main()
