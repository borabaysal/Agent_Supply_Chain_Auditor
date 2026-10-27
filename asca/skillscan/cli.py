"""asca-skills: fake-app & skill scanner.

  asca-skills scan [PATH ...]      scan skill folders (default: Hermes, OpenClaw, Claude, Codex skill dirs)
                                   plus installed plugins, MCP servers and packages for look-alike names
  asca-skills check-name NAME      is NAME official, a look-alike, or unknown? (before you install it)
  asca-skills update-official      refresh the official list from the live Hermes/OpenClaw sources

Exit codes for `scan`: 0 = PASS, 1 = FAIL (findings at or above --fail-on), 2 = usage/alert error.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__, discover, report
from ..cli import _default_home, _default_install, _previous_state, apply_baseline
from ..model import Finding, Report, Severity
from . import apps, official, scan


def _state_dir() -> Path:
    return Path(os.environ.get("ASCA_SKILLS_DIR") or
                Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "asca" / "skills")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asca-skills", description=__doc__.split("\n\n")[0])
    p.add_argument("--hermes-home", type=Path, help="Hermes data dir (default $HERMES_HOME or ~/.hermes)")
    p.add_argument("--hermes-install", type=Path, help="Hermes install dir (adds its catalogs to the official list)")
    p.add_argument("--official", type=Path, help="official-list JSON (default: <state>/official.json if present)")
    p.add_argument("--dir", type=Path, help="state dir (default $ASCA_SKILLS_DIR or ~/.local/state/asca/skills)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan skills and installed apps")
    s.add_argument("paths", nargs="*", type=Path, help="skill folders to scan (default: auto-discover)")
    s.add_argument("--no-apps", action="store_true", help="skip plugin / MCP / package / app name checks")
    s.add_argument("--site-packages", type=Path, action="append", default=[], metavar="DIR",
                   help="extra Python site-packages dir to check for look-alike packages (repeatable)")
    s.add_argument("--fail-on", default="high")
    s.add_argument("--baseline", type=Path, help="JSON file of accepted fingerprints (same format as asca)")
    s.add_argument("--write-baseline", type=Path, metavar="FILE")
    s.add_argument("-o", "--output", type=Path, help="report prefix (default <state>/skills-latest)")
    s.add_argument("--format", choices=("text", "json", "none"), default="text")
    s.add_argument("--telegram", choices=("never", "fail", "always", "change"), default="never")
    s.add_argument("--telegram-chat")
    s.add_argument("--env-file", type=Path)
    s.add_argument("--host-label", default=socket.gethostname())

    c = sub.add_parser("check-name", help="check a name before installing it")
    c.add_argument("names", nargs="+")

    u = sub.add_parser("update-official", help="refresh the official list from live sources")
    u.add_argument("--timeout", type=float, default=180.0)
    return p


def _load_official(args, home: Path | None, install: Path | None, state: Path) -> official.Official:
    refreshed = args.official or (state / "official.json")
    return official.load(hermes_install=install, hermes_home=home, refreshed=refreshed)


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = args.dir or _state_dir()
    home = args.hermes_home or _default_home()
    install = args.hermes_install or _default_install()

    if args.cmd == "update-official":
        state.mkdir(parents=True, exist_ok=True)
        o, errors = official.refresh(timeout=args.timeout,
                                     github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
        for e in errors:
            print(f"asca-skills: {e}", file=sys.stderr)
        if not (o.skills or o.plugins):
            print("asca-skills: nothing fetched; keeping the previous list", file=sys.stderr)
            return 2
        out = args.official or state / "official.json"
        out.write_text(json.dumps(o.to_json(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"asca-skills: wrote {out}: {len(o.skills)} skills, {len(o.plugins)} plugins, "
              f"{len(o.openclaw_extensions)} OpenClaw extensions" + (" (partial)" if errors else ""))
        return 1 if errors else 0

    o = _load_official(args, home, install, state)
    mm = apps.Matchers(o)

    if args.cmd == "check-name":
        rc = 0
        for n in args.names:
            res = apps.check_name(n, mm)
            if not res:
                print(f"{n}: not in the official list and not a look-alike of anything in it (unknown, review "
                      f"its source before installing)")
                continue
            for kind, verdict, detail in res:
                print(f"{n}: {kind}: {verdict}: {detail}")
                if verdict.startswith(("look-alike", "removed")):
                    rc = 1
        return rc

    # ---- scan
    try:
        fail_on = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"asca-skills: {exc}", file=sys.stderr)
        return 2
    if args.paths:
        roots = []
        for p in args.paths:
            if not p.is_dir():
                print(f"asca-skills: {p} is not a directory", file=sys.stderr)
                return 2
            eco = "hermes" if home and p.resolve() == (home / "skills").resolve() else "generic"
            roots.append((p, eco))
    else:
        roots = scan.default_roots(Path.home(), home)
    skills: list[scan.Skill] = []
    for r, eco in roots:
        skills += scan.find_skills(r, eco, home)
    findings: list[Finding] = []
    for sk in skills:
        findings += scan.scan_skill(sk, o, mm.skills)
    stats = {"skills_scanned": len(skills), "skill_roots": len(roots),
             "official_skills": len(o.skills), "official_plugins": len(o.plugins)}
    if not args.no_apps:
        if home:
            findings += apps.check_hermes_plugins(home, mm)
        findings += apps.check_openclaw_extensions(Path.home(), mm)
        cfgs = discover.default_client_configs(Path.home())
        findings += apps.check_mcp_servers(cfgs, (home / "config.yaml") if home else None, mm)
        site = list(args.site_packages)
        if install:
            site += sorted((install / ".venv" / "lib").glob("python3*/site-packages"))
        findings += apps.check_packages(Path.home(), site, mm)
        findings += apps.check_desktop_apps(mm)
    uniq: dict[str, Finding] = {}
    for f in findings:
        uniq.setdefault(f.fingerprint, f)
    findings = list(uniq.values())

    if args.write_baseline:
        args.write_baseline.write_text(json.dumps({"suppress": [
            {"fingerprint": f.fingerprint, "rule": f.rule, "title": f.title, "reason": "accepted at baseline"}
            for f in sorted(findings, key=lambda x: x.fingerprint)]}, indent=2) + "\n", encoding="utf-8")
        print(f"asca-skills: wrote {len(findings)} fingerprints to {args.write_baseline}")
        return 0
    if args.baseline:
        try:
            apply_baseline(findings, args.baseline)
        except (OSError, ValueError) as exc:
            print(f"asca-skills: cannot read baseline: {exc}", file=sys.stderr)
            return 2

    rep = Report(targets={"skill_roots": [str(r) for r, _ in roots], "official_sources": o.sources},
                 findings=findings, stats=stats, fail_on=fail_on, version=__version__,
                 generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    state.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    out = args.output or state / "skills-latest"
    md_path = out.with_suffix(".md")
    json_path = md_path.with_suffix(".json")
    prev = _previous_state(json_path)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    for p, text in ((md_path, report.to_markdown(rep).replace("Agent supply-chain audit", "Skill & fake-app scan", 1)),
                    (json_path, report.to_json(rep))):
        p.write_text(text, encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    if args.format == "json":
        sys.stdout.write(report.to_json(rep))
    elif args.format == "text":
        c = rep.counts()
        print(f"asca-skills: {'PASS' if rep.passed else 'FAIL'} · {len(skills)} skills in {len(roots)} folders · "
              + " ".join(f"{k}={v}" for k, v in c.items()))
        for f in rep.failing[:20]:
            print(f"  [{f.severity.name}] {f.title}\n      {f.location}")
        if len(rep.failing) > 20:
            print(f"  … {len(rep.failing) - 20} more")
        print(f"  report: {md_path}")
    rc = _alert(args, rep, md_path, prev)
    return rc or (0 if rep.passed else 1)


def _alert(args, rep, md_path, prev) -> int:
    mode = args.telegram
    if mode == "never" or (mode == "fail" and rep.passed):
        return 0
    if mode == "change":
        now = ("PASS" if rep.passed else "FAIL", frozenset(f.fingerprint for f in rep.failing))
        if prev == now:
            return 0
    token, chat = report.resolve_telegram(args.telegram_chat, args.env_file)
    if not token or not chat:
        print("asca-skills: telegram: missing bot token or chat id", file=sys.stderr)
        return 2
    ok, desc = report.send_telegram(report.telegram_text(rep, host=args.host_label,
                                                         report_path=str(md_path.resolve()),
                                                         title="Skill & fake-app scan"),
                                    token=token, chat_id=chat)
    print(f"asca-skills: telegram: {desc}", file=sys.stderr)
    return 0 if ok else 2


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
