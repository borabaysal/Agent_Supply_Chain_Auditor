"""asca inventory: what IDE extensions, MCP servers, agent plugins and skills are installed, and what changed.

  asca inventory                       inventory + diff against the last run (first run learns silently)
  asca inventory --telegram change     alert when something new, swapped or tampered shows up
  asca inventory --write-approved F    add every current publisher to F's approved_publishers

Exit codes: 0 = nothing at or above --fail-on, 1 = something is (e.g. tamper, publisher swap,
known-bad build), 2 = usage, parse or alert-delivery error.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import socket
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__, report
from ..model import Finding, Severity
from . import collect, diff
from .hashing import MiB, Budget, Limits

STATE_VERSION = 1
TITLE = "IDE & agent inventory"


def _state_dir() -> Path:
    return Path(os.environ.get("ASCA_INVENTORY_DIR") or
                Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "asca" / "inventory")


def _default_home() -> Path | None:
    from ..cli import _default_home as d
    return d()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asca inventory", description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", type=Path, help="state dir (default $ASCA_INVENTORY_DIR or ~/.local/state/asca/inventory)")
    p.add_argument("--home", type=Path, default=Path.home(), help="home dir to discover IDEs/agents in")
    p.add_argument("--hermes-home", type=Path, help="Hermes data dir (default $HERMES_HOME or ~/.hermes)")
    p.add_argument("--no-hermes", action="store_true")
    p.add_argument("--no-skills", action="store_true", help="don't inventory agent skills")
    p.add_argument("--ide-dir", action="append", default=[], metavar="LABEL=PATH",
                   help="extra extensions folder, e.g. trae=~/.trae/extensions (repeatable)")
    p.add_argument("--mcp-config", type=Path, action="append", default=[], metavar="FILE")
    p.add_argument("--item-cap-mb", type=int, default=64, help="max MiB hashed per item (default 64)")
    p.add_argument("--node-modules-cap-mb", type=int, default=16, help="max MiB of node_modules per item (default 16)")
    p.add_argument("--total-mb", type=int, default=1024, help="max MiB hashed per run (default 1024)")
    p.add_argument("--baseline", type=Path, help='JSON: {"suppress": [...], "approved_publishers": [...]}')
    p.add_argument("--write-approved", type=Path, metavar="FILE",
                   help="merge every current publisher into FILE's approved_publishers, then exit")
    p.add_argument("--known-bad", type=Path, metavar="FILE", help='extra known-bad builds: [{"kind","id","versions"}]')
    p.add_argument("--fail-on", default="high")
    p.add_argument("--alert-on", default="medium", help="lowest severity that triggers a `change` alert")
    p.add_argument("-o", "--output", type=Path, help="report prefix (default <dir>/inventory-latest)")
    p.add_argument("--format", choices=("text", "json", "none"), default="text")
    p.add_argument("--telegram", choices=("never", "fail", "always", "change"), default="never")
    p.add_argument("--telegram-chat")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--host-label", default=socket.gethostname())
    return p


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _load_baseline(path: Path | None) -> tuple[dict, set[str]]:
    if not path:
        return {}, set()
    data = json.loads(path.read_text(encoding="utf-8"))
    sup = {i["fingerprint"]: i.get("reason", "accepted") for i in data.get("suppress", [])
           if isinstance(i, dict) and i.get("fingerprint")}
    return sup, {str(a) for a in data.get("approved_publishers", [])}


def to_markdown(items, findings, *, first_run: bool, generated: str, host: str, errors) -> str:
    kinds = Counter(i.kind for i in items)
    out = [f"# {TITLE} ({host})", "", f"Generated {generated} · {len(items)} items: "
           + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())), ""]
    if first_run:
        out += ["_First run: this inventory is now the baseline. Changes are reported from the next run._", ""]
    active = [f for f in findings if not f.suppressed]
    loud = [f for f in active if f.severity >= Severity.LOW]
    digest = [f for f in active if f.severity == Severity.INFO]
    if loud:
        out += ["## Changes and findings", "", "| severity | rule | what |", "|---|---|---|"]
        for f in sorted(loud, key=lambda f: (-int(f.severity), f.rule, f.title)):
            out.append(f"| {report.ICON[f.severity.name.lower()]} {f.severity.name.lower()} | {f.rule} | "
                       f"{f.title.replace('|', '/')} |")
        out.append("")
        for f in sorted(loud, key=lambda f: (-int(f.severity), f.rule, f.title)):
            out += [f"### {f.title}", "", f"- where: `{f.location}`"]
            if f.detail:
                out.append(f"- why: {f.detail}")
            if f.remediation:
                out.append(f"- fix: {f.remediation}")
            out.append("")
    if digest:
        out += ["## Digest (no alert)", ""] + [f"- {f.title}" for f in sorted(digest, key=lambda f: f.title)] + [""]
    if errors:
        out += ["## Sources that couldn't be read", ""] + [f"- `{l}`: {m}" for l, m in errors] + [""]
    if not loud and not digest and not first_run:
        out += ["No changes since the last run. ✅", ""]
    sup = [f for f in findings if f.suppressed]
    if sup:
        out += ["## Suppressed", ""] + [f"- `{f.fingerprint}` {f.title} ({f.suppress_reason})" for f in sup] + [""]
    return "\n".join(out)


def to_telegram(findings, *, host: str, alert_on: Severity, items: int, report_path: str, max_items: int = 8) -> str:
    e = html.escape
    loud = sorted([f for f in findings if not f.suppressed and f.severity >= alert_on],
                  key=lambda f: (-int(f.severity), f.title))
    digest = Counter(f.rule.split(".", 1)[1] for f in findings if not f.suppressed and f.severity == Severity.INFO)
    worst = loud[0].severity.name.lower() if loud else "info"
    parts = [f"🧩 <b>{TITLE}</b>: {len(loud)} change{'s' if len(loud) != 1 else ''} to review",
             f"Host: <code>{e(host)}</code> · {items} items · worst: {report.ICON[worst]} {worst}", ""]
    for f in loud[:max_items]:
        parts.append(f"{report.ICON[f.severity.name.lower()]} {e(f.title)}")
    if len(loud) > max_items:
        parts.append(f"…and {len(loud) - max_items} more")
    if digest:
        parts += ["", "Digest: " + ", ".join(f"{n} {k.replace('-', ' ')}" for k, n in sorted(digest.items()))]
    parts += ["", f"Report: <code>{e(report_path)}</code>"]
    text = "\n".join(parts)
    return text if len(text) <= 4096 else text[:4076] + "\n…(truncated)"


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fail_on, alert_on = Severity.parse(args.fail_on), Severity.parse(args.alert_on)
        suppress, approved = _load_baseline(args.baseline)
        known_bad = diff.load_known_bad(args.known_bad)
        ide_dirs = []
        for spec in args.ide_dir:
            label, sep, path = spec.partition("=")
            if not sep:
                raise ValueError(f"--ide-dir needs LABEL=PATH, got {spec!r}")
            ide_dirs.append((label, Path(path).expanduser()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"asca inventory: {exc}", file=sys.stderr)
        return 2
    state = args.dir or _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state, 0o700)
    except OSError:
        pass
    hermes_home = None if args.no_hermes else (args.hermes_home or _default_home())
    limits = Limits(item_cap=args.item_cap_mb * MiB, node_modules_cap=args.node_modules_cap_mb * MiB,
                    total=args.total_mb * MiB)
    col = collect.collect(args.home, hermes_home, Budget(limits), mcp_configs=args.mcp_config,
                          ide_dirs=ide_dirs, include_skills=not args.no_skills)

    if args.write_approved:
        try:
            data = json.loads(args.write_approved.read_text(encoding="utf-8")) if args.write_approved.exists() else {}
        except (OSError, ValueError) as exc:
            print(f"asca inventory: {exc}", file=sys.stderr)
            return 2
        pubs = set(data.get("approved_publishers", [])) | {i.publisher for i in col.items
                                                           if i.publisher not in ("", "local", "builtin")}
        data["approved_publishers"] = sorted(pubs)
        _write_private(args.write_approved, json.dumps(data, indent=2) + "\n")
        print(f"asca inventory: {len(pubs)} approved publishers in {args.write_approved}")
        return 0

    state_file = state / "state.json"
    prev_state = {}
    if state_file.exists():
        try:
            prev_state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"asca inventory: corrupt state {state_file}: {exc}. Move it aside to re-learn.", file=sys.stderr)
            return 2
    first_run = not prev_state
    prev_items = prev_state.get("items", {})
    same_limits = prev_state.get("limits") == limits.to_dict()

    findings: list[Finding] = diff.state_findings(col.items, known_bad)
    if not first_run:
        findings += diff.diff(prev_items, col.items, approved=approved, same_limits=same_limits)
    for loc, msg in col.errors:
        findings.append(Finding(rule="scanner.parse-error", category="scanner", severity=Severity.HIGH,
                                title=f"Couldn't read {Path(loc).name}", location=loc, subject=loc, detail=msg,
                                remediation="Fix or move the file; until then items it lists aren't tracked."))
    for f in findings:
        if f.fingerprint in suppress:
            f.suppressed, f.suppress_reason = True, suppress[f.fingerprint]
    active = [f for f in findings if not f.suppressed]
    failed = any(f.severity >= fail_on for f in active)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out = args.output or state / "inventory-latest"
    md_path, json_path = out.with_suffix(".md"), out.with_suffix(".json")
    md = to_markdown(col.items, findings, first_run=first_run, generated=generated, host=args.host_label,
                     errors=col.errors)
    payload = {"tool": "asca-inventory", "version": __version__, "generated_at": generated,
               "result": "FAIL" if failed else "PASS", "first_run": first_run, "sources": col.sources,
               "counts": dict(Counter(i.kind for i in col.items)),
               "findings": [f.to_dict() for f in findings], "items": [i.to_dict() for i in col.items]}
    _write_private(md_path, md)
    _write_private(json_path, json.dumps(payload, indent=1, ensure_ascii=False) + "\n")

    if args.format == "text":
        loud = [f for f in active if f.severity >= Severity.LOW]
        print(f"asca inventory: {'FAIL' if failed else 'PASS'} · {len(col.items)} items"
              + (" · first run, baseline learned" if first_run else f" · {len(active)} changes/findings"))
        for f in sorted(loud, key=lambda f: -int(f.severity))[:20]:
            print(f"  [{f.severity.name}] {f.title}")
        print(f"  report: {md_path}")
    elif args.format == "json":
        print(json.dumps(payload, indent=1, ensure_ascii=False))

    prev_alerted = set(prev_state.get("alerted", []))
    alertable = {f.fingerprint for f in active if f.severity >= alert_on}
    mode = args.telegram
    send = (mode == "always" or (mode == "fail" and failed)
            or (mode == "change" and bool(alertable - prev_alerted)))
    if send:
        token, chat = report.resolve_telegram(args.telegram_chat, args.env_file)
        if not token or not chat:
            print("asca inventory: telegram: missing bot token or chat id", file=sys.stderr)
            return 2
        ok, desc = report.send_telegram(to_telegram(findings, host=args.host_label, alert_on=alert_on,
                                                    items=len(col.items), report_path=str(md_path.resolve())),
                                        token=token, chat_id=chat)
        print(f"asca inventory: telegram: {desc}", file=sys.stderr)
        if not ok:
            return 2   # state not saved: the same changes alert again next run
    new_state = {"version": STATE_VERSION, "generated_at": generated, "limits": limits.to_dict(),
                 "items": {i.key: i.to_dict() for i in col.items},
                 # keep known-bad / persistent findings from re-alerting every day in `change` mode
                 "alerted": sorted(alertable)}
    _write_private(state_file, json.dumps(new_state, indent=1, ensure_ascii=False) + "\n")
    return 1 if failed else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
