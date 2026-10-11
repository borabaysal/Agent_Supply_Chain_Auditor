"""asca-fleet: "you're N security fixes behind" for every Hermes instance you run.

  asca-fleet check --target apollonia=local:/opt/hermes --target nas=http://nas:9119 \\
                   --telegram change --telegram-chat <id> --env-file ~/.hermes/.env

Exit codes: 0 = every instance current on security fixes, 1 = at least one instance is behind
or unreadable, or the release feed failed, 2 = usage / alert-delivery error.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

from .. import hermes as asca_hermes
from .. import report as asca_report
from . import monitor, releases, targets


def _state_dir() -> Path:
    return Path(os.environ.get("ASCA_FLEET_DIR") or
                Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "asca" / "fleet")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asca-fleet", description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", type=Path, help="state dir (default $ASCA_FLEET_DIR or ~/.local/state/asca/fleet)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check every target against the Hermes release feed")
    c.add_argument("--target", action="append", default=[], metavar="NAME=SPEC",
                   help="local:/opt/hermes | http://host:9119 | docker:<ctr>[:/path] | ssh:<host>[:/path] (repeatable)")
    c.add_argument("--fleet", type=Path, help='JSON file: {"targets":[{"name":..,"spec":..}]}')
    c.add_argument("--repo", default=releases.REPO, help="GitHub repo with Hermes releases")
    c.add_argument("--advisories", type=Path, help="asca advisory file to include (same as `asca --advisories`)")
    c.add_argument("--telegram", choices=("never", "change", "always"), default="never")
    c.add_argument("--telegram-chat")
    c.add_argument("--env-file", type=Path)
    c.add_argument("-o", "--output", type=Path, help="report prefix (default <dir>/fleet-latest)")
    c.add_argument("--format", choices=("text", "json", "none"), default="text")
    c.add_argument("--timeout", type=float, default=15.0)
    return p


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state_dir = args.dir or _state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except OSError:
        pass
    tlist = [targets.parse_target(t) for t in args.target]
    if args.fleet:
        tlist += targets.load_fleet(args.fleet)
    if not tlist:
        default = os.environ.get("HERMES_INSTALL_DIR") or "/opt/hermes"
        tlist = [targets.Target(name=socket.gethostname(), spec=f"local:{default}")]
    if len({t.name for t in tlist}) != len(tlist):
        print("asca-fleet: target names must be unique", file=sys.stderr)
        return 2

    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        rels, feed_error = releases.fetch(args.repo, token=gh_token, timeout=args.timeout), None
    except Exception as exc:
        rels, feed_error = [], f"{type(exc).__name__}: {exc}"[:200]
    advs = list(asca_hermes.HERMES_ADVISORIES)
    if args.advisories:
        try:
            advs += asca_hermes.load_advisories(args.advisories)
        except (OSError, ValueError, KeyError) as exc:
            print(f"asca-fleet: bad advisory file: {exc}", file=sys.stderr)
            return 2
    obs = [targets.observe(t, timeout=args.timeout) for t in tlist]
    status = monitor.evaluate(obs, rels, advisories=advs, feed_error=feed_error)

    out = args.output or state_dir / "fleet-latest"
    for suffix, text in ((".md", monitor.to_markdown(status)), (".json", json.dumps(status.to_dict(), indent=1))):
        fd = os.open(out.with_suffix(suffix), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    state_path = state_dir / "state.json"
    prev = monitor.load_state(state_path)
    what = monitor.changes(prev, status)

    if args.format == "text":
        print(monitor.to_markdown(status))
        if what:
            print("Changed: " + "; ".join(what))
    elif args.format == "json":
        print(json.dumps({**status.to_dict(), "changed": what}, indent=1))

    send = args.telegram == "always" or (args.telegram == "change" and bool(what) and
                                         (what != ["first run"] or not status.ok))
    rc = 0 if status.ok else 1
    if send:
        token, chat = asca_report.resolve_telegram(args.telegram_chat, args.env_file)
        if not token or not chat:
            print("asca-fleet: telegram: missing bot token or chat id", file=sys.stderr)
            return 2
        ok, desc = asca_report.send_telegram(
            monitor.to_telegram(status, what_changed=what, report_path=str(out.with_suffix(".md").resolve())),
            token=token, chat_id=chat)
        print(f"asca-fleet: telegram: {desc}", file=sys.stderr)
        if not ok:
            return 2   # don't save state: retry the alert next run
    monitor.save_state(state_path, status)
    return rc


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
