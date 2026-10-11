"""asca-egress: log every outbound destination your agents use and get a daily diff.

  asca-egress proxy    run the logging proxy (foreground; use your supervisor to keep it up)
  asca-egress env      print the shell exports that route a process through the proxy
  asca-egress summary  diff the log against the baseline, write a report, optionally alert
  asca-egress show     print raw log records (filters: --agent, --host, --since)

Exit codes for `summary`: 0 = no changes, 1 = changes (new destinations / bypass / proxy down),
2 = usage or alert-delivery error.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

from .. import report as asca_report
from . import log as elog
from . import summary as esum


def _state_dir() -> Path:
    return Path(os.environ.get("ASCA_EGRESS_DIR") or
                Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "asca" / "egress")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asca-egress", description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", type=Path, default=None, help="state dir (default: $ASCA_EGRESS_DIR or "
                                                          "~/.local/state/asca/egress)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("proxy", help="run the logging forward proxy")
    pr.add_argument("--host", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    pr.add_argument("--port", type=int, default=8899)
    pr.add_argument("--allow", action="append", metavar="CIDR",
                    help="client networks allowed to use the proxy (default loopback only; repeatable)")
    pr.add_argument("--hermes-home", type=Path, default=None,
                    help="Hermes home for cron-job correlation (default $HERMES_HOME if set)")
    pr.add_argument("--sample-direct", type=float, default=30.0, metavar="SECONDS",
                    help="poll for direct (proxy-bypassing) connections every N seconds; 0 disables (default 30)")
    pr.add_argument("--sampler-ignore", action="append", metavar="NAME", default=[],
                    help="don't report direct connections from processes whose command contains NAME, "
                         "e.g. tailscaled (repeatable)")
    pr.add_argument("--keep-days", type=int, default=30, help="delete day logs older than this (default 30)")

    env = sub.add_parser("env", help="print proxy environment exports")
    env.add_argument("--port", type=int, default=8899)
    env.add_argument("--label", help="also set ASCA_EGRESS_LABEL so this process is named in reports")

    sm = sub.add_parser("summary", help="diff the log vs the baseline and report")
    sm.add_argument("--since-hours", type=float, help="window size (default: since the last summary run)")
    sm.add_argument("--no-learn", action="store_true", help="don't add this window to the baseline")
    sm.add_argument("-o", "--output", type=Path, help="report path prefix (default: <dir>/summary-latest)")
    sm.add_argument("--telegram", choices=("never", "change", "always"), default="never",
                    help="change = alert only when there are differences or the proxy looks dead")
    sm.add_argument("--telegram-chat")
    sm.add_argument("--env-file", type=Path)
    sm.add_argument("--host-label", default=socket.gethostname())
    sm.add_argument("--format", choices=("text", "json", "none"), default="text")

    sh = sub.add_parser("show", help="print log records")
    sh.add_argument("--since-hours", type=float, default=24)
    sh.add_argument("--agent")
    sh.add_argument("--host")
    return p


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state = args.dir or _state_dir()
    logs = state / "logs"
    if args.cmd in ("proxy", "summary"):
        # the baseline and pidfile live here; keep the whole state dir private
        state.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(state, 0o700)
        except OSError:
            pass
    if args.cmd == "proxy":
        from .proxy import run as run_proxy
        if args.host not in ("127.0.0.1", "::1", "localhost") and not args.allow:
            print("asca-egress: refusing to listen on a non-loopback address without --allow CIDR "
                  "(an open proxy is an abuse risk)", file=sys.stderr)
            return 2
        elog.prune(logs, args.keep_days)
        home = args.hermes_home or (Path(os.environ["HERMES_HOME"]) if os.environ.get("HERMES_HOME") else None)
        run_proxy(logs, args.host, args.port, args.allow, home, args.sample_direct, state / "proxy.pid",
                  args.sampler_ignore)
        return 0
    if args.cmd == "env":
        url = f"http://127.0.0.1:{args.port}"
        lines = [f"export HTTPS_PROXY={url} HTTP_PROXY={url} https_proxy={url} http_proxy={url}",
                 "export NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1"]
        if args.label:
            lines.append(f"export ASCA_EGRESS_LABEL={args.label}")
        print("\n".join(lines))
        return 0
    if args.cmd == "show":
        since = time.time() - args.since_hours * 3600
        for r in elog.iter_records(logs, since, time.time()):
            if args.agent and args.agent not in json.dumps(r.get("client", {})):
                continue
            if args.host and args.host not in (r.get("host") or ""):
                continue
            print(json.dumps(r, ensure_ascii=False))
        return 0
    # summary
    state.mkdir(parents=True, exist_ok=True)
    bpath = state / "baseline.json"
    baseline = esum.load_baseline(bpath)
    now = time.time()
    since = now - args.since_hours * 3600 if args.since_hours else None
    diff = esum.compute(logs, baseline, since=since, until=now)
    md = esum.to_markdown(diff, args.host_label)
    out = args.output or state / "summary-latest"
    mdp = out.with_suffix(".md")
    fd = os.open(mdp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(md)
    if not args.no_learn:
        esum.save_baseline(bpath, esum.learn(baseline, logs, diff))
    if args.format == "text":
        print(md)
    elif args.format == "json":
        print(json.dumps({"changes": diff.has_changes, "proxy_alive": diff.proxy_alive, "total": diff.total,
                          "new_domains": sorted(diff.new_domains), "new_hosts": sorted(diff.new_hosts),
                          "direct": sorted(v["dest"] for v in diff.direct.values()),
                          "ip_literals": sorted(diff.ip_literals)}, indent=2))
    send = args.telegram == "always" or (args.telegram == "change" and diff.has_changes and not diff.first_run)
    if args.telegram == "change" and diff.first_run:
        print("asca-egress: first run, baseline learned; no alert", file=sys.stderr)
    if send:
        token, chat = asca_report.resolve_telegram(args.telegram_chat, args.env_file)
        if not token or not chat:
            print("asca-egress: telegram: missing bot token or chat id", file=sys.stderr)
            return 2
        ok, desc = asca_report.send_telegram(esum.to_telegram(diff, args.host_label, str(mdp.resolve())),
                                             token=token, chat_id=chat)
        print(f"asca-egress: telegram: {desc}", file=sys.stderr)
        if not ok:
            return 2
    return 1 if diff.has_changes and not diff.first_run else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
