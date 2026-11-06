#!/bin/bash
# asca job runner for macOS LaunchAgents (also works on Linux). bash 3.2 compatible: no
# associative arrays, no ${var,,}, no mapfile, no &>>.
#
#   scripts/macos/asca-run.sh audit|skills|inventory
#
# Settings come from ~/.config/asca/asca.conf (see examples/macos/asca.conf); Telegram
# credentials from ~/.config/asca/telegram.env. Each job keeps its own state under
# ~/.local/state/asca/<job> and logs to ~/Library/Logs/asca/<job>.log.
#
# Exit codes are the tool's: 0 clean, 1 findings (already alerted by the tool), 2 error.
# On an error this script sends its own short Telegram note, so a broken scheduled run is
# never silent.
set -u

job="${1:-}"
case "$job" in
  audit|skills|inventory) ;;
  *) echo "usage: $0 audit|skills|inventory" >&2; exit 2 ;;
esac

CONF_DIR="${ASCA_CONF_DIR:-$HOME/.config/asca}"
CONF="${ASCA_CONF:-$CONF_DIR/asca.conf}"
# shellcheck disable=SC1090  # user-owned settings file
[ -f "$CONF" ] && . "$CONF"

here="$(cd "$(dirname "$0")/../.." && pwd)"
ASCA_DIR="${ASCA_DIR:-$here}"
STATE="${ASCA_STATE:-$HOME/.local/state/asca}"
TG_ENV="${ASCA_TELEGRAM_ENV:-$CONF_DIR/telegram.env}"
MODE="${ASCA_TELEGRAM:-change}"
LOG_DIR="${ASCA_LOG_DIR:-$HOME/Library/Logs/asca}"
LABEL="${ASCA_HOST_LABEL:-}"
if [ -z "$LABEL" ]; then
  LABEL="$(scutil --get ComputerName 2>/dev/null || hostname)"
fi
export SSL_CERT_FILE="${SSL_CERT_FILE:-/etc/ssl/cert.pem}"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# Python 3.11+ (tomllib is needed to read Codex config.toml). Homebrew first.
PY="${ASCA_PYTHON:-}"
if [ -z "$PY" ]; then
  for cand in /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
      PY="$cand"; break
    fi
  done
fi

mkdir -p "$STATE/$job" "$LOG_DIR"
# reports list your setup: keep them private
chmod 700 "$STATE" "$STATE/$job" "$CONF_DIR" 2>/dev/null
log="$LOG_DIR/$job.log"
# keep logs small: rotate at ~5 MB
if [ -f "$log" ] && [ "$(wc -c < "$log")" -gt 5000000 ]; then mv -f "$log" "$log.1"; fi
exec >>"$log" 2>&1
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) asca $job (host $LABEL)"

notify_error() {   # $1 = message. Token stays inside Python, never on a command line.
  [ "$MODE" = "never" ] && return 0
  [ -n "$PY" ] || return 0
  ( cd "$ASCA_DIR" && ASCA_MSG="$1" "$PY" - "$TG_ENV" <<'EOF'
import html, os, sys
from pathlib import Path
from asca import report
token, chat = report.resolve_telegram(os.environ.get("ASCA_CHAT") or None, Path(sys.argv[1]))
if token and chat:
    ok, desc = report.send_telegram("⚠️ " + html.escape(os.environ["ASCA_MSG"]), token=token, chat_id=chat)
    print("error note:", desc)
EOF
  )
}

if [ -z "$PY" ]; then
  echo "no Python 3.11+ found (install with: brew install python)"
  exit 2
fi
if [ ! -d "$ASCA_DIR/asca" ]; then
  echo "asca checkout not found at $ASCA_DIR"
  exit 2
fi
cd "$ASCA_DIR" || exit 2

tg=(--telegram "$MODE")
[ -f "$TG_ENV" ] && tg+=(--env-file "$TG_ENV")
[ -n "${ASCA_CHAT:-}" ] && tg+=(--telegram-chat "$ASCA_CHAT")

repos=()
# ASCA_REPOS: space-separated folders that hold your git repos and venvs (no spaces in paths)
for r in ${ASCA_REPOS:-$HOME/Projects}; do
  [ -d "$r" ] && repos+=(--repos "$r")
done

extra=()
case "$job" in
  audit)
    [ -f "$CONF_DIR/baseline.json" ] && extra+=(--baseline "$CONF_DIR/baseline.json")
    [ -f "$CONF_DIR/advisories.json" ] && extra+=(--advisories "$CONF_DIR/advisories.json")
    # shellcheck disable=SC2206  # intentional splitting of user-supplied args
    user=(${ASCA_AUDIT_ARGS:-})
    "$PY" -m asca -o "$STATE/audit/latest" --format text --host-label "$LABEL" \
      ${repos[@]+"${repos[@]}"} ${extra[@]+"${extra[@]}"} "${tg[@]}" ${user[@]+"${user[@]}"}
    rc=$?
    # dated copies for history (reports never contain secret values); keep the newest 60
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$STATE/audit/latest.json" "$STATE/audit/history-$stamp.json" 2>/dev/null
    # names are UTC timestamps, so glob order is oldest first
    set -- "$STATE"/audit/history-*.json
    if [ -e "$1" ] && [ "$#" -gt 60 ]; then
      drop=$(($# - 60))
      for f in "$@"; do
        [ "$drop" -le 0 ] && break
        rm -f "$f"; drop=$((drop - 1))
      done
    fi
    ;;
  skills)
    [ -f "$CONF_DIR/skills-baseline.json" ] && extra+=(--baseline "$CONF_DIR/skills-baseline.json")
    # shellcheck disable=SC2206
    user=(${ASCA_SKILLS_ARGS:-})
    "$PY" -m asca.skillscan --dir "$STATE/skills" scan --format text --host-label "$LABEL" \
      ${extra[@]+"${extra[@]}"} "${tg[@]}" ${user[@]+"${user[@]}"}
    rc=$?
    ;;
  inventory)
    [ -f "$CONF_DIR/inventory-baseline.json" ] && extra+=(--baseline "$CONF_DIR/inventory-baseline.json")
    # shellcheck disable=SC2206
    user=(${ASCA_INVENTORY_ARGS:-})
    "$PY" -m asca inventory --dir "$STATE/inventory" --format text --host-label "$LABEL" \
      ${extra[@]+"${extra[@]}"} "${tg[@]}" ${user[@]+"${user[@]}"}
    rc=$?
    ;;
esac

echo "=== exit $rc"
if [ "$rc" -ge 2 ] && ! { [ "$job" = "skills" ] && [ "$rc" -eq 3 ]; }; then
  notify_error "asca $job on $LABEL failed (exit $rc). Log: $log"
fi
exit "$rc"
