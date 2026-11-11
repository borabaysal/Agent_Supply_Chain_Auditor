#!/usr/bin/env bash
# Daily/periodic asca run for cron, systemd timers or agent schedulers.
#
# Configure via environment (all optional):
#   ASCA_DIR         checkout of this repo            (default: directory of this script's parent)
#   ASCA_STATE_DIR   where reports are kept            (default: ~/.local/state/asca)
#   ASCA_ENV_FILE    dotenv with TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID (default: none -> use env)
#   ASCA_TELEGRAM    never|fail|always|change          (default: change)
#   ASCA_ARGS        extra CLI args, e.g. "--repos $HOME/Projects --baseline $HOME/.config/asca/baseline.json"
#
# `--telegram change` compares against the previous report in ASCA_STATE_DIR, so keep
# that directory persistent. Exit code: 0 PASS, 1 FAIL, 2 scanner/alert error.
set -euo pipefail

ASCA_DIR="${ASCA_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ASCA_STATE_DIR="${ASCA_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/asca}"
ASCA_TELEGRAM="${ASCA_TELEGRAM:-change}"
#   ASCA_DASHBOARD_FILE  dashboard page rebuilt after each run (default: $ASCA_STATE_DIR/dashboard.html)
#   ASCA_DASHBOARD       where reports say the page is (default: ASCA_DASHBOARD_FILE; set it when you
#                        open the page from another machine or path, e.g. "myhost:~/.hermes/state/asca/
#                        dashboard.html"); "off" disables both the page and the report line
ASCA_DASHBOARD_FILE="${ASCA_DASHBOARD_FILE:-$ASCA_STATE_DIR/dashboard.html}"
ASCA_DASHBOARD="${ASCA_DASHBOARD:-$ASCA_DASHBOARD_FILE}"
if [[ "$ASCA_DASHBOARD" == "off" ]]; then unset ASCA_DASHBOARD; else export ASCA_DASHBOARD; fi
PYTHON="${PYTHON:-python3}"

mkdir -p "$ASCA_STATE_DIR"
chmod 700 "$ASCA_STATE_DIR"

args=(-o "$ASCA_STATE_DIR/latest" --format text --telegram "$ASCA_TELEGRAM")
if [[ -n "${ASCA_ENV_FILE:-}" ]]; then
  args+=(--env-file "$ASCA_ENV_FILE")
fi
# shellcheck disable=SC2206  # intentional word splitting of user-supplied extra args
extra=(${ASCA_ARGS:-})

cd "$ASCA_DIR"
set +e
"$PYTHON" -m asca "${args[@]}" "${extra[@]}"
rc=$?
set -e

# keep a dated copy for history (reports are 0600; never contain secret values)
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$ASCA_STATE_DIR/latest.json" "$ASCA_STATE_DIR/history-$stamp.json" 2>/dev/null || true
# retain the last 60 history files
ls -1t "$ASCA_STATE_DIR"/history-*.json 2>/dev/null | tail -n +61 | xargs -r rm -f
if [[ -n "${ASCA_DASHBOARD:-}" ]]; then
  # never changes the audit's exit code; a failure is only reported
  "$PYTHON" -m asca dashboard --state-dir "$ASCA_STATE_DIR" -o "$ASCA_DASHBOARD_FILE" --quiet \
    || echo "asca: dashboard rebuild failed (audit result unaffected)" >&2
fi
exit "$rc"
