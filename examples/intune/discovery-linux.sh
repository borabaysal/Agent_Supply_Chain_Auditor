#!/bin/bash
# Intune custom compliance discovery script for Linux: asca results for this device.
# On Linux, Intune runs discovery scripts in the user's context, so $HOME is the user's.
# Prints ONE line of JSON keyed by setting name and always exits 0. Reads the last asca report.

ASCA_DIR="${ASCA_DIR:-/opt/Agent_Supply_Chain_Auditor}"   # where IT deployed the asca checkout
STATE="${ASCA_STATE:-$HOME/.local/state/asca}"

fail() {
  echo '{"AscaReportFound":false,"AscaReportAgeHours":999999,"AscaCritical":0,"AscaHigh":0,"AscaMedium":0,"AscaResult":"MISSING","AscaVersion":"0.0.0"}'
  exit 0
}
if ! command -v python3 >/dev/null 2>&1 || [ ! -d "$ASCA_DIR/asca" ] || [ ! -d "$STATE" ]; then fail; fi
out=$(cd "$ASCA_DIR" && python3 -m asca export intune --state-dir "$STATE" 2>/dev/null)
case "$out" in
  \{*\}) echo "$out" ;;
  *) fail ;;
esac
exit 0
