#!/bin/bash
# Intune custom compliance discovery script for macOS: asca results for this Mac.
# Upload under Devices > Compliance > Scripts > Add > macOS, then use examples/intune/rules.json in the policy.
# Prints ONE line of JSON keyed by setting name and always exits 0 (Intune requirement).
# Reads the last report of the user's scheduled asca job; it doesn't run an audit.
# Written for /bin/bash 3.2.

ASCA_DIR="/Users/Shared/Agent_Supply_Chain_Auditor"   # where IT deployed the asca checkout
PY=/usr/bin/python3

fail() {   # fail closed: no report means non-compliant
  /bin/echo '{"AscaReportFound":false,"AscaReportAgeHours":999999,"AscaCritical":0,"AscaHigh":0,"AscaMedium":0,"AscaResult":"MISSING","AscaVersion":"0.0.0"}'
  exit 0
}

# Intune runs this as root: use the logged-in user's asca state.
user=$(/usr/bin/stat -f %Su /dev/console 2>/dev/null)
if [ -z "$user" ] || [ "$user" = "root" ]; then fail; fi
home=$(/usr/bin/dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')
[ -d "$home/.local/state/asca" ] || fail
if [ ! -x "$PY" ] || [ ! -d "$ASCA_DIR/asca" ]; then fail; fi

out=$(cd "$ASCA_DIR" && "$PY" -m asca export intune --state-dir "$home/.local/state/asca" 2>/dev/null)
case "$out" in
  \{*\}) /bin/echo "$out" ;;
  *) fail ;;
esac
exit 0
