#!/bin/bash
# Install (or remove) daily LaunchAgents for the asca jobs on macOS. bash 3.2 compatible.
#
#   scripts/macos/install-launchd.sh             write ~/Library/LaunchAgents/com.asca.<job>.plist and load them
#   scripts/macos/install-launchd.sh --dry-run   print the plists, change nothing
#   scripts/macos/install-launchd.sh --uninstall unload and delete them
#
# Jobs and times come from ~/.config/asca/asca.conf:
#   ASCA_JOBS="audit skills inventory"
#   ASCA_TIME_audit=08:00  ASCA_TIME_skills=08:10  ASCA_TIME_inventory=08:15
set -u

action="install"
case "${1:-}" in
  --dry-run) action="dry-run" ;;
  --uninstall) action="uninstall" ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--uninstall]" >&2; exit 2 ;;
esac

CONF_DIR="${ASCA_CONF_DIR:-$HOME/.config/asca}"
CONF="${ASCA_CONF:-$CONF_DIR/asca.conf}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

here="$(cd "$(dirname "$0")/../.." && pwd)"
ASCA_DIR="${ASCA_DIR:-$here}"
AGENTS="${ASCA_LAUNCHAGENTS:-$HOME/Library/LaunchAgents}"
LOG_DIR="${ASCA_LOG_DIR:-$HOME/Library/Logs/asca}"
JOBS="${ASCA_JOBS:-audit skills inventory}"
: "${ASCA_TIME_audit:=08:00}" "${ASCA_TIME_skills:=08:10}" "${ASCA_TIME_inventory:=08:15}"

case "$ASCA_DIR" in
  "$HOME/Documents"*|"$HOME/Desktop"*|"$HOME/Downloads"*)
    echo "warning: $ASCA_DIR is in a folder macOS blocks for background jobs (TCC); move the checkout to ~/Projects" >&2 ;;
esac

xml() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

plist() {   # $1 job, $2 hour, $3 minute
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.asca.$1</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$(xml "$ASCA_DIR/scripts/macos/asca-run.sh")</string>
    <string>$1</string>
  </array>
  <key>WorkingDirectory</key><string>$(xml "$ASCA_DIR")</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>SSL_CERT_FILE</key><string>/etc/ssl/cert.pem</string>
  </dict>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>$2</integer><key>Minute</key><integer>$3</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>Nice</key><integer>10</integer>
  <key>LowPriorityIO</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$(xml "$LOG_DIR/launchd-$1.log")</string>
  <key>StandardErrorPath</key><string>$(xml "$LOG_DIR/launchd-$1.log")</string>
</dict>
</plist>
EOF
}

uid="$(id -u)"
rc=0
mkdir -p "$LOG_DIR"
[ "$action" = "install" ] && mkdir -p "$AGENTS"
for job in $JOBS; do
  case "$job" in audit|skills|inventory) ;; *) echo "skipping unknown job '$job'" >&2; continue ;; esac
  label="com.asca.$job"
  file="$AGENTS/$label.plist"
  if [ "$action" = "uninstall" ]; then
    launchctl bootout "gui/$uid/$label" 2>/dev/null
    rm -f "$file" && echo "removed $label"
    continue
  fi
  case "$job" in
    audit) t="$ASCA_TIME_audit" ;;
    skills) t="$ASCA_TIME_skills" ;;
    inventory) t="$ASCA_TIME_inventory" ;;
  esac
  hour="${t%%:*}"; minute="${t##*:}"
  case "$hour$minute" in ''|*[!0-9]*) echo "bad time '$t' for $job (use HH:MM)" >&2; rc=2; continue ;; esac
  hour=$((10#$hour)); minute=$((10#$minute))
  if [ "$hour" -gt 23 ] || [ "$minute" -gt 59 ]; then
    echo "bad time '$t' for $job" >&2; rc=2; continue
  fi
  if [ "$action" = "dry-run" ]; then
    echo "# $file"; plist "$job" "$hour" "$minute"; continue
  fi
  plist "$job" "$hour" "$minute" > "$file.tmp" && mv -f "$file.tmp" "$file"
  chmod 644 "$file"
  if command -v plutil >/dev/null 2>&1 && ! plutil -lint "$file" >/dev/null; then
    echo "invalid plist $file" >&2; rc=2; continue
  fi
  launchctl bootout "gui/$uid/$label" 2>/dev/null   # replace an older copy cleanly
  if launchctl bootstrap "gui/$uid" "$file"; then
    printf 'installed %-22s daily at %02d:%02d\n' "$label" "$hour" "$minute"
  else
    echo "launchctl bootstrap failed for $label" >&2; rc=2
  fi
done
[ "$action" = "install" ] && [ "$rc" -eq 0 ] && \
  echo "run one now:  launchctl kickstart -k gui/$uid/com.asca.inventory   (logs: $LOG_DIR)"
exit "$rc"
