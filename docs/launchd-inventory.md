# Running `asca inventory` daily on macOS with launchd

This sets up a per-user LaunchAgent that runs the IDE & agent inventory once a day and sends a
Telegram message only when something changes (new extension, publisher swap, tampered files,
known-bad build). About ten minutes, once.

## 1. Get the code and a modern Python

```bash
mkdir -p ~/Projects && cd ~/Projects
git clone https://github.com/borabaysal/Agent_Supply_Chain_Auditor.git
cd Agent_Supply_Chain_Auditor
/opt/homebrew/bin/python3 --version     # needs 3.10+; `brew install python` if missing
/opt/homebrew/bin/python3 -m asca inventory --help
```

- **Keep the checkout out of `~/Documents`, `~/Desktop` and `~/Downloads`.** macOS privacy
  controls (TCC) block background jobs from reading those folders, and the job would fail
  with "Operation not permitted".
- **Use Homebrew Python, not `/usr/bin/python3`.** The system Python may be older than 3.10.
  On an Intel Mac, Homebrew is at `/usr/local/bin/python3`.
- asca has no dependencies, so there's nothing to `pip install`.

## 2. Telegram settings, outside the repo

```bash
mkdir -p ~/.config/asca && chmod 700 ~/.config/asca
cat > ~/.config/asca/telegram.env <<'EOF'
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
EOF
chmod 600 ~/.config/asca/telegram.env
open -e ~/.config/asca/telegram.env      # paste the bot token and chat id, save
```

Never put the token in the plist or the repo. The plist only names this file.

## 3. First run by hand (learns the baseline, sends nothing)

```bash
cd ~/Projects/Agent_Supply_Chain_Auditor
SSL_CERT_FILE=/etc/ssl/cert.pem /opt/homebrew/bin/python3 -m asca inventory --host-label "$(scutil --get ComputerName)"
```

- **The output:** you'll see how many extensions, MCP servers, plugins and skills it found.
  The report is in `~/.local/state/asca/inventory/inventory-latest.md`.
- **Approving publishers:** if you trust the publishers you have today, approve them so only
  *new* ones are flagged:

```bash
/opt/homebrew/bin/python3 -m asca inventory --write-approved ~/.config/asca/inventory-baseline.json
```

- **Checking the alert path:** send one test message.

```bash
SSL_CERT_FILE=/etc/ssl/cert.pem /opt/homebrew/bin/python3 -m asca inventory --format none \
  --telegram always --env-file ~/.config/asca/telegram.env
```

`SSL_CERT_FILE` points Homebrew Python at the macOS certificate bundle. Without it, HTTPS to
Telegram can fail with a certificate error.

## 4. The LaunchAgent

Save this as `~/Library/LaunchAgents/com.asca.inventory.plist`. Replace `YOURNAME` with your
macOS short user name (`whoami`) in all four places.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.asca.inventory</string>
  <key>WorkingDirectory</key><string>/Users/YOURNAME/Projects/Agent_Supply_Chain_Auditor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/python3</string>
    <string>-m</string><string>asca</string><string>inventory</string>
    <string>--format</string><string>none</string>
    <string>--telegram</string><string>change</string>
    <string>--env-file</string><string>/Users/YOURNAME/.config/asca/telegram.env</string>
    <string>--baseline</string><string>/Users/YOURNAME/.config/asca/inventory-baseline.json</string>
    <string>--host-label</string><string>macbook</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SSL_CERT_FILE</key><string>/etc/ssl/cert.pem</string>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <!-- daily at 08:15; if the Mac was asleep, launchd runs it once on wake -->
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>8</integer><key>Minute</key><integer>15</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>Nice</key><integer>10</integer>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>/Users/YOURNAME/Library/Logs/asca-inventory.log</string>
  <key>StandardErrorPath</key><string>/Users/YOURNAME/Library/Logs/asca-inventory.log</string>
</dict>
</plist>
```

- **No baseline file?** If you skipped `--write-approved`, delete the two `--baseline` lines.
- **Different schedule?** Change the time in `StartCalendarInterval`.

Load it and run it once now:

```bash
plutil -lint ~/Library/LaunchAgents/com.asca.inventory.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.asca.inventory.plist
launchctl kickstart -k gui/$(id -u)/com.asca.inventory
sleep 5; tail -n 20 ~/Library/Logs/asca-inventory.log
launchctl print gui/$(id -u)/com.asca.inventory | grep -E "state|last exit"
```

`last exit code` meanings:

| Code | Meaning |
|---|---|
| 0 | Nothing serious changed |
| 1 | A high/critical finding (tamper, publisher swap, known-bad build). You'll also get it on Telegram. |
| 2 | Error. Read the log. |

## 5. Day to day

- **Reports:** `~/.local/state/asca/inventory/inventory-latest.md`. The JSON next to it has
  the full item list with hashes.
- **After you install an extension on purpose:** the next run reports it once (medium) and
  then learns it.
- **Updating asca:** `cd ~/Projects/Agent_Supply_Chain_Auditor && git pull`. There's no need
  to reload the agent.
- **Turning it off:** `launchctl bootout gui/$(id -u)/com.asca.inventory`, then delete the
  plist.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Operation not permitted` in the log | The checkout or a path is under a TCC-protected folder. Move it to `~/Projects`, or grant `/opt/homebrew/bin/python3` Full Disk Access (less preferable). |
| `CERTIFICATE_VERIFY_FAILED` | `SSL_CERT_FILE` is missing from `EnvironmentVariables`. |
| `No module named asca` | `WorkingDirectory` doesn't point at the checkout. |
| `telegram: missing bot token or chat id` | Check `~/.config/asca/telegram.env` and its path in the plist. |
| `corrupt state` (exit 2) | Move `~/.local/state/asca/inventory/state.json` aside. The next run re-learns silently. |
