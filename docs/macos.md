# Running asca on macOS: full audit + daily jobs

This sets up every asca check that applies to a Mac and schedules it with launchd. You only
get a Telegram message when something changes. Setup takes about 20 minutes, once.

| Job | What it checks | Default time |
|---|---|---|
| `audit` (`asca`) | Unpinned skills/MCP servers, risky git config in your repos, exposed keys and permissions, secrets in agent session history, stray agent instructions, **agent-config tamper** (Codex/Claude Code sandbox, endpoints, telemetry), **Python startup hooks**, Hermes advisories if Hermes is installed | 08:00 |
| `skills` (`asca-skills scan`) | Look-alike agent apps/plugins/skills and risky skill content | 08:10 |
| `inventory` (`asca inventory`) | VS Code / Cursor / Windsurf / VSCodium extensions, MCP servers, plugins and skills, with tamper and publisher-swap detection | 08:15 |

**Not covered on a Mac:**
- `asca-egress` attributes connections through Linux `/proc`, so it doesn't run on macOS.
- `asca-fleet` is only useful if you self-host Hermes. Run it on that host instead.

## 1. Prerequisites

```bash
xcode-select --install 2>/dev/null   # git; skip if already installed
brew install python                  # Python 3.11+; asca has no other dependencies
/opt/homebrew/bin/python3 --version  # Intel Macs: /usr/local/bin/python3
```

asca's minimum is Python 3.10, but the scheduled jobs need **3.11+**: reading Codex's
`config.toml` uses `tomllib`. On 3.10 you'd get a LOW "Codex config not checked" finding
instead. Don't rely on `/usr/bin/python3`.

## 2. Get the code (outside protected folders)

```bash
mkdir -p ~/Projects && cd ~/Projects
git clone https://github.com/borabaysal/Agent_Supply_Chain_Auditor.git
cd Agent_Supply_Chain_Auditor
/opt/homebrew/bin/python3 -m asca --help >/dev/null && echo ok
```

Keep the checkout **out of `~/Documents`, `~/Desktop` and `~/Downloads`**. macOS privacy
controls (TCC) block background jobs from reading those folders. The jobs would fail with
`Operation not permitted`, and the installer warns if you try.

## 3. Settings and Telegram

```bash
mkdir -p ~/.config/asca && chmod 700 ~/.config/asca
cp examples/macos/asca.conf ~/.config/asca/asca.conf
open -e ~/.config/asca/asca.conf
```

Set at least the following:
- `ASCA_HOST_LABEL`: the name shown in alerts.
- `ASCA_REPOS`: the folders holding your git repos and Python virtualenvs. The audit checks
  their git config and startup hooks; default `~/Projects`.
- The job times, if you want different ones.

Telegram credentials go in their own file, never in the repo or a plist:

```bash
printf 'TELEGRAM_BOT_TOKEN=\nTELEGRAM_CHAT_ID=\n' > ~/.config/asca/telegram.env
chmod 600 ~/.config/asca/telegram.env
open -e ~/.config/asca/telegram.env
```

- **New bot:** message @BotFather, `/newbot`.
- **Chat id:** send the bot a message, then open
  `https://api.telegram.org/bot<TOKEN>/getUpdates`.
- **Reusing a bot:** if you already have one (e.g. the Hermes one), reuse its token and chat id.
- **No Telegram at all:** set `ASCA_TELEGRAM=never` in `asca.conf`. Otherwise a missing token
  makes every run end in an error (exit 2), so the problem isn't silent.

## 4. First runs by hand

Run each job once in the foreground with alerts off. The first run of each learns the current
state.

```bash
cd ~/Projects/Agent_Supply_Chain_Auditor
ASCA_TELEGRAM=never scripts/macos/asca-run.sh audit;     echo "audit exit $?"
ASCA_TELEGRAM=never scripts/macos/asca-run.sh skills;    echo "skills exit $?"
ASCA_TELEGRAM=never scripts/macos/asca-run.sh inventory; echo "inventory exit $?"
```

Output goes to `~/Library/Logs/asca/<job>.log`, and reports to
`~/.local/state/asca/<job>/`. Read the audit report first:

```bash
open ~/.local/state/asca/audit/latest.md
```

| Exit | Meaning |
|---|---|
| 0 | Clean (nothing at or above the fail level) |
| 1 | Findings to look at |
| 2 | Error: read the log |
| 3 | `skills` only: a gated skill was blocked (only with `--gate`) |

The first audit on a developer laptop usually flags a few things.

| Common first-run finding | Typical fix |
|---|---|
| `agent.sandbox-disabled` (Codex `danger-full-access`, Claude Code `bypassPermissions`) | Go back to the default unless you set it on purpose |
| `agent.endpoint-override` | Fine if it's your gateway/provider; accept it (below) |
| `python.executable-pth` naming a package | Check you meant to install that package |
| `secret.*` in a shell profile or `.env` | Tighten the permissions (`chmod 600`) or move the key into the Keychain |
| `repo.*` git hooks / fsmonitor | Remove them unless you set them up |

**Accept what you've reviewed.** Accepted findings stay in the report as "suppressed" but
no longer fail or alert:

```bash
/opt/homebrew/bin/python3 -m asca --repos ~/Projects --write-baseline ~/.config/asca/baseline.json
/opt/homebrew/bin/python3 -m asca.skillscan --dir ~/.local/state/asca/skills scan --write-baseline ~/.config/asca/skills-baseline.json
/opt/homebrew/bin/python3 -m asca inventory --dir ~/.local/state/asca/inventory --write-approved ~/.config/asca/inventory-baseline.json
```

- **Same folders as the jobs:** pass the folders from `ASCA_REPOS` to the audit command as
  `--repos`, one per folder.
- **What these write:** every *current* finding (or, for the inventory, every current
  publisher). Edit the files and delete anything you don't actually accept.
- **How the jobs use them:** the runner picks these files up automatically.
- **Advisories file:** if you keep an `advisories.json` (see the README), put it in
  `~/.config/asca/` too.

**Test the alert path once:**

```bash
ASCA_TELEGRAM=always scripts/macos/asca-run.sh inventory
```

## 4b. One-command check: secrets in "don't ask again" allow rules

Claude Code saves every "Yes, and don't ask again" approval as the literal command, passwords
included, in `~/.claude/settings*.json` and each project's `.claude/settings.local.json`. That
file is easy to commit by accident. This checks those files, VS Code / Cursor auto-approve
settings, every repo under `~/Projects`, and your agent session history, and prints only what
it finds (secrets redacted):

```bash
cd ~/Projects/Agent_Supply_Chain_Auditor && git pull --ff-only && SSL_CERT_FILE=/etc/ssl/cert.pem /opt/homebrew/bin/python3 -m asca --repos ~/Projects --no-hermes --no-client-configs --no-global-git --no-stray-instructions --no-python-startup --no-agent-config --no-repo-hooks -o /tmp/asca-allowlist --format text --telegram never
```

- **Exit 0:** nothing at high or above. **Exit 1:** read the `[HIGH]` lines, and the full
  report with `open /tmp/asca-allowlist.md`.
- **For each `secret.agent-allowlist` or `repo.claude-local-settings-committed` finding:**
  1. Rotate that password or key first.
  2. If the file is committed: `git rm --cached .claude/settings.local.json`, add it to the
     repo's `.gitignore`, then commit.
  3. Delete the rule (Claude Code: `/permissions`).
- **Faster check:** add `--no-session-history` to skip transcripts (about a minute on a busy
  laptop).
- **Every day:** the scheduled `audit` job (section 5) includes this check.

## 5. Schedule the jobs

```bash
scripts/macos/install-launchd.sh --dry-run   # shows the three plists
scripts/macos/install-launchd.sh             # writes ~/Library/LaunchAgents/com.asca.*.plist and loads them
launchctl kickstart -k gui/$(id -u)/com.asca.inventory
sleep 10; tail -n 5 ~/Library/Logs/asca/inventory.log
launchctl print gui/$(id -u)/com.asca.audit | grep -E "state|last exit code|runs"
```

- **Sleep:** a job missed while the Mac was asleep runs once when it wakes. A Mac that's
  powered off at the scheduled time skips that day.
- **Changing jobs or times:** after editing `ASCA_JOBS` or the times in `asca.conf`, run the
  installer again.
- **Resources:** jobs run at low CPU and IO priority. A full audit takes about a minute;
  session history is the slow part. Set `--session-budget-mb` in `ASCA_AUDIT_ARGS` to cap it.

## 6. What you'll receive

- **Audit and skills:** a message when PASS/FAIL or the set of failing findings (high and
  above by default) changes.
- **Inventory:** a message when a new change at or above medium appears. It reports each
  change once, then learns it.
- **Errors:** if a job fails (exit 2), the runner sends a short ⚠️ note with the log path, so
  a broken job isn't mistaken for a quiet one.

## 7. Updating and removing

```bash
cd ~/Projects/Agent_Supply_Chain_Auditor && git pull     # no reload needed; jobs run the checkout
scripts/macos/install-launchd.sh --uninstall             # removes all three LaunchAgents
rm -rf ~/.local/state/asca ~/Library/Logs/asca           # optional: delete history
```

## Troubleshooting

| Symptom (in `~/Library/Logs/asca/<job>.log`) | Fix |
|---|---|
| `Operation not permitted` | A path is in Documents/Desktop/Downloads or iCloud Drive. Move it, or give `/opt/homebrew/bin/python3` Full Disk Access in System Settings → Privacy & Security (less preferable). |
| `no Python 3.11+ found` | `brew install python`, or set `ASCA_PYTHON` in `asca.conf`. |
| `CERTIFICATE_VERIFY_FAILED` | The runner sets `SSL_CERT_FILE=/etc/ssl/cert.pem`. If you run `python3 -m asca` by hand, export it too. |
| `telegram: missing bot token or chat id` | Check `~/.config/asca/telegram.env`. |
| `corrupt state … Move it aside to re-learn` | `mv ~/.local/state/asca/inventory/state.json{,.bad}` (or the skills one); the next run re-learns silently. |
| Nothing in the log at all | `launchctl print gui/$(id -u)/com.asca.<job>`. Check `~/Library/Logs/asca/launchd-<job>.log` for launchd-level errors. |
| `last exit code = 1` every day | That's findings, not an error. Read `latest.md` and fix or accept them. |

## What the scripts do

- **`scripts/macos/asca-run.sh <job>`:** reads `~/.config/asca/asca.conf`, finds Python
  3.11+, and runs the job with its own state folder (0700) and log, rotating the log at
  ~5 MB. The audit also keeps 60 dated JSON reports. Written for macOS's bash 3.2;
  shellcheck-clean.
- **`scripts/macos/install-launchd.sh`:** writes one LaunchAgent per job (validated with
  `plutil`), runs `bootout` + `bootstrap` so re-running it is safe, and has `--dry-run` and
  `--uninstall`.
