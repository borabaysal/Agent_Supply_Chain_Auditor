# Agent Supply-Chain Auditor (`asca`)

A zero-dependency CLI for people who **self-host AI agents**: Hermes Agent, Claude Code, Codex CLI, Gemini CLI, goose, Cursor, Windsurf, VS Code, Claude Desktop, or any MCP client. It audits the setup for supply-chain risk, writes a **PASS/FAIL report**, and can **alert you on Telegram**.

```
$ asca --repos ~/Projects --telegram fail --env-file ~/.hermes/.env
asca 0.5.0: FAIL (fail-on high)
  critical=1  high=2  medium=1  low=5  info=2  suppressed=0
  [CRITICAL] core.fsmonitor names a program git runs on every index refresh
      ~/Projects/downloaded-repo/.git/config:3
  [HIGH] Hub skill `some-community-skill` is not pinned to a commit
      ~/.hermes/skills/.hub/lock.json#installed.some-community-skill
  ...
  report: asca-report.md  (asca-report.json)
```

## What it checks

_Also included: an [egress auditor](#egress-auditor-asca-egress) that logs where your agents connect and alerts on new destinations, a [fleet patch monitor](#fleet-patch-monitor-asca-fleet) that tells you how many Hermes security fixes each instance is behind, a [fake-app & skill scanner](#fake-app--skill-scanner-asca-skills) for look-alike names and malicious skill content, and an [IDE & agent inventory](#ide--agent-inventory-asca-inventory) that records installed extensions, MCP servers, plugins and skills and alerts when they change._

| Category | Checks |
|---|---|
| **Pinning** | Hermes Skills Hub installs with no upstream commit pin · skill taps that track a branch · plugins checked out on a moving branch · MCP servers launched with `npx`/`bunx`/`uvx`/`pipx` without an exact version · `docker run` images without `@sha256:` digest · `git+https://` installs without a commit SHA · skills that tell the agent to `curl … \| sh` · remote MCP servers (reported as *info*, since they can't be pinned) · [plugin checkouts with a branch named like a commit hash, or moved off their pin (Plugin4Shell)](#plugin-checkouts-that-arent-on-their-pinned-commit-plugin4shell) |
| **Repo config** (GitSpawn) | `core.fsmonitor` set to a program (**critical**, see [CVE-2026-71963](https://www.rapid7.com/db/vulnerabilities/cve-2026-71963/) for Hermes, CVE-2026-19592 for Codex, CVE-2026-72718 for goose), plus every other git key that names a program: `core.hooksPath`, `core.sshCommand`, `core.askPass`, `core.pager`/`pager.*`, `core.editor`, `diff.external`, `diff.*.textconv`, `filter.*.{clean,smudge,process}`, `merge.*.driver`, `credential.helper` (non-builtin), `protocol.ext.allow`, `include.path`/`includeIf`, `!` aliases, `gpg.program` · active (non-`.sample`) git hooks · linked worktrees/submodules (`.git` files) · project `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` / `.gemini/settings.json` MCP servers that ship with a repo · [coding agents in `.github/workflows` that anyone can trigger](#coding-agents-in-github-workflows-that-anyone-can-trigger-on-by-default---no-ci-agents-to-skip) · [npm install hooks and workflow steps that dump secrets (wfx)](#install-hooks-and-secret-dumping-workflow-steps-wfx-on-by-default---no-install-hooks-to-skip) |
| **Exposed keys** | Literal API keys in agent config, cron jobs, memories, skills, plugins, scripts and MCP `env`/`headers` (Anthropic, OpenAI, OpenRouter, GitHub, Slack, Telegram, AWS, Google, Stripe, HF, wallet private keys, PEM keys, generic `api_key=` assignments) · tokens embedded in git remote URLs and MCP URLs · credential files (`.env`, `auth.json`, `.git-credentials`, `config.yaml`, MCP OAuth tokens) readable by group/other |
| **Session history** | Literal keys saved in agents' transcripts: Hermes `sessions/*.json(l)` and `cron/output/**` (incl. `profiles/*`), Claude Code `~/.claude/projects/**/*.jsonl`, Codex `~/.codex/sessions/**/*.jsonl` and `history.jsonl`, Cursor chat rows in `state.vscdb` · transcript files/dirs that group/other can actually reach and read. See [Session history](#session-history-secretsession-history). |
| **Stray agent instructions** | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*` … left in `~/Downloads`, `~/Desktop` or the temp dir, outside any git repo; HIGH when the `asca-skills` content rules match. See [Stray agent instructions](#stray-agent-instructions-repostray-agent-instructions). |
| **Integrity** | Hub skills whose on-disk content no longer matches the install-time hash (same algorithm as Hermes' Skills Guard) · skills installed despite a non-`safe` scanner verdict · Hermes Agent versions inside a known-vulnerable range · [installed Claude Code, Codex, Gemini CLI, goose and Claude Desktop versions with known vulnerabilities](#other-coding-agents-claude-code-codex-gemini-cli-goose-claude-desktop), including advisories that never got a CVE or never reached OSV |
| **Agent takeover** | Hermes `SOUL.md` and memories rewritten to take orders, collect keys or hide activity (Carbonato) · gateway open to anyone (`GATEWAY_ALLOW_ALL_USERS`, `*` allow lists) · Docker API reachable over TCP without client certificates · [details](#agent-takeover-workspace-and-response-checks-part-of-asca) · [macOS Full Disk Access / Accessibility for terminals, IDEs and agent apps](#full-disk-access-for-terminals-ides-and-agents-macos) |
| **Workspace** | Symlinks that lead out of a repo or the agent home, high when they point at credentials (CVE-2026-103916) · MCP servers that are archived and will never be patched (MCPhantom) |
| **Response** | [`asca spend`](#stolen-key-spend-tripwire-asca-spend-opt-in-online): hourly spend tripwire for stolen OpenRouter and Anthropic keys · Provider-specific steps on every leaked-key finding, plus a local blast-radius card for AWS keys (profile, long-lived or temporary, assumable roles) · a dashboard card per leaked key: every copy across agents, days exposed, and whether it's still your live key · [`asca github-check`](#were-your-github-repos-hit-by-wfx-asca-github-check-opt-in-online) for wfx traces on GitHub |

### Safety properties of the auditor itself

- **It never runs `git`.** Running `git status` inside a hostile repo is exactly how GitSpawn fires, so `.git/config` is parsed as text. A test (`test_never_invokes_git`) blocks process spawning and asserts the payload never runs.
- **It never prints secrets.** Findings show a 4-char prefix, the length, and a short SHA-256 tag, so you can tell *which* key leaked without the report becoming a leak itself. Reports are written `0600`.
- **It fails closed.** An unparseable lock file or config produces a HIGH `scanner.parse-error` finding instead of a silent pass.
- **It has no dependencies.** Python ≥3.10 stdlib only. YAML is read by a small built-in parser (PyYAML's `safe_load` is used instead if it happens to be installed). The built-in parser is differential-tested against PyYAML on real Hermes configs and skill front-matter.

## Install

```bash
git clone https://github.com/borabaysal/Agent_Supply_Chain_Auditor && cd Agent_Supply_Chain_Auditor
python3 -m asca --help                 # run in place, no install needed
# or
uv tool install .   # / pipx install .   -> `asca` on PATH
```

## Usage

```bash
asca                                   # Hermes home ($HERMES_HOME or ~/.hermes) + MCP client configs + global git config
asca --repos ~/Projects --repos ~/Downloads     # also audit every git repo under these dirs (4 levels deep)
asca --mcp-config ./some/mcp.json      # extra MCP client config
asca --fail-on critical                # threshold: info|low|medium|high|critical (default high)
asca -o reports/2026-10-05             # writes reports/2026-10-05.md and .json
asca --format json                     # machine-readable on stdout
asca --no-session-history              # skip transcript scanning (on by default)
asca --session-budget-mb 4096          # read more history per run (default 1024 MiB, newest first)
asca --instructions-dir ~/shared       # also look for stray AGENTS.md/CLAUDE.md here
```

Exit codes: `0` PASS · `1` FAIL · `2` usage/config/alert-delivery error.

### Accepting a risk (baseline)

```bash
asca --write-baseline asca-baseline.json   # snapshot current fingerprints
# edit the "reason" fields, then:
asca --baseline asca-baseline.json         # suppressed findings are listed but don't fail
```

Fingerprints are `sha256(rule, location, subject)`, so a *new* problem in the same file still fails.

### Telegram alerts

```bash
export TELEGRAM_BOT_TOKEN=...   # or ASCA_TELEGRAM_BOT_TOKEN
export TELEGRAM_CHAT_ID=...     # or ASCA_TELEGRAM_CHAT_ID / TELEGRAM_HOME_CHANNEL / --telegram-chat
asca --telegram fail            # alert only on FAIL
asca --telegram change          # alert when PASS/FAIL or the failing set changes vs the previous report
asca --telegram always
asca --env-file ~/.hermes/.env --telegram fail   # reuse the Hermes gateway's bot settings
```

The alert lists counts, up to 8 failing findings, and the report path. It never includes secret material.

### Scheduling (daily, alert only on change)

`scripts/asca-daily.sh` wraps the CLI for schedulers. It keeps reports in `~/.local/state/asca` (mode 700), and `--telegram change` compares each run against the previous one, so you only get a message when PASS/FAIL or the set of failing findings changes. It also keeps the last 60 dated JSON reports.

```bash
# environment knobs (all optional)
export ASCA_ENV_FILE=~/.hermes/.env          # TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID (or TELEGRAM_HOME_CHANNEL)
export ASCA_ARGS="--repos $HOME/Projects --baseline $HOME/.config/asca/baseline.json"
scripts/asca-daily.sh
```

**macOS (launchd)**: full guide in [docs/macos.md](docs/macos.md). Short version:

```bash
mkdir -p ~/.config/asca && cp examples/macos/asca.conf ~/.config/asca/   # set repos, times, host label
printf 'TELEGRAM_BOT_TOKEN=\nTELEGRAM_CHAT_ID=\n' > ~/.config/asca/telegram.env && chmod 600 ~/.config/asca/telegram.env
ASCA_TELEGRAM=never scripts/macos/asca-run.sh audit   # first run by hand; review ~/.local/state/asca/audit/latest.md
scripts/macos/install-launchd.sh                      # daily audit 08:00, skills 08:10, inventory 08:15
```

**cron**

```cron
0 7 * * * ASCA_ENV_FILE=$HOME/.hermes/.env ASCA_ARGS="--repos $HOME/Projects" /path/to/Agent_Supply_Chain_Auditor/scripts/asca-daily.sh >/dev/null 2>&1
```

**Hermes Agent scheduler** (no LLM tokens: the script itself is the job)

```text
cronjob create  schedule="0 7 * * *"  no_agent=true  script=<wrapper that exports the env vars above and calls asca-daily.sh>  deliver=local
```

Use `deliver=local` so Hermes doesn't post the script's stdout as well. asca sends the Telegram alert itself, and only on change.

**systemd** (user timer)

```ini
# ~/.config/systemd/user/asca.service
[Service]
Type=oneshot
Environment=ASCA_ENV_FILE=%h/.hermes/.env
Environment=ASCA_ARGS=--repos %h/Projects
ExecStart=%h/Agent_Supply_Chain_Auditor/scripts/asca-daily.sh
SuccessExitStatus=1
# ~/.config/systemd/user/asca.timer
[Timer]
OnCalendar=*-*-* 07:00
Persistent=true
[Install]
WantedBy=timers.target
```

### Session history (`secret.session-history`)

Agents save every tool result. When an agent reads `.env` or prints a config, the key ends up in a
transcript that outlives the file, and any later skill that "summarises past sessions" can read it.
[Backslash's research](https://www.backslash.security/blog/secrets-in-ai-agent-session-history) found
about 3 in 4 secrets in Claude Code/Cursor/Codex history came from the agent's own tool output, and a
"weekly report" skill pulled keys that a direct `.env`-read guard had blocked.

| Source | Files |
|---|---|
| Hermes | `$HERMES_HOME/sessions/**/*.json`, `*.jsonl`; `$HERMES_HOME/cron/output/**`; the same under `profiles/*/` |
| Claude Code | `~/.claude/projects/**/*.jsonl` (`$CLAUDE_CONFIG_DIR` respected) |
| Codex CLI | `~/.codex/sessions/**/*.jsonl`, `~/.codex/history.jsonl` (`$CODEX_HOME` respected) |
| Cursor | `User/globalStorage/state.vscdb` and `User/workspaceStorage/*/state.vscdb` (Linux, macOS, Windows paths): rows whose key mentions chat/composer/bubble/aiService/prompt only |

- The same secret patterns and placeholder filters as the rest of asca. JSON string escapes (up to
  3 levels, since tool arguments are JSON inside JSON) are undone first, so `\"api_key\": \"…\"` and
  `\n`-joined `.env` dumps are found.
- **One finding per distinct secret.** It shows the redacted preview, how many times and in how many
  files it appears, which agents, and up to 5 example `file:line` locations. The fingerprint is the
  secret's hash, so it stays stable as transcripts pile up. Private keys are identified by their body,
  and no preview is shown.
- Severity: HIGH, or MEDIUM for the heuristic `api_key=`/`password=` assignment rule.
- `secret.session-history-permissions` (MEDIUM): one finding per history root that has files or dirs
  group/other can read **and reach**, meaning every parent dir is traversable. A 0644 transcript
  under a 0700 home isn't reported.
- **Bounded.** Files are scanned newest first (recent keys are likelier to be live). There are three
  limits, each with a flag: `--session-file-cap-mb` (default 32), `--session-budget-mb` (1024) and
  `--session-max-files` (100000). Hitting a limit produces a LOW `secret.session-history-budget`
  finding, so a partial scan never looks like a clean pass. Unreadable transcripts and corrupt
  SQLite files produce `scanner.parse-error`.
- Cursor databases are opened with stdlib `sqlite3` in read-only URI mode (`mode=ro`). If that
  fails, it retries with `immutable=1`, which never writes but ignores an un-checkpointed WAL.
- Turn it off with `--no-session-history`.
- Measured on a real Hermes host: 45,482 files (562 MB) in ~67 s. Opening files dominates, so small
  files are prefetched by 8 threads.

Fix: **rotate the key first.** Moving it out of `.env` doesn't remove the copies already saved in
transcripts. Then delete or redact the old transcripts, `chmod -R go-rwx` the history directory,
and shorten the agent's history retention (or turn off persistence) where the agent has a setting.

### Stray agent instructions (`repo.stray-agent-instructions`)

Coding agents load instruction files from the folder they start in.
[Forever Security](https://forever.security/blog/hijacking-ai-agents-via-downloads-folder) found a
malicious `AGENTS.md` in a customer's `~/Downloads`. A coding agent started there read it and tried
to install a malicious npm package.

asca searches `~/Downloads`, `~/Desktop`, the temp dir (`tempfile.gettempdir()`, plus `/tmp` on
POSIX) and any `--instructions-dir DIR` for these files:

| File | Loaded by |
|---|---|
| `AGENTS.md` | Codex CLI and other AGENTS.md readers |
| `CLAUDE.md`, `CLAUDE.local.md` | Claude Code |
| `GEMINI.md` | Gemini CLI |
| `.cursorrules`, `.cursor/rules/*` | Cursor |
| `.windsurfrules`, `.windsurf/rules/*` | Windsurf |
| `.clinerules` (file or dir) | Cline |
| `.github/copilot-instructions.md` | GitHub Copilot |

- It searches each folder and two levels below it. Symlinked dirs aren't followed, and directories
  with a `.git` aren't entered: instruction files inside repos are expected.
- Matches are MEDIUM. A file is HIGH when the `asca-skills` content rules (prompt injection, hidden
  text, credential access, exfiltration, malicious installs) match at MEDIUM or above. The finding
  lists the matched rules and lines.
- Files are read as text only, at most 512 KiB. Symlinks, FIFOs and devices are never read.
- Turn the default folders off with `--no-stray-instructions`. `--instructions-dir` still adds its
  own folders.

### MCP clients discovered automatically

| Client | File (relative to `$HOME`) |
|---|---|
| Hermes Agent | `$HERMES_HOME/config.yaml` (`mcp_servers`) |
| Claude Code | `.claude.json` (incl. per-project `mcpServers`), `.claude/settings.json` |
| Codex CLI | `.codex/config.toml` (`[mcp_servers.*]`) |
| Gemini CLI | `.gemini/settings.json` |
| goose | `.config/goose/config.yaml` (`extensions`) |
| Cursor / Windsurf | `.cursor/mcp.json`, `.codeium/windsurf/mcp_config.json` |
| VS Code | `Code/User/mcp.json` (Linux, macOS, Windows paths; JSONC) |
| Claude Desktop | `claude_desktop_config.json` (Linux, macOS, Windows paths) |
| Repo-level | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` in every scanned repo |

Use `--mcp-config FILE` to add others (JSON, JSONC, TOML or YAML).

### Tracking new advisories

asca checks the installed Hermes Agent version against three sources:

| Source | Updates | Coverage |
|---|---|---|
| Built-in table (`asca/hermes.py`) | with asca releases | hand-curated; includes advisories feeds lack (e.g. CVE-2026-71963 was missing from OSV/GHSA a month after publication) |
| `--online-advisories` | live, every run | [OSV.dev](https://osv.dev) + [GitHub Advisory Database](https://github.com/advisories). Range matching is done server-side for the exact installed version. Sends package name + version to those services. Set `ASCA_GITHUB_TOKEN` if you hit the anonymous rate limit. |
| `--advisories FILE` | whenever you edit it | your own additions, format: [`examples/advisories.json`](examples/advisories.json) |

Duplicates across sources are merged by alias (CVE ↔ GHSA ↔ PYSEC), keeping the highest severity. A feed outage is reported as a LOW `scanner.feed-unavailable` finding, not a silent pass.

Advisory file fields: `first` plus either `last` (inclusive) or `before` (exclusive, matching NVD's "X prior to Y" wording), and optionally `aliases`, `fixed`, `severity` and `summary`. A top-level `dismissed` list (`{"id", "reason"}`) records IDs you reviewed and chose not to track. asca ignores it, but periodic search jobs should treat it as known so they don't re-report those IDs.

#### Other coding agents: Claude Code, Codex, Gemini CLI, goose, Claude Desktop

On by default (`--no-agent-versions` to skip). asca reads each agent's installed version **from files only**, never running a binary:

| Agent | Version read from |
|---|---|
| Claude Code | `@anthropic-ai/claude-code/package.json` in global npm, nvm, fnm, volta, pnpm and bun folders and `~/.claude/local`; the native installer's `~/.local/share/claude/versions/<version>`, the one `~/.local/bin/claude` links to |
| Codex | `@openai/codex/package.json`; Homebrew `codex/<version>` |
| Gemini CLI | `@google/gemini-cli/package.json`; Homebrew `gemini-cli/<version>` |
| goose | Homebrew `block-goose-cli/<version>` (the curl installer leaves no version on disk) |
| Claude Desktop | `Claude.app/Contents/Info.plist` (macOS) |

Each version is matched against a bundled table (`asca/agentadv_data.py`) built from the GitHub Advisory Database **and each vendor's own repository advisories**. The second source matters: some advisories are published only in the vendor's repo and never reach the global database or OSV. In November 2026 that was 6 for Claude Code and Claude Desktop (including the symlink file write GHSA-5j29-h97v-84ch) and goose's CVE-2026-72718. With `--online-advisories`, OSV.dev, the GitHub Advisory Database and the vendor's repository advisories are queried live as well, and duplicates are merged by alias.

You get one finding per installed agent, e.g. `Claude Code 2.1.128 is affected by 6 known vulnerabilities (4 high, 1 medium, 1 low)`, listing each advisory, which ones have no CVE ID, which are only in the vendor's repo, and the version to upgrade to. A new advisory for your version changes the finding, so `--telegram change` alerts once. Refresh the bundled table with `python3 scripts/update_agent_advisories.py` (read-only GitHub API).

Codex's Plugin4Shell fix (0.146.0) has no published advisory, so it's a hand-curated entry (`CURATED` in `asca/agentvers.py`); Claude Code's is GHSA-pq7j-f95f-qfcv / CVE-2026-86063 (2.1.179).

**Freshness:** if the newest review date (built-in table or your file's `"reviewed_at"`) is older than 30 days, asca adds a LOW `advisories.stale` finding. Bump `reviewed_at` whenever you check for new advisories. A weekly scheduled search that updates it is a good pattern: search NVD, vendor advisories and security news for new IDs, ask a human to confirm candidates, and only then add them to the file.

## Egress auditor (`asca-egress`)

The supply-chain audit looks at what's *installed*. The egress auditor looks at what your agents
actually *talk to*. It is a small logging forward proxy plus a daily diff: "these destinations
are new since yesterday".

```bash
# 1. run the proxy (loopback only; use your supervisor / cron watchdog to keep it up)
python3 -m asca.egress proxy --port 8899 --hermes-home ~/.hermes --sampler-ignore tailscaled

# 2. route an agent or job through it (and optionally name it in reports)
eval "$(python3 -m asca.egress env --port 8899 --label nightly-scraper)"

# 3. once a day: diff vs the learned baseline; Telegram only when something changed
python3 -m asca.egress summary --telegram change --telegram-chat <chat-id> --env-file ~/.hermes/.env

# inspect raw records
python3 -m asca.egress show --since-hours 6 --agent nightly-scraper
```

**What gets flagged** (exit code 1 from `summary`):

| Signal | Why it matters |
|---|---|
| 🆕 New registrable domain (`evil.xyz`, `foo.github.io`) | The classic exfiltration / C2 / surprise-telemetry signal |
| 🔸 New host under a known domain (`uploads.github.com`) | Lower risk, but new capability use |
| 🔁 Known host, first use by this agent | A tool or job reaching somewhere it never did before |
| 🔢 IP-literal destination | Skipping DNS is unusual for legitimate agent traffic |
| 🚧 Direct connection that bypassed the proxy | Something ignores `HTTPS_PROXY` (sampled from `/proc/net/tcp`) |
| ⚠️ No proxy activity in the window | Silence must not look like "all fine" |

The first `summary` run learns a baseline and sends no alert. After that, each run diffs only the
window since the previous run and folds it into the baseline (`--no-learn` to keep it out).

**Attribution.** On Linux, each proxied connection is traced to the client process via
`/proc/net/tcp` → socket inode → `/proc/<pid>/fd`, then up the parent chain. It's labelled by
`ASCA_EGRESS_LABEL` if any ancestor sets it, else a recognised agent (Hermes gateway/TUI/
dashboard, Claude Code, Codex, goose, Gemini CLI), else the command name. Hermes cron jobs
running at the time are recorded from `cron/executions.db`. That is a correlation, not proof.
Other users' processes and non-Linux hosts are logged as `unknown`.

**Privacy and safety.**
- TLS is never intercepted: HTTPS is an opaque `CONNECT` tunnel, so only host, port, timing
  and byte counts are known, and no CA certificate is needed.
- For plain HTTP, the path is kept **without** its query string. Headers, bodies, cookies and
  auth are never written.
- Logs are append-only JSONL, one file per UTC day, mode `0600` in a `0700` directory, pruned
  after `--keep-days`.
- The proxy logs and forwards; it never blocks. It listens on loopback only and refuses
  non-loopback binds unless you pass `--allow CIDR`, because an open proxy is an abuse magnet.

**Limits.**
- It only sees programs that honour `HTTPS_PROXY`/`HTTP_PROXY`. Most Python, Node and Go HTTP
  clients do; raw sockets, some SDKs and malicious code may not.
- The bypass sampler polls, so connections shorter than `--sample-direct` seconds can be missed.
  It's a tripwire, not a complete record.
- For real enforcement, block direct egress at the firewall/container network and allow only
  the proxy out.
- WebSocket and HTTP/2 work through `CONNECT`; plain-HTTP requests are one per connection.

## Fleet patch monitor (`asca-fleet`)

"You're N security fixes behind." It reads the Hermes GitHub releases, pulls the security
fixes out of each release's notes, checks which version every instance you run is on, and
alerts when that picture changes.

```bash
python3 -m asca.fleet check \
  --target home=local:/opt/hermes \
  --target nas=http://nas.tailnet:9119 \
  --target vps=ssh:deploy@vps:/opt/hermes \
  --target box2=docker:hermes-2 \
  --advisories ~/.hermes/asca-advisories.json \
  --telegram change --telegram-chat <chat-id> --env-file ~/.hermes/.env
```

| Target spec | How the version is read |
|---|---|
| `local:/path` | `hermes_cli/__init__.py` in that install dir |
| `http(s)://host:port` | the dashboard's `/api/status` → `version` |
| `docker:<container>[:/path]` | `docker exec <container> cat <path>/hermes_cli/__init__.py` |
| `ssh:<host>[:/path]` | `ssh -o BatchMode=yes <host> cat <path>/hermes_cli/__init__.py` |

Many targets can also go in a JSON file (`--fleet fleet.json`, `{"targets":[{"name":..,"spec":..}]}`).
Remote checks only `cat` a version file. Names and paths are validated, and nothing goes through a shell.

**How fixes are counted.**
- Bullets under a release-notes heading like *Security Fixes* count as **security fixes**, and
  so does any bullet naming a CVE or GHSA ID.
- Bullets under other *Security* headings (e.g. *🔒 Security & Reliability*) count as
  **hardening** and are reported separately, because they're often defence-in-depth rather
  than an exploitable bug.
- Tracked advisories from asca's built-in table and your `--advisories` file are included too.

The counts depend on how releases are written up, so treat them as a floor.

**Alerts** (`--telegram change`):
- **When:** on any new Hermes release, when an instance is upgraded or becomes unreadable, or
  when the feed starts or stops failing. The headline says what it is: "N security fixes behind",
  "N releases behind (no security fixes)", or "up to date".
- **Reminders** (`--remind-days N`, off by default): while an instance stays behind (with or
  without security fixes), the alert repeats every N days instead of going quiet until the next
  change. A reminder restarts the count, and any change alert does too.
- **How long:** headlines, per-instance lines and the dashboard's patch card say how long an instance
  has been behind, e.g. `⏰ Reminder · 🟨 myhost/hermes: 1 release behind for 3 days (v0.23.1 released
  10 Nov, no security fixes)`. Days count from the publish date of the oldest release it's missing. If
  that date is unknown, the count is left out rather than guessed. The count doesn't make `change` alert
  daily: only reminders and real changes send a message.
- **First run:** sends one message if anything is already behind, so a fleet that's behind on
  day one doesn't go unannounced.
- **Failed delivery:** if a Telegram message can't be delivered, the state isn't saved, so it's
  retried on the next run.

**Exit codes:** 0 when every instance is current on security fixes; 1 when one is behind or
unreadable, or the feed failed; 2 on errors.

## Fake-app & skill scanner (`asca-skills`)

Skills are markdown the model obeys and scripts it runs, so a malicious skill can steal keys
without any exploit. In early 2026 hundreds of cloned ClawHub skills (ClawHavoc) did exactly
that: an official-sounding name, a "prerequisite" to download, and an infostealer behind it.
`asca-skills` looks for both halves of that playbook.

```bash
python3 -m asca.skillscan scan                       # auto-discovers Hermes, OpenClaw, Claude, Codex skill dirs
python3 -m asca.skillscan scan ./skills ~/Downloads/new-skill --no-apps
python3 -m asca.skillscan check-name openclaw-core   # before you install something
python3 -m asca.skillscan update-official            # refresh the official list from live sources
```

**Look-alike names.** Skill, plugin, MCP-server, package and app names are compared with an
official list:
- Hermes builtin + trusted skills, the Hermes plugin and MCP catalogs (incl. the removed-plugin
  kill list), OpenClaw's bundled skills and extensions, and the vendors' own packages
  (`openclaw`, `@anthropic-ai/claude-code`, `@openai/codex`, `hermes-agent`, …);
- taken from a bundled snapshot, your local Hermes install, Hermes' cached catalog, and
  `update-official`.

| Trick | Example | Severity |
|---|---|---|
| Homoglyphs (Cyrillic/Greek letters) | `gооgle` | critical / high |
| Digit/letter swaps, `rn`→`m` | `g00gle` | high |
| Brand + "core/helper/pro/…" (fake prerequisite) | `openclaw-core` | high |
| One edit away | `summarise` vs `summarize` | medium |
| Official name + random suffix (ClawHub clones) | `google-qx4` | medium |
| Official name installed from a community hub | `github` from ClawHub | high |
| Plugin under a catalog name, different repo | `homeassistant` from `evil/…` | critical |
| Former project names | `clawdbot`, `moltbot` packages | medium |

**Risky skill content** (every file in the skill folder):

| Category | What it catches |
|---|---|
| prompt-injection | "ignore previous instructions", fake `<system>`/`[INST]` markers, "don't tell the user", "bypass the approval prompt", writing itself into AGENTS.md/MEMORY.md, asking for seed phrases or passwords · **oversight-loosening** (`skill.inject.oversight-loosening`): `--no-verify`, `--no-gpg-sign`, `HUSKY=0`, "proceed without approval", "don't check in", "don't ask before pushing", "skip code review / hooks / verification" |
| hidden-content | invisible Unicode tag characters (decoded in the report), bidi overrides, zero-width runs, agent-directed text in HTML comments, base64 blobs that decode to commands |
| credential-access | `~/.ssh`, cloud/registry creds, agent `.env`/`auth.json`, keychain dumps, browser password/cookie DBs, crypto wallets, full env dumps |
| exfiltration | request-capture services, paste sites and chat webhooks, raw-IP URLs, file uploads |
| malicious-install | decode-and-run, removing macOS quarantine / disabling Defender, fake password dialogs (AMOS), reverse shells, password-protected archives, `curl \| sh` from unknown hosts, executables presented as prerequisites, bundled binaries |
| bytecode (PyCache Trap) | `__pycache__/*.pyc` that Python would run instead of the visible source: a cache whose header matches the `.py` (or an unchecked hash-based cache) but whose code differs (`skill.bytecode-mismatch`, high) · a `.pyc` with no `.py` beside it, which `import` runs directly (`skill.bytecode-sourceless`, high) · orphan, foreign-version or malformed caches (`skill.bundled-bytecode`, low/medium) |

- **Credential access plus an outbound sink in the same skill is critical** (the stealer shape).
- **Oversight-loosening** ([arXiv 2610.37734](https://arxiv.org/abs/2610.37734): about 1 in 17 skills carry such a directive, and open-source scanners catch at most 46%):
  - Medium by default.
  - High when it's a concrete flag (`--no-verify` and the others) or sits in a script, *and* the skill also runs shell, `sudo` or package installs.
  - Low when scoped to CI/automation, or in a documentation table.
  - Tightening ("never use `--no-verify`", "never ask the user for their password", items under a "Never do these" heading) is ignored, as is UX guidance about clarifying questions.
- **Bytecode** ([PyCache Trap, arXiv 2610.10612](https://arxiv.org/abs/2610.10612): a swapped cache got past seven skill scanners in 94–100% of cases):
  - asca reads each `.pyc` header and decides what CPython would do with it.
  - It compares code objects only for caches Python would actually load: it compiles the visible source and loads the cache body in a separate `python -I -S` helper (isolated mode, no `site`/`.pth`), never running either.
  - Caches Python generated itself match their source and stay quiet. Stale caches are ignored, because Python recompiles them.
  - Limit: caches for another Python version can't be compared and are reported low. With `PYTHONPYCACHEPREFIX` set, Python ignores in-tree `__pycache__` folders, but asca still reports a planted one.
- **Context adjusts severity:**
  - Prose mentions count lower than the same text in a script.
  - Chat-template markers in quotes or code fences are documentation.
  - Negations ("never start without the user's consent") are ignored.
  - Hermes builtin skills and security-topic skills (which quote attacks on purpose) are
    lowered and labelled. Hidden-content and encoded-payload findings are never lowered.
- **Tested both ways.** Fixtures modelled on the published ClawHavoc/AMOS samples are all
  caught. Hermes' official skills, scored as if their origin were unknown, produce 0 high or
  critical findings (re-checked for v0.3.0 on 186 skills from Hermes 0.23.0). Forged PyCache
  Trap caches (timestamp and unchecked-hash variants) are caught without being executed.

Reports, baselines, exit codes and `--telegram never|fail|always|change` work exactly like `asca`.
It never executes anything it scans.

**Warn or block: the per-rule gate.** By default `asca-skills` only reports, because pattern rules
are tripwires. `--gate` turns chosen rules into hard stops (exit code **3**), so the same scanner
can be a pre-install hook or CI step:

```bash
asca-skills gates                                          # list presets and their rules
asca-skills scan ~/Downloads/new-skill --no-apps --gate default && cp -r ~/Downloads/new-skill ~/.hermes/skills/
asca-skills scan --gate strict --gate 'skill.exfil.*:medium'   # presets + your own rule globs
asca-skills scan --gate default --quarantine ~/.local/state/asca/quarantine   # move blocked skills out
asca-skills restore <name> --quarantine ~/.local/state/asca/quarantine        # undo
```

| Preset | Blocks |
|---|---|
| `default` | near-certain signals only: hidden Unicode-tag instructions, base64 that decodes to commands, decode-and-run, credential access + outbound sink in one skill, fake password dialogs, Gatekeeper/Defender tampering, reverse shells, plugins impersonating a catalog entry, bytecode that runs different code than its source |
| `strict` | `default` plus the ClawHavoc delivery tricks (password-protected archives, "run what's in this zip", capture services), keychain dumps, browser/wallet theft, concealment and override injections, bytecode with no source, and look-alike names at high or above |

- **Context still applies:** a gate rule blocks only at high severity or above unless you add a
  suffix such as `:medium`. Quoted examples and security docs still only warn.
- **Baselines still apply:** suppressed findings never block.
- **Quarantine is safe to undo:** it moves the skill folder, never deletes it, records why in
  `quarantine.json`, and skips Hermes builtin skills (Hermes would restore them anyway).
- **Measured:** on the ClawHavoc-style fixtures, `default` blocks 3 of 6 and `strict` blocks 5
  of 6 (the one-letter typosquat stays a warning). Hermes' 210 official skills: 0 blocked
  with either preset.

Exit codes for `asca-skills scan`: 0 PASS, 1 FAIL (warnings at or above `--fail-on`), 2 error,
**3 BLOCKED** (a gated finding; takes precedence).

## IDE & agent inventory (`asca inventory`)

Coding agents increasingly arrive as IDE extensions, and extensions auto-update. On 29 Oct 2026
the Cursor extension marketplace served a tampered **Anthropic.claude-code 2.1.312/2.1.313** that
added an attacker SSH key, persistence and a reverse SSH tunnel
([Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice)). The first
questions after a notice like that are "did I have it, since when, and what else changed?" To
answer them you need a record from *before* the incident. `asca inventory` keeps that record.

```bash
python3 -m asca inventory                         # first run learns silently; later runs diff
python3 -m asca inventory --telegram change --env-file ~/.config/asca/telegram.env
python3 -m asca inventory --write-approved ~/.config/asca/inventory-baseline.json   # approve today's publishers
python3 -m asca inventory --baseline ~/.config/asca/inventory-baseline.json
```

**What it inventories** (read-only; it never runs `code`, `npm`, `git` or anything it finds):

| Source | Where | Identity / version / publisher |
|---|---|---|
| VS Code, Insiders, Cursor, Windsurf, VSCodium (+ their `-server` remotes) | `~/.vscode*/extensions`, `~/.cursor/extensions`, … (`--ide-dir LABEL=PATH` for others) | `extensions.json` + each `package.json`: id, version, publisher, marketplace publisher ID, gallery vs VSIX |
| MCP servers | Claude Code, Cursor, Windsurf, Gemini, VS Code, Codex, goose, Claude Desktop configs, Hermes `config.yaml` | package scope / image owner / URL host; pinned version; hash of command, args, URL and env/header **names** (values are never read into the inventory) |
| Hermes plugins | `$HERMES_HOME/plugins` | catalog repo owner or git remote; version + catalog/HEAD commit (read from `.git` as text) |
| Claude Code plugins | `~/.claude/plugins/installed_plugins.json` | marketplace, version |
| OpenClaw extensions | `~/.openclaw/extensions` | npm scope/author, version |
| Agent skills | Hermes, OpenClaw, Claude Code, Codex skill folders | Hermes provenance: bundled (manifest hash), hub (lock content hash), local |

Each extension and plugin is hashed over its **code and manifests** (JS/TS, Python, shell,
native binaries, `package.json`, `plugin.yaml`…), not docs or images. Skills are hashed over all
files. Budgets keep runs cheap and comparable: `--item-cap-mb` (64), `--node-modules-cap-mb`
(16) and `--total-mb` per run (1024). Files are cut in a fixed order, so a partly hashed item is
still compared like for like, and it's listed as a LOW `hash-budget` finding.

**What changes mean:**

| Change | Severity |
|---|---|
| Installed build is on the known-bad list (built in: the two Cursor builds above; add your own with `--known-bad`) | 🟥 critical, every run until removed |
| Files changed but the version didn't (third-party extension, plugin, hub skill) | 🟧 high (tamper) |
| Same item, different publisher or marketplace publisher ID; or the same name reappears from another publisher | 🟧 high |
| New item | 🟨 medium |
| First item from a publisher that isn't approved | 🟨 medium |
| MCP server launch definition changed | 🟨 medium |
| Hermes persona (`SOUL.md`) changed, or who can command the agent changed (allow lists, allow-all switches, home channel) | 🟨 medium |
| Extension switched from marketplace to side-loaded VSIX | 🟨 medium |
| Bundled Hermes skill edited locally | 🟦 low |
| Version updated, your own skill edited, item removed | digest only, no alert |

- **Approving publishers:** `approved_publishers` in the `--baseline` file stops the
  new-publisher finding for publishers you trust. The new item itself is still reported.
- **Suppressing a finding:** `suppress` entries work exactly as in `asca`.
- **Alerts:** `--telegram change` alerts when a finding at or above `--alert-on` (default medium)
  appears that wasn't alerted before. The first run learns silently, unless it already finds a
  known-bad build. If delivery fails, state isn't saved, so the alert is retried next run.
- **Exit codes:** 0 = nothing at or above `--fail-on` (high), 1 = something is, 2 = error
  (including unreadable `extensions.json` or agent config, which also show as HIGH parse errors).

**Limits:**
- **Version-number tampering:** a malicious build that ships as a *new version* (as the
  Cursor one did) shows as a routine version update until it's on the known-bad list. The
  inventory's job there is the record: which version you had and when it arrived.
- **Offline only:** no marketplace lookups, so it can't tell you a version is bad before
  someone publishes that.
- **Hashing:** files outside the hashed set (docs, images, beyond the caps) aren't watched.
- **Local edits:** a change to your own or agent-edited skills is reported as an edit, not
  tamper, because those change legitimately all the time.
- **Platforms:** Linux/macOS/Windows paths are covered; extension dirs on other drives need
  `--ide-dir`.

**Running it daily:**
- **macOS (launchd):** see [docs/macos.md](docs/macos.md). It sets up the inventory together with the full audit and the skills scan.
- **Linux:** `scripts/asca-daily.sh`, or a cron line such as
  `15 8 * * * cd ~/Projects/Agent_Supply_Chain_Auditor && python3 -m asca inventory --format none --telegram change --env-file ~/.config/asca/telegram.env`.

## Agent config tamper and Python startup hooks (part of `asca`)

Two checks in the main audit, both on by default (`--no-agent-config`, `--no-python-startup` to skip).

### Agent configuration tamper

In Oct 2026 Symantec described an unauthorized relay service that installs the *genuine*
Codex and Claude Code CLIs, then rewrites their config: it sets
`sandbox_mode = "danger-full-access"`, allows network access from the write sandbox, points
`base_url` / `ANTHROPIC_BASE_URL` at its own servers, installs its own token as a user
environment variable, and switches off telemetry and error reporting
([report](https://www.security.com/threat-intelligence/openai-claude-unauthorized-relays)).
HiddenLayer's "Man-in-the-Model" research shows why the endpoint matters: whoever answers the
model calls can steer what a coding agent runs.

**Where it looks:** `~/.codex/config.toml` (incl. profiles and `model_providers`), Claude Code
`settings.json` / `settings.local.json` / managed settings (`env`, `permissions`), Hermes
`config.yaml` (every `base_url`, `approvals.mode`), shell profiles (`.zshrc`, `.bashrc`, …) and
the process environment.

| Finding | Severity |
|---|---|
| Model endpoint on a known relay domain (Symantec's published list) | 🟥 critical |
| Endpoint override **plus** a disabled sandbox/approvals, telemetry off or a token in config (the relay combination) | 🟧 high |
| Codex `danger-full-access`, write-sandbox network access, `approval_policy = "never"` with full access; Claude Code `bypassPermissions`; Hermes approvals off | 🟧 high |
| Endpoint on an unknown host | 🟨 medium |
| `ANTHROPIC_AUTH_TOKEN` / `CODEX_API_KEY` set in a settings or shell file (the value is never read into the report) | 🟨 medium |
| Telemetry / error reporting off | 🟦 low |
| Endpoint on a well-known provider (OpenRouter, Together, Groq, …) | ⬜ info |

Each signal alone is often a deliberate choice: a company gateway, a sandbox-less container,
privacy settings. Accept those in your baseline. Official, local and private-network endpoints
(Ollama, LiteLLM on your LAN) are never flagged.

### Python startup hooks

Python runs every `import …` line in any `*.pth` file in site-packages, and imports
`sitecustomize`/`usercustomize`, at **every** start, pip included. Both LiteLLM compromises
used this: 1.82.8 shipped `litellm_init.pth` (Mar 2026), 1.107.0 shipped `cook.pth` +
`sitecustomize.py` in every wheel (Oct 2026).

**Where it looks:** the Hermes venv and bundled Pythons, user site-packages, pipx and uv tool
environments, every virtualenv under `--repos` (4 levels deep), system site-packages, and
`--python-site DIR`.

| Finding | Severity |
|---|---|
| Known-bad distribution installed (litellm 1.82.7, 1.82.8, 1.107.0) or known-bad hook file (`litellm_init.pth`, `cook.pth`) | 🟥 critical |
| Executable `.pth` or `sitecustomize` that no installed package owns (not in any `RECORD`), or that uses exec/eval/base64/subprocess/sockets/URLs | 🟧 high |
| Executable `.pth` or `sitecustomize` owned by an installed package | 🟨 medium, naming the package |

Standard hooks stay quiet when **both** name and content match: virtualenv, setuptools'
distutils shim, editable installs (setuptools, hatch, pdm), namespace packages, pywin32,
coverage. Path-only `.pth` files are ignored. A standard *name* with extra code is flagged.
Files are read as text; no interpreter is started and nothing is imported.

**Limits:** the relay domain and bad-package lists are as published (Oct 2026). Windows
user-scope environment variables in the registry aren't read. A malicious hook installed by a
package you trust and named after a standard tool's file, with standard-looking content,
would pass.

## Repo hooks and GitHub token scopes (part of `asca`)

### Repo-supplied agent hooks (on by default; `--no-repo-hooks` to skip)

A cloned repository can make your agent or editor run commands nobody typed. asca reads these
files in every repo under `--repos`:

| File | What can run |
|---|---|
| `.claude/settings.json`, `.claude/settings.local.json` | Claude Code `hooks` (SessionStart, PreToolUse, …), `statusLine`, `apiKeyHelper`; plus `env` endpoint overrides, `permissions`, `enableAllProjectMcpServers` |
| `.cursor/hooks.json` | Cursor hooks (beforeShellExecution, afterFileEdit, …) |
| `.vscode/tasks.json` | Tasks with `"runOn": "folderOpen"` (VS Code, Cursor, Windsurf) |
| `.gemini/settings.json` | Gemini CLI `hooks` (SessionStart, BeforeTool, …; [docs](https://geminicli.com/docs/hooks/)). Project settings override the user's. JFrog lists it among the AI/IDE hook files (with `.claude/settings.json`, `.cursor/mcp.json` and `.vscode/tasks.json`) in 42 GitHub repos hijacked by the testmetest campaign ([JFrog, Oct 2026](https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/)). Its `mcpServers` are audited like a repo's `.mcp.json`. |

A file **committed** to the repo travels with every clone, so it's rated higher than your own
uncommitted `settings.local.json`. asca checks this by reading `.git/index` as bytes; it never
runs `git`. If the index is in v4 format, which asca can't read, files are treated as committed.

| Finding | Severity |
|---|---|
| Repo settings point the model endpoint at a known relay domain | 🟥 critical |
| Hook, status line or folder-open task whose command fetches or sends data (curl, wget, `\| sh`, base64, `/dev/tcp`, URLs, `python -c` …) | 🟧 high |
| Committed `apiKeyHelper`, `bypassPermissions`, or an endpoint override to an unknown host | 🟧 high |
| Any other committed hook or folder-open task; `Bash(*)` pre-approved; `enableAllProjectMcpServers` | 🟨 medium |
| An uncommitted plain hook (your own local settings) | 🟦 low |

Local and private endpoints in repo settings are never flagged. A changed command gets a new
fingerprint, so a hook you accepted in the baseline is reported again if it changes.

### Coding agents in GitHub workflows that anyone can trigger (on by default; `--no-ci-agents` to skip)

A workflow that runs Claude Code, Gemini CLI, Codex or GitHub's AI action on an event that anyone
with a GitHub account can cause (`issues`, `issue_comment`, `pull_request_target`, `discussion`)
hands a stranger's text to an agent that holds the job's token and secrets. In 2026 researchers
used this to steal keys from Claude Code, Gemini CLI and Copilot agents through issue and PR text
([Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/);
[Aikido PromptPwnd](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents)). The vendors
patched related flaws in their actions
([GHSA-8q5r-mmjf-575q](https://github.com/anthropics/claude-code-action/security/advisories/GHSA-8q5r-mmjf-575q),
[GHSA-wpqr-6v78-jr5g](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g)),
but the workflow itself decides who can start the agent and what it can reach.

asca reads `.github/workflows/*.yml` as text. It never runs anything, and only parses files that
use a known agent action (`anthropics/claude-code-action`, `google-github-actions/run-gemini-cli`,
`openai/codex-action`, `actions/ai-inference`, …) or call an agent CLI (`claude -p`, `gemini`,
`codex exec`, `copilot` …) in a `run:` step.

| Finding | Severity |
|---|---|
| Untrusted trigger, and the agent can be steered and holds something worth stealing: issue/PR/comment text pasted into its prompt (`${{ github.event.issue.body }}` …), a `pull_request_target` job that checks out the PR's code first (so the agent reads the attacker's `CLAUDE.md` / `AGENTS.md` / `.mcp.json`), or claude-code-action's write-access check switched off (`allowed_non_write_users`, `allowed_bots: '*'`), together with a write token, extra secrets or an OIDC token | 🟧 high |
| The same, but the job is read-only with no secrets in reach; or claude-code-action's write check is off in the vendor's documented triage setup (only `issues`/`pull-requests` write and the model key); or text is pasted into the prompt of a job that a write-access gate starts; or an ungated agent holds a write token or secrets | 🟨 medium |
| Ungated agent in a read-only job without secrets · an agent action not pinned to a commit SHA (`repo.ci-agent-unpinned`) · an agent workflow asca couldn't parse | 🟦 low |

What counts as a gate: claude-code-action's default write-access check; an `if:` that tests
`author_association` for OWNER/MEMBER/COLLABORATOR, a specific actor or an allow list of actors, a
same-repo PR (`head.repo.full_name == github.repository`), or an earlier job's `authorized`-style
output; or a step that queries the collaborator permission API. These don't limit who runs it, so they
don't count: checking the repository name, the commenter being the issue's author, `user.type != 'Bot'`,
or a trigger phrase like `@claude` in the comment. `pull_request` from a fork gets no secrets and a
read-only token, so it isn't flagged. codex-action keeps the OpenAI key in its own proxy, so that key
isn't counted as reachable. Uncommitted workflows are one level lower.

**Benchmark (Nov 2026, 794 real workflow files):** the vendor examples, 18 large agent/tooling repos
and 106 repos found by GitHub code search for agent actions; 188 of the files run an agent (a few
repos appear in two samples). HIGH went to 6 jobs,
each read by hand: 3 paste issue or PR text into an agent holding a write token or extra secrets, 2
switch the write check off with extra bot PATs in the job, and 1 does both on `pull_request_target`
with a PR-head checkout. claude-code-action's own `issue-triage.yml` example is MEDIUM. asca's
YAML reader now resolves anchors and aliases (`&steps` / `*steps`), which real workflows use to
share steps between jobs. Over 2,069 YAML files the reader parsed 33 more than before and lost none;
the 15 whose result changed differ only where an anchor is now resolved.

### Install hooks and secret-dumping workflow steps (wfx) (on by default; `--no-install-hooks` to skip)

In November 2026 the wfx credential stealer ([SafeDep](https://safedep.io/blog/github-actions-wfx-credential-stealer), [Aikido](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories)) used stolen GitHub tokens to push two payloads into thousands of repositories:
- **An npm hook (771 repos):** a `postinstall` script that silently runs a hidden `.ci-xxxxxx.sh`, so every `npm install`, on CI or a laptop, sends secrets, cloud credentials and AI-tool keys out.
- **Workflow steps (7,309 repos):** one copies the Actions runtime token into `$GITHUB_ENV`, the next passes `${{ toJSON(secrets) }}`, every secret in the repo, to the payload.

asca reads every `package.json` (up to 3 folders deep, not `node_modules`) and every `.github/workflows/*.yml` in your repos, as text:

| Finding | Severity |
|---|---|
| `repo.wfx-indicator`: wfx's published indicators: a `.ci-xxxxxx.sh` runner, the `exit 42` sentinel, `WF_CALLBACK` / `WF_CTOKEN`, its exfil servers, a `build-audit-xxxxxx.yml` workflow | critical |
| `repo.install-hook`: a lifecycle script that runs a hidden file, hides its output while running a file, pipes a download to a shell, decodes or `eval`s, or whose file uploads data or reads credential files and uploads | high |
| `repo.workflow-secret-dump`: the Actions runtime or OIDC request token persisted by name into `$GITHUB_ENV` / `$GITHUB_OUTPUT` or sent to a hard-coded URL; `toJSON(secrets)` in the same workflow, or in a step that sends data out | high |
| `toJSON(secrets)` on its own (often deliberate, e.g. a secrets-to-env action) | medium |
| `toJSON(vars)` (every repository variable) | low |

A hook or workflow that isn't committed yet is one level lower. In the daily audit only high and critical install hooks are reported, because your own `prepare: husky` is expected; `asca check-repo` lists every hook. Using the runtime token normally (requesting an OIDC token, cache tools) isn't reported.

**Tested** on 788 workflow files from 124 repos (vendor examples, large projects and agent workflows) plus 195 found by searching GitHub for `toJSON(secrets)`/`toJSON(vars)`: 0 high. The 93 medium findings are `toJSON(secrets)` used on purpose, mostly with secrets-to-env actions. On 76 repos found by searching GitHub for install hooks, with the files those hooks run: 1 high, a script that really does POST to a service API during install. On 39 popular JS projects: 0 high.

**Limits:** wfx reverted most commits within minutes, so on disk you'll find it only in a checkout pulled in that window or where the revert failed. Its traces on GitHub (probe pull requests, deleted runs) need an online check.

### GitHub token scopes (opt-in, online: `--github-token-scopes`)

Agents and the tools they call reuse any GitHub credentials they can find: the `gh` login in
`hosts.yml`, `GH_TOKEN`/`GITHUB_TOKEN`, and `~/.git-credentials` (including Hermes'
`$HERMES_HOME/home/.git-credentials`). A prompt injection gets the token's full rights.

GitHub only reveals a classic token's scopes in the `X-OAuth-Scopes` response header. So this
check makes **one HTTPS request per distinct token**, sent only to that token's own host
(`api.github.com`, or `https://<host>/api/v3` for GitHub Enterprise Server). That's why it's
off unless you ask for it. Tokens are never printed; findings show a 4-character prefix, the
length and a short hash.

| Finding | Severity |
|---|---|
| Scopes `delete_repo`, `admin:org`, `admin:enterprise`, `site_admin`, `admin:org_hook`, `admin:public_key` | 🟧 high |
| Scopes `workflow`, `write:packages`, `delete:packages`, `admin:repo_hook`, `user`, `codespace`, signing-key admin | 🟨 medium |
| Classic token with no expiry; stored token that no longer works (401); check failed | 🟦 low |
| Fine-grained token: GitHub doesn't expose its permissions, so asca lists it and tells you where to review it | ⬜ info |

**Limits:**
- **Keyring storage:** `gh`'s default store (macOS Keychain, OS keyring) isn't read, so on a
  Mac the `gh` login is usually invisible to asca unless `GH_TOKEN` is set.
- **Fine-grained and GitHub App tokens:** their permissions can't be checked.

## Secrets in agent allow lists ("don't ask again") (part of `asca`)

When you approve a command with **"Yes, and don't ask again"**, Claude Code saves the *literal*
command as a permission rule, e.g. `Bash(PGPASSWORD=… psql -h db.prod…)`, in
`<project>/.claude/settings.local.json`. Claude Code excludes that file only in your **global**
git config, never in the repo's `.gitignore`, so it's easy to commit. Apiiro found 104,185
public copies and 1,122 with a real secret; many were passwords next to a host that neither
gitleaks nor TruffleHog flagged
([Apiiro, Nov 2026](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again)).

On by default; `--no-agent-allowlist` to skip.

**What it reads** (as text; nothing is executed and `git` is never run):

| Where | What |
|---|---|
| `~/.claude/settings.json`, `settings.local.json`, managed settings, every repo's `.claude/settings*.json` | Claude Code `permissions.allow` / `ask` / `deny` rules |
| `~/.claude.json` | older Claude Code's per-project `allowedTools` |
| VS Code, Insiders, Cursor, Windsurf, VSCodium user settings; every repo's `.vscode/settings.json` | `chat.tools.terminal.autoApprove` and `chat.tools.urls.autoApprove` ([VS Code docs](https://code.visualstudio.com/docs/agents/run/approvals)), plus the older `chat.agent.terminal.allowList` / `denyList` |
| Every repo under `--repos` | whether `.claude/settings.local.json` is committed (`.git/index`) or not excluded by the repo's own `.gitignore`; committed `.specstory/` transcripts |

| Finding | Severity |
|---|---|
| Provider key, or a password/token for a public host, in an allow rule (`secret.agent-allowlist`) | 🟧 high |
| `.claude/settings.local.json` committed and holding a secret | 🟧 high |
| Password for a local/private host in an allow rule; committed `settings.local.json` without a secret; committed `.specstory/` transcripts | 🟨 medium |
| `.claude/` exists but the repo's `.gitignore` doesn't exclude `settings.local.json` (fix: `echo '.claude/settings.local.json' >> .gitignore`) | 🟦 low |

Findings show the rule with the secret redacted (4-character prefix, length and short hash).
The remediation is ordered:
1. Rotate first: removal doesn't clear history, forks or clones.
2. `git rm --cached` and the repo `.gitignore`.
3. Delete the rule.
4. Use `$VAR` in commands.
5. Approve patterns like `Bash(npm run:*)` instead of literal commands.

### Passwords typed into commands (all secret scans)

Provider keys have recognisable prefixes; passwords don't. asca now also detects these in every
secret scan (allow rules, `.env`/config files, MCP definitions and agent session history):

- **Environment variables:** `PGPASSWORD=`, `MYSQL_PWD=`, `REDISCLI_AUTH=`, `SSHPASS=`.
- **Command options:** `mysql -p<pw>`, `--password=`, `sshpass -p`.
- **Credentials in URLs:** `user:pass@host` (postgres, mysql, mongodb, redis, amqp, http(s), ftp, smtp, ldap).
- **HTTP auth:** `curl -u user:pass`, `Authorization: Bearer <token>` (JWTs included).

**Severity follows the host:** public host is 🟧 high (`secret.command-password`). Loopback,
private ranges, `*.local`/`*.internal`, bare compose service names (`db`, `postgres`) and
documentation hosts (`example.com`, `*.test`, TEST-NET) are 🟦 low
(`secret.command-password-private`); in an allow rule that becomes medium. A database command
with no host counts as local (it uses the socket).

**Not reported:**
- Variables (`$PGPASSWORD`, `${DB_PASS}`, `$(…)`) and placeholders (`<password>`, `***`,
  `YOUR_TOKEN`).
- Common example passwords (`password`, `changeme`, `postgres:postgres`) and URLs without a host.
- Regex and `sed` fragments, and phrases (`a%20secret`).

**False-positive benchmark (0 hits):** 15,685 benign files, 5.2 million lines, covering
1,068 official Hermes skill files, 1,011 host skill/plugin files, 1,991 repo files and the
11,615-file Hermes `site-packages`. The first run had 13 hits, all fixed and kept as
regression tests.

**Real host:** on the maintainer's Hermes host it found one genuine leak the old patterns
missed. An OpenRouter token sent as `Authorization: Bearer` in a `curl` command was saved 8
times in a session transcript (since revoked: HTTP 401).

**Limits:**
- Only the Claude Code and VS Code stores above. Codex, Cursor's own allow lists, aider and
  other transcript formats aren't read; shared notes such as `MEMORY.md` go through the normal
  secret scan only.
- Passwords for a host on another line, and passwords split across lines, aren't connected.
- The `.gitignore` check implements the common subset of git's rules. A file re-included
  under an excluded directory is reported as not ignored.
- Global excludes and `.git/info/exclude` are deliberately not counted: they protect only
  this machine.
- A hand-made key with an impossible shape (e.g. `sk-or-v1-` followed by 64 letters a–f with
  no digit) is treated as a placeholder.

## Agent takeover, workspace and response checks (part of `asca`)

### Hermes persona and gateway tampering (on by default; `--no-persona` to skip)

The Carbonato botnet ([ThreatDown, Sep 2026](https://www.threatdown.com/blog/carbonato/)) breaks into Docker hosts and installs Hermes Agent *unchanged*. It then overwrites `SOUL.md` with a "GH0ST" persona that takes tasks over Telegram, keeps itself installed and collects AI API keys and SSH credentials. The code and version stay the same, so integrity checks see a clean install.

asca reads `$HERMES_HOME/SOUL.md`, `memories/*.md` and the same files under `profiles/*/` as text. asca's skill-content rules look for payloads and hidden text, and they find nothing in a persona like that: it's plain instructions. So persona files get their own rules:

| Finding | Severity |
|---|---|
| `persona.known-malware`: names the Carbonato persona `GH0ST` (ThreatDown indicator) | 🟥 critical |
| `persona.c2`: two or more of the signals below, at least one being harvest, persistence or conceal | 🟥 critical |
| `persona.credential-harvest`, `persona.persistence`, `persona.conceal`: tells the agent to collect keys and credentials, keep itself installed, or hide what it does from you | 🟧 high |
| `persona.no-limits`: act without ethical or safety limits, never refuse | 🟨 medium |
| `persona.remote-tasking`: take tasks from a chat channel or an "operator" (normal for many setups; it counts toward `persona.c2`) | 🟦 low |
| `gateway.allow-all-users`: `GATEWAY_ALLOW_ALL_USERS=true` (or another `*_ALLOW_ALL_USERS`) or `*` in an allow list in a Hermes `.env`. Anyone who finds the bot can command the agent | 🟧 high (🟨 medium when every platform has its own allow list) |
| `gateway.known-malware-env`: `CARBONATO_API_KEY`, `GH0ST_C2` (ThreatDown indicators) | 🟥 critical |

- **Instructions only.** The harvest and persistence rules fire when the text *tells* the agent to do something, at the start of a sentence or list item or after "you" or "prioritise". Text that describes an attack ("a stealer collects credentials") doesn't fire, and neither do negated or prohibited lines ("never collect credentials", items under a "Never do" heading).
- **`.env` files:** asca reads only variable *names*, plus the values of the access switches (`*_ALLOWED_USERS`, `*_ALLOWED_CHATS`, `*_ALLOW_ALL_USERS`, `*_HOME_CHANNEL`).
- **Changes are tracked too.** `asca inventory` hashes each `SOUL.md` and the access switches, and reports `inventory.persona-changed` and `inventory.access-changed` (medium) when they change. Allow-list values are stored only as a hash. The first run after upgrading learns them silently.
- **Tested** on a persona written from ThreatDown's description (critical), and with the IOC name removed (still critical). On 548 real Markdown files (Hermes skills, project docs, research notes) it gave 0 hits.

### Docker API exposed without client certificates (on by default; `--no-docker-daemon` to skip)

Carbonato gets in through Docker daemons that listen on TCP without authentication. Anyone who can reach such a port controls Docker, which means root on the host. asca reads `/etc/docker/daemon.json` (also rootless and snap), docker's systemd units and drop-ins (`ExecStart= … -H tcp://…`, honouring `ExecStart=` resets), and `/etc/default/docker` / `/etc/sysconfig/docker`. It never contacts the daemon.

| `host.docker-api-exposed` without `--tlsverify` | Severity |
|---|---|
| all interfaces (`tcp://0.0.0.0`, `tcp://:2375`, `[::]`) | 🟥 critical |
| a specific non-loopback address (LAN, VPN, tailnet) | 🟧 high |
| loopback only | 🟨 medium |

`--tls` without `--tlsverify` encrypts the traffic but still lets anyone in, so it counts as unauthenticated. Docker Desktop on macOS has no TCP option (its "expose on 2375" switch exists on Windows only), so on a Mac this check finds nothing.

### Symlinks that lead out of a repo or the agent home (on by default; `--no-symlinks` to skip)

In [CVE-2026-103916](https://www.endorlabs.com/learn/docker-sandboxes-vulnerability-lets-ai-agents-access-sensitive-files-outside-their-sandbox-cve-2026-103916) (Endor Labs), a sandboxed agent planted a symlink in its workspace. A later copy by the operator followed it and read or wrote host files outside the sandbox. A link left behind is the trap even after the agent has gone. asca lists links with `os.readlink` in every repo under `--repos` and in the Hermes home (caches and session folders are skipped). Targets are never opened or followed.

| `repo.symlink-escape` | Severity |
|---|---|
| target is a credential location (`~/.ssh`, `~/.aws`, `.env`, `auth.json`, `.git-credentials`, wallets, keychains, browser profiles, agent homes) or a whole home folder / `/` | 🟧 high |
| committed to the repo and pointing outside it | 🟨 medium |
| any other link leaving the repo or agent home | 🟦 low |

Links inside `node_modules`, virtualenvs and `.git` are skipped, because package managers make them on purpose. Links into `/tmp`, `/run` and macOS `/var/folders` (sockets that get new names on every restart) are skipped unless they point at a credential.

### MCP servers that are archived and will never be patched

Anthropic moved 13 of its original reference MCP servers to [servers-archived](https://github.com/modelcontextprotocol/servers-archived): no security fixes will come. [Glow Labs' MCPhantom research](https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-mcp-servers-from-training-data) (Nov 2026) found coding agents still installing them from their training data. One of them, the Puppeteer server, has a prompt-injection-to-command-execution bug its maintainers declined to fix. Before this check, pinning such a server made asca's "unpinned" finding go away, even though no fixed version will ever exist.

- **`mcp.archived-server`:** high for `server-puppeteer`, medium for the rest (`server-github`, `-postgres`, `-slack`, `-brave-search`, `-google-maps`, `-gitlab`, `-gdrive`, `-redis`, `-aws-kb-retrieval`, `-everart`, PyPI `mcp-server-sentry` and `mcp-server-sqlite`).
- **Where the list comes from:** package names are read from each server's `package.json` / `pyproject.toml` in the archive repo. `mcp-server-git` isn't on it, because it went back to the maintained repo.
- **The fix names the vendor's own server where one exists:** GitHub's `github-mcp-server`, Microsoft's `@playwright/mcp`, `@brave/brave-search-mcp-server`, Redis' `mcp-redis`, `@sentry/mcp-server`.
- **Add your own:** `--known-archived FILE`, one package name per line.

### What to do when a key leaked: provider steps and the AWS card

Every secret finding (config, transcripts, allow rules, MCP `env` …) now carries the steps for its provider, instead of a generic "rotate it": where to revoke the key (Anthropic, OpenAI, OpenRouter, GitHub, Slack, Telegram's @BotFather, Google, Stripe, Hugging Face), what to check afterwards, and for private keys and wallets what can't be revoked.

For AWS access key IDs, asca reads `~/.aws/credentials` and `~/.aws/config` locally and adds a **blast-radius card** to the finding:
- which profile the key is, and whether it's a long-lived IAM user key (`AKIA…`) or temporary (`ASIA…`, which expires on its own)
- which roles that profile can assume through `source_profile`
- the `aws iam` commands to deactivate, replace and delete it, and the CloudTrail lookup to see what it did

AWS isn't called and the secret access key is never read into a report, so the card says what's local and leaves effective permissions to `aws iam`. A key that isn't in your credentials file is labelled as someone else's or an old one. `~/.aws/credentials` is also checked for group or world read permissions.

## Check a repo before you open it (`asca check-repo`)

Fake recruiters have sent developers, crypto and fintech especially, "take-home tests" that run code the moment the repo is opened in an IDE or `npm install` runs. `asca check-repo` runs asca's repo checks on one folder, offline, and prints one verdict before you open it:

```bash
python3 -m asca check-repo ~/Downloads/take-home-test
python3 -m asca check-repo ~/Downloads/take-home-test --telegram always --env-file ~/.hermes/.env   # verdict on your phone
```

- ⛔ **Don't open it yet:** a high finding, for example a folder-open task that runs `curl … | sh`, an install script whose file runs commands and talks to the network, wfx's hidden `.ci-*.sh` hook or a workflow step that dumps every secret, a link to `~/.ssh`, or an archived Puppeteer MCP server.
- ⚠️ **Check these first:** medium findings, such as a committed IDE hook, or an install script that runs a repo file you should read first.
- ✅ **No red flags:** low notes only, such as `prepare: husky`.

**What it checks:** git config that runs programs; IDE and agent hooks that run on open; project MCP configs; saved allow rules; agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, Copilot instructions, `.claude/` commands and skills) against the skill-content rules; coding agents in `.github/workflows`; symlinks; and npm lifecycle scripts:
- **LOW:** a build tool such as `husky` or `only-allow`.
- **MEDIUM:** runs a file from the repo, or downloads something.
- **HIGH:** runs a hidden file or hides its output, pipes a download to a shell, decodes or `eval`s, or the file it runs both runs commands and reaches the network, or uploads data. The last one is stricter than the daily audit, which treats it as medium in your own repos because binary downloaders look the same.
- **CRITICAL:** wfx's published indicators.

Workflows are checked for steps that hand out every secret or the Actions runtime token, see [wfx](#install-hooks-and-secret-dumping-workflow-steps-wfx-on-by-default---no-install-hooks-to-skip).

Nothing in the repo is executed and git is never run. A folder without `.git` (an unpacked zip) is treated as if every file were committed. Exit code 1 means findings at or above `--fail-on` (default medium); `--json` prints them all.

**Tested** on the root `package.json` of 39 popular JS projects (React, Next.js, VS Code, Vite, Angular, Electron …): 0 high. The 13 medium findings all run a file from the repo. On 76 repos found by searching GitHub for install hooks: 6 high, each an install hook that runs commands and reaches the network (binary downloaders, one service registration), worth reading before you install a stranger's repo.

**Limits:** it reads only what's in the folder. It doesn't follow dependencies (a malicious package in `node_modules` after install) or run code to see what it does. Its source-code checks cover install scripts and agent files, not every `.js` file, so the safest way to try an untrusted repo is still a throwaway VM or container with no keys in it.

## Plugin checkouts that aren't on their pinned commit (Plugin4Shell)

On by default (`--no-plugin-pins` to skip). [Air Security's Plugin4Shell](https://www.air.security/blog-posts/plugin4shell) showed Claude Code, Codex and Copilot installing a plugin with `git clone` + `git checkout <pinned-sha>`. If the upstream repo's default branch is named exactly like that SHA, git prefers the branch: the agent reports "installed at the pinned commit" while the attacker's code is on disk, and background auto-update repeats it with no click. A Gemini CLI variant uses a branch named `FETCH_HEAD`. GitHub rejects such branch names; Bitbucket and self-hosted git allow them.

asca reads every git checkout under `~/.claude/plugins`, `~/.codex/plugins`, `~/.copilot`, `~/.gemini/extensions` and the Hermes `plugins/` folder, as text: `HEAD`, loose refs and `packed-refs`. It never runs git.

| Finding | Severity |
|---|---|
| `plugin.hash-named-branch`: HEAD is on a branch named like a 40-hex commit or `FETCH_HEAD` (the swap landed) | critical |
| the same kind of branch exists locally or as a remote-tracking ref, not checked out yet | high |
| `plugin.pin-drift`: a Hermes catalog plugin is on a different commit than the one Hermes recorded and verified at install | medium |

No normal workflow creates a branch named like a commit hash, so it isn't a guess. **Not compared:** Claude Code's `gitCommitSha` in `installed_plugins.json`, which keeps its install-time value after updates (anthropics/claude-code#54969, #56740, #52218), so a mismatch there means nothing. Your agent's own version is covered by the [version check](#other-coding-agents-claude-code-codex-gemini-cli-goose-claude-desktop): Claude Code < 2.1.179 and Codex < 0.146.0 are flagged.

**Tested** by reproducing the attack with real git in the test suite (a hash-named default branch, then `git clone` + `git checkout <sha>`): git really checks out the attacker's branch, and asca rates it critical.

## Full Disk Access for terminals, IDEs and agents (macOS)

On by default on macOS (`--no-tcc` to skip). Apple says agents misusing Full Disk Access put "all of the data on their Mac at risk" and is tightening the prompt in macOS 27.3, but grants you already gave stay. A grant to a **terminal or IDE** is inherited by every CLI agent you start inside it (Claude Code, Codex, Gemini CLI, Hermes) and by every `node`/`python` script they run.

asca opens the privacy database (`TCC.db`, system and user) with sqlite in read-only mode, and reads `MDMOverrides.plist` for grants pushed by an MDM profile, which aren't in TCC.db:

| Finding | Severity |
|---|---|
| `host.tcc-full-disk`: Full Disk Access for a terminal (Terminal, iTerm2, Warp, Ghostty …), an IDE (VS Code, Cursor, Windsurf, Zed, JetBrains …), an agent app (Claude Desktop, ChatGPT, Codex, Hermes Desktop) or a raw `node`/`python`/`bun`/agent binary | high |
| `host.tcc-app-control`: Accessibility, or Automation of Terminal / System Events / Finder, for one of those. An agent inside can click, type and approve its own prompts | medium |
| `host.tcc-unreadable`: the database couldn't be read | low |

**TCC.db is itself protected:** only a process with Full Disk Access can read it. From a scheduled job you'll usually get the low "couldn't read" finding instead of a silent pass, with the place to check by hand. If asca *can* read it, whatever launched asca has Full Disk Access, and the report's stats say so. asca never asks for or changes a permission. Grants to other apps (backup tools and the like) aren't reported.

**Tested** against TCC.db files built with Apple's schema (current, and the pre-Big Sur `allowed` column) and an MDM overrides file. It hasn't run against a live Mac's database in CI.

## Intune compliance (`asca export intune`)

Microsoft Intune's [custom compliance](https://learn.microsoft.com/en-us/intune/device-security/compliance/custom-settings) (Windows, Linux and, since July 2026, macOS) runs a discovery script on each device and compares its JSON output with a rules file; Conditional Access can then block non-compliant devices. `asca export intune` is that script's payload. It reads the device's **last** asca report (it doesn't run an audit inside Intune's 5–10 minute limit) and prints one line:

```
{"AscaReportFound":true,"AscaReportAgeHours":5,"AscaCritical":0,"AscaHigh":1,"AscaMedium":2,"AscaResult":"FAIL","AscaVersion":"0.8.0"}
```

To set it up:
1. Deploy the asca checkout and the scheduled job on each device, as for any asca install.
2. Upload [`examples/intune/discovery-macos.sh`](examples/intune/discovery-macos.sh) (bash 3.2; Intune runs it as root, so it reads the logged-in user's asca state) or [`discovery-linux.sh`](examples/intune/discovery-linux.sh) (user context) under Devices → Compliance → Scripts. Set `ASCA_DIR` to where you deployed asca.
3. Create a custom compliance policy with [`examples/intune/rules.json`](examples/intune/rules.json). Regenerate it with other limits: `python3 -m asca export intune --rules --max-high 2 --max-medium 10 --max-age-hours 72`.

The default rules require a report, at most 48 hours old, with no critical and no high findings. **Fail closed:** no report, an unreadable one or a stale one makes the device non-compliant, so a stopped asca job doesn't leave a device compliant forever. Baseline-accepted findings don't count, so an accepted risk doesn't block anyone. No Windows script ships yet, because asca's checks are written for macOS and Linux.

## Stolen-key spend tripwire (`asca spend`, opt-in, online)

Stolen AI keys (LLMjacking) usually show up first on the bill. `asca spend` checks your providers' usage and alerts when it jumps, so you can revoke the key the same day. Run it hourly:

```bash
python3 -m asca spend                                   # keys from the environment or your agents' .env files
python3 -m asca spend --telegram change                 # scheduled: one message when it starts, one when it's normal again
python3 -m asca spend --max-daily-usd 20                # also a hard daily ceiling, active from the first run
```

| Provider | Key it needs | What it checks |
|---|---|---|
| OpenRouter | any normal key (`OPENROUTER_API_KEY`) | `GET /api/v1/key` for that key's cumulative usage. asca keeps one sample per run and compares today's spend with the median of the last 7 complete days, and the last hour with a normal day. Also flags a key close to its credit limit (medium) or without one (low). |
| Anthropic | an **Admin key** (`ANTHROPIC_ADMIN_KEY`, `sk-ant-admin01-…`); normal API keys can't read usage | Daily cost from the Cost API, compared the same way. The Usage API grouped by key and model flags an **API key** (high) or **model** (medium) used today that wasn't used in the previous 8 days, a common sign of a key being resold. |

A spike is `spend.spike` (high): today's spend is over 3× the 7-day median and at least $2 more (`--factor`, `--min-usd`), or the last hour cost more than a normal day. It needs 3 complete days of history first; until then it only reports "learning", except for `--max-daily-usd`.

**Safe by construction:** only GET requests, and each key goes only to its own provider's API host. Keys are never printed or stored. The state file (`~/.local/state/asca/spend.json`, mode `0600`) keeps usage numbers, a short hash per key, and Anthropic API key IDs and model names, none of which are secret.

**Limits:** neither provider reports where requests come from (Anthropic's `inference_geo` is where the model ran, not the caller), so there is no "new region" alert. Anthropic cost data lags a few minutes. Spend from a key on another platform (OpenAI, Google, Bedrock) isn't covered yet.

## Were your GitHub repos hit by wfx? (`asca github-check`, opt-in, online)

The wfx stealer ([SafeDep](https://safedep.io/blog/github-actions-wfx-credential-stealer), [Aikido](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories)) pushed with stolen tokens into the victims' own repos, ran once, then reverted within a minute and deleted the workflow run with its logs. The traces are on GitHub, not on your disk, so this command checks them through the GitHub API:

```bash
python3 -m asca github-check                          # every repo your token's user owns (incl. private)
python3 -m asca github-check --owner my-org           # every repo of an org or user
python3 -m asca github-check --repo me/app --json     # one repo; JSON output
python3 -m asca github-check --telegram change        # schedule it: a message only when the result changes
```

| Finding | Severity |
|---|---|
| `github.wfx-probe-pr`: a `docs: dependency audit notes` PR or one from a `wfx-docs` branch, open or closed. SafeDep: "a probe pull request on its own means the account is compromised" | critical |
| `github.wfx-payload-commit`: `chore: add ci helper` / `chore: add dependency audit workflow` (high), `ci: refresh build cache` (medium, generic wording); critical when a `ci: restore` / `ci: cleanup` commit is there too | medium to critical |
| `github.wfx-branch`: `wfx-docs` (critical); `chore/` plus 8 random characters or `ci-check-NNNN` (medium, could be yours) | medium, critical |
| `github.deleted-runs`: gaps in a workflow's run numbers since the campaign started. Aikido: "a missing run number … is the more reliable sign that the payload ran". High next to a probe PR or payload commit; on its own it's a low note, because maintainers of busy repos delete runs too | low, high |
| `github.wfx-loot`: a `wfx-loot` artifact or a `wfx-` cache entry | critical |
| The default branch's `package.json`, the file its hook runs, and its workflows, checked with the offline [wfx rules](#install-hooks-and-secret-dumping-workflow-steps-wfx-on-by-default---no-install-hooks-to-skip) | as there |

Each repo gets a verdict: 🟥 payload pushed · 🟥 probed (account compromised) · 🟧/🟨 check · ✅ clean · ❔ couldn't check (a repo that can't be read is never called clean). The window starts on 10 Nov 2026, the first probe (`--since`).

**Read-only.** Only GET requests, only to `api.github.com` (or your Enterprise host). Nothing is cloned and nothing is written to GitHub. The token is found the same way as `--github-token-scopes` (gh login, `GH_TOKEN`/`GITHUB_TOKEN`, `.git-credentials`) or given with `--token-env VAR`, and it's never printed. Deleted runs can only be checked where the token can read Actions (fine-grained: *Actions: read*); the output says how many repos that skipped.

**Tested** on four repositories SafeDep lists as affected: it finds their probe PRs, the payload commits SafeDep cites, the cleanup commits and the deleted runs (one repo has since been deleted and is reported as "couldn't check"). On 40 busy public repos (Hermes, OpenClaw, Codex, VS Code, React, CPython …): all clean. 15 run-number gaps there are low notes only; the first version, which grouped runs by name, reported 84. On the 24 repos of a real account: clean, using 194 API calls.

**Limits:** GitHub keeps only what the attacker didn't delete. A force-push that rewrote history removes the commits, and a deleted branch leaves no trace. If a probe PR is there, treat the account as compromised even when nothing else shows.

## Dashboard (`asca dashboard`)

One page per host with every asca job's status and the fixes to act on, so you don't have to dig
through `.md` reports.

```bash
python3 -m asca dashboard                      # reads ~/.local/state/asca, writes dashboard.html there
open ~/.local/state/asca/dashboard.html        # macOS; xdg-open on Linux
```

**What's on it:**
- **One card per job** (audit, skills, inventory, fleet, egress) with its status, counts, last run
  time and report file. A job with no new report for over 26 hours is marked **STALE**
  (`--stale-hours`), so a scheduled job that silently stopped is visible.
- **Act on these:** every critical, high and medium finding, with *where*, *why* and *fix*.
  Commands in a fix are in boxes that select with one click. New findings (first seen within the
  last 36 hours) get a **NEW** badge. Lower-priority and baseline-accepted findings are folded away.
- **Leaked keys: where each one is.** One card per leaked key instead of one finding per copy, grouped
  by the hash tag every report uses (never the value). Each card shows:
  - The provider and the masked key (4-character prefix and length).
  - Every place a copy was found, by agent (Hermes, Claude Code, Codex, Cursor …) and kind (config,
    transcripts with a file count, allow rule, MCP config, cron job …).
  - How many days it has been exposed, from the first-seen date in the dashboard's memory. A key
    that was already there when tracking started says so, rather than guessing a date.
  - **Whether it's still your live key:** the values in your agents' `.env` files
    (`$HERMES_HOME/.env`, `~/.hermes/.env`, `~/.openclaw/.env`, `~/.config/goose/.env`, or
    `--env-file`) are hashed in memory and compared with the tags; values are never written or
    shown. A live key needs rotating; a copy of a rotated key only needs deleting.
    `--no-live-check` skips this.
  - The provider's revoke steps, once.

  Keys accepted in a baseline ("rotated on …") are listed folded away, and flagged if a key you
  accepted as rotated is in fact still live.
- **Fixed recently:** audit and skill findings that disappeared in the last 7 days. A report that's
  missing or unreadable never counts as a fix.
- **Audit trend** (from `history-*.json`), Hermes patch level, and the egress summary.

**Where the reports come from:** both layouts in use are found automatically: one folder per job
(`audit/latest.json`, `skills/skills-latest.json`, …, as `scripts/macos/asca-run.sh` writes them) or
the audit report at the state root (as `scripts/asca-daily.sh` writes it). Use `--state-dir` and
`-o` for other places, and `--host-label` for the page title.

**Its location at the end of every report.** When `ASCA_DASHBOARD` is set, every Markdown report and
Telegram alert ends with `Dashboard: <path>`, so you never have to remember where the page is. The
macOS runner and `scripts/asca-daily.sh` set it to the page they rebuild. Set it yourself when you open
the page from another machine, e.g. `ASCA_DASHBOARD="myhost:~/.hermes/state/asca/dashboard.html"`.
It's only a path: no report content or secret is added.

**Safe by construction:**
- **A file, not a server.** No listening port, nothing to log in to, no network access.
- **Nothing in it can run.** No JavaScript at all, and a strict `Content-Security-Policy`
  (`default-src 'none'`) blocks scripts, external images, fonts and frames.
- **Scanned content is shown as text.** Findings quote things an attacker can choose (skill names,
  paths, commands), so every value is HTML-escaped; the tests include a hostile skill name.
- **No secrets, private file.** Reports never contain secret values, and the page is written
  atomically with mode `0600`, next to `dashboard-state.json` (first-seen dates, also `0600`).

## Limits (MVP)

- Hub "pinning" means an upstream **commit** is recorded. Hermes' lock currently stores only a content hash, so every community hub skill is reported until Hermes records commits or you vendor skills into a repo you control.
- Secret detection is pattern-based. It catches common providers and obvious assignments, not every possible secret.
- A private-key header on its own (`-----BEGIN … PRIVATE KEY-----` in docs, checklists or secret-scanner regexes) isn't reported: asca needs base64 key material after the header (same line, the next lines of a file, or a quoted string in source code; encrypted PEMs included). A truncated key that shows only its header is therefore missed.
- AWS access key IDs inside pre-signed URLs (`AWSAccessKeyId=`, `X-Amz-Credential=`) aren't reported: the ID is public by design and the URL's signature expires.
- Session-history scanning reads plain-text and JSON transcripts plus Cursor's SQLite chat rows. It doesn't read other binary or encrypted stores, Claude Desktop or ChatGPT app history, or transcripts from agents not listed above. Each file is scanned up to the per-file cap, and the remainder of a larger file is skipped.
- A secret split across two JSON lines, or longer than the 256-char window overlap, can be missed.
- Stray-instruction search covers only the folders listed (plus `--instructions-dir`), two levels deep. It can't tell a legitimate instruction file from an extracted archive. Use a baseline for ones you accept.
- Remote (URL) MCP servers can't be pinned and are reported as `info`.
- Persona rules read instructions in English. A rewritten persona in another language, or one that only changes the agent's goals without these phrases, is caught by the inventory's `SOUL.md` hash, not by content.
- The symlink check finds links left on disk or committed; a link created and used within one run is gone before asca looks.
- The Docker check reads the host's daemon configuration. Run inside a container, it can't see the host's.
- The CI-agent check reads workflow files only. It doesn't see repository or organisation settings (the default token permissions, "require approval for fork PRs", branch rules), reusable workflows in other repos, or composite actions that wrap an agent under another name. A job without a `permissions:` block is reported as "doesn't restrict" because the repository default may be read-write.
- `global core.fsmonitor=false` is suggested as defence in depth only. A repo-local value still overrides it.
- Version advisories cover Hermes Agent, Claude Code, Codex, Gemini CLI, goose and Claude Desktop. IDE extensions (Cursor, Copilot, Cline …) aren't matched: no advisory feed covers the VS Code Marketplace, so the inventory only tracks their versions. A goose installed with the curl script has no version on disk and isn't checked.

## Contributing

Issues and PRs are welcome, especially new MCP client config locations, git program-executing keys, and secret patterns. Every rule needs a test, and fixtures must build fake secrets at runtime (see `tests/test_asca.py: fake()`) so the repo stays clean under its own scan. Security problems in asca itself: see [SECURITY.md](SECURITY.md).

## Development

```bash
uv venv .venv && uv pip install --python .venv/bin/python pytest==8.4.2
.venv/bin/python -m pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
