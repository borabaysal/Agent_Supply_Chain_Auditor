# Agent Supply-Chain Auditor (`asca`)

A zero-dependency CLI for people who **self-host AI agents**: Hermes Agent, Claude Code, Codex CLI, Gemini CLI, goose, Cursor, Windsurf, VS Code, Claude Desktop, or any MCP client. It audits the setup for supply-chain risk, writes a **PASS/FAIL report**, and can **alert you on Telegram**.

```
$ asca --repos ~/Projects --telegram fail --env-file ~/.hermes/.env
asca 0.3.0: FAIL (fail-on high)
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
| **Pinning** | Hermes Skills Hub installs with no upstream commit pin · skill taps that track a branch · plugins checked out on a moving branch · MCP servers launched with `npx`/`bunx`/`uvx`/`pipx` without an exact version · `docker run` images without `@sha256:` digest · `git+https://` installs without a commit SHA · skills that tell the agent to `curl … \| sh` · remote MCP servers (reported as *info*, since they can't be pinned) |
| **Repo config** (GitSpawn) | `core.fsmonitor` set to a program (**critical**, see [CVE-2026-71963](https://www.rapid7.com/db/vulnerabilities/cve-2026-71963/) for Hermes, CVE-2026-19592 for Codex, CVE-2026-72718 for goose), plus every other git key that names a program: `core.hooksPath`, `core.sshCommand`, `core.askPass`, `core.pager`/`pager.*`, `core.editor`, `diff.external`, `diff.*.textconv`, `filter.*.{clean,smudge,process}`, `merge.*.driver`, `credential.helper` (non-builtin), `protocol.ext.allow`, `include.path`/`includeIf`, `!` aliases, `gpg.program` · active (non-`.sample`) git hooks · linked worktrees/submodules (`.git` files) · project `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` / `.gemini/settings.json` MCP servers that ship with a repo · [coding agents in `.github/workflows` that anyone can trigger](#coding-agents-in-github-workflows-that-anyone-can-trigger-on-by-default---no-ci-agents-to-skip) |
| **Exposed keys** | Literal API keys in agent config, cron jobs, memories, skills, plugins, scripts and MCP `env`/`headers` (Anthropic, OpenAI, OpenRouter, GitHub, Slack, Telegram, AWS, Google, Stripe, HF, wallet private keys, PEM keys, generic `api_key=` assignments) · tokens embedded in git remote URLs and MCP URLs · credential files (`.env`, `auth.json`, `.git-credentials`, `config.yaml`, MCP OAuth tokens) readable by group/other |
| **Session history** | Literal keys saved in agents' transcripts: Hermes `sessions/*.json(l)` and `cron/output/**` (incl. `profiles/*`), Claude Code `~/.claude/projects/**/*.jsonl`, Codex `~/.codex/sessions/**/*.jsonl` and `history.jsonl`, Cursor chat rows in `state.vscdb` · transcript files/dirs that group/other can actually reach and read. See [Session history](#session-history-secretsession-history). |
| **Stray agent instructions** | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*` … left in `~/Downloads`, `~/Desktop` or the temp dir, outside any git repo; HIGH when the `asca-skills` content rules match. See [Stray agent instructions](#stray-agent-instructions-repostray-agent-instructions). |
| **Integrity** | Hub skills whose on-disk content no longer matches the install-time hash (same algorithm as Hermes' Skills Guard) · skills installed despite a non-`safe` scanner verdict · Hermes Agent versions inside a known-vulnerable range |

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
- The CI-agent check reads workflow files only. It doesn't see repository or organisation settings (the default token permissions, "require approval for fork PRs", branch rules), reusable workflows in other repos, or composite actions that wrap an agent under another name. A job without a `permissions:` block is reported as "doesn't restrict" because the repository default may be read-write.
- `global core.fsmonitor=false` is suggested as defence in depth only. A repo-local value still overrides it.
- Version advisories cover Hermes Agent only (extend `asca/advisories.py: PACKAGES` for other agents). For other agents, check vendor advisories; contributions are welcome.

## Contributing

Issues and PRs are welcome, especially new MCP client config locations, git program-executing keys, and secret patterns. Every rule needs a test, and fixtures must build fake secrets at runtime (see `tests/test_asca.py: fake()`) so the repo stays clean under its own scan. Security problems in asca itself: see [SECURITY.md](SECURITY.md).

## Development

```bash
uv venv .venv && uv pip install --python .venv/bin/python pytest==8.4.2
.venv/bin/python -m pytest -q
```

## License

MIT. See [LICENSE](LICENSE).
