# Agent Supply-Chain Auditor (`asca`)

A zero-dependency CLI for people who **self-host AI agents**: Hermes Agent, Claude Code, Codex CLI, Gemini CLI, goose, Cursor, Windsurf, VS Code, Claude Desktop, or any MCP client. It audits the setup for supply-chain risk, writes a **PASS/FAIL report**, and can **alert you on Telegram**.

```
$ asca --repos ~/Projects --telegram fail --env-file ~/.hermes/.env
asca 0.1.0: FAIL (fail-on high)
  critical=1  high=2  medium=1  low=5  info=2  suppressed=0
  [CRITICAL] core.fsmonitor names a program git runs on every index refresh
      ~/Projects/downloaded-repo/.git/config:3
  [HIGH] Hub skill `some-community-skill` is not pinned to a commit
      ~/.hermes/skills/.hub/lock.json#installed.some-community-skill
  ...
  report: asca-report.md  (asca-report.json)
```

## What it checks

_Also included: an [egress auditor](#egress-auditor-asca-egress) that logs where your agents connect and alerts on new destinations._

| Category | Checks |
|---|---|
| **Pinning** | Hermes Skills Hub installs with no upstream commit pin · skill taps that track a branch · plugins checked out on a moving branch · MCP servers launched with `npx`/`bunx`/`uvx`/`pipx` without an exact version · `docker run` images without `@sha256:` digest · `git+https://` installs without a commit SHA · skills that tell the agent to `curl … \| sh` · remote MCP servers (reported as *info*, since they can't be pinned) |
| **Repo config** (GitSpawn) | `core.fsmonitor` set to a program (**critical**, see [CVE-2026-71963](https://www.rapid7.com/db/vulnerabilities/cve-2026-71963/) for Hermes, CVE-2026-19592 for Codex, CVE-2026-72718 for goose), plus every other git key that names a program: `core.hooksPath`, `core.sshCommand`, `core.askPass`, `core.pager`/`pager.*`, `core.editor`, `diff.external`, `diff.*.textconv`, `filter.*.{clean,smudge,process}`, `merge.*.driver`, `credential.helper` (non-builtin), `protocol.ext.allow`, `include.path`/`includeIf`, `!` aliases, `gpg.program` · active (non-`.sample`) git hooks · linked worktrees/submodules (`.git` files) · project `.mcp.json` / `.cursor/mcp.json` that ship with a repo |
| **Exposed keys** | Literal API keys in agent config, cron jobs, memories, skills, plugins, scripts and MCP `env`/`headers` (Anthropic, OpenAI, OpenRouter, GitHub, Slack, Telegram, AWS, Google, Stripe, HF, wallet private keys, PEM keys, generic `api_key=` assignments) · tokens embedded in git remote URLs and MCP URLs · credential files (`.env`, `auth.json`, `.git-credentials`, `config.yaml`, MCP OAuth tokens) readable by group/other |
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

## Limits (MVP)

- Hub "pinning" means an upstream **commit** is recorded. Hermes' lock currently stores only a content hash, so every community hub skill is reported until Hermes records commits or you vendor skills into a repo you control.
- Secret detection is pattern-based. It catches common providers and obvious assignments, not every possible secret.
- Remote (URL) MCP servers can't be pinned and are reported as `info`.
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
