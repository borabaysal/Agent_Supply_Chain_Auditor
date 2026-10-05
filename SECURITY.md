# Security policy

`asca` is a defensive auditing tool. If you find a way to make it

- execute code from a scanned repository or config (it must never run `git` or any scanned program),
- write a secret value into a report, JSON output, stdout or a Telegram alert, or
- silently PASS a configuration it failed to parse,

please report it privately via GitHub's **"Report a vulnerability"** (Security → Advisories) on this repository rather than a public issue. Include a minimal reproducer (synthetic secrets only).

False negatives (a risky setting it does not flag) can be filed as normal issues.
