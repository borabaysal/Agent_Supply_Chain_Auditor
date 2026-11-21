# asca on Windows

**Status: not tested yet.** This page is the test plan and kit. It gets rewritten with measured results after the Windows test.

asca is Python standard library only and never runs what it scans, so most checks should work unchanged. What's known before testing:

- **Paths:** Claude Desktop (`%APPDATA%\Claude`), VS Code and Cursor (`%APPDATA%\Code`, `%APPDATA%\Cursor`), global npm (`%APPDATA%\npm\node_modules`, for Claude Code / Codex / Gemini CLI versions) and the home-relative agent folders (`%USERPROFILE%\.claude`, `.codex`, `.gemini` …) are in the discovery lists.
- **File permissions aren't checked:** NTFS uses ACLs, which the standard library can't read, and the POSIX mode bits Python reports are meaningless there. Instead of a silent pass, every run on Windows reports one low `scanner.permissions-not-checked` finding.
- **macOS-only and Linux-only checks** (Full Disk Access, Docker daemon config, egress attribution) do nothing on Windows.
- **Not read:** the registry, including environment variables set there.
- **WSL:** asca run inside WSL scans the Linux side only.

## Test kit

- **`scripts/platform_check.py`:** plants known problems in a **throwaway profile** in a temp folder, runs asca and its subcommands, and prints a pass/fail table. It never reads or changes your real profile, and its fake keys are generated at runtime and never printed.
- **`docs/ci/tests.yml`:** a GitHub Actions workflow running the test suite on Linux, macOS and Windows with Python 3.10 and 3.12. It has a read-only token, no secrets, and pins actions to commits. Install it with:
  ```bash
  mkdir -p .github/workflows && git mv docs/ci/tests.yml .github/workflows/tests.yml
  git commit -m "CI: tests on Linux, macOS and Windows" && git push
  ```
  The maintainer pushes this: GitHub requires the `workflow` permission to add a workflow, and asca's own token check rates that permission as risky for an agent's token.
- **`scripts/windows/asca-daily.ps1`:** a daily-audit wrapper for Task Scheduler.

## Test plan (a disposable Windows 11 VM)

**Use a throwaway VM: no real accounts, keys or repos.** Sign in with a local account, and never copy a real `.env`, SSH keys or agent configs into it. Unactivated Windows is fine (watermark only). 4 vCPU, 8 GB RAM and 64 GB disk are enough.

**Step 1, the VM.**
- **Apple Silicon Mac:** Windows 11 **ARM64** (Microsoft's official ARM64 ISO) in **UTM** (free) or **VMware Fusion Pro** (free for personal use).
- **Intel Mac:** Windows 11 x64 in UTM, VMware Fusion or VirtualBox.

**Step 2, install** (in PowerShell):
```powershell
winget install -e --id Python.Python.3.12; winget install -e --id Python.Python.3.10; winget install -e --id Git.Git
winget install -e --id Microsoft.VisualStudioCode; winget install -e --id OpenJS.NodeJS.LTS; winget install -e --id Anthropic.Claude
```
Then open a **new** PowerShell window, so the new PATH is loaded:
```powershell
npm install -g @anthropic-ai/claude-code@2.1.150     # an old version on purpose; don't log in
code --install-extension ms-python.python; code --install-extension esbenp.prettier-vscode
git clone https://github.com/borabaysal/Agent_Supply_Chain_Auditor.git C:\asca; cd C:\asca
py -3.12 -m pip install pytest; py -3.10 -m pip install pytest
```
Open Claude Desktop once and close it without logging in.

**Step 3, the tests.** Paste the output of each block back:
```powershell
# A. test suite on Python 3.12, then 3.10 (the minimum)
py -3.12 -m pytest -q -rs -p no:cacheprovider 2>&1 | Select-Object -Last 40
py -3.10 -m pytest -q -p no:cacheprovider 2>&1 | Select-Object -Last 15

# B. planted problems in a throwaway profile
py -3.12 scripts\platform_check.py
py -3.10 scripts\platform_check.py

# C. symlinks: turn on Settings > System > For developers > Developer Mode, open a new window, then:
py -3.12 scripts\platform_check.py | Select-String symlink

# D. the VM's real profile (finds VS Code, Claude Desktop, Claude Code 2.1.150); counts only, no values
py -3.12 -m asca --format none -o $env:TEMP\asca-real; "exit $LASTEXITCODE"
py -3.12 -c "import json,os,collections as c; d=json.load(open(os.path.join(os.environ['TEMP'],'asca-real.json'))); print(d['result'], {k:v for k,v in d['counts'].items() if v}); print(d['stats'].get('agent_versions')); print(sorted(c.Counter((f['rule'],f['severity']) for f in d['findings']).items()))"

# E. scheduled daily run (Task Scheduler, current user, no Telegram)
schtasks /Create /SC DAILY /ST 09:00 /TN "asca daily audit" /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\asca\scripts\windows\asca-daily.ps1" /F
schtasks /Run /TN "asca daily audit"; Start-Sleep 90
Get-Content $env:LOCALAPPDATA\asca\run.log; Get-ChildItem $env:LOCALAPPDATA\asca | Select-Object Name, Length
schtasks /Delete /TN "asca daily audit" /F
```
**Expected:** the test suite passes, or the failures are listed; every `platform_check` row passes, with the symlink row SKIP until Developer Mode is on; D shows `claude-code: 2.1.150` with an `agent.vulnerable-version` finding (5 known vulnerabilities); E logs `rc=1` or `rc=0` (not 2).

**Step 4 (optional): WSL.** Run `wsl --install`, then in Ubuntu install python3, clone, and run `python3 scripts/platform_check.py` to confirm it only sees the Linux side.

## Results

_To be filled in from the test: Windows version and architecture, Python versions, what works, what doesn't, and the fixes._
