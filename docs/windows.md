# asca on Windows

**Status: tested** on Windows 11 Pro 26100 (ARM64 VM) and in CI on Windows x64; results below. The limits are listed under "Known before testing" and "Still open".

asca is Python standard library only and never runs what it scans, so most checks should work unchanged. What's known before testing:

- **Paths:** Claude Desktop (`%APPDATA%\Claude`), VS Code and Cursor (`%APPDATA%\Code`, `%APPDATA%\Cursor`), global npm (`%APPDATA%\npm\node_modules`, for Claude Code / Codex / Gemini CLI versions) and the home-relative agent folders (`%USERPROFILE%\.claude`, `.codex`, `.gemini` …) are in the discovery lists.
- **File permissions aren't checked:** NTFS uses ACLs, which the standard library can't read, and the POSIX mode bits Python reports are meaningless there. Instead of a silent pass, every run on Windows reports one low `scanner.permissions-not-checked` finding.
- **macOS-only and Linux-only checks** (Full Disk Access, Docker daemon config, egress attribution) do nothing on Windows.
- **Not read:** the registry, including environment variables set there.
- **WSL:** asca run inside WSL scans the Linux side only.

## Test kit

- **`scripts/platform_check.py`:** plants known problems in a **throwaway profile** in a temp folder, runs asca and its subcommands, and prints a pass/fail table. It never reads or changes your real profile, and its fake keys are generated at runtime and never printed.
- **`.github/workflows/tests.yml`:** CI runs the test suite on Linux, macOS and Windows (x64) with Python 3.10 and 3.12 on every push and PR. It has a read-only token, no secrets, and pins actions to commits.
- **`scripts/windows/asca-daily.ps1`:** a daily-audit wrapper for Task Scheduler.
- **`examples/intune/discovery-windows.ps1`:** an Intune custom-compliance discovery script for Windows (see the README's Intune section).
- **`scripts/windows/vm_test.ps1`:** runs every step below and writes one results file you can paste back.

## Test plan (a disposable Windows 11 VM)

**Use a throwaway VM: no real accounts, keys or repos.** Never copy a real `.env`, SSH keys or agent configs into it, and don't log in to any agent. Unactivated Windows is fine for testing (watermark only).

### 1. The VM (Apple Silicon Mac, UTM)
1. Install **UTM** from [mac.getutm.app](https://mac.getutm.app) (free; the App Store version is the same app).
2. Get the **Windows 11 ARM64 ISO** from Microsoft: [microsoft.com/software-download/windows11arm64](https://www.microsoft.com/en-us/software-download/windows11arm64). Pick "Windows 11 (multi-edition ISO for Arm64)" and your language. (UTM's guide also suggests CrystalFetch, which builds the same ISO from Microsoft's servers.)
3. UTM → **+** → **Virtualize** → **Windows**. Give it 8 GB RAM and 4 cores. Tick **Install Windows 10 or higher** and **Install drivers and SPICE tools**, then **Browse** to the ISO. Use a 64 GB disk, skip the shared folder, **Save**, then **Run**.
4. **Press any key** right away when it says "Press any key to boot from CD". If you miss it, you land in an EFI shell: type `exit`, choose Boot Manager, then the CD.
5. Setup: choose **"I don't have a product key"** and **Windows 11 Pro**, then a custom install onto the empty disk.
6. Account (first-boot setup):
   - At the region screen press **Shift+F10** and type `start ms-cxh:localonly`. A local-account window should appear.
   - Microsoft is blocking this on some 26H2 builds. If it doesn't work, sign in with a **new throwaway Microsoft account made just for this VM**, never your real one.
7. If the screen goes black after install (a known 24H2+ graphics-driver issue), restart the VM from UTM's toolbar.
8. In Windows: if there's no network, open the **CD drive (UTM guest tools)** in Explorer and run the installer. It contains the network drivers.

**Intel Mac:** the same, with the x64 ISO from [microsoft.com/software-download/windows11](https://www.microsoft.com/en-us/software-download/windows11).

### 2. Install Python, Git, VS Code, Node, Claude Desktop and an old Claude Code
In **PowerShell** (Start → type PowerShell):
```powershell
winget install -e --id Python.Python.3.12; winget install -e --id Python.Python.3.10; winget install -e --id Git.Git
winget install -e --id Microsoft.VisualStudioCode; winget install -e --id OpenJS.NodeJS.LTS; winget install -e --id Anthropic.Claude
```
Accept the agreements when asked. If winget fails with "Failed when searching source: msstore … certificate", add `--source winget` (the Store source on a fresh install is the problem, not the package). If the **Node.js installer fails with 1603**, use the official zip instead: download `node-<version>-win-arm64.zip` from nodejs.org, check it against `SHASUMS256.txt`, unpack it to `%LOCALAPPDATA%\Programs`, and add that folder to your user PATH. On a stock install PowerShell blocks `.ps1` launchers, so type **`npm.cmd`** (and `code.cmd`) instead of `npm`. On ARM64, Python 3.12, Git, Node, VS Code and Claude are native ARM64 builds. Python 3.10 has no ARM64 build, so it runs as x64 under Windows' emulation (useful extra coverage). Then **close PowerShell and open a new window**, so the new PATH is loaded:
```powershell
npm install -g @anthropic-ai/claude-code@2.1.150     # an old version on purpose: asca should flag it. Don't log in.
code --install-extension ms-python.python; code --install-extension esbenp.prettier-vscode
git clone https://github.com/borabaysal/Agent_Supply_Chain_Auditor.git C:\asca; cd C:\asca
py -3.12 -m pip install pytest; py -3.10 -m pip install pytest
```
Open **Claude Desktop** once and close it without logging in. For symlink tests, turn on **Settings → System → For developers → Developer Mode**.

### 3. Run every test with one command
```powershell
cd C:\asca
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\vm_test.ps1
```
It takes a few minutes and writes **`asca-windows-results.txt` on the Desktop**. It covers:
- the test suite on Python 3.12 (ARM64) and 3.10 (x64)
- `platform_check.py` on both
- redirected output
- an audit and inventory of the VM's real profile
- a Task Scheduler run of `asca-daily.ps1` (the task is deleted afterwards)

The output is shape only (rules, severities, counts, versions, exit codes), so you can paste the file back as-is.

**Expected:**
- The test suite passes (any failures are listed).
- Every `platform_check` row passes.
- D shows `claude-code: 2.1.150` with `agent.vulnerable-version`, plus the VS Code extensions and Claude Desktop in the inventory.
- E logs `rc=0` or `rc=1` (not 2) with `Last Result: 0`.

### 4. Optional: WSL
Run `wsl --install`, then in Ubuntu install python3, clone, and run `python3 scripts/platform_check.py`. It should only see the Linux side.

## Results

**First VM run (2026-11-22):** Windows 11 Pro 26100 on ARM64 (UTM on an Apple Silicon Mac), Python 3.12.10 ARM64 and Python 3.10.11 x64 (emulated), Developer Mode on.

| Check | Result |
|---|---|
| `platform_check.py`, both Pythons | **17/17 passed**: every planted problem found at the right severity, symlinks included; the planted `fsmonitor` command never ran |
| Redirected output (cp1252) | OK: no crash, nothing on stderr |
| Task Scheduler via `asca-daily.ps1` | OK: `rc=0`, Last Result 0, reports written, empty error.log |
| Test suite | **Didn't run**: Microsoft Defender quarantined `tests/test_skillscan.py` (`Trojan:AIAgent/ClawHavoc!AMTB`) because of its malware-skill samples. Fixed: the samples are now stored ROT13-encoded and decoded at test time. |
| Real profile | **Missed Claude Code 2.1.150 and Claude Desktop.** With Node from the zip, npm's global folder is the Node folder (not `%APPDATA%\npm`), and Claude Desktop's per-user install (`%LOCALAPPDATA%\AnthropicClaude\app-<version>`) wasn't a known location. Fixed: global npm folders are now also found from `.npmrc` `prefix=` and from the Node folder on `PATH` (plus nvm-windows, Volta and fnm), and the per-user Claude Desktop install is detected. |

**Second VM run (2026-11-22, after PR #25):** same VM, asca `e5241da`.

| Check | Result |
|---|---|
| `platform_check.py`, both Pythons | **17/17 passed** |
| Real profile | **Found** `claude-code 2.1.150` (high `agent.vulnerable-version`) and `claude-desktop 6.28899.6` (no known advisories), plus 5 VS Code extensions |
| Test suite | Ran: 642 passed on 3.12 and 638 on 3.10. The 5 (3.12) and 4 (3.10) failures were the tests seeing the VM's real, deliberately old Claude Code on `PATH`: asca was right, the tests weren't isolated. Fixed with a conftest fixture that gives tests an empty host; reproduced and verified on Linux with a fake old Claude Code on `PATH`. |
| Defender | `test_skillscan.py` was readable all run. The one detection listed was the first run's, which stays in Defender's history; `vm_test.ps1` now counts only detections made during the run. |
| Task Scheduler | OK: `rc=1` (findings) logged, Last Result 0, empty error.log |
| Redirected output | OK |

**Intune discovery script as SYSTEM (2026-11-22):** `examples/intune/discovery-windows.ps1` ran from a SYSTEM scheduled task in the 32-bit Windows PowerShell 5.1 host (Intune's default) while a standard user was at the console. It returned `AscaReportFound:true, AscaReportAgeHours:2, AscaHigh:1, AscaResult:FAIL`, matching that user's report. A first attempt returned the fail-closed result because a different account (with no asca report) was at the console after a user switch. That's the intended behaviour: only the account at the console counts.

**Verdict:** asca works on Windows 11, including ARM64, with the limits listed on this page.

Still open: the Store (MSIX) edition of Claude Desktop installs into `WindowsApps`, which standard users can't list, so its version isn't detected.




