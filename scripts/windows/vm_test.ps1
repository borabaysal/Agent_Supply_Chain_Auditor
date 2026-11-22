# asca Windows VM test: runs every step of docs\windows.md and writes one results file to the Desktop.
# Run from the asca folder in a normal (non-admin) PowerShell window:
#     powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\vm_test.ps1
# Output is shape only (rules, severities, counts, exit codes, versions), never file contents or key values.
$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [Text.Encoding]::UTF8      # decode Python's UTF-8 output; PYTHONIOENCODING is NOT set on purpose
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Started = Get-Date          # Defender keeps old detections in its history; only count the ones from this run
$Out = Join-Path ([Environment]::GetFolderPath("Desktop")) "asca-windows-results.txt"
Set-Location $Root
Remove-Item $Out -ErrorAction SilentlyContinue

function Step([string]$Title, [scriptblock]$Body) {
    Write-Host "`n===== $Title" -ForegroundColor Cyan
    $text = "`n===== $Title`n" + ((& $Body 2>&1 | ForEach-Object { "$_" }) -join "`n")
    $text | Out-File -FilePath $Out -Append -Encoding utf8
    Write-Host $text
}

Step "system" {
    $os = Get-CimInstance Win32_OperatingSystem
    "$($os.Caption) build $($os.BuildNumber), CPU arch $env:PROCESSOR_ARCHITECTURE"
    "asca commit: $(git rev-parse --short HEAD 2>$null)"
    py --list
    foreach ($v in "3.12", "3.10") { py -$v -c "import platform,sys; print(sys.version.split()[0], platform.machine())" }
    "node $(node --version 2>$null) | git $(git --version 2>$null)"
    $dev = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -ErrorAction SilentlyContinue).AllowDevelopmentWithoutDevLicense
    "Developer Mode (symlinks): $(if ($dev -eq 1) { 'on' } else { 'off' })"
    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { ($_.Resources -join ' ') -like '*asca*' }
    "Defender detections in the asca folder (all time, incl. old): $(@($det).Count)"
}

foreach ($v in "3.12", "3.10") {
    Step "A. test suite, Python $v" { py -$v -m pytest -q -p no:cacheprovider -rfs 2>&1 | Select-Object -Last 40 }
    Step "B. planted problems (platform_check), Python $v" { py -$v scripts\platform_check.py }
}

Step "C. redirected output (Task Scheduler / pipes use cp1252)" {
    py -3.12 -m asca check-repo $Root > "$env:TEMP\asca-cr.txt" 2> "$env:TEMP\asca-cr.err"
    "check-repo to a file: exit $LASTEXITCODE, stderr bytes $((Get-Item "$env:TEMP\asca-cr.err").Length)"
    Get-Content "$env:TEMP\asca-cr.err" -TotalCount 5
}

Step "D. this VM's real profile (counts only)" {
    py -3.12 -m asca --format none -o "$env:TEMP\asca-real" 2>&1 | Select-Object -Last 5
    "audit exit: $LASTEXITCODE (0 pass, 1 findings, 2 error)"
    @'
import collections, json, os
d = json.load(open(os.path.join(os.environ["TEMP"], "asca-real.json"), encoding="utf-8"))
print("result:", d["result"], {k: v for k, v in d["counts"].items() if v})
print("agent versions:", d["stats"].get("agent_versions"))
print("configs scanned:", {k: v for k, v in d["stats"].items() if isinstance(v, int) and v})
for (rule, sev), n in sorted(collections.Counter((f["rule"], f["severity"]) for f in d["findings"]).items()):
    print(f"  {sev:8} {rule}  x{n}")
'@ | py -3.12 -
    py -3.12 -m asca inventory --dir "$env:TEMP\asca-inv" --format none -o "$env:TEMP\asca-inv.json" 2>&1 | Select-Object -Last 3
    "inventory exit: $LASTEXITCODE"
    @'
import collections, json, os
d = json.load(open(os.path.join(os.environ["TEMP"], "asca-inv.json"), encoding="utf-8"))
print("inventory:", d["result"], "first run" if d.get("first_run") else "", "sources:", len(d["sources"]))
for (kind, src), n in sorted(collections.Counter((i["kind"], i["source"]) for i in d["items"]).items()):
    print(f"  {kind:16} {src:14} x{n}")
'@ | py -3.12 -
}

Step "E. Task Scheduler (current user, no Telegram)" {
    $ps1 = Join-Path $Root "scripts\windows\asca-daily.ps1"
    schtasks /Create /SC DAILY /ST 09:00 /TN "asca daily audit" /TR "powershell -NoProfile -ExecutionPolicy Bypass -File `"$ps1`"" /F
    schtasks /Run /TN "asca daily audit"
    $log = Join-Path $env:LOCALAPPDATA "asca\run.log"
    for ($i = 0; $i -lt 40 -and -not (Test-Path $log); $i++) { Start-Sleep 5 }
    Start-Sleep 5
    if (Test-Path $log) { Get-Content $log -Tail 3 } else { "no run.log after 200 s" }
    Get-ChildItem (Join-Path $env:LOCALAPPDATA "asca") -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) $($_.Length) bytes" }
    $err = Join-Path $env:LOCALAPPDATA "asca\error.log"
    if ((Test-Path $err) -and (Get-Item $err).Length) { "error.log (last lines):"; Get-Content $err -Tail 5 }
    schtasks /Query /TN "asca daily audit" /V /FO LIST | Select-String "Last Result|Last Run"
    schtasks /Delete /TN "asca daily audit" /F
}

Step "Defender after the run" {
    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { ($_.Resources -join ' ') -like '*asca*' -and $_.InitialDetectionTime -ge $Started }
    "new detections in the asca folder during this run: $(@($det).Count)"
    $det | ForEach-Object { ($_.Resources -join ' ') }
}

Write-Host "`nDone. Results: $Out  (paste its contents back to Hermes)" -ForegroundColor Green
