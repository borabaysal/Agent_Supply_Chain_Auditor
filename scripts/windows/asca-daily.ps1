# asca daily audit for Windows Task Scheduler (user context). Untested until the Windows VM run; see docs\windows.md.
# Writes %LOCALAPPDATA%\asca\latest.md/.json, appends one line to run.log, prints nothing on success.
# Exit code: 0 = ran (pass or findings), 2 = asca itself failed, so Task Scheduler shows a failed last run.
param(
    [string]$AscaDir = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path,
    [ValidateSet("never", "change", "fail", "always")][string]$Telegram = "never",
    [string]$EnvFile = ""
)
$state = Join-Path $env:LOCALAPPDATA "asca"
New-Item -ItemType Directory -Force -Path $state | Out-Null
$pyArgs = @("-3", "-m", "asca", "--format", "none", "-o", (Join-Path $state "latest"), "--telegram", $Telegram)
if ($EnvFile) { $pyArgs += @("--env-file", $EnvFile) }
Push-Location $AscaDir
try {
    & py @pyArgs 2>> (Join-Path $state "error.log")
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
}
Add-Content -Path (Join-Path $state "run.log") -Value "$(Get-Date -Format o) rc=$rc"
if ($rc -ge 2) { exit $rc }
exit 0
