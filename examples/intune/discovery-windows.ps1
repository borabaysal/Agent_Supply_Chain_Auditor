# Intune custom compliance discovery script for Windows: asca results for this PC.
# Upload under Endpoint security > Device compliance > Scripts > Add > Windows 10 and later, then use
# examples/intune/rules.json in a custom compliance policy (Windows Pro/Enterprise/Education; not Home).
#
# Pure PowerShell (5.1 and 7, 32- or 64-bit host): it needs no Python at compliance time and never runs asca.
# It reads the last report of the user's daily asca task (scripts/windows/asca-daily.ps1 writes
# %LOCALAPPDATA%\asca\latest.json) and returns the same JSON as `asca export intune`:
#   {"AscaReportFound":true,"AscaReportAgeHours":5,"AscaCritical":0,"AscaHigh":1,"AscaMedium":2,"AscaResult":"FAIL","AscaVersion":"0.5.0"}
# Fail closed: no user, no report, or an unreadable one gives AscaReportFound=false, so the device is non-compliant.
#
# Intune runs it as SYSTEM by default; it then reads the report of the user signed in at the console.
# With "Run this script using the logged on credentials" = Yes, it reads the signed-in user's own report.
# Nobody signed in at the console (or only RDP sessions): non-compliant until the next check with a user present.
param(
    [string]$Report = "",       # tests and special setups: a specific report file
    [string]$NowUtc = ""        # tests: the current time, yyyy-MM-ddTHH:mm:ssZ
)

$ReportOverride = ""            # IT: set to a fixed path (e.g. a shared folder) to skip per-user discovery

$Fmt = "yyyy-MM-dd'T'HH:mm:ss'Z'"      # the only timestamp form asca writes (and `asca export intune` accepts)
$Inv = [Globalization.CultureInfo]::InvariantCulture
$Utc = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal

$hash = [ordered]@{
    AscaReportFound = $false; AscaReportAgeHours = [int64]999999; AscaCritical = [int64]0; AscaHigh = [int64]0
    AscaMedium = [int64]0; AscaResult = "MISSING"; AscaVersion = "0.0.0"
}

function Find-Report {
    if ($Report) { return $Report }
    if ($ReportOverride) { return $ReportOverride }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsSystem) { return (Join-Path $env:LOCALAPPDATA "asca\latest.json") }
    # SYSTEM: find the console user's profile folder (Win32_UserProfile works from the 32-bit host too)
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if (-not $user) { return $null }
    $sid = (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value
    $prof = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$sid'"
    if (-not $prof -or -not $prof.LocalPath) { return $null }
    return (Join-Path $prof.LocalPath "AppData\Local\asca\latest.json")
}

try {
    $ErrorActionPreference = "Stop"
    $path = Find-Report
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
        # Only a JSON object counts: PowerShell 7 would unroll a one-item list into an object
        $d = if ($raw.TrimStart([char]0xFEFF, ' ', "`t", "`r", "`n").StartsWith("{")) { $raw | ConvertFrom-Json } else { $null }
        if ($d -is [Management.Automation.PSCustomObject] -and $d.counts -is [Management.Automation.PSCustomObject]) {
            $now = if ($NowUtc) { [datetime]::ParseExact($NowUtc, $Fmt, $Inv, $Utc) } else { [datetime]::UtcNow }
            # Take generated_at from the raw text: PowerShell 7's ConvertFrom-Json turns dates into local time.
            $age = [int64]999999
            $m = [regex]::Match($raw, '"generated_at"\s*:\s*"([^"]*)"')
            $gen = [datetime]::MinValue
            if ($m.Success -and [datetime]::TryParseExact($m.Groups[1].Value, $Fmt, $Inv, $Utc, [ref]$gen)) {
                $age = [int64][math]::Floor(($now - $gen).TotalHours)
            }
            $c = $d.counts
            $result = [ordered]@{
                AscaReportFound = $true; AscaReportAgeHours = $age
                AscaCritical = [int64]$c.critical; AscaHigh = [int64]$c.high; AscaMedium = [int64]$c.medium
                AscaResult = $(if ($d.result) { [string]$d.result } else { "UNKNOWN" })
                AscaVersion = $(if ($d.version) { [string]$d.version } else { "0.0.0" })
            }
            $hash = $result
        }
    }
} catch {
    # unreadable report, unknown user, bad JSON or numbers: keep the fail-closed default
}

return $hash | ConvertTo-Json -Compress
