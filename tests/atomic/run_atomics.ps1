<#
.SYNOPSIS
    Runs Atomic Red Team tests for all techniques listed in a Radegast pack's attack_coverage,
    or for a single technique supplied directly.

.PARAMETER Pack
    Pack path in the form "os/level" (e.g. "windows/essential", "windows/hunting").
    Optional when -Technique is provided.

.PARAMETER Technique
    Technique ID to run (e.g. "T1003" or "T1003.001").
    When used with -Pack, must be present in the pack's attack_coverage list.
    When used without -Pack, runs the technique directly without pack validation.

.PARAMETER MappingFile
    Optional override: path to a pre-built technique map JSON to use instead of
    the auto-generated one. When omitted, the script locates the Radegast sigma
    directory on any fixed drive, builds technique_map.json there automatically,
    and uses it for detection checking.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential"
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential" -Technique T1003
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Technique T1003
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential" -MappingFile "map.json"
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Technique T1003 -MappingFile "map.json"

.NOTES
    RECOMMENDATION: It is highly recommended to run tests one technique at a time
    using -Technique (e.g. -Technique T1003) rather than running an entire pack.
    Executing all pack techniques in a single session can cause irreversible changes,
    system instability, or data loss on the test machine.
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Pack = "",

    [Parameter(Mandatory = $false)]
    [string]$Technique = "",

    [Parameter(Mandatory = $false)]
    [string]$MappingFile = ""
)

if (-not $Pack -and -not $Technique) {
    Write-Error "You must supply at least -Pack or -Technique."
    exit 1
}

# Re-launch under ExecutionPolicy Bypass if not already running with it
if ((Get-ExecutionPolicy) -ne 'Bypass') {
    Write-Host "Re-launching with ExecutionPolicy Bypass..."
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Pack)        { $argList += " -Pack `"$Pack`"" }
    if ($Technique)   { $argList += " -Technique `"$Technique`"" }
    if ($MappingFile) { $argList += " -MappingFile `"$MappingFile`"" }
    powershell $argList
    exit $LASTEXITCODE
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot  = Split-Path -Parent (Split-Path -Parent $scriptDir)

# ---------------------------------------------------------------------------
# Pre-flight: exactly one sigma rule pack must be installed
# ---------------------------------------------------------------------------
$preflightSigmaDir = $null
foreach ($drv in @([System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
        ForEach-Object { $_.Name })) {
    $candidate = Join-Path $drv "Program Files\Radegast\agent\rules\sigma"
    if (Test-Path $candidate) { $preflightSigmaDir = $candidate; break }
}

if ($preflightSigmaDir) {
    $sigmaSubFolders = @(Get-ChildItem -Path $preflightSigmaDir -Directory -ErrorAction SilentlyContinue)
    if ($sigmaSubFolders.Count -gt 1) {
        Write-Error (
            "Multiple sigma rule packs detected in $preflightSigmaDir " +
            "($($sigmaSubFolders.Count) folders: $($sigmaSubFolders.Name -join ', ')). " +
            "The system must have exactly ONE sigma pack assigned to ensure accurate atomic test results. " +
            "Remove the extra pack(s) and re-run."
        )
        exit 1
    }
}

if ($Pack) {
    $packRelPath = $Pack.Replace('/', '\').Replace('\', [System.IO.Path]::DirectorySeparatorChar)
    $packYmlPath = Join-Path $repoRoot "packs\$packRelPath\pack.yml"

    if (-not (Test-Path $packYmlPath)) {
        Write-Error "pack.yml not found: $packYmlPath"
        exit 1
    }

    Write-Host "Pack      : $Pack"
    Write-Host "Pack YAML : $packYmlPath"
}

# ---------------------------------------------------------------------------
# Step 1 - Exclude main drives from Windows Defender to prevent test blocking
# ---------------------------------------------------------------------------
Write-Host "`n[1/3] Adding Windows Defender exclusions for C:\ and D:\..."
Add-MpPreference -ExclusionPath "C:\", "D:\" -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Step 2 - Download and install Invoke-AtomicRedTeam + atomics (skip if present)
# ---------------------------------------------------------------------------
$modulePath  = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
$atomicsPath = "C:\AtomicRedTeam\atomics"

if ((Test-Path $modulePath) -and (Test-Path $atomicsPath)) {
    Write-Host "`n[2/3] Invoke-AtomicRedTeam and atomics already present - skipping download."
} else {
    Write-Host "`n[2/3] Installing Invoke-AtomicRedTeam and downloading atomics..."
    Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
}

if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    Write-Warning "Module not found at expected path: $modulePath - Invoke-AtomicTest may already be loaded."
}

# ---------------------------------------------------------------------------
# Step 3 - Resolve the technique list
# ---------------------------------------------------------------------------
$techniques = @()

if ($Pack) {
    Write-Host "`n[3/3] Parsing attack_coverage from $Pack..."
    $inSection = $false

    foreach ($line in (Get-Content -Path $packYmlPath)) {
        if ($line -match '^attack_coverage\s*:') {
            $inSection = $true
            continue
        }
        if ($inSection) {
            if ($line -match '^\s+-\s+(T\d+(?:\.\d+)?)') {
                $techniques += $Matches[1]
            } elseif ($line -match '^\S' -and $line.Trim() -ne '') {
                $inSection = $false
            }
        }
    }

    if ($techniques.Count -eq 0) {
        Write-Warning "No attack_coverage techniques found in pack '$Pack'. Nothing to run."
        exit 0
    }

    if ($Technique) {
        $normalized = $Technique.Trim().ToUpper()
        if ($techniques -notcontains $normalized) {
            Write-Error "Technique '$normalized' is not in the attack_coverage of pack '$Pack'."
            Write-Host "Available techniques: $($techniques -join ', ')"
            exit 1
        }
        $techniques = @($normalized)
        Write-Host "Filtering to technique: $normalized"
    }
} else {
    Write-Host "`n[3/3] Using supplied technique: $Technique"
    $techniques = @($Technique.Trim().ToUpper())
}

Write-Host "Found $($techniques.Count) technique(s): $($techniques -join ', ')"

# ---------------------------------------------------------------------------
# Auto-build technique map from Radegast's installed sigma rules
# ---------------------------------------------------------------------------
if (-not $MappingFile) {
    $radegastSigmaDir = $null
    foreach ($drv in @([System.IO.DriveInfo]::GetDrives() |
            Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
            ForEach-Object { $_.Name })) {
        $candidate = Join-Path $drv "Program Files\Radegast\agent\rules\sigma"
        if (Test-Path $candidate) { $radegastSigmaDir = $candidate; break }
    }

    if ($radegastSigmaDir) {
        Write-Host "`n[map] Building technique map from: $radegastSigmaDir"
        $rawMap = @{}
        $ymlFiles = @(Get-ChildItem -Path $radegastSigmaDir -Recurse -Filter "*.yml" -ErrorAction SilentlyContinue)
        Write-Host "  [map] Scanning $($ymlFiles.Count) sigma file(s)..."

        foreach ($ymlFile in $ymlFiles) {
            try { $lines = Get-Content $ymlFile.FullName -ErrorAction Stop } catch { continue }
            $ruleTitle = ""; $inTags = $false; $ruleTechs = @()
            foreach ($ln in $lines) {
                if ($ln -match '^title\s*:\s*(.+)') {
                    $ruleTitle = $Matches[1].Trim().Trim('"').Trim("'")
                }
                if ($ln -match '^tags\s*:') { $inTags = $true; continue }
                if ($inTags) {
                    if ($ln -match '^\s+-\s+attack\.(t\d+(?:\.\d+)?)\s*$') {
                        $ruleTechs += $Matches[1].ToUpper()
                    } elseif ($ln -match '^\S' -and $ln.Trim() -ne '') {
                        $inTags = $false
                    }
                }
            }
            if ($ruleTitle -and $ruleTechs.Count -gt 0) {
                foreach ($tid in $ruleTechs) {
                    if (-not $rawMap.ContainsKey($tid)) { $rawMap[$tid] = @() }
                    if ($rawMap[$tid] -notcontains $ruleTitle) { $rawMap[$tid] += $ruleTitle }
                }
            }
        }

        $techObj = [ordered]@{}
        foreach ($k in ($rawMap.Keys | Sort-Object)) { $techObj[$k] = @($rawMap[$k]) }
        $autoMapPath = Join-Path $radegastSigmaDir "technique_map.json"
        [PSCustomObject]@{ techniques = [PSCustomObject]$techObj } |
            ConvertTo-Json -Depth 5 |
            Set-Content -Path $autoMapPath -Encoding UTF8
        Write-Host "  [map] technique_map.json written: $($rawMap.Count) technique(s) -> $autoMapPath"
        $MappingFile = $autoMapPath
    } else {
        Write-Warning "[map] Radegast sigma directory not found on any fixed drive. Detection checking disabled."
    }
}

# ---------------------------------------------------------------------------
# Load sigma technique map
# ---------------------------------------------------------------------------
$techniqueMap = @{}
if ($MappingFile) {
    if (-not (Test-Path $MappingFile)) {
        Write-Error "Mapping file not found: $MappingFile"
        exit 1
    }
    $mapData = Get-Content $MappingFile -Raw | ConvertFrom-Json
    foreach ($prop in $mapData.techniques.PSObject.Properties) {
        $techniqueMap[$prop.Name] = @($prop.Value)
    }
    Write-Host "Mapping file: $MappingFile -- $($techniqueMap.Count) technique(s) loaded"
}

# Radegast alerts log - one JSON object per line, named alerts.json.<date>
$logDir  = "C:\Program Files\Radegast\agent\logs"
$logFile = Join-Path $logDir "alerts.json.$(Get-Date -Format 'yyyy-MM-dd')"

Write-Host "`nRunning Invoke-AtomicTest for each technique...`n"

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
$failed    = @()
$detected  = @()
$missed    = @()

$divider = "=" * 60
$techIndex = 0
foreach ($technique in $techniques) {
    $techIndex++
    $techStart = Get-Date
    Write-Host $divider
    Write-Host "[$techIndex/$($techniques.Count)] $technique  started at $($techStart.ToString('HH:mm:ss'))"
    Write-Host $divider

    # Record test start in UTC ISO-8601 for timestamp-based log filtering
    $testStartUtc = $techStart.ToUniversalTime()
    $testStartStr = $testStartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "  [log] Test start time (UTC): $testStartStr"

    Write-Host "  [test] Invoking Invoke-AtomicTest $technique (timeout 120s)..."
    $testErrored = $false
    try {
        Invoke-AtomicTest $technique -TimeoutSeconds 120 -ErrorAction Continue
    } catch {
        Write-Warning "  [test] Error running ${technique}: $_"
        $failed += $technique
        $testErrored = $true
    }
    $testElapsed = [int](New-TimeSpan -Start $techStart -End (Get-Date)).TotalSeconds
    Write-Host "  [test] Invoke-AtomicTest finished in ${testElapsed}s (errored: $testErrored)"

    if (-not $MappingFile) { continue }

    # Wait for the EDR to process and write alerts
    Write-Host "  [wait] Sleeping 10s for Radegast to process events..."
    for ($i = 10; $i -gt 0; $i--) {
        Write-Host "  [wait] $i..." -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host ""

    # Filter log to alerts whose timestamp is at or after the test start time
    Write-Host "  [log] Reading $logFile for alerts at or after $testStartStr"
    $newAlerts = @()
    if (Test-Path $logFile) {
        $allLines = @(Get-Content $logFile)
        Write-Host "  [log] Total lines in log: $($allLines.Count)"
        foreach ($rawLine in $allLines) {
            if (-not $rawLine.Trim()) { continue }
            try {
                $parsed = $rawLine | ConvertFrom-Json
                $alertTs = $parsed.'@timestamp'
                if (-not $alertTs) { $alertTs = $parsed.'event.created' }
                if (-not $alertTs) { $alertTs = $parsed.'timestamp' }
                if ($alertTs) {
                    $alertTime = [DateTimeOffset]::Parse($alertTs).UtcDateTime
                    if ($alertTime -ge $testStartUtc) {
                        $newAlerts += $rawLine
                    }
                }
            } catch {
                # unparseable line - skip silently
            }
        }
        Write-Host "  [log] Alerts at or after test start: $($newAlerts.Count)"
    } else {
        Write-Warning "  [log] Log file still not found: $logFile"
    }

    # Match new alert rule names against the sigma rules for this technique
    $rulesForTech = if ($techniqueMap.ContainsKey($technique)) { $techniqueMap[$technique] } else { @() }
    Write-Host "  [map] $($rulesForTech.Count) sigma rule(s) mapped to $technique"
    $detectedRules = [ordered]@{}  # rule.name -> timestamp, deduped, first occurrence wins

    foreach ($line in $newAlerts) {
        if (-not $line.Trim()) { continue }
        try {
            $entry    = $line | ConvertFrom-Json
            $ruleName = $entry.'rule.name'
            Write-Host "  [alert] $ruleName"
            if ($ruleName -and $rulesForTech -contains $ruleName -and -not $detectedRules.Contains($ruleName)) {
                $ts = $entry.'@timestamp'
                if (-not $ts) { $ts = $entry.'event.created' }
                if (-not $ts) { $ts = $entry.'timestamp' }
                if (-not $ts) { $ts = '(no timestamp)' }
                $detectedRules[$ruleName] = $ts
            }
        } catch {
            Write-Warning "  [alert] Failed to parse alert line: $_"
        }
    }

    $totalElapsed = [int](New-TimeSpan -Start $techStart -End (Get-Date)).TotalSeconds
    if ($detectedRules.Count -gt 0) {
        Write-Host "  [DETECTED] $technique  ($($detectedRules.Count) rule(s) fired, total: ${totalElapsed}s)" -ForegroundColor Green
        foreach ($ruleName in $detectedRules.Keys) {
            Write-Host "    rule: $ruleName  at: $($detectedRules[$ruleName])" -ForegroundColor Green
        }
        $detected += $technique
    } else {
        Write-Warning "  [NOT DETECTED] $technique -- $($newAlerts.Count) new alerts, none matched  (total: ${totalElapsed}s)"
        $missed += $technique
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$separator = "=" * 60
Write-Host "`n$separator"
Write-Host "Atomic tests complete."
Write-Host "Ran          : $($techniques.Count) technique(s)"
if ($failed.Count -gt 0) {
    Write-Warning "Exec errors  : $($failed -join ', ')"
}
if ($MappingFile) {
    Write-Host "Detected     : $($detected.Count)  [ $($detected -join ', ') ]" -ForegroundColor Green
    if ($missed.Count -gt 0) {
        Write-Warning ('Not detected : ' + $missed.Count + '  [ ' + ($missed -join ', ') + ' ]')
    }
}
