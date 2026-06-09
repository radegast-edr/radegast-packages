<#
.SYNOPSIS
    Runs Atomic Red Team tests for all techniques listed in a Radegast pack's attack_coverage.

.PARAMETER Pack
    Pack path in the form "os/level" (e.g. "windows/essential", "windows/hunting").

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential"
    powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/hunting"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Pack
)

# Re-launch under ExecutionPolicy Bypass if not already running with it
if ((Get-ExecutionPolicy) -ne 'Bypass') {
    Write-Host "Re-launching with ExecutionPolicy Bypass..."
    $argList = "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Pack `"$Pack`""
    powershell $argList
    exit $LASTEXITCODE
}

# Resolve the pack.yml path relative to this script:
#   tests/atomic/run_atomics.ps1 -> repo root -> packs/<os>/<level>/pack.yml
$scriptDir   = Split-Path -Parent $PSCommandPath
$repoRoot    = Split-Path -Parent (Split-Path -Parent $scriptDir)
$packRelPath = $Pack.Replace('/', '\').Replace('\', [System.IO.Path]::DirectorySeparatorChar)
$packYmlPath = Join-Path $repoRoot "packs\$packRelPath\pack.yml"

if (-not (Test-Path $packYmlPath)) {
    Write-Error "pack.yml not found: $packYmlPath"
    exit 1
}

Write-Host "Pack      : $Pack"
Write-Host "Pack YAML : $packYmlPath"

# ---------------------------------------------------------------------------
# Step 1 - Exclude main drives from Windows Defender to prevent test blocking
# ---------------------------------------------------------------------------
Write-Host "`n[1/3] Adding Windows Defender exclusions for C:\ and D:\..."
Add-MpPreference -ExclusionPath "C:\", "D:\" -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Step 2 - Download and install Invoke-AtomicRedTeam + atomics
# ---------------------------------------------------------------------------
Write-Host "`n[2/3] Installing Invoke-AtomicRedTeam and downloading atomics..."
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Import the module so Invoke-AtomicTest is available in this session
$modulePath = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
} else {
    Write-Warning "Module not found at expected path: $modulePath - Invoke-AtomicTest may already be loaded."
}

# ---------------------------------------------------------------------------
# Step 3 - Parse attack_coverage from pack.yml (no external YAML dependency)
# ---------------------------------------------------------------------------
Write-Host "`n[3/3] Parsing attack_coverage from $Pack..."
$techniques = @()
$inSection  = $false

foreach ($line in (Get-Content -Path $packYmlPath)) {
    if ($line -match '^attack_coverage\s*:') {
        $inSection = $true
        continue
    }
    if ($inSection) {
        if ($line -match '^\s+-\s+(T\d+(?:\.\d+)?)') {
            $techniques += $Matches[1]
        } elseif ($line -match '^\S' -and $line.Trim() -ne '') {
            # A new top-level key means the section is over
            $inSection = $false
        }
    }
}

if ($techniques.Count -eq 0) {
    Write-Warning "No attack_coverage techniques found in pack '$Pack'. Nothing to run."
    exit 0
}

Write-Host "Found $($techniques.Count) technique(s): $($techniques -join ', ')"
Write-Host "`nRunning Invoke-AtomicTest for each technique...`n"

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
$failed = @()

$divider = "=" * 60
foreach ($technique in $techniques) {
    Write-Host $divider
    Write-Host "Invoke-AtomicTest $technique"
    Write-Host $divider
    try {
        Invoke-AtomicTest $technique -TimeoutSeconds 120 -ErrorAction Continue
    } catch {
        Write-Warning "Error running ${technique}: $_"
        $failed += $technique
    }
}

$separator = "=" * 60
Write-Host "`n$separator"
Write-Host "Atomic tests complete."
Write-Host "Ran   : $($techniques.Count) technique(s)"
if ($failed.Count -gt 0) {
    Write-Warning "Failed: $($failed -join ', ')"
}
