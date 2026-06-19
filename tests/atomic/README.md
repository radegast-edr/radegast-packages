# Atomic Red Team Tests

## Overview

`run_atomics.ps1` runs [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam) tests against MITRE ATT&CK techniques and checks whether Radegast EDR detected them.

The script handles its own setup — it installs Invoke-AtomicRedTeam if not already present, adds Windows Defender exclusions so tests are not blocked, builds a technique-to-sigma-rule map from the installed Radegast rules, and reports detection results after each test.

> **Warning:** Run tests one technique at a time. Executing an entire pack in a single session can cause irreversible changes, system instability, or data loss on the test machine.

---

## Prerequisites

- Windows machine with Radegast EDR agent installed
- PowerShell running as Administrator
- Exactly **one** sigma rule pack assigned in `C:\Program Files\Radegast\agent\rules\sigma\` (or equivalent drive)
- Internet access for the first run (downloads Invoke-AtomicRedTeam)

---

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Pack` | No* | Pack path in the form `os/level` (e.g. `windows/essential`). |
| `-Technique` | No* | Single MITRE technique ID to test (e.g. `T1003` or `T1003.001`). |
| `-MappingFile` | No | Path to a pre-built `technique_map.json`. Defaults to auto-generated from installed sigma rules. |

\* At least one of `-Pack` or `-Technique` must be supplied.

---

## Usage

**Test a single technique (recommended):**
```powershell
powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Technique T1003
```

**Test one technique from a specific pack (validates the technique is in the pack):**
```powershell
powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential" -Technique T1003
```

**Run all techniques in a pack (not recommended — see warning above):**
```powershell
powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Pack "windows/essential"
```

**Use a custom mapping file instead of the auto-generated one:**
```powershell
powershell -ExecutionPolicy Bypass -File run_atomics.ps1 -Technique T1003 -MappingFile "C:\path\to\technique_map.json"
```

---

## What the script does

1. Validates that exactly one sigma rule pack is installed (exits with an error if more than one is found).
2. Adds Windows Defender exclusions for `C:\` and `D:\` to prevent test interference.
3. Installs Invoke-AtomicRedTeam and downloads atomics if not already present.
4. Resolves the list of techniques to test (from the pack's `attack_coverage` or from `-Technique`).
5. Scans the installed sigma rules and generates `technique_map.json` mapping each MITRE technique ID to the sigma rule titles that cover it.
6. For each technique:
   - Records the test start time.
   - Runs `Invoke-AtomicTest` (120s timeout per sub-test).
   - Waits 10 seconds for Radegast to process events.
   - Reads the Radegast alert log and filters to entries generated after the test started.
   - Reports `[DETECTED]` with the matched rule name and timestamp, or `[NOT DETECTED]` if no alert matched.
7. Prints a summary of detected vs. not-detected techniques.

---

## Detection output

A detected technique looks like:
```
  [DETECTED] T1003  (1 rule(s) fired, total: 42s)
    rule: OS Credential Dumping  at: 2026-06-19T10:15:32Z
```

A missed technique looks like:
```
  WARNING: [NOT DETECTED] T1003 -- 0 new alerts, none matched  (total: 42s)
```
