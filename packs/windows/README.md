# Windows Detection Packs

Detection packs for standalone Windows workstations, organized by detection maturity. Domain-joined tactics/techniques (lateral movement, Kerberos, AD enumeration) are excluded from all packs.

All packs include only **critical** and **high** severity rules.

---

## Pack Tiers

The three packs form a layered hierarchy — each tier extends the one below it.

```
windows-hunting
  └─ extends windows-advanced
       └─ extends windows-essential
```

This means `windows-advanced` covers all techniques from `windows-essential` plus its own additions, and `windows-hunting` covers all techniques from both previous tiers plus its own.

---

## windows-essential

Basic coverage targeting commodity threats and known-bad patterns. High-confidence, low false-positive detections suitable for initial rollout or lower-maturity SOC environments. Each detection should be actionable on a single event with minimal tuning.

**Expected false positive level:** Low

| Technique | Tactic | Name |
|---|---|---|
| T1059 | Execution | Command & Scripting Interpreter |
| T1547 | Persistence | Boot/Logon Autostart Execution |
| T1053 | Persistence | Scheduled Task / Job |
| T1543 | Persistence | Create or Modify System Process |
| T1082 | Discovery | System Information Discovery |
| T1685 | Defense Evasion | Disable or Modify Tools |
| T1003 | Credential Access | OS Credential Dumping |
| T1105 | Command & Control | Ingress Tool Transfer |
| T1204 | Execution | User Execution |

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack essential \
  --level critical high \
  --technique T1059 T1547 T1053 T1543 T1082 T1685 T1003 T1105
```

T1204 was added separately, per rule, via `--description` filters rather than a blanket `--technique T1204` — see the [Notes](#notes) section below for why.

---

## windows-advanced

Middle-ground coverage adding evasion techniques, process injection, and living-off-the-land binary (LOLBin) abuse. Detections at this tier work on patterns and context — parent-child relationships, path and hash correlation, sequences of events — rather than single indicators.

Extends `windows-essential`. All essential techniques are included via pack inheritance.

**Expected false positive level:** Medium

### Techniques added by this tier

| Technique | Tactic | Name |
|---|---|---|
| T1027 | Defense Evasion | Obfuscated Files / Info |
| T1218 | Defense Evasion | Signed Binary Proxy Execution |
| T1055 | Privilege Escalation | Process Injection |
| T1134 | Privilege Escalation | Access Token Manipulation |
| T1083 | Discovery | File & Directory Discovery |
| T1518 | Discovery | Software Discovery |
| T1552 | Credential Access | Unsecured Credentials |
| T1112 | Defense Evasion | Modify Registry |
| T1070 | Defense Evasion | Indicator Removal |
| T1564 | Defense Evasion | Hide Artifacts |

### Full technique coverage (essential + advanced)

T1003, T1027, T1053, T1055, T1059, T1070, T1082, T1083, T1105, T1112, T1134, T1204, T1218, T1518, T1543, T1547, T1552, T1564, T1685

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack advanced \
  --level critical high \
  --technique T1003 T1027 T1053 T1055 T1059 T1070 T1082 T1083 T1105 T1112 T1134 T1218 T1518 T1543 T1547 T1552 T1564 T1685
```

---

## windows-hunting

Advanced threat hunting coverage for subtle, fileless, and living-off-the-land techniques. Detections at this tier produce candidates for analyst review rather than high-confidence standalone alerts.

Extends `windows-advanced`. All essential and advanced techniques are included via pack inheritance.

**Expected false positive level:** High

### Techniques added by this tier

| Technique | Tactic | Name |
|---|---|---|
| T1620 | Defense Evasion | Reflective Code Loading |
| T1574 | Privilege Escalation | Hijack Execution Flow |
| T1548 | Privilege Escalation | Abuse Elevation Control Mechanism |
| T1036 | Defense Evasion | Masquerading |
| T1140 | Defense Evasion | Deobfuscate / Decode Files or Information |
| T1497 | Defense Evasion | Virtualization / Sandbox Evasion |
| T1059.001 | Execution | PowerShell — advanced patterns |
| T1106 | Execution | Native API |
| T1055.012 | Defense Evasion | Process Hollowing |
| T1078.003 | Persistence | Local Accounts |
| T1047 | Execution | Windows Management Instrumentation |

### Full technique coverage (essential + advanced + hunting)

T1003, T1027, T1036, T1047, T1053, T1055, T1055.012, T1059, T1059.001, T1070, T1078.003, T1082, T1083, T1105, T1106, T1112, T1134, T1140, T1204, T1218, T1497, T1518, T1543, T1547, T1548, T1552, T1564, T1574, T1620, T1685

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack hunting \
  --level critical high \
  --technique T1003 T1027 T1036 T1047 T1053 T1055 T1055.012 T1059 T1059.001 T1070 T1078.003 T1082 T1083 T1105 T1106 T1112 T1134 T1140 T1218 T1497 T1518 T1543 T1547 T1548 T1552 T1564 T1574 T1620 T1685
```

---

## Deployment order

Deploy and validate each tier before progressing to the next:

1. Deploy `windows-essential` → run Atomic tests for all nine technique IDs → resolve gaps → tune false positives.
2. Deploy `windows-advanced` → run Atomic tests → tune.
3. Deploy `windows-hunting` → validate against Atomic tests → iterate on analyst triage workflow.

---

## Notes

- All packs exclude domain-joined tactics (lateral movement, Kerberos abuse, AD enumeration).
- T1059 appears in `windows-essential` (commodity execution detection) and `windows-hunting` (T1059.001 — advanced PowerShell pattern hunting) as distinct detection logic targeting different sub-technique behaviors.
- T1078.003 is placed in `windows-hunting` rather than `windows-essential` despite being a standalone-host-relevant technique, because reliable detection requires behavioral context that a single event cannot provide.
- T1685 is used in this pack in place of T1562 for Disable or Modify Tools, consistent with the updated technique identifier.
- T1204 (User Execution) sub-technique T1204.001 and some T1204.004 rules are ClickFix/FileFix detections that live exclusively in the separate `windows-clickfix` pack (`packs/windows/clickfix/`), which targets a specific campaign rather than general ATT&CK coverage. A blanket `python tools/populate_pack.py --technique T1204` would prefix-match those sub-techniques and duplicate them here, so the 9 general (non-ClickFix) T1204-family rules were added individually via `--description "<unique substring>" --level critical high` instead. This also skipped 8 T1204.002/.004 rules that were already present in `windows-advanced`/`windows-hunting` only, leaving essential's T1204 footprint intentionally narrower until those are deliberately backfilled.
- The `--sync` flag can be appended to any populate command to remove rules from the pack that no longer match the current filter criteria.
