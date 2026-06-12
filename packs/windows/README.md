# Windows Detection Packs

Detection packs for standalone Windows workstations, organized by detection maturity and telemetry requirements. Domain-joined tactics (lateral movement, Kerberos, AD enumeration) are excluded from all packs.

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

**Telemetry required:** Windows Security Event Log, Sysmon (basic — EID 1, 3, 11), PowerShell logging.

**Expected false positive level:** Low

| Technique | Tactic | Name |
|---|---|---|
| T1059 | Execution | Command & Scripting Interpreter |
| T1547 | Persistence | Boot/Logon Autostart Execution |
| T1053 | Persistence | Scheduled Task / Job |
| T1543 | Persistence | Create or Modify System Process |
| T1082 | Discovery | System Information Discovery |
| T1562 | Defense Evasion | Impair Defenses |
| T1003 | Credential Access | OS Credential Dumping |
| T1105 | Command & Control | Ingress Tool Transfer |

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack essential \
  --level critical high \
  --technique T1059 T1547 T1053 T1543 T1082 T1562 T1003 T1105
```

---

## windows-advanced

Middle-ground coverage adding evasion techniques, process injection, and living-off-the-land binary (LOLBin) abuse. Detections at this tier work on patterns and context — parent-child relationships, path and hash correlation, sequences of events — rather than single indicators. Requires a tuned Sysmon deployment and noise suppression before detections are operationally useful.

Extends `windows-essential`. All essential techniques are included via pack inheritance.

**Telemetry required:** Full Sysmon coverage (EID 1, 3, 7, 10, 11, 12, 13), PowerShell ScriptBlock logging, Windows Security Event Log.

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

T1003, T1027, T1053, T1055, T1059, T1070, T1082, T1083, T1105, T1112, T1134, T1218, T1518, T1543, T1547, T1552, T1562, T1564

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack advanced \
  --level critical high \
  --technique T1003 T1027 T1053 T1055 T1059 T1070 T1082 T1083 T1105 T1112 T1134 T1218 T1518 T1543 T1547 T1552 T1562 T1564
```

---

## windows-hunting

Advanced threat hunting coverage for subtle, fileless, and living-off-the-land techniques. Detections at this tier produce candidates for analyst review rather than high-confidence standalone alerts. Requires full telemetry including ETW-level kernel events, PowerShell ScriptBlock logging, and behavioral correlation across multiple events over time.

Extends `windows-advanced`. All essential and advanced techniques are included via pack inheritance.

**Telemetry required:** Full Sysmon, ETW kernel provider events, PowerShell ScriptBlock and Module logging, Windows Defender ATP or equivalent EDR telemetry.

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

### Full technique coverage (essential + advanced + hunting)

T1003, T1027, T1036, T1053, T1055, T1055.012, T1059, T1059.001, T1070, T1078.003, T1082, T1083, T1105, T1106, T1112, T1134, T1140, T1218, T1497, T1518, T1543, T1547, T1548, T1552, T1562, T1564, T1574, T1620

**Populate command:**

```bash
python tools/populate_pack.py \
  --os windows \
  --pack hunting \
  --level critical high \
  --technique T1003 T1027 T1036 T1053 T1055 T1055.012 T1059 T1059.001 T1070 T1078.003 T1082 T1083 T1105 T1106 T1112 T1134 T1140 T1218 T1497 T1518 T1543 T1547 T1548 T1552 T1562 T1564 T1574 T1620
```

---

## Deployment order

Deploy and validate each tier before progressing to the next:

1. Deploy `windows-essential` → run Atomic tests for all eight technique IDs → resolve gaps → tune false positives.
2. Verify Sysmon coverage is complete → deploy `windows-advanced` → run Atomic tests → tune.
3. Confirm ETW and ScriptBlock logging are operational → deploy `windows-hunting` → validate against Atomic tests → iterate on analyst triage workflow.

---

## Notes

- All packs exclude domain-joined tactics (lateral movement, Kerberos abuse, AD enumeration).
- T1059 appears in `windows-essential` (commodity execution detection) and `windows-hunting` (T1059.001 — advanced PowerShell pattern hunting) as distinct detection logic targeting different sub-technique behaviors.
- T1078.003 is placed in `windows-hunting` rather than `windows-essential` despite being a standalone-host-relevant technique, because reliable detection requires behavioral context that a single event cannot provide.
- The `--sync` flag can be appended to any populate command to remove rules from the pack that no longer match the current filter criteria.
