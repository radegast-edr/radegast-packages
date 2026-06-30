# Linux Detection Packs

Detection packs for standalone Linux hosts (RHEL/CentOS/Rocky and Ubuntu/Debian), organized by detection maturity. Domain-joined tactics/techniques (SSSD/Winbind-based AD enumeration, Kerberos) are excluded from all packs.

---

## Pack Tiers

The three packs form a layered hierarchy — each tier extends the one below it.

```
linux-hunting
  └─ extends linux-advanced
       └─ extends linux-essential
```

This means `linux-advanced` covers all techniques from `linux-essential` plus its own additions, and `linux-hunting` covers all techniques from both previous tiers plus its own.

---

## linux-essential

Basic coverage targeting commodity threats and known-bad patterns. High-confidence, low false-positive detections suitable for initial rollout or lower-maturity SOC environments. Each detection should be actionable on a single event with minimal tuning.

**Expected false positive level:** Low

| Technique | Tactic | Name |
|---|---|---|
| T1059 | Execution | Command & Scripting Interpreter |
| T1053 | Persistence | Scheduled Task / Job |
| T1543 | Persistence | Create or Modify System Process |
| T1548 | Privilege Escalation | Abuse Elevation Control Mechanism |
| T1110 | Credential Access | Brute Force |
| T1003 | Credential Access | OS Credential Dumping |
| T1105 | Command & Control | Ingress Tool Transfer |
| T1082 | Discovery | System Information Discovery |

**Populate command:**

```bash
python tools/populate_pack.py \
  --os linux \
  --pack essential \
  --technique T1059 T1053 T1543 T1548 T1110 T1003 T1105 T1082
```

---

## linux-advanced

Middle-ground coverage adding evasion techniques, interpreter abuse, and permission manipulation. Detections at this tier work on patterns and sequences — process ancestry, file path context, command argument correlation — rather than single events.

Extends `linux-essential`. All essential techniques are included via pack inheritance.

**Expected false positive level:** Medium

### Techniques added by this tier

| Technique | Tactic | Name |
|---|---|---|
| T1547 | Persistence | Boot/Logon Autostart Execution |
| T1070 | Defense Evasion | Indicator Removal |
| T1027 | Defense Evasion | Obfuscated Files / Info |
| T1083 | Discovery | File & Directory Discovery |
| T1552 | Credential Access | Unsecured Credentials |
| T1564 | Defense Evasion | Hide Artifacts |
| T1136 | Persistence | Create Account |
| T1222 | Defense Evasion | File & Directory Permissions Modification |
| T1518 | Discovery | Software Discovery |
| T1112 | Defense Evasion | Modify Registry |

### Full technique coverage (essential + advanced)

T1003, T1027, T1053, T1059, T1070, T1082, T1083, T1105, T1110, T1112, T1136, T1222, T1518, T1543, T1547, T1548, T1552, T1564

**Populate command:**

```bash
python tools/populate_pack.py \
  --os linux \
  --pack advanced \
  --technique T1003 T1027 T1053 T1059 T1070 T1082 T1083 T1105 T1110 T1112 T1136 T1222 T1518 T1543 T1547 T1548 T1552 T1564
```

---

## linux-hunting

Advanced threat hunting coverage for subtle, fileless, memory-resident, and kernel-level techniques. Detections at this tier produce candidates for analyst review rather than high-confidence standalone alerts.

Extends `linux-advanced`. All essential and advanced techniques are included via pack inheritance.

**Expected false positive level:** High

### Techniques added by this tier

| Technique | Tactic | Name |
|---|---|---|
| T1574 | Privilege Escalation | Hijack Execution Flow |
| T1620 | Defense Evasion | Reflective Code Loading |
| T1036 | Defense Evasion | Masquerading |
| T1055 | Privilege Escalation | Process Injection |
| T1106 | Execution | Native API |
| T1014 | Defense Evasion | Rootkit |
| T1685 | Defense Evasion | Impair Defenses |
| T1205 | Command & Control | Traffic Signaling |
| T1078.003 | Persistence | Local Accounts |
| T1497 | Defense Evasion | Virtualization / Sandbox Evasion |

### Full technique coverage (essential + advanced + hunting)

T1003, T1014, T1027, T1036, T1053, T1055, T1059, T1070, T1078.003, T1082, T1083, T1105, T1106, T1110, T1112, T1136, T1205, T1222, T1497, T1518, T1543, T1547, T1548, T1552, T1564, T1574, T1620, T1685

**Populate command:**

```bash
python tools/populate_pack.py \
  --os linux \
  --pack hunting \
  --technique T1003 T1014 T1027 T1036 T1053 T1055 T1059 T1070 T1078.003 T1082 T1083 T1105 T1106 T1110 T1112 T1136 T1205 T1222 T1497 T1518 T1543 T1547 T1548 T1552 T1564 T1574 T1620 T1685
```

---

## Deployment order

Deploy and validate each tier before progressing to the next:

1. Deploy `linux-essential` → run Atomic tests for all eight technique IDs on both RHEL and Ubuntu hosts → resolve gaps → tune false positives.
2. Deploy `linux-advanced` → run Atomic tests → tune.
3. Deploy `linux-hunting` → validate against Atomic tests → iterate on analyst triage workflow.

---

## Notes

- All packs exclude domain-joined tactics (SSSD/Winbind-based AD enumeration, Kerberos abuse). A separate pack set covers Linux hosts joined to Active Directory.
- T1548 (Abuse Elevation Control) is placed in `linux-essential` rather than `linux-hunting` as on Windows, because SUID/SGID misconfigurations and sudo abuse are high-prevalence and high-confidence on Linux without requiring behavioral correlation.
- T1112 (Modify Registry) covers the Linux equivalent: sysctl parameter modification and /proc/sys writes that disable kernel security features such as `kernel.yama.ptrace_scope`.
- T1685 is used in this pack in place of T1562 for Impair Defenses, consistent with the updated technique identifier.
- T1014 (Rootkit) detection via eBPF covers both kernel module rootkits (init_module/finit_module) and eBPF-based rootkits detectable via bpf() syscall program type inspection.
- The `--sync` flag can be appended to any populate command to remove rules from the pack that no longer match the current filter criteria.

---

## Excluded tactics and techniques (domain-joined only)

The following tactics and techniques are excluded from all Linux standalone packs because they require Active Directory or SSSD/Winbind domain infrastructure to produce meaningful telemetry. They will be covered in the domain-joined Linux pack set.

### Fully excluded

| Technique | Tactic | Name | Reason for exclusion |
|---|---|---|---|
| T1021 | Lateral Movement | Remote Services | SSH-based lateral movement to domain-authenticated targets requires domain credential context. |
| T1550 | Lateral Movement | Use Alternate Authentication Material | Pass-the-Hash and Pass-the-Ticket via impacket or similar require domain account material. |
| T1558 | Credential Access | Steal or Forge Kerberos Tickets | Kerberoasting and ticket forging require a Kerberos KDC reachable via SSSD or Winbind. |
| T1482 | Discovery | Domain Trust Discovery | Domain trust enumeration via ldapsearch or realm list returns no data on a standalone host. |
| T1615 | Discovery | Group Policy Discovery | GPO enumeration via samba-tool or LDAP requires domain membership. |
| T1018 | Discovery | Remote System Discovery | LDAP and domain-based host enumeration produces no actionable output on a standalone host. |
| T1069.002 | Discovery | Permission Groups Discovery — Domain Groups | Domain group enumeration via LDAP or getent group against AD requires domain membership. |
| T1087.002 | Discovery | Account Discovery — Domain Accounts | Domain account enumeration via ldapsearch or getent passwd against SSSD requires domain membership. |

### Partially excluded — local subtechniques retained

These techniques have both local and domain subtechniques. The local subtechniques are already included in the packs above; only the domain subtechniques are deferred.

| Technique | Included in packs | Excluded subtechnique | Reason |
|---|---|---|---|
| T1078 | T1078.003 (Local Accounts) in `linux-hunting` | T1078.002 (Domain Accounts) | Abusing domain credentials requires SSSD/Winbind AD authentication. |
| T1136 | T1136.001 (Local Account) in `linux-advanced` | T1136.002 (Domain Account) | Creating domain accounts requires AD write access via realm or net ads. |
| T1003 | T1003.007 (Proc Filesystem), T1003.008 (/etc/passwd and /etc/shadow) in `linux-essential` | T1003.003 (NTDS) | NTDS dumping requires access to a Windows Domain Controller. |