# Linux Technique Priority List

This folder holds the ranked ATT&CK technique priority list used to decide what
Linux detection content to build next, plus the mapping data used to keep
that list in sync with MITRE ATT&CK revisions.

| File | Purpose |
|---|---|
| `linux_top_techniques.json` | Ranked list of ATT&CK techniques (and their sub-techniques) relevant to Linux, scored by an external prioritization pipeline. |
| `t1562_v19_mapping.json` | Source-of-truth mapping for the ATT&CK v19 revision that revoked `T1562` and replaced it with `T1685`-`T1690`. Kept for reference/audit — see [ATT&CK v19 migration](#attck-v19-migration-t1562--t1685-t1690) below. Identical to [`techniques/windows/t1562_v19_mapping.json`](../windows/t1562_v19_mapping.json) — the mapping is framework-wide, not OS-specific. |

## `linux_top_techniques.json` schema

Each top-level entry:

```jsonc
{
  "rank": 1,                 // position when all entries are sorted by score, descending; null if not yet scored
  "tid": "T1685",
  "name": "Disable or Modify Tools",
  "description": "...",      // verbatim ATT&CK technique description
  "url": "https://attack.mitre.org/techniques/T1685",
  "detection": "...",        // verbatim ATT&CK detection guidance
  "score": 3.61,              // composite priority score; null if not yet scored
  "scoring_status": "pending_rescore",  // present only when score/rank are null
  "mitigations": [ { "mid": "M1047", "name": "Audit", "description": "...", "url": "..." }, ... ],
  "subtechniques": [ { "tid": "T1685.001", "name": "...", "url": "...", "description": "...", "detection": "...", "mitigations": [...] }, ... ],
  "actionability_score": { "combined_score": 0.70, "mitigation_score": 0.44, "detection_score": 1 },
  "choke_point_score": 0.1,
  "prevalence_score": 1
}
```

Sub-technique entries carry no score of their own — only the parent technique
is ranked. `rank` is contiguous across every *scored* entry (currently `1..308`,
no gaps); entries pending a score are appended at the end of the array with
`rank: null` so the ranked ordering above them stays untouched.

The `score` breakdown (`actionability_score`, `choke_point_score`,
`prevalence_score`) is produced by a scoring pipeline that lives **outside**
this repo. Nothing in `tools/` recomputes it — when a technique has no real
score, it is marked `"scoring_status": "pending_rescore"` rather than given a
guessed number.

## Cross-checking coverage

`tools/crosscheck_coverage.py --os linux` compares this list against the
ATT&CK technique tags actually present in `packs/linux/{essential,advanced,hunting}`
(sigma rule tags, via `tools/search_packs.py`) to show what's covered, what's
partially covered (only some sub-techniques), and what's missing entirely,
weighted by rank/score so the highest-priority gaps surface first. For any
technique with sub-techniques, the detail table also lists exactly which
sub-technique ids are covered vs. missing. Entries with
`scoring_status: pending_rescore` are excluded from the ranked stats and
reported in their own section, since they have no score to weight by yet.
Unlike Windows, there is no `linux/clickfix` pack to exclude. Repeat `--os`
(or pass `--os all`) to also report on Windows in the same run -- each OS is
reported independently, this is not a cross-OS comparison.

```sh
python tools/crosscheck_coverage.py --os linux                    # gap list, top 25 by rank
python tools/crosscheck_coverage.py --os linux --status all --top 0
python tools/crosscheck_coverage.py --os linux --os windows
```

## ATT&CK v19 migration (T1562 → T1685-T1690)

MITRE ATT&CK v19 (released 2026-04-28) split the **Defense Evasion** tactic
into **Stealth** (`TA0005`) and **Defense Impairment** (`TA0112`), and revoked
`T1562` "Impair Defenses," reorganizing its sub-techniques (plus one
sub-technique moved out of `T1070` "Indicator Removal") into six new
techniques: `T1685`-`T1690`. `t1562_v19_mapping.json` records the full
old-ID → new-ID mapping, the relationship type for each (`merged_into_parent`,
`reissued`, `promoted_to_technique`, `new`, ...), and stub definitions for the
new techniques — sourced from and verified against the live ATT&CK pages
linked in its `metadata.sources`. This migration mirrors the one already
applied to [`techniques/windows/windows_top_techniques.json`](../windows/README.md#attck-v19-migration-t1562--t1685-t1690);
two of the new sub-techniques are directly Linux-relevant:
`T1685.004` "Disable or Modify Linux Audit System Log" and `T1685.006`
"Clear Linux or Mac System Logs."

Applying that mapping to `linux_top_techniques.json` involved:

- **Removed** the revoked `T1562` entry (was rank 1, score 3.61).
- **Added `T1685` "Disable or Modify Tools"** at rank 1, inheriting T1562's
  score/rank/`actionability_score`/`choke_point_score`/`prevalence_score`
  exactly, since it's the direct `merged_into_parent` successor carrying the
  bulk of T1562's old sub-techniques. Its 6 sub-techniques (`T1685.001`-`.006`)
  were populated from the live ATT&CK pages.
- **Added `T1686`-`T1690`** (System Firewall, Exploitation for Defense
  Impairment, Safe Mode Boot, Downgrade Attack, Prevent Command History
  Logging) as `scoring_status: pending_rescore` entries (`rank`/`score: null`),
  appended at the end of the list — there is no legitimate basis to assign
  them a score without re-running the external scoring pipeline, so none was
  invented. `T1686` carries its 3 real sub-techniques.
- **Adjusted `T1070`** ("Indicator Removal"): removed sub-techniques
  `T1070.001`/`.002`, which moved to become `T1685.005`/`.006`.
- Every new field (`name`, `description`, `url`, `detection`) was pulled from
  the live ATT&CK technique pages rather than paraphrased or invented, reusing
  the exact same content already verified for the Windows list (these fields
  are framework text, not OS-specific); `mitigations` entries reuse the
  canonical `mid`-keyed objects already present elsewhere in the file for
  consistency.
- The file was rewritten via `json.dump(..., indent=4, ensure_ascii=False)`.

### Playbook for the next ATT&CK revision

1. Get (or write, mirroring `t1562_v19_mapping.json`'s shape) an
   `<old_id>_v<N>_mapping.json` capturing: revision metadata, the revoked
   technique(s), an old-ID → new-ID mapping table with relationship types, and
   stub definitions for any new techniques.
2. **Verify it against the live ATT&CK site** (`attack.mitre.org/techniques/<id>`)
   before trusting it — don't assume a mapping file is accurate just because
   it exists.
3. Decide a scoring policy per new/changed technique and apply it
   consistently:
   - A technique that's a direct 1:1 successor (`merged_into_parent`,
     `reissued`) inherits its predecessor's `rank`/`score`/score-breakdown.
   - A technique with no direct predecessor or no scoring history
     (`promoted_to_technique`, `new`) gets `rank: null`, `score: null`,
     `scoring_status: "pending_rescore"` — never a guessed number.
4. Pull real `name`/`description`/`url`/`detection` text from the ATT&CK
   pages for every new ID; reuse existing `mid`-keyed mitigation objects from
   this file instead of re-typing them.
5. Check whether any *other* technique in the file lost a sub-technique to the
   revision (as `T1070` did here) and remove it from that parent's
   `subtechniques` array.
6. Rewrite the file with `json.dump(..., indent=4, ensure_ascii=False)` — this
   also normalizes any encoding issues.
7. Re-run `tools/crosscheck_coverage.py --os linux` to sanity-check the new
   ranked list against real pack coverage, and confirm any pending-rescore
   entries show up in their own section.

### Changelog

- **2026-08-25** — Migrated `T1562` → `T1685`-`T1690` per ATT&CK v19
  (`t1562_v19_mapping.json`), mirroring the Windows migration. `T1685`
  inherited T1562's rank/score (unchanged: rank 1, score 3.61); `T1686`-`T1690`
  added as `pending_rescore`; `T1070.001`/`.002` moved under `T1685`.
