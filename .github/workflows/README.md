# Workflows

## Sigma → packs → Radegast pipeline

Four workflows form a chain that takes upstream SigmaHQ rule changes all the
way to a live upload on Radegast EDR, with a human review gate at each hop:

```
 SigmaHQ/sigma (upstream)
        │
        ▼
 sigma-sync.yml ────────────────► PR: sigma-sync/{os} → master
        │                          (review + approve)
        ▼
 pack-sync.yml ─────────────────► PR: pack-sync/{os}-{pack} → packs-dev
        │                          (review + merge)
        ▼
 pack-pr.yml ───────────────────► PR: packs-dev → master
        │                          (review + merge)
        ▼
 pack-release.yml ──────────────► build + upload to Radegast EDR (live)
```

### [sigma-sync.yml](sigma-sync.yml)

- **Trigger:** monthly cron (1st of the month, 06:00 UTC) or manual dispatch.
- **What it does:** for each OS (`windows`, `linux`, `macos`), diffs
  `rules/sigma/{os}/` against upstream `SigmaHQ/sigma`. If there are new or
  changed rules, downloads them into `rules/sigma/{os}/` and opens/updates a
  PR (`sigma-sync/{os}` → `master`) summarizing what changed.
- **Human step:** review and approve that PR.

### [pack-sync.yml](pack-sync.yml)

- **Trigger:** a PR review being submitted as **approved**, on any PR that
  targets `master` and touches `rules/sigma/**` (this is what fires right
  after you approve a `sigma-sync/*` PR — merge isn't required). Also
  runnable manually via `workflow_dispatch` with a `pr_number` input, for
  re-running against a PR after the fact.
- **What it does:** checks out the approved PR's head commit (which already
  has the new rule content, while `packs/` there still matches `master`) and
  runs `tools/sync_packs.py --diff` to find which `(os, pack)` pairs would
  drift once those rules land. For each affected pack, it stages the updated
  rule files onto a fresh branch off **`packs-dev`** (not `master`) and
  opens/updates a PR (`pack-sync/{os}-{pack}` → `packs-dev`) describing the
  changed rule IDs/fields, with a link back to the source PR.
- **Why `packs-dev` and not `master`:** so sigma-driven pack updates go
  through the same staging/consolidation step as manually-edited packs,
  instead of a separate path straight to production.
- **Human step:** review and merge each pack PR into `packs-dev`.

### [pack-pr.yml](pack-pr.yml)

- **Trigger:** push to `packs-dev` touching `packs/**` (from the merges
  above, or from any manual edit pushed directly to `packs-dev`).
- **What it does:** diffs the push to find which `{os}/{pack}` pairs
  changed, and opens/updates a single consolidated PR (`packs-dev` →
  `master`) listing them. Multiple pack-sync merges landing close together
  fold into the same consolidated PR rather than creating duplicates.
- **Human step:** review and merge into `master`.

### [pack-release.yml](pack-release.yml)

- **Trigger:** push to `master` touching `packs/**`.
- **What it does:** for each changed pack, builds `pack.yml`
  (`tools/build_packs.py`) and uploads it (`tools/upload_radegast.py`) —
  this is the step that actually goes live on Radegast EDR. No further
  human step; this is the production release.

## Other workflows

- **[atomic.yml](atomic.yml)** (`atomic-general`) — manual dispatch. Installs
  Radegast on a Windows or Linux runner and runs Atomic Red Team tests for a
  given pack (`inputs.pack`), uploading the workspace as an artifact.
- **[atomic_windows.yml](atomic_windows.yml)** (`atomic-windows`) — manual
  dispatch. Installs the `rustinel` engine on a Windows runner for a given
  pack and uploads the workspace as an artifact.
- **[install_cleanup_test.yml](install_cleanup_test.yml)**
  (`install-cleanup-test`) — manual dispatch. Installs Radegast, waits, then
  uninstalls/cleans it up on a Windows or Linux runner, to smoke-test the
  install/cleanup scripts themselves.
