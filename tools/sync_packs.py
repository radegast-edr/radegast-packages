"""Check packs/{os}/{pack}/sigma/ copies for drift against rules/sigma/{os}/.

Packs are curated copies of rules/sigma/{os}/ content (see populate_pack.py):
each file under packs/{os}/{pack}/sigma/ started as a byte-for-byte copy of a
file under rules/sigma/{os}/, matched by rule `id`. rules/sigma/ is the
canonical source -- when a rule there is edited (by hand, or via
download_sigma.py --update-changed pulling in an upstream SigmaHQ change),
every pack that already carries that rule ends up with a stale copy. This
tool finds and fixes that drift.

Matching is by the sigma `id` field, not file path, and comparison is on
parsed YAML content (not raw text), mirroring download_sigma.py's --diff /
--update-changed so line-ending and key-order differences don't count as
drift.

Usage:
    python tools/sync_packs.py --list --json                    # enumerate (os, pack) pairs, for CI
    python tools/sync_packs.py --diff                            # report drifted packs
    python tools/sync_packs.py --diff --json                     # JSON report (for CI)
    python tools/sync_packs.py --diff --os windows --pack essential
    python tools/sync_packs.py --update --os windows --pack essential
    python tools/sync_packs.py --update --os windows --pack essential --dry-run

A pack rule whose `id` no longer exists anywhere under rules/sigma/ is
reported separately as "orphaned" (the canonical rule was removed or
renamed upstream). --update never deletes pack files -- orphans are
reported only, for a human to decide whether to remove them.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "sigma"
PACKS_DIR = REPO_ROOT / "packs"


def eprint(*args, **kwargs) -> None:
    """Print progress/status noise to stderr, keeping stdout clean for --json output."""
    print(*args, file=sys.stderr, **kwargs)


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def discover_packs(target_os: list[str] | None, target_packs: list[str] | None) -> list[tuple[str, str]]:
    """Return sorted (os, pack) pairs under packs/ that have a sigma/ subfolder."""
    found: list[tuple[str, str]] = []
    if not PACKS_DIR.is_dir():
        return found
    for os_dir in sorted(PACKS_DIR.iterdir()):
        if not os_dir.is_dir():
            continue
        if target_os and os_dir.name not in target_os:
            continue
        for pack_dir in sorted(os_dir.iterdir()):
            if not pack_dir.is_dir():
                continue
            if target_packs and pack_dir.name not in target_packs:
                continue
            if not (pack_dir / "sigma").is_dir():
                continue
            found.append((os_dir.name, pack_dir.name))
    return found


# --------------------------------------------------------------------------- #
# Rule loading / diffing
# --------------------------------------------------------------------------- #


def load_id_index(base_dir: Path) -> dict[str, tuple[Path, dict]]:
    """Return {rule_id: (path, doc)} for every parseable .yml under base_dir."""
    index: dict[str, tuple[Path, dict]] = {}
    if not base_dir.is_dir():
        return index
    for path in sorted(base_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            eprint(f"  Warning: could not parse {path.relative_to(REPO_ROOT)}")
            continue
        rule_id = str(doc.get("id", "")).strip()
        if not rule_id:
            eprint(f"  Warning: no id in {path.relative_to(REPO_ROOT)}")
            continue
        index[rule_id] = (path, doc)
    return index


def _changed_fields(a: dict, b: dict) -> list[str]:
    """Return the top-level field names that differ between two parsed rule docs."""
    keys = sorted(set(a) | set(b))
    return [key for key in keys if a.get(key) != b.get(key)]


def compute_pack_diff(os_name: str, pack_name: str, canonical_index: dict[str, tuple[Path, dict]]) -> dict:
    """Compare one pack's sigma copies against the canonical rules/sigma/{os}/ index."""
    pack_sigma_dir = PACKS_DIR / os_name / pack_name / "sigma"
    pack_index = load_id_index(pack_sigma_dir)

    drifted = []
    orphaned = []
    for rule_id, (pack_path, pack_doc) in pack_index.items():
        canonical = canonical_index.get(rule_id)
        if canonical is None:
            orphaned.append({"id": rule_id, "pack_path": str(pack_path.relative_to(REPO_ROOT))})
            continue
        canonical_path, canonical_doc = canonical
        fields = _changed_fields(pack_doc, canonical_doc)
        if fields:
            drifted.append(
                {
                    "id": rule_id,
                    "pack_path": str(pack_path.relative_to(REPO_ROOT)),
                    "rules_path": str(canonical_path.relative_to(REPO_ROOT)),
                    "fields": fields,
                }
            )

    return {
        "os": os_name,
        "pack": pack_name,
        "pack_rule_count": len(pack_index),
        "drifted": sorted(drifted, key=lambda d: d["pack_path"]),
        "orphaned": sorted(orphaned, key=lambda d: d["pack_path"]),
    }


def compute_diff(target_os: list[str] | None, target_packs: list[str] | None) -> list[dict]:
    """Compute the drift report for every matching (os, pack)."""
    pairs = discover_packs(target_os, target_packs)
    canonical_by_os: dict[str, dict[str, tuple[Path, dict]]] = {}

    results = []
    for os_name, pack_name in pairs:
        if os_name not in canonical_by_os:
            eprint(f"Indexing rules/sigma/{os_name}/ …")
            canonical_by_os[os_name] = load_id_index(RULES_DIR / os_name)
        results.append(compute_pack_diff(os_name, pack_name, canonical_by_os[os_name]))
    return results


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def show_diff(target_os: list[str] | None, target_packs: list[str] | None, json_output: bool) -> None:
    results = compute_diff(target_os, target_packs)

    if json_output:
        print(json.dumps(results, indent=2))
        return

    print()
    any_drift = False
    for r in results:
        label = f"{r['os']}/{r['pack']}"
        print(f"── {label} ────────────────────────────────────────────────")
        print(
            f"   pack rules: {r['pack_rule_count']:>5}   drifted: {len(r['drifted']):>5}   "
            f"orphaned: {len(r['orphaned']):>5}"
        )
        if r["drifted"]:
            any_drift = True
            print()
            for d in r["drifted"]:
                print(f"  DRIFTED  {d['id']}  ({d['pack_path']})  [{', '.join(d['fields'])}]")
        if r["orphaned"]:
            print()
            for o in r["orphaned"]:
                print(f"  ORPHANED  {o['id']}  ({o['pack_path']})  -- no longer in rules/sigma/{r['os']}/")
        if not r["drifted"] and not r["orphaned"]:
            print("   In sync with rules/sigma/.")
        print()

    if any_drift:
        print("Tip: run with --update to overwrite drifted pack files with the canonical rules/sigma/ content.")
    else:
        print("All packs are in sync with rules/sigma/ for the selected targets.")


def do_update(target_os: list[str] | None, target_packs: list[str] | None, dry_run: bool) -> None:
    results = compute_diff(target_os, target_packs)

    print()
    total_drifted = 0
    updated = 0

    for r in results:
        if not r["drifted"]:
            continue
        total_drifted += len(r["drifted"])
        label = f"{r['os']}/{r['pack']}"
        print(f"── {label} ────────────────────────────────────────────────")
        for d in r["drifted"]:
            label_line = f"{d['pack_path']}  [{', '.join(d['fields'])}]"
            if dry_run:
                print(f"  would update  {label_line}")
                continue
            print(f"  update  {label_line}")
            shutil.copy2(REPO_ROOT / d["rules_path"], REPO_ROOT / d["pack_path"])
            updated += 1
        print()

    if total_drifted == 0:
        print("All packs are in sync with rules/sigma/ for the selected targets.")
        return

    action = "would update" if dry_run else "updated"
    count = total_drifted if dry_run else updated
    print(f"Done. {action} {count}/{total_drifted} drifted rule(s).")
    if dry_run:
        print("Re-run without --dry-run to write files.")


def show_list(target_os: list[str] | None, target_packs: list[str] | None, json_output: bool) -> None:
    pairs = discover_packs(target_os, target_packs)
    if json_output:
        print(json.dumps([{"os": os_name, "pack": pack_name} for os_name, pack_name in pairs], indent=2))
        return
    for os_name, pack_name in pairs:
        print(f"{os_name}/{pack_name}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check/sync packs/{os}/{pack}/sigma/ copies against rules/sigma/{os}/.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--os", nargs="+", metavar="OS", help="Limit to these OS(es) (default: all found under packs/)")
    parser.add_argument("--pack", nargs="+", metavar="PACK", help="Limit to these pack name(s) (default: all)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a human report")
    parser.add_argument("--diff", action="store_true", help="Report drifted/orphaned pack rules (default action)")
    parser.add_argument(
        "--update",
        action="store_true",
        help="Overwrite drifted pack files with the current rules/sigma/ content. Never touches orphaned files.",
    )
    parser.add_argument("--dry-run", action="store_true", help="(with --update) Preview without writing files")
    parser.add_argument("--list", action="store_true", help="List matching (os, pack) pairs and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list:
        show_list(args.os, args.pack, args.json)
        return

    if args.update:
        do_update(args.os, args.pack, args.dry_run)
        return

    show_diff(args.os, args.pack, args.json)


if __name__ == "__main__":
    main()
