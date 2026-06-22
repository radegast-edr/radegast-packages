"""Populate pack folders with Sigma rules filtered by various criteria.

Copies matching rule files from rules/sigma/{os}/ into packs/{os}/{pack}/sigma/,
preserving the source directory structure. Optionally updates pack.yml.

Usage:
    python tools/populate_pack.py --os windows --level critical --pack hunting
    python tools/populate_pack.py --os windows --tactic lateral-movement --pack hunting
    python tools/populate_pack.py --os windows --level high critical --pack hunting
    python tools/populate_pack.py --os windows --description "credential" --pack hunting --dry-run
    python tools/populate_pack.py --os windows --level high critical --tactic execution --pack essential --sync
    python tools/populate_pack.py --os windows --technique T1059 --pack hunting
    python tools/populate_pack.py --os windows --technique T1059.001 T1078 --pack hunting

Options:
    --os OS [OS ...]                  Source OS(es) (windows, linux, macos; default: windows)
    --pack PACK                       Destination pack name, e.g. hunting, advanced, essential
    --level LEVEL [LEVEL ...]         Filter by severity level(s): critical, high, medium, low, informational
    --tactic TACTIC [TACTIC ...]      Filter by MITRE ATT&CK tactic(s), e.g. lateral-movement, persistence
    --technique TECHNIQUE [...]       Filter by MITRE ATT&CK technique ID(s), e.g. T1059, T1059.001
                                      Case-insensitive. A parent ID (T1059) also matches sub-techniques.
    --description TEXT                Substring match against rule description
    --tag TAG [TAG ...]               Rule must carry all listed tags (exact match)
    --case-sensitive                  Disable case-folding for text searches (default: insensitive)
    --dry-run                         Print matches without copying files or modifying pack.yml
    --no-update-pack-yml              Skip updating pack.yml (default: update is enabled)
    --prune                           Remove sigma files from the pack whose IDs are not listed in pack.yml
    --sync                            Make the pack match exactly the current criteria: add new matches and
                                      remove any pack files whose rules do not satisfy the filters
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO_ROOT / "rules" / "sigma"
PACKS_DIR = REPO_ROOT / "packs"

ALL_OS: tuple[str, ...] = ("windows", "linux", "macos")

_NON_TACTIC_RE = re.compile(r"^attack\.(t|s|g|ds)\d+", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #


def iter_rules(target_os: tuple[str, ...]):
    """Yield (os_name, path, doc) for every parseable .yml file under target OS dirs."""
    for os_name in target_os:
        os_dir = SIGMA_DIR / os_name
        if not os_dir.is_dir():
            print(f"Warning: {os_dir} does not exist, skipping.", file=sys.stderr)
            continue
        for path in sorted(os_dir.rglob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                print(f"Warning: skipping {path.name} — {exc}", file=sys.stderr)
                continue
            yield os_name, path, doc


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


def matches_criteria(doc: dict, args: argparse.Namespace) -> bool:
    cs = args.case_sensitive

    if args.level:
        level = (doc.get("level") or "").lower()
        if level not in {lv.lower() for lv in args.level}:
            return False

    if args.tactic:
        tags = [t.lower() for t in (doc.get("tags") or [])]
        rule_tactics: set[str] = set()
        for tag in tags:
            if tag.startswith("attack.") and not _NON_TACTIC_RE.match(tag):
                rule_tactics.add(tag[len("attack."):])
        if not {t.lower() for t in args.tactic} & rule_tactics:
            return False

    if args.technique:
        tags = [t.lower() for t in (doc.get("tags") or [])]
        matched = any(
            tag == f"attack.{tech.lower()}" or tag.startswith(f"attack.{tech.lower()}.")
            for tech in args.technique
            for tag in tags
        )
        if not matched:
            return False

    if args.description:
        desc = doc.get("description") or ""
        needle = args.description if cs else args.description.lower()
        haystack = desc if cs else desc.lower()
        if needle not in haystack:
            return False

    if args.tag:
        rule_tags = {t.lower() for t in (doc.get("tags") or [])}
        for t in args.tag:
            needle = t if cs else t.lower()
            if needle not in rule_tags:
                return False

    return True


# --------------------------------------------------------------------------- #
# File copying
# --------------------------------------------------------------------------- #


def dest_path_for(src_path: Path, os_name: str, pack_name: str) -> Path:
    rel = src_path.relative_to(SIGMA_DIR / os_name)
    return PACKS_DIR / os_name / pack_name / "sigma" / rel


def copy_rule(src: Path, dst: Path, dry_run: bool) -> bool:
    """Copy src to dst, creating parent dirs as needed. Returns True if copied."""
    if dst.exists():
        return False
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return True


# --------------------------------------------------------------------------- #
# Pruning
# --------------------------------------------------------------------------- #


def load_pack_yml_ids(pack_yml_path: Path) -> set[str]:
    """Return the set of sigma rule IDs listed under rules.has.sigma in pack.yml."""
    if not pack_yml_path.exists():
        return set()
    doc = yaml.safe_load(pack_yml_path.read_text(encoding="utf-8")) or {}
    sigma_list = ((doc.get("rules") or {}).get("has") or {}).get("sigma") or []
    return {str(item) for item in sigma_list}


def prune_pack_sigma(pack_sigma_dir: Path, allowed_ids: set[str], dry_run: bool) -> int:
    """Delete sigma files whose IDs are absent from allowed_ids. Returns count removed."""
    if not pack_sigma_dir.is_dir():
        return 0
    removed = 0
    for path in sorted(pack_sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        rule_id = str(doc.get("id", ""))
        if rule_id not in allowed_ids:
            print(f"  [PRUNE] {path.relative_to(REPO_ROOT)}")
            if not dry_run:
                path.unlink()
            removed += 1
    if not dry_run:
        for dirpath in sorted(pack_sigma_dir.rglob("*"), reverse=True):
            if dirpath.is_dir() and not any(dirpath.iterdir()):
                dirpath.rmdir()
    return removed


def sync_pack_sigma(pack_sigma_dir: Path, matched_ids: set[str], dry_run: bool) -> int:
    """Remove pack files whose rule IDs are not in matched_ids (criteria-based sync).

    Unlike prune_pack_sigma, the allowed set comes from the current filter run,
    not from pack.yml — so the pack on disk ends up matching exactly what the
    current criteria produce.  Returns count removed.
    """
    if not pack_sigma_dir.is_dir():
        return 0
    removed = 0
    for path in sorted(pack_sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        rule_id = str(doc.get("id", ""))
        if rule_id not in matched_ids:
            print(f"  [SYNC-REMOVE] {path.relative_to(REPO_ROOT)}")
            if not dry_run:
                path.unlink()
            removed += 1
    if not dry_run:
        for dirpath in sorted(pack_sigma_dir.rglob("*"), reverse=True):
            if dirpath.is_dir() and not any(dirpath.iterdir()):
                dirpath.rmdir()
    return removed


# --------------------------------------------------------------------------- #
# pack.yml update
# --------------------------------------------------------------------------- #


def update_pack_yml(pack_yml_path: Path, new_rules: list[tuple[str, str]]) -> int:
    """Append new rule IDs to pack.yml rules.has.sigma. Returns count of IDs added.

    Uses ruamel.yaml to round-trip the file preserving existing comments and formatting.
    Falls back to raw text append if ruamel.yaml is unavailable.
    """
    if not pack_yml_path.exists():
        print(f"  pack.yml not found at {pack_yml_path}, skipping update.", file=sys.stderr)
        return 0

    try:
        from ruamel.yaml import YAML  # type: ignore[import]

        ryaml = YAML()
        ryaml.preserve_quotes = True
        ryaml.width = 4096

        with open(pack_yml_path, encoding="utf-8") as f:
            doc = ryaml.load(f)

        # Navigate (and create) rules.has.sigma
        if "rules" not in doc:
            doc["rules"] = {}
        if "has" not in doc["rules"]:
            doc["rules"]["has"] = {}
        if "sigma" not in doc["rules"]["has"]:
            doc["rules"]["has"]["sigma"] = []

        sigma_list = doc["rules"]["has"]["sigma"]
        existing_ids: set[str] = {str(item) for item in sigma_list}

        added = 0
        for rule_id, title in new_rules:
            if rule_id and rule_id not in existing_ids:
                sigma_list.append(rule_id)
                sigma_list.yaml_add_eol_comment(title, key=len(sigma_list) - 1)
                existing_ids.add(rule_id)
                added += 1

        with open(pack_yml_path, "w", encoding="utf-8") as f:
            ryaml.dump(doc, f)

        return added

    except ImportError:
        return _update_pack_yml_text(pack_yml_path, new_rules)


def _update_pack_yml_text(pack_yml_path: Path, new_rules: list[tuple[str, str]]) -> int:
    """Fallback: append rule IDs to pack.yml via raw text manipulation."""
    text = pack_yml_path.read_text(encoding="utf-8")

    with open(pack_yml_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}

    existing_ids: set[str] = set()
    sigma_block = (doc.get("rules") or {}).get("has") or {}
    for item in sigma_block.get("sigma") or []:
        existing_ids.add(str(item))

    lines_to_add = []
    for rule_id, title in new_rules:
        if rule_id and rule_id not in existing_ids:
            lines_to_add.append(f"          - {rule_id}     # {title}\n")
            existing_ids.add(rule_id)

    if not lines_to_add:
        return 0

    # Insert after the last sigma rule line in rules.has.sigma
    # Find anchor: last line that looks like a sigma list entry before 'excludes:'
    insert_after = _find_last_sigma_rule_line(text)
    if insert_after == -1:
        print("  Could not locate sigma list in pack.yml; skipping update.", file=sys.stderr)
        return 0

    lines = text.splitlines(keepends=True)
    lines[insert_after + 1 : insert_after + 1] = lines_to_add
    pack_yml_path.write_text("".join(lines), encoding="utf-8")
    return len(lines_to_add)


def _find_last_sigma_rule_line(text: str) -> int:
    """Return 0-based line index of the last sigma rule entry before excludes."""
    lines = text.splitlines()
    in_has_sigma = False
    last_rule_line = -1
    uuid_re = re.compile(r"^\s+-\s+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "sigma:" and in_has_sigma is False:
            # check context: look back for 'has:'
            for j in range(max(0, i - 5), i):
                if lines[j].strip() == "has:":
                    in_has_sigma = True
                    break
        if in_has_sigma:
            if uuid_re.match(line):
                last_rule_line = i
            elif stripped in ("excludes:", "ioc:") and last_rule_line != -1:
                break

    return last_rule_line


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy Sigma rules into a pack folder, filtered by criteria.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--os",
        nargs="+",
        choices=list(ALL_OS),
        default=["windows"],
        metavar="OS",
        help=f"Source OS(es). Choices: {', '.join(ALL_OS)} (default: windows)",
    )
    parser.add_argument(
        "--pack",
        required=True,
        metavar="PACK",
        help="Destination pack name under packs/{os}/, e.g. hunting",
    )
    parser.add_argument(
        "--level",
        nargs="+",
        metavar="LEVEL",
        help="Filter by severity level(s): critical, high, medium, low, informational",
    )
    parser.add_argument(
        "--tactic",
        nargs="+",
        metavar="TACTIC",
        help="Filter by MITRE ATT&CK tactic(s), e.g. lateral-movement, persistence",
    )
    parser.add_argument(
        "--technique",
        nargs="+",
        metavar="TECHNIQUE",
        help=(
            "Filter by MITRE ATT&CK technique ID(s), e.g. T1059 or T1059.001. "
            "Case-insensitive. A parent ID (T1059) also matches all its sub-techniques."
        ),
    )
    parser.add_argument(
        "--description",
        metavar="TEXT",
        help="Substring to match against the rule description field",
    )
    parser.add_argument(
        "--tag",
        nargs="+",
        metavar="TAG",
        help="Rule must carry all listed tags (exact match, e.g. attack.t1059.001)",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Disable case-folding for text searches (default: insensitive)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print matches without copying files or modifying pack.yml",
    )
    parser.add_argument(
        "--no-update-pack-yml",
        action="store_true",
        help="Skip updating pack.yml with new rule IDs",
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Remove sigma files from the pack whose IDs are not listed in pack.yml",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Make the pack match exactly the current criteria: copy new matches and "
            "remove any existing pack files whose rules do not satisfy the filters"
        ),
    )
    return parser.parse_args()


def print_rule(os_name: str, path: Path, doc: dict, dst: Path, already_exists: bool) -> None:
    title = doc.get("title", "<no title>")
    level = doc.get("level", "")
    rule_id = doc.get("id", "")
    status = "EXISTS" if already_exists else "NEW"
    print(f"  [{status}] [{level}] {title}")
    print(f"         src: {path.relative_to(REPO_ROOT)}")
    if not already_exists:
        print(f"         dst: {dst.relative_to(REPO_ROOT)}")
    print()


def main() -> None:
    args = parse_args()
    target_os = tuple(args.os)

    if not any([args.level, args.tactic, args.technique, args.description, args.tag]):
        print("Error: at least one filter is required (--level, --tactic, --technique, --description, --tag).")
        print("Run with --help for usage.")
        sys.exit(1)

    dry_run = args.dry_run
    if dry_run:
        print("--- DRY RUN: no files will be copied or modified ---\n")

    total_new = 0
    total_exists = 0
    new_rules_by_os: dict[str, list[tuple[str, str]]] = {os_name: [] for os_name in target_os}
    matched_ids_by_os: dict[str, set[str]] = {os_name: set() for os_name in target_os}

    for os_name, path, doc in iter_rules(target_os):
        if not matches_criteria(doc, args):
            continue

        dst = dest_path_for(path, os_name, args.pack)
        already_exists = dst.exists()

        rule_id = doc.get("id", "")
        title = doc.get("title", "")

        if rule_id:
            matched_ids_by_os[os_name].add(rule_id)

        if already_exists:
            total_exists += 1
        else:
            total_new += 1
            if rule_id:
                new_rules_by_os[os_name].append((rule_id, title))

        print_rule(os_name, path, doc, dst, already_exists)

        if not already_exists:
            copy_rule(path, dst, dry_run)

    print(f"--- {total_new + total_exists} rule(s) matched: {total_new} new, {total_exists} already in pack ---")

    if not args.no_update_pack_yml:
        for os_name in target_os:
            new_rules = new_rules_by_os.get(os_name, [])
            if not new_rules:
                continue
            pack_yml = PACKS_DIR / os_name / args.pack / "pack.yml"
            if dry_run:
                print(f"\n[DRY RUN] Would add {len(new_rules)} rule ID(s) to {pack_yml.relative_to(REPO_ROOT)}")
            else:
                added = update_pack_yml(pack_yml, new_rules)
                if added:
                    print(f"\nUpdated {pack_yml.relative_to(REPO_ROOT)}: +{added} rule ID(s)")

    if args.prune:
        for os_name in target_os:
            pack_yml = PACKS_DIR / os_name / args.pack / "pack.yml"
            allowed_ids = load_pack_yml_ids(pack_yml)
            pack_sigma_dir = PACKS_DIR / os_name / args.pack / "sigma"
            if dry_run:
                print(f"\n[DRY RUN] Pruning {pack_sigma_dir.relative_to(REPO_ROOT)} against {pack_yml.relative_to(REPO_ROOT)}")
            removed = prune_pack_sigma(pack_sigma_dir, allowed_ids, dry_run)
            if removed:
                label = "Would remove" if dry_run else "Pruned"
                print(f"{label} {removed} sigma file(s) not in {pack_yml.relative_to(REPO_ROOT)}")

    if args.sync:
        for os_name in target_os:
            pack_sigma_dir = PACKS_DIR / os_name / args.pack / "sigma"
            matched = matched_ids_by_os[os_name]
            if dry_run:
                print(f"\n[DRY RUN] Sync would remove pack files not matching current criteria from {pack_sigma_dir.relative_to(REPO_ROOT)}")
            removed = sync_pack_sigma(pack_sigma_dir, matched, dry_run)
            if removed:
                label = "Would remove" if dry_run else "Removed"
                print(f"\n{label} {removed} sigma file(s) from pack that did not match current criteria")


if __name__ == "__main__":
    main()
