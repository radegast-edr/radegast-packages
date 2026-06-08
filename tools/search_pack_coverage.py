"""Extract MITRE ATT&CK tactics and techniques from sigma rules in a pack.

Usage:
    python tools/search_pack_coverage.py windows-essential
    python tools/search_pack_coverage.py windows-essential --summary
    python tools/search_pack_coverage.py windows-hunting

Options:
    pack            Pack ID to search (e.g. windows-essential, windows-hunting)
    --summary       Print only the unique tactics/techniques with rule counts
                    instead of the full per-rule table
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# Tags of the form attack.t<digits> or attack.t<digits>.<digits>
_TECHNIQUE_RE = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)

# Tags of the form attack.<word> that are NOT technique IDs
_TACTIC_RE = re.compile(r"^attack\.[a-z_]+$", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Pack discovery
# --------------------------------------------------------------------------- #


def find_pack_dir(pack_id: str) -> Path | None:
    for pack_yml in sorted((REPO_ROOT / "packs").glob("**/pack.yml")):
        try:
            data = yaml.safe_load(pack_yml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        if data.get("id") == pack_id:
            return pack_yml.parent
    return None


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #


def iter_rules(sigma_dir: Path):
    """Yield (path, doc) for every parseable .yml under sigma_dir."""
    for path in sorted(sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            print(f"Warning: skipping {path.name} — {exc}", file=sys.stderr)
            continue
        yield path, doc


def split_tags(tags: list) -> tuple[list[str], list[str]]:
    """Return (tactics, techniques) extracted from a rule's tag list."""
    tactics = []
    techniques = []
    for tag in tags or []:
        tag = str(tag)
        if _TECHNIQUE_RE.match(tag):
            techniques.append(tag)
        elif _TACTIC_RE.match(tag):
            tactics.append(tag)
    return tactics, techniques


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def print_table(sigma_dir: Path, pack_id: str) -> tuple[dict, dict]:
    rules = list(iter_rules(sigma_dir))

    tactic_to_rules: dict[str, list[str]] = defaultdict(list)
    technique_to_rules: dict[str, list[str]] = defaultdict(list)

    print(f"Pack: {pack_id}  ({len(rules)} rules)\n")
    print(f"{'Rule':<60}  {'Tactics':<35}  Techniques")
    print("-" * 120)

    for _path, doc in rules:
        title = doc.get("title", _path.stem)
        tactics, techniques = split_tags(doc.get("tags"))

        for tac in tactics:
            tactic_to_rules[tac].append(title)
        for tec in techniques:
            technique_to_rules[tec].append(title)

        tactics_str = ", ".join(t[len("attack."):] for t in tactics) or "-"
        techniques_str = ", ".join(t[len("attack."):].upper() for t in techniques) or "-"
        print(f"{title:<60}  {tactics_str:<35}  {techniques_str}")

    return tactic_to_rules, technique_to_rules


def print_summary(tactic_to_rules: dict, technique_to_rules: dict, pack_id: str) -> None:
    print()
    print("=" * 60)
    print(f"SUMMARY for pack: {pack_id}")
    print("=" * 60)

    print(f"\nTactics ({len(tactic_to_rules)} unique):")
    for tac in sorted(tactic_to_rules):
        label = tac[len("attack."):]
        count = len(tactic_to_rules[tac])
        print(f"  {label:<35} ({count} rule{'s' if count != 1 else ''})")

    print(f"\nTechniques ({len(technique_to_rules)} unique):")
    for tec in sorted(technique_to_rules):
        label = tec[len("attack."):].upper()
        count = len(technique_to_rules[tec])
        print(f"  {label:<15} ({count} rule{'s' if count != 1 else ''})")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List ATT&CK tactics and techniques covered by sigma rules in a pack."
    )
    parser.add_argument("pack", help="Pack ID to search (e.g. windows-essential)")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print only unique tactics/techniques with rule counts",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    pack_dir = find_pack_dir(args.pack)
    if pack_dir is None:
        print(f"Error: pack '{args.pack}' not found under {REPO_ROOT / 'packs'}", file=sys.stderr)
        sys.exit(1)

    sigma_dir = pack_dir / "sigma"
    if not sigma_dir.is_dir():
        print(f"Error: no sigma directory found at {sigma_dir}", file=sys.stderr)
        sys.exit(1)

    if args.summary:
        tactic_to_rules: dict[str, list[str]] = defaultdict(list)
        technique_to_rules: dict[str, list[str]] = defaultdict(list)
        for _path, doc in iter_rules(sigma_dir):
            title = doc.get("title", _path.stem)
            tactics, techniques = split_tags(doc.get("tags"))
            for tac in tactics:
                tactic_to_rules[tac].append(title)
            for tec in techniques:
                technique_to_rules[tec].append(title)
    else:
        tactic_to_rules, technique_to_rules = print_table(sigma_dir, args.pack)

    print_summary(tactic_to_rules, technique_to_rules, args.pack)


if __name__ == "__main__":
    main()
