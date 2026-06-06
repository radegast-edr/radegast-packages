"""Search Sigma rules across rules/sigma/ by one or more fields.

Usage:
    python tools/search_sigma.py --description "persistence"
    python tools/search_sigma.py --description "WMI" --os windows
    python tools/search_sigma.py --description "lateral movement" --case-sensitive

Options:
    --description TEXT      Substring to match against the 'description' field
    --os OS [OS ...]        Restrict search to one or more OS subtrees
                            (choices: windows linux macos; default: all)
    --case-sensitive        Disable case-folding (default: case-insensitive)
    --show-path             Print the file path of each match
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO_ROOT / "rules" / "sigma"

ALL_OS: tuple[str, ...] = ("windows", "linux", "macos")


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #


def iter_rules(target_os: tuple[str, ...]):
    """Yield (path, doc) for every parseable .yml file under the target OS dirs."""
    for os_name in target_os:
        os_dir = SIGMA_DIR / os_name
        if not os_dir.is_dir():
            continue
        for path in sorted(os_dir.rglob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                print(f"Warning: skipping {path.name} — {exc}", file=sys.stderr)
                continue
            yield path, doc


# --------------------------------------------------------------------------- #
# Field matchers
# --------------------------------------------------------------------------- #


def _text_match(value: object, query: str, case_sensitive: bool) -> bool:
    text = str(value) if value is not None else ""
    if not case_sensitive:
        return query.lower() in text.lower()
    return query in text


def matches(doc: dict, args: argparse.Namespace) -> bool:
    if args.description is not None:
        if not _text_match(doc.get("description"), args.description, args.case_sensitive):
            return False
    return True


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def print_match(path: Path, doc: dict, show_path: bool) -> None:
    title = doc.get("title", "<no title>")
    rule_id = doc.get("id", "")
    description = doc.get("description", "")
    level = doc.get("level", "")

    parts = [f"  Title      : {title}"]
    if rule_id:
        parts.append(f"  ID         : {rule_id}")
    if description:
        parts.append(f"  Description: {description}")
    if level:
        parts.append(f"  Level      : {level}")
    if show_path:
        parts.append(f"  Path       : {path.relative_to(REPO_ROOT)}")

    print("\n".join(parts))
    print()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search Sigma rules by field values."
    )
    parser.add_argument(
        "--description",
        metavar="TEXT",
        help="Substring to match against the 'description' field",
    )
    parser.add_argument(
        "--os",
        nargs="+",
        choices=list(ALL_OS),
        default=list(ALL_OS),
        metavar="OS",
        help=f"Restrict search to one or more OS subtrees (default: all). Choices: {', '.join(ALL_OS)}",
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Disable case-folding (default: case-insensitive)",
    )
    parser.add_argument(
        "--show-path",
        action="store_true",
        help="Include the file path in output",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.description is None:
        print("No search criteria provided. Use --description TEXT (more fields coming soon).")
        print("Run with --help for usage.")
        sys.exit(1)

    target_os = tuple(args.os)
    count = 0

    for path, doc in iter_rules(target_os):
        if matches(doc, args):
            count += 1
            print_match(path, doc, args.show_path)

    print(f"─── {count} rule(s) matched ───")


if __name__ == "__main__":
    main()
