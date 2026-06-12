"""Search Sigma rules across rules/sigma/ by one or more fields.

Usage:
    python tools/search_sigma.py --description "persistence"
    python tools/search_sigma.py --description "WMI" --os windows
    python tools/search_sigma.py --description "lateral movement" --case-sensitive
    python tools/search_sigma.py --technique T1059
    python tools/search_sigma.py --technique T1059.001 T1078 --os windows
    python tools/search_sigma.py --stats
    python tools/search_sigma.py --stats --os windows

Options:
    --description TEXT          Substring to match against the 'description' field
    --technique TECHNIQUE [...] Filter by MITRE ATT&CK technique ID(s), e.g. T1059, T1059.001
                                Case-insensitive. A parent ID (T1059) also matches sub-techniques.
    --os OS [OS ...]            Restrict search to one or more OS subtrees
                                (choices: windows linux macos; default: all)
    --case-sensitive            Disable case-folding (default: case-insensitive)
    --stats                     Print rule counts grouped by severity and tactic
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
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

    if args.technique:
        tags = [t.lower() for t in (doc.get("tags") or [])]
        matched = any(
            tag == f"attack.{tech.lower()}" or tag.startswith(f"attack.{tech.lower()}.")
            for tech in args.technique
            for tag in tags
        )
        if not matched:
            return False

    return True


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #

# Matches technique IDs (t\d+), sub-technique IDs, software (s\d+),
# groups (g\d+), and data sources (ds\d+) — anything that is not a named tactic.
_NON_TACTIC_RE = re.compile(r"^attack\.(t|s|g|ds)\d+", re.IGNORECASE)


def count_by_severity_and_tactic(target_os: tuple[str, ...]) -> dict:
    """Return counts of rules grouped by severity (level) and by MITRE tactic.

    Tactics are tags of the form ``attack.<name>`` where the name is not a
    technique/sub-technique ID (i.e. does not start with t followed by digits).
    """
    severity_counts: dict[str, int] = defaultdict(int)
    tactic_counts: dict[str, int] = defaultdict(int)

    for _path, doc in iter_rules(target_os):
        level = doc.get("level") or "unknown"
        severity_counts[level] += 1

        tags = doc.get("tags") or []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower.startswith("attack.") and not _NON_TACTIC_RE.match(tag_lower):
                tactic = tag_lower[len("attack."):]
                tactic_counts[tactic] += 1

    return {"severity": dict(severity_counts), "tactic": dict(tactic_counts)}


def print_stats(stats: dict) -> None:
    severity_counts = stats["severity"]
    tactic_counts = stats["tactic"]

    print("Alerts by Severity")
    print("-" * 30)
    for level in ("critical", "high", "medium", "low", "informational", "unknown"):
        if level in severity_counts:
            print(f"  {level:<15} {severity_counts[level]:>5}")
    for level, count in sorted(severity_counts.items()):
        if level not in ("critical", "high", "medium", "low", "informational", "unknown"):
            print(f"  {level:<15} {count:>5}")
    print(f"  {'TOTAL':<15} {sum(severity_counts.values()):>5}")

    print()
    print("Alerts by Tactic")
    print("-" * 40)
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        print(f"  {tactic:<30} {count:>5}")
    print(f"  {'TOTAL':<30} {sum(tactic_counts.values()):>5}")


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def print_match(path: Path, doc: dict) -> None:
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
        "--technique",
        nargs="+",
        metavar="TECHNIQUE",
        help=(
            "Filter by MITRE ATT&CK technique ID(s), e.g. T1059 or T1059.001. "
            "Case-insensitive. A parent ID (T1059) also matches all its sub-techniques."
        ),
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Disable case-folding (default: case-insensitive)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print rule counts grouped by severity and tactic, then exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target_os = tuple(args.os)

    if args.stats:
        stats = count_by_severity_and_tactic(target_os)
        print_stats(stats)
        return

    if args.description is None and not args.technique:
        print("No search criteria provided. Use --description TEXT, --technique ID, or --stats.")
        print("Run with --help for usage.")
        sys.exit(1)

    count = 0

    for path, doc in iter_rules(target_os):
        if matches(doc, args):
            count += 1
            print_match(path, doc)

    print(f"--- {count} rule(s) matched ---")


if __name__ == "__main__":
    main()
