"""Search pack sigma rules for MITRE ATT&CK coverage and technique/tactic exports.

Usage:
    python tools/search_packs.py coverage windows/essential
    python tools/search_packs.py coverage windows/essential --summary
    python tools/search_packs.py csv windows/hunting T1059
    python tools/search_packs.py csv windows/hunting T1059 T1003 --output results.csv
    python tools/search_packs.py csv windows/hunting --tactic execution
    python tools/search_packs.py csv windows/hunting --tactic execution persistence --output results.csv
    python tools/search_packs.py csv windows/hunting T1059 --tactic persistence
    python tools/search_packs.py list windows/essential
    python tools/search_packs.py list windows/essential --output pack_rules.csv
    python tools/search_packs.py tactics
    python tools/search_packs.py tactics windows/essential
    python tools/search_packs.py tactics --output tactic_coverage.csv

Pack can be specified as:
    - A path relative to the packs/ directory: windows/essential, windows/hunting
    - A pack ID as defined in pack.yml:        windows-essential, windows-hunting

Subcommands:
    coverage    Print ATT&CK tactics and techniques covered by sigma rules in a pack.
                Without --summary also prints the full per-rule table.
    csv         Export rules covering the specified technique(s) and/or tactic(s) to CSV.
                All matching is case-insensitive. A bare technique (e.g. T1059) also
                matches all its sub-techniques (T1059.001, T1059.003, …). A rule is
                included when it matches any of the given techniques OR any of the
                given tactics.
    list        Export all sigma rules in a pack to CSV with title, id, tactics, and
                techniques.  No filter required — every rule in the pack is included.
    tactics     Show how many detections each tactic has across every pack (or one pack).
                Optionally export the breakdown as CSV.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# Tags of the form attack.t<digits> or attack.t<digits>.<digits>
_TECHNIQUE_RE = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)

# Tags of the form attack.<word(s)> that are NOT technique IDs (tactics / groups)
_TACTIC_RE = re.compile(r"^attack\.[a-z_-]+$", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Pack discovery
# --------------------------------------------------------------------------- #


def find_pack_dir(pack_ref: str) -> Path | None:
    """Return the pack directory for *pack_ref*.

    Accepts either:
    - A slash-separated path relative to packs/  (e.g. ``windows/essential``)
    - A pack ID as stored in pack.yml             (e.g. ``windows-essential``)
    """
    normalized = pack_ref.replace("\\", "/")

    if "/" in normalized:
        candidate = REPO_ROOT / "packs" / normalized
        if candidate.is_dir() and (candidate / "pack.yml").exists():
            return candidate
        return None

    for pack_yml in sorted((REPO_ROOT / "packs").glob("**/pack.yml")):
        try:
            data = yaml.safe_load(pack_yml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        if data.get("id") == normalized:
            return pack_yml.parent
    return None


def iter_all_pack_dirs():
    """Yield (pack_path_str, pack_id, pack_dir) for every pack that has a sigma directory."""
    for pack_yml in sorted((REPO_ROOT / "packs").glob("**/pack.yml")):
        pack_dir = pack_yml.parent
        if not (pack_dir / "sigma").is_dir():
            continue
        try:
            data = yaml.safe_load(pack_yml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        pack_path_str = str(pack_dir.relative_to(REPO_ROOT / "packs")).replace("\\", "/")
        pack_id = data.get("id", pack_path_str)
        yield pack_path_str, pack_id, pack_dir


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
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags or []:
        tag = str(tag)
        if _TECHNIQUE_RE.match(tag):
            techniques.append(tag)
        elif _TACTIC_RE.match(tag):
            tactics.append(tag)
    return tactics, techniques


def matches_technique(technique_tag: str, search_term: str) -> bool:
    """Return True if *technique_tag* equals or is a sub-technique of *search_term*.

    Both the tag and the search term are compared case-insensitively, so
    ``attack.t1059`` matches search term ``T1059``, and ``attack.T1059.001``
    also matches ``t1059``.
    """
    tag_upper = technique_tag.upper()
    if not tag_upper.startswith("ATTACK."):
        return False
    tag_id = tag_upper[len("ATTACK."):]
    search_upper = search_term.upper()
    return tag_id == search_upper or tag_id.startswith(search_upper + ".")


def matches_tactic(tactic_tag: str, search_term: str) -> bool:
    """Case-insensitive exact match of a tactic tag against *search_term*.

    ``attack.execution`` matches search term ``execution`` or ``Execution``.
    The ``attack.`` prefix is optional in *search_term*.
    """
    tag_upper = tactic_tag.upper()
    if not tag_upper.startswith("ATTACK."):
        return False
    tag_name = tag_upper[len("ATTACK."):]
    search_upper = search_term.upper()
    if search_upper.startswith("ATTACK."):
        search_upper = search_upper[len("ATTACK."):]
    return tag_name == search_upper


# --------------------------------------------------------------------------- #
# Importable helper
# --------------------------------------------------------------------------- #


def get_techniques(pack_ref: str) -> set[str]:
    """Return uppercase technique IDs (e.g. ``T1003``, ``T1003.001``) for *pack_ref*.

    Reads the pre-computed ``attack_coverage`` list from pack.yml when available;
    falls back to scanning sigma rule tags.  Calls sys.exit(1) if the pack is not
    found.
    """
    pack_dir = find_pack_dir(pack_ref)
    if pack_dir is None:
        print(f"Error: pack '{pack_ref}' not found under {REPO_ROOT / 'packs'}", file=sys.stderr)
        sys.exit(1)

    pack_yml = pack_dir / "pack.yml"
    try:
        data = yaml.safe_load(pack_yml.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        data = {}

    coverage = data.get("attack_coverage")
    if coverage:
        return {str(t).upper() for t in coverage}

    sigma_dir = pack_dir / "sigma"
    if not sigma_dir.is_dir():
        return set()

    techniques: set[str] = set()
    for _path, doc in iter_rules(sigma_dir):
        _, tecs = split_tags(doc.get("tags") or [])
        for tec in tecs:
            techniques.add(tec[len("attack."):].upper())
    return techniques


# --------------------------------------------------------------------------- #
# coverage subcommand
# --------------------------------------------------------------------------- #


def _print_table(sigma_dir: Path, pack_ref: str) -> tuple[dict, dict]:
    rules = list(iter_rules(sigma_dir))

    tactic_to_rules: dict[str, list[str]] = defaultdict(list)
    technique_to_rules: dict[str, list[str]] = defaultdict(list)

    print(f"Pack: {pack_ref}  ({len(rules)} rules)\n")
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


def _print_summary(tactic_to_rules: dict, technique_to_rules: dict, pack_ref: str) -> None:
    print()
    print("=" * 60)
    print(f"SUMMARY for pack: {pack_ref}")
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


def cmd_coverage(args: argparse.Namespace) -> None:
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
        tactic_to_rules, technique_to_rules = _print_table(sigma_dir, args.pack)

    _print_summary(tactic_to_rules, technique_to_rules, args.pack)


# --------------------------------------------------------------------------- #
# csv subcommand
# --------------------------------------------------------------------------- #

_CSV_FIELDS = ["file", "rule_id", "title", "tactics", "techniques", "matched_techniques", "matched_tactics"]


def cmd_csv(args: argparse.Namespace) -> None:
    technique_terms = [t.strip() for t in (args.techniques or [])]
    tactic_terms = [t.strip() for t in (args.tactic or [])]

    if not technique_terms and not tactic_terms:
        print("Error: provide at least one technique (positional) or --tactic", file=sys.stderr)
        sys.exit(1)

    pack_dir = find_pack_dir(args.pack)
    if pack_dir is None:
        print(f"Error: pack '{args.pack}' not found under {REPO_ROOT / 'packs'}", file=sys.stderr)
        sys.exit(1)

    sigma_dir = pack_dir / "sigma"
    if not sigma_dir.is_dir():
        print(f"Error: no sigma directory found at {sigma_dir}", file=sys.stderr)
        sys.exit(1)

    rows: list[dict] = []

    for path, doc in iter_rules(sigma_dir):
        tags = doc.get("tags") or []
        tactics, techniques = split_tags(tags)

        matched_techs = [
            t for t in techniques
            if any(matches_technique(t, term) for term in technique_terms)
        ]
        matched_tacs = [
            t for t in tactics
            if any(matches_tactic(t, term) for term in tactic_terms)
        ]

        if not matched_techs and not matched_tacs:
            continue

        rows.append({
            "file": str(path.relative_to(REPO_ROOT)),
            "rule_id": doc.get("id", ""),
            "title": doc.get("title", path.stem),
            "tactics": ", ".join(t[len("attack."):] for t in tactics),
            "techniques": ", ".join(t[len("attack."):].upper() for t in techniques),
            "matched_techniques": ", ".join(t[len("attack."):].upper() for t in matched_techs),
            "matched_tactics": ", ".join(t[len("attack."):] for t in matched_tacs),
        })

    if not rows:
        parts = [f"techniques: {', '.join(technique_terms)}"] if technique_terms else []
        if tactic_terms:
            parts.append(f"tactics: {', '.join(tactic_terms)}")
        print(f"No rules found matching {'; '.join(parts)}", file=sys.stderr)
        sys.exit(0)

    output_path = Path(args.output) if args.output else None

    if output_path:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rule{'s' if len(rows) != 1 else ''} to {output_path}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------- #
# list subcommand
# --------------------------------------------------------------------------- #

_LIST_CSV_FIELDS = ["file", "rule_id", "title", "tactics", "techniques"]


def cmd_list(args: argparse.Namespace) -> None:
    pack_dir = find_pack_dir(args.pack)
    if pack_dir is None:
        print(f"Error: pack '{args.pack}' not found under {REPO_ROOT / 'packs'}", file=sys.stderr)
        sys.exit(1)

    sigma_dir = pack_dir / "sigma"
    if not sigma_dir.is_dir():
        print(f"Error: no sigma directory found at {sigma_dir}", file=sys.stderr)
        sys.exit(1)

    rows: list[dict] = []
    for path, doc in iter_rules(sigma_dir):
        tactics, techniques = split_tags(doc.get("tags") or [])
        rows.append({
            "file": str(path.relative_to(REPO_ROOT)),
            "rule_id": doc.get("id", ""),
            "title": doc.get("title", path.stem),
            "tactics": ", ".join(t[len("attack."):] for t in tactics),
            "techniques": ", ".join(t[len("attack."):].upper() for t in techniques),
        })

    output_path = Path(args.output) if args.output else None

    if output_path:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_LIST_CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rule{'s' if len(rows) != 1 else ''} to {output_path}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=_LIST_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------- #
# tactics subcommand
# --------------------------------------------------------------------------- #

_TACTICS_CSV_FIELDS = ["pack_path", "pack_id", "tactic", "rule_count"]


def _tactic_counts(sigma_dir: Path) -> dict[str, int]:
    """Return {tactic_name: rule_count} for rules under *sigma_dir*."""
    counts: dict[str, int] = defaultdict(int)
    for _, doc in iter_rules(sigma_dir):
        tactics, _ = split_tags(doc.get("tags") or [])
        for tac in tactics:
            counts[tac[len("attack."):]] += 1
    return dict(counts)


def cmd_tactics(args: argparse.Namespace) -> None:
    if args.pack:
        pack_dir = find_pack_dir(args.pack)
        if pack_dir is None:
            print(
                f"Error: pack '{args.pack}' not found under {REPO_ROOT / 'packs'}",
                file=sys.stderr,
            )
            sys.exit(1)
        sigma_dir = pack_dir / "sigma"
        if not sigma_dir.is_dir():
            print(f"Error: no sigma directory found at {sigma_dir}", file=sys.stderr)
            sys.exit(1)
        pack_path_str = str(pack_dir.relative_to(REPO_ROOT / "packs")).replace("\\", "/")
        try:
            data = yaml.safe_load((pack_dir / "pack.yml").read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            data = {}
        pack_id = data.get("id", pack_path_str)
        packs = [(pack_path_str, pack_id, pack_dir)]
    else:
        packs = list(iter_all_pack_dirs())

    rows: list[dict] = []

    for pack_path_str, pack_id, pack_dir in packs:
        sigma_dir = pack_dir / "sigma"
        counts = _tactic_counts(sigma_dir)
        total = sum(counts.values())

        print(f"\nPack: {pack_path_str}  (id: {pack_id})  —  {total} rules with tactic tags")
        print(f"  {'Tactic':<35}  Rules")
        print(f"  {'-'*35}  -----")
        for tactic in sorted(counts, key=lambda t: (-counts[t], t)):
            print(f"  {tactic:<35}  {counts[tactic]}")
            rows.append({
                "pack_path": pack_path_str,
                "pack_id": pack_id,
                "tactic": tactic,
                "rule_count": counts[tactic],
            })
        if not counts:
            print("  (no tactic tags found)")

    if args.output and rows:
        output_path = Path(args.output)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_TACTICS_CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nWrote {len(rows)} rows to {output_path}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search pack sigma rules for ATT&CK coverage or export technique matches.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python tools/search_packs.py coverage windows/essential
  python tools/search_packs.py coverage windows/essential --summary
  python tools/search_packs.py coverage windows-hunting --summary

  python tools/search_packs.py csv windows/hunting T1059
  python tools/search_packs.py csv windows/hunting T1059 T1003
  python tools/search_packs.py csv windows/hunting t1059.001 --output results.csv

  python tools/search_packs.py csv windows/hunting --tactic execution
  python tools/search_packs.py csv windows/hunting --tactic execution persistence
  python tools/search_packs.py csv windows/hunting T1059 --tactic persistence --output results.csv

  python tools/search_packs.py list windows/essential
  python tools/search_packs.py list windows/essential --output pack_rules.csv

  python tools/search_packs.py tactics
  python tools/search_packs.py tactics windows/essential
  python tools/search_packs.py tactics --output tactic_coverage.csv
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    cov = sub.add_parser(
        "coverage",
        help="Show ATT&CK tactics/techniques covered by a pack's sigma rules",
    )
    cov.add_argument(
        "pack",
        help="Pack path (e.g. windows/essential) or pack ID (e.g. windows-essential)",
    )
    cov.add_argument(
        "--summary",
        action="store_true",
        help="Print only unique tactics/techniques with rule counts (skip the per-rule table)",
    )

    exp = sub.add_parser(
        "csv",
        help="Export rules matching specified technique(s) and/or tactic(s) to CSV",
    )
    exp.add_argument(
        "pack",
        help="Pack path (e.g. windows/hunting) or pack ID (e.g. windows-hunting)",
    )
    exp.add_argument(
        "techniques",
        nargs="*",
        metavar="TECHNIQUE",
        help=(
            "Technique ID(s) to search for (case-insensitive). "
            "A bare ID like T1059 also matches sub-techniques T1059.001, T1059.003, …"
        ),
    )
    exp.add_argument(
        "--tactic", "-t",
        nargs="+",
        metavar="TACTIC",
        help=(
            "Tactic name(s) to filter by (case-insensitive, e.g. execution persistence). "
            "A rule matches if it has ANY of the given tactics."
        ),
    )
    exp.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write CSV to FILE; if omitted, output goes to stdout",
    )

    lst = sub.add_parser(
        "list",
        help="Export all sigma rules in a pack to CSV (title, id, tactics, techniques)",
    )
    lst.add_argument(
        "pack",
        help="Pack path (e.g. windows/essential) or pack ID (e.g. windows-essential)",
    )
    lst.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write CSV to FILE; if omitted, output goes to stdout",
    )

    tac = sub.add_parser(
        "tactics",
        help="Show tactic detection counts for every pack (or a single pack)",
    )
    tac.add_argument(
        "pack",
        nargs="?",
        default=None,
        help=(
            "Pack path (e.g. windows/essential) or pack ID (e.g. windows-essential). "
            "Omit to scan all packs."
        ),
    )
    tac.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Also write results as CSV to FILE (columns: pack_path, pack_id, tactic, rule_count)",
    )

    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.command == "coverage":
        cmd_coverage(args)
    elif args.command == "csv":
        cmd_csv(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "tactics":
        cmd_tactics(args)


if __name__ == "__main__":
    main()
