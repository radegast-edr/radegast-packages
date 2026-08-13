"""Cross-check ATT&CK technique coverage of the Windows sigma packs against
the ranked priority list in techniques/windows/windows_top_techniques.json.

Usage:
    python tools/crosscheck_coverage.py
    python tools/crosscheck_coverage.py --status all
    python tools/crosscheck_coverage.py --status covered --top 0
    python tools/crosscheck_coverage.py --status missing --top 50

Packs checked: windows/essential, windows/advanced, windows/hunting.
windows/clickfix is intentionally excluded -- it targets a specific campaign,
not general ATT&CK technique coverage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from search_packs import get_techniques

REPO_ROOT = Path(__file__).resolve().parent.parent
TOP_TECHNIQUES_JSON = REPO_ROOT / "techniques" / "windows" / "windows_top_techniques.json"

_TIERS = ["essential", "advanced", "hunting"]
_PACK_REFS = {tier: f"windows/{tier}" for tier in _TIERS}


class SubTechnique:
    __slots__ = ("tid", "name", "covered")

    def __init__(self, tid: str, name: str, covered: bool):
        self.tid = tid
        self.name = name
        self.covered = covered


class Technique:
    __slots__ = ("tid", "name", "rank", "score", "covered", "first_tier", "subtechniques")

    def __init__(
        self,
        tid: str,
        name: str,
        rank: int,
        score: float,
        covered: bool,
        first_tier: str | None,
        subtechniques: list[SubTechnique],
    ):
        self.tid = tid
        self.name = name
        self.rank = rank
        self.score = score
        self.covered = covered
        self.first_tier = first_tier
        self.subtechniques = subtechniques

    @property
    def sub_covered_count(self) -> int:
        return sum(1 for s in self.subtechniques if s.covered)

    @property
    def status(self) -> str:
        if self.covered:
            return "covered"
        if self.sub_covered_count:
            return "partial"
        return "missing"


# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #


def load_top_techniques(path: Path) -> list[dict]:
    """Load the ranked technique list, tolerating the file's known quirks:
    a stray non-UTF-8 byte and a few unescaped control characters in strings.
    """
    if not path.exists():
        print(f"Error: priority list not found at {path}", file=sys.stderr)
        sys.exit(1)
    raw = path.read_bytes().decode("utf-8", errors="replace")
    return json.loads(raw, strict=False)


def load_pack_coverage() -> tuple[dict[str, set[str]], set[str]]:
    """Return ({tier: technique_ids}, merged_technique_ids) for essential/advanced/hunting."""
    per_tier: dict[str, set[str]] = {}
    merged: set[str] = set()
    for tier, pack_ref in _PACK_REFS.items():
        techs = get_techniques(pack_ref)
        per_tier[tier] = techs
        merged |= techs
    return per_tier, merged


def first_tier_covering(tid: str, per_tier: dict[str, set[str]]) -> str | None:
    for tier in _TIERS:
        if tid in per_tier[tier]:
            return tier
    return None


def build_techniques(
    raw_techniques: list[dict], per_tier: dict[str, set[str]], merged: set[str]
) -> list[Technique]:
    techniques = []
    for entry in raw_techniques:
        tid = str(entry["tid"]).upper()
        subtechniques = [
            SubTechnique(
                str(sub["tid"]).upper(), sub["name"], str(sub["tid"]).upper() in merged
            )
            for sub in entry.get("subtechniques") or []
        ]
        techniques.append(
            Technique(
                tid=tid,
                name=entry["name"],
                rank=entry["rank"],
                score=entry["score"],
                covered=tid in merged,
                first_tier=first_tier_covering(tid, per_tier),
                subtechniques=subtechniques,
            )
        )
    return techniques


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def pct(numerator: float, denominator: float) -> str:
    if denominator == 0:
        return "n/a"
    return f"{100 * numerator / denominator:.1f}%"


def print_report(
    techniques: list[Technique],
    per_tier: dict[str, set[str]],
    merged: set[str],
    status_filter: str,
    top: int,
) -> None:
    # Entries with rank=None have no score yet (e.g. techniques added by an ATT&CK
    # revision ahead of the next scoring pass) and are kept out of the ranked stats,
    # reported separately at the end instead.
    ranked = [t for t in techniques if t.rank is not None]
    pending = [t for t in techniques if t.rank is None]

    total = len(ranked)
    covered = [t for t in ranked if t.status == "covered"]
    partial = [t for t in ranked if t.status == "partial"]
    missing = [t for t in ranked if t.status == "missing"]

    total_score = sum(t.score for t in ranked)
    covered_score = sum(t.score for t in covered)

    all_subs = [s for t in ranked for s in t.subtechniques]
    covered_subs = [s for s in all_subs if s.covered]

    known_ids = {t.tid for t in techniques} | {s.tid for t in techniques for s in t.subtechniques}
    extra = merged - known_ids

    print("Windows Technique Coverage Report")
    print("=" * 70)
    print(f"Priority list : {TOP_TECHNIQUES_JSON.relative_to(REPO_ROOT)}")
    print(f"                ({total} ranked techniques, {len(all_subs)} subtechniques", end="")
    if pending:
        print(f", {len(pending)} pending re-score)")
    else:
        print(")")
    print("Packs checked : " + ", ".join(_PACK_REFS.values()) + "  (clickfix excluded)")
    print()
    print("Coverage summary")
    print("-" * 70)
    print(f"  Covered (own tag)       : {len(covered):>4} / {total}  ({pct(len(covered), total)})")
    print(f"  Partial (subtech only)  : {len(partial):>4} / {total}  ({pct(len(partial), total)})")
    print(f"  Missing entirely        : {len(missing):>4} / {total}  ({pct(len(missing), total)})")
    print(f"  Score-weighted coverage : {pct(covered_score, total_score)}")
    print(
        f"  Subtechniques covered   : {len(covered_subs):>4} / {len(all_subs)}"
        f"  ({pct(len(covered_subs), len(all_subs))})"
    )
    print()
    print("By tier (cumulative techniques covered by own tag):")
    cumulative: set[str] = set()
    for tier in _TIERS:
        cumulative |= per_tier[tier]
        count = sum(1 for t in techniques if t.tid in cumulative)
        print(f"  +{tier:<10}: {count:>4} / {total}  ({pct(count, total)})")
    if extra:
        print()
        print(
            f"  Note: {len(extra)} technique id(s) covered by the packs do not appear in the "
            f"priority list (e.g. deprecated/renamed ATT&CK ids)."
        )

    by_status = {"covered": covered, "partial": partial, "missing": missing}
    if status_filter == "all":
        selected = list(ranked)
    elif status_filter == "gaps":
        selected = partial + missing
    else:
        selected = by_status[status_filter]
    selected.sort(key=lambda t: t.rank)
    if top:
        selected = selected[:top]

    label = "ALL" if status_filter == "all" else status_filter.upper()
    print()
    print(f"{label} techniques ({len(selected)} shown), sorted by rank:")
    print("-" * 100)
    print(f"{'Rank':>4}  {'TID':<11} {'Score':>6}  {'Status':<8} {'Tier':<10} {'Subtech':>9}  Name")
    print("-" * 100)
    for t in selected:
        subtech = f"{t.sub_covered_count}/{len(t.subtechniques)}" if t.subtechniques else "-"
        tier = t.first_tier or "-"
        print(
            f"{t.rank:>4}  {t.tid:<11} {t.score:>6.2f}  {t.status:<8} {tier:<10} "
            f"{subtech:>9}  {t.name}"
        )

    if pending:
        print()
        print(
            f"Pending re-score ({len(pending)} techniques from an ATT&CK update not yet "
            f"scored, excluded from the ranking above):"
        )
        print("-" * 100)
        print(f"{'TID':<11} {'Status':<8} {'Tier':<10} {'Subtech':>9}  Name")
        print("-" * 100)
        for t in sorted(pending, key=lambda t: t.tid):
            subtech = f"{t.sub_covered_count}/{len(t.subtechniques)}" if t.subtechniques else "-"
            tier = t.first_tier or "-"
            print(f"{t.tid:<11} {t.status:<8} {tier:<10} {subtech:>9}  {t.name}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Cross-check ATT&CK technique coverage of the Windows sigma packs "
            "against the ranked priority list in windows_top_techniques.json."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python tools/crosscheck_coverage.py
  python tools/crosscheck_coverage.py --status all
  python tools/crosscheck_coverage.py --status covered --top 0
  python tools/crosscheck_coverage.py --status missing --top 50
""",
    )
    parser.add_argument(
        "--status",
        choices=["gaps", "covered", "partial", "missing", "all"],
        default="gaps",
        help="Which techniques to list in the detail table (default: gaps = partial + missing)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Limit the detail table to the N highest-priority rows (0 = no limit; default: 25)",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    raw_techniques = load_top_techniques(TOP_TECHNIQUES_JSON)
    per_tier, merged = load_pack_coverage()
    techniques = build_techniques(raw_techniques, per_tier, merged)
    print_report(techniques, per_tier, merged, args.status, args.top)


if __name__ == "__main__":
    main()
