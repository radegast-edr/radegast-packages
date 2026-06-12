"""
Find available Atomic Red Team tests for a given Radegast pack.

Usage:
    python find_atomic_tests.py <pack>
    python find_atomic_tests.py windows/essential
    python find_atomic_tests.py windows/essential --output json
"""

import argparse
import json
import sys
from pathlib import Path

import yaml


SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent.parent
INDEX_PATH = SCRIPT_DIR / "windows-index.yaml"


def load_pack_yaml(pack: str) -> dict:
    pack_dir = REPO_ROOT / "packs" / Path(pack)
    for name in ("pack.yml", "pack.yaml"):
        path = pack_dir / name
        if path.exists():
            with path.open(encoding="utf-8") as f:
                return yaml.safe_load(f)
    raise FileNotFoundError(f"No pack.yml found at {pack_dir}")


def build_technique_map(index: dict) -> dict[str, dict]:
    """Return {technique_id: {tactic, technique_name, atomic_tests}} from the index."""
    mapping: dict[str, dict] = {}
    for tactic, techniques in index.items():
        if not isinstance(techniques, dict):
            continue
        for tech_id, entry in techniques.items():
            if not isinstance(entry, dict):
                continue
            technique_obj = entry.get("technique", {})
            atomic_tests = entry.get("atomic_tests", [])
            mapping[tech_id] = {
                "tactic": tactic,
                "name": technique_obj.get("name", ""),
                "atomic_tests": atomic_tests or [],
            }
    return mapping


def find_tests(pack_coverage: list[str], technique_map: dict) -> tuple[list, list]:
    """
    Returns (matched, unmatched).
    matched: list of dicts with technique info and its atomic tests.
    unmatched: list of technique IDs in the pack with no entry in the index.
    """
    matched = []
    unmatched = []

    for tech_id in pack_coverage:
        if tech_id in technique_map:
            entry = technique_map[tech_id]
            if entry["atomic_tests"]:
                tests = []
                for t in entry["atomic_tests"]:
                    tests.append({
                        "name": t.get("name", ""),
                        "guid": t.get("auto_generated_guid", ""),
                        "description": t.get("description", ""),
                        "platforms": t.get("supported_platforms", []),
                    })
                matched.append({
                    "technique_id": tech_id,
                    "tactic": entry["tactic"],
                    "technique_name": entry["name"],
                    "tests": tests,
                })
        else:
            unmatched.append(tech_id)

    return matched, unmatched


def print_text(pack: str, matched: list, unmatched: list) -> None:
    total_tests = sum(len(m["tests"]) for m in matched)
    print(f"\nPack: {pack}")
    print(f"Techniques with atomic tests : {len(matched)}")
    print(f"Techniques with no tests     : {len(unmatched)}")
    print(f"Total atomic tests available : {total_tests}")

    if matched:
        print("\n" + "=" * 60)
        print("TECHNIQUES WITH ATOMIC TESTS")
        print("=" * 60)
        for entry in matched:
            print(f"\n[{entry['technique_id']}] {entry['technique_name']}")
            print(f"  Tactic : {entry['tactic']}")
            for i, t in enumerate(entry["tests"], 1):
                platforms = ", ".join(t["platforms"]) if t["platforms"] else "unknown"
                print(f"  Test {i}: {t['name']}")
                print(f"    GUID      : {t['guid']}")
                print(f"    Platforms : {platforms}")
                if t["description"]:
                    desc = t["description"].strip().replace("\n", " ")
                    if len(desc) > 120:
                        desc = desc[:117] + "..."
                    print(f"    Desc      : {desc}")

    if unmatched:
        print("\n" + "=" * 60)
        print("TECHNIQUES WITH NO ATOMIC TESTS IN INDEX")
        print("=" * 60)
        print("  " + ", ".join(unmatched))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find Atomic Red Team tests available for a Radegast pack."
    )
    parser.add_argument(
        "pack",
        help='Pack path in the form "os/level" (e.g. windows/essential)',
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    try:
        pack_data = load_pack_yaml(args.pack)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    attack_coverage: list[str] = pack_data.get("attack_coverage") or []
    if not attack_coverage:
        print(f"No attack_coverage found in pack '{args.pack}'.", file=sys.stderr)
        sys.exit(0)

    if not INDEX_PATH.exists():
        print(f"Error: index not found at {INDEX_PATH}", file=sys.stderr)
        sys.exit(1)

    with INDEX_PATH.open(encoding="utf-8") as f:
        index = yaml.safe_load(f)

    technique_map = build_technique_map(index)
    matched, unmatched = find_tests(attack_coverage, technique_map)

    if args.output == "json":
        result = {
            "pack": args.pack,
            "summary": {
                "techniques_with_tests": len(matched),
                "techniques_without_tests": len(unmatched),
                "total_atomic_tests": sum(len(m["tests"]) for m in matched),
            },
            "matched": matched,
            "unmatched": unmatched,
        }
        print(json.dumps(result, indent=2))
    else:
        print_text(args.pack, matched, unmatched)


if __name__ == "__main__":
    main()
