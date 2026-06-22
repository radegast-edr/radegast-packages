"""Find Atomic Red Team tests that cover the techniques in a Radegast pack.

For each technique ID listed in a pack's ``attack_coverage`` field, the script
looks up matching Atomic Red Team tests in a local index file
(``windows-index.yaml``) and reports which techniques have tests available and
which do not.

Index file
----------
``windows-index.yaml`` is a YAML snapshot of the Atomic Red Team index for
Windows, structured as::

    <tactic>:
      <TECHNIQUE_ID>:
        technique:
          name: <technique name>
        atomic_tests:
          - name: <test name>
            auto_generated_guid: <uuid>
            description: <text>
            supported_platforms: [windows, ...]

The file is not included in the repo by default; generate or download it
before running this script.

Output formats
--------------
text (default)
    Human-readable summary followed by a per-technique breakdown listing every
    available atomic test with its GUID, supported platforms, and a truncated
    description.

json
    Machine-readable JSON with the shape::

        {
          "pack": "<pack>",
          "summary": {
            "techniques_with_tests": <int>,
            "techniques_without_tests": <int>,
            "total_atomic_tests": <int>
          },
          "matched": [ { "technique_id", "tactic", "technique_name", "tests": [...] } ],
          "unmatched": [ "<technique_id>", ... ]
        }

Usage
-----
    python tests/atomic/find_atomic_tests.py windows/essential
    python tests/atomic/find_atomic_tests.py windows/essential --output json
    python tests/atomic/find_atomic_tests.py windows/hunting --output json > results.json

Pack can be specified as a path relative to the ``packs/`` directory, e.g.
``windows/essential`` or ``windows/hunting``.
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
    """Load and return the pack manifest for *pack* (a path like ``windows/essential``).

    Tries both ``pack.yml`` and ``pack.yaml``.  Raises ``FileNotFoundError`` if
    neither exists under ``packs/<pack>/``.
    """
    pack_dir = REPO_ROOT / "packs" / Path(pack)
    for name in ("pack.yml", "pack.yaml"):
        path = pack_dir / name
        if path.exists():
            with path.open(encoding="utf-8") as f:
                return yaml.safe_load(f)
    raise FileNotFoundError(f"No pack.yml found at {pack_dir}")


def build_technique_map(index: dict) -> dict[str, dict]:
    """Build a flat lookup from technique ID to its tactic, name, and tests.

    Returns a dict keyed by uppercase technique ID (e.g. ``"T1059.001"``) where
    each value has the shape::

        {
            "tactic": str,          # parent tactic name from the index
            "name": str,            # technique display name
            "atomic_tests": list,   # raw atomic test objects from the index
        }
    """
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
    """Cross-reference pack techniques against the atomic test index.

    Parameters
    ----------
    pack_coverage:
        List of technique IDs from the pack's ``attack_coverage`` field
        (e.g. ``["T1003", "T1003.001", "T1059.001"]``).
    technique_map:
        Flat lookup returned by :func:`build_technique_map`.

    Returns
    -------
    matched:
        List of dicts for techniques that have at least one atomic test.  Each
        entry has the shape::

            {
                "technique_id": str,
                "tactic": str,
                "technique_name": str,
                "tests": [
                    {"name": str, "guid": str, "description": str, "platforms": list},
                    ...
                ],
            }

    unmatched:
        List of technique IDs that were not found in the index (no tests exist
        or the technique is not present in the index at all).
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
    """Print a human-readable summary and per-technique test listing to stdout."""
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
        description=(
            "Find Atomic Red Team tests that cover the techniques in a Radegast pack. "
            "Reads the pack's attack_coverage list and looks up each technique ID in "
            "the local windows-index.yaml, then reports which techniques have tests "
            "available and which do not."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Print a human-readable summary for the windows/essential pack
  python tests/atomic/find_atomic_tests.py windows/essential

  # Same, but emit JSON (useful for piping into other tools)
  python tests/atomic/find_atomic_tests.py windows/essential --output json

  # Save JSON output to a file
  python tests/atomic/find_atomic_tests.py windows/hunting --output json > results.json

notes:
  The index file (windows-index.yaml) must be present in the same directory as
  this script.  It is not included in the repository by default.
""",
    )
    parser.add_argument(
        "pack",
        help=(
            'Pack path relative to the packs/ directory, e.g. "windows/essential" '
            'or "windows/hunting".'
        ),
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help=(
            'Output format. "text" (default) prints a human-readable report; '
            '"json" emits a structured JSON object suitable for further processing.'
        ),
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
