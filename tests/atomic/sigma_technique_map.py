"""Map sigma rules in a Radegast pack to MITRE ATT&CK techniques.

Scans every ``.yml`` file under ``packs/<pack>/sigma/``, extracts the rule
title and any ``attack.tXXXX`` tags, then writes a JSON file that maps each
technique ID to the sigma rules that cover it.

Output shape
------------
::

    {
      "pack": "windows/essential",
      "techniques": {
        "T1071.004": [
          "DNS Query by Finger Utility",
          ...
        ],
        ...
      },
      "rules_without_techniques": [
        "Some Rule With No ATT&CK Tags",
        ...
      ]
    }

Usage
-----
    python tests/atomic/sigma_technique_map.py windows/essential
    python tests/atomic/sigma_technique_map.py windows/essential --output results.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent.parent

TECHNIQUE_RE = re.compile(r"^attack\.(t\d+(?:\.\d+)?)$", re.IGNORECASE)


def iter_sigma_files(pack: str):
    sigma_dir = REPO_ROOT / "packs" / Path(pack) / "sigma"
    if not sigma_dir.exists():
        raise FileNotFoundError(f"No sigma directory found at {sigma_dir}")
    yield from sigma_dir.rglob("*.yml")


def extract_techniques(tags: list) -> list[str]:
    techniques = []
    for tag in tags:
        m = TECHNIQUE_RE.match(str(tag))
        if m:
            techniques.append(m.group(1).upper())
    return techniques


def build_map(pack: str) -> tuple[dict[str, list[str]], list[str]]:
    techniques: dict[str, list[str]] = defaultdict(list)
    no_techniques: list[str] = []

    for path in sorted(iter_sigma_files(pack)):
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            continue

        title = data.get("title", path.stem)
        tags = data.get("tags") or []
        found = extract_techniques(tags)

        if found:
            for tech_id in found:
                if title not in techniques[tech_id]:
                    techniques[tech_id].append(title)
        else:
            no_techniques.append(title)

    return dict(sorted(techniques.items())), no_techniques


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Map sigma rules in a Radegast pack to MITRE ATT&CK techniques. "
            "Reads every .yml file under packs/<pack>/sigma/ and writes a JSON "
            "file that groups rule titles by technique ID."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python tests/atomic/sigma_technique_map.py windows/essential
  python tests/atomic/sigma_technique_map.py windows/essential --output my_map.json
""",
    )
    parser.add_argument(
        "pack",
        help='Pack path relative to packs/, e.g. "windows/essential".',
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help=(
            "Write JSON to FILE instead of printing to stdout. "
            "The file is created/overwritten relative to the current directory."
        ),
    )
    args = parser.parse_args()

    try:
        techniques, no_techniques = build_map(args.pack)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    result = {
        "pack": args.pack,
        "techniques": techniques,
        "rules_without_techniques": no_techniques,
    }

    output = json.dumps(result, indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output, encoding="utf-8")
        total_rules = sum(len(v) for v in techniques.values()) + len(no_techniques)
        print(
            f"Wrote {len(techniques)} technique(s) from {total_rules} rule(s) "
            f"to {out_path}"
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
