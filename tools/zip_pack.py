"""Create a distributable zip from a pack.yml.

Reads rules.has.{sigma,yara,ioc} from a pack.yml, collects the actual rule
files, and writes a zip archive next to the pack.yml.

Sigma rules are sourced from rules/sigma/**/*.yml (matched by id field).
YARA and IOC files are taken directly from the pack's yara/ and ioc/ folders.

Usage:
    python tools/zip_pack.py                         # interactive: pick from menu
    python tools/zip_pack.py --pack windows/essential
    python tools/zip_pack.py --pack windows/essential linux/advanced
    python tools/zip_pack.py --all
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = REPO_ROOT / "packs"
RULES_DIR = REPO_ROOT / "rules"


# ---------------------------------------------------------------------------
# Sigma index
# ---------------------------------------------------------------------------


def _build_sigma_index() -> dict[str, Path]:
    """Return {rule_id: path} for every sigma rule file under rules/sigma/."""
    index: dict[str, Path] = {}
    sigma_root = RULES_DIR / "sigma"
    if not sigma_root.is_dir():
        return index
    for path in sigma_root.rglob("*.yml"):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            print(f"  Warning: skipping unparseable {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            continue
        rule_id = str(doc.get("id", "")).strip()
        if rule_id and rule_id not in index:
            index[rule_id] = path
    return index


# ---------------------------------------------------------------------------
# Pack helpers
# ---------------------------------------------------------------------------


def discover_packs() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if not PACKS_DIR.is_dir():
        return found
    for os_dir in sorted(PACKS_DIR.iterdir()):
        if not os_dir.is_dir():
            continue
        for level_dir in sorted(os_dir.iterdir()):
            if not level_dir.is_dir():
                continue
            found.append((os_dir.name, level_dir.name))
    return found


def _read_pack_yml(pack_dir: Path) -> dict:
    p = pack_dir / "pack.yml"
    if not p.exists():
        raise FileNotFoundError(f"pack.yml not found at {p}")
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


# ---------------------------------------------------------------------------
# Zip builder
# ---------------------------------------------------------------------------


def build_zip(os_name: str, level: str, sigma_index: dict[str, Path]) -> None:
    pack_dir = PACKS_DIR / os_name / level
    pack_yml = pack_dir / "pack.yml"
    print(f"\n{'-' * 60}")
    print(f"  Pack : {os_name}/{level}")
    print(f"  Path : {pack_yml.relative_to(REPO_ROOT)}")

    doc = _read_pack_yml(pack_dir)
    pack_id = str(doc.get("id", f"{os_name}-{level}")).strip()
    has = (doc.get("rules") or {}).get("has") or {}

    sigma_ids: list[str] = [str(s).strip() for s in (has.get("sigma") or [])]
    yara_ids: list[str] = [str(s).strip() for s in (has.get("yara") or [])]
    ioc_ids: list[str] = [str(s).strip() for s in (has.get("ioc") or [])]

    # ── collect sigma files from rules/ ────────────────────────────────────
    sigma_files: list[tuple[str, Path]] = []  # (arc_name, disk_path)
    missing_sigma: list[str] = []
    sigma_root = RULES_DIR / "sigma"
    for rule_id in sigma_ids:
        path = sigma_index.get(rule_id)
        if path is None:
            missing_sigma.append(rule_id)
            continue
        arc_name = "sigma/" + path.relative_to(sigma_root).as_posix()
        sigma_files.append((arc_name, path))

    # ── collect yara files from pack dir ───────────────────────────────────
    yara_files: list[tuple[str, Path]] = []
    yara_dir = pack_dir / "yara"
    if yara_dir.is_dir():
        for path in sorted(yara_dir.rglob("*")):
            if path.is_file():
                arc_name = "yara/" + path.relative_to(yara_dir).as_posix()
                yara_files.append((arc_name, path))

    # ── collect ioc files from pack dir ────────────────────────────────────
    ioc_files: list[tuple[str, Path]] = []
    ioc_dir = pack_dir / "ioc"
    if ioc_dir.is_dir():
        for path in sorted(ioc_dir.rglob("*")):
            if path.is_file():
                arc_name = "ioc/" + path.relative_to(ioc_dir).as_posix()
                ioc_files.append((arc_name, path))

    # ── report ─────────────────────────────────────────────────────────────
    print(f"  sigma: {len(sigma_files):>4} found / {len(sigma_ids):>4} listed")
    if missing_sigma:
        print(f"  WARNING: {len(missing_sigma)} sigma rule(s) not found in rules/:")
        for rid in missing_sigma:
            print(f"    - {rid}")
    print(f"  yara:  {len(yara_files):>4} files")
    print(f"  ioc:   {len(ioc_files):>4} files")

    all_files = sigma_files + yara_files + ioc_files

    zip_path = pack_dir / f"{pack_id}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for folder, files in (("sigma", sigma_files), ("yara", yara_files), ("ioc", ioc_files)):
            if not files:
                zf.mkdir(folder)
            else:
                for arc_name, disk_path in files:
                    zf.write(disk_path, arc_name)

    print(f"  Written: {zip_path.relative_to(REPO_ROOT)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _interactive_select(packs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    print("\nAvailable packs:\n")
    for i, (os_name, level) in enumerate(packs, 1):
        print(f"  {i:2}.  {os_name}/{level}")
    print("\nEnter number(s) separated by spaces, or 'all':")
    try:
        raw = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\nCancelled.")

    if raw.lower() == "all":
        return packs

    selected: list[tuple[str, str]] = []
    for token in raw.split():
        try:
            idx = int(token) - 1
            if 0 <= idx < len(packs):
                selected.append(packs[idx])
            else:
                print(f"  Warning: '{token}' out of range — skipped.")
        except ValueError:
            print(f"  Warning: '{token}' is not a number — skipped.")
    return selected


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a distributable zip from a pack.yml."
    )
    parser.add_argument(
        "--pack",
        nargs="+",
        metavar="OS/LEVEL",
        help="Pack(s) to zip, e.g. windows/essential or linux/advanced",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Zip all discovered packs",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    all_packs = discover_packs()

    if not all_packs:
        sys.exit(f"No pack directories found under {PACKS_DIR}")

    if args.all:
        selected = all_packs
    elif args.pack:
        selected = []
        for spec in args.pack:
            parts = spec.strip("/").split("/")
            if len(parts) != 2:
                print(f"  Warning: invalid pack spec '{spec}' — expected OS/LEVEL. Skipping.")
                continue
            pair = (parts[0], parts[1])
            if pair not in all_packs:
                print(f"  Warning: pack '{spec}' not found. Skipping.")
                continue
            selected.append(pair)
    else:
        selected = _interactive_select(all_packs)

    if not selected:
        print("No packs selected. Nothing to do.")
        return

    print("Building sigma index…")
    sigma_index = _build_sigma_index()
    print(f"  Indexed {len(sigma_index)} sigma rules.")

    for os_name, level in selected:
        build_zip(os_name, level, sigma_index)

    print(f"\n{'-' * 60}")
    print(f"Done. Zipped {len(selected)} pack(s).\n")


if __name__ == "__main__":
    main()
