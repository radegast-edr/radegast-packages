"""Build or rebuild pack.yml files from sigma, ioc, and yara content in each pack directory.

Scans each pack's sigma/, ioc/, and yara/ subdirectories to collect rule IDs,
then writes a fresh pack.yml that preserves all existing metadata fields and
replaces rules.has with what is actually on disk.

Usage:
    python tools/build_packs.py                          # interactive: pick from menu
    python tools/build_packs.py --pack windows/hunting   # one pack
    python tools/build_packs.py --pack windows/hunting linux/essential
    python tools/build_packs.py --all                    # every pack
    python tools/build_packs.py --all --dry-run          # preview without writing
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import NamedTuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = REPO_ROOT / "packs"
RULES_DIR = REPO_ROOT / "rules"

# Level → default extends list (template: {os} is replaced at runtime)
_LEVEL_EXTENDS: dict[str, list[str]] = {
    "essential": [],
    "advanced": ["{os}-essential"],
    "hunting": ["{os}-advanced"],
}

_FP_LEVEL: dict[str, str] = {
    "essential": "low",
    "advanced": "medium",
    "hunting": "high",
}

_OS_DISPLAY: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
}


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #


class RuleEntry(NamedTuple):
    rule_id: str
    comment: str  # text that goes after # (no leading #)


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def discover_packs() -> list[tuple[str, str]]:
    """Return all (os, level) pairs that have a directory under packs/."""
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


def _pack_path(os_name: str, level: str) -> Path:
    return PACKS_DIR / os_name / level


# --------------------------------------------------------------------------- #
# Rule scanning
# --------------------------------------------------------------------------- #


def _extract_attack_ids(tags: list) -> list[str]:
    """Return canonical ATT&CK technique IDs (e.g. T1059.001) from a sigma tags list."""
    ids = []
    for tag in tags or []:
        m = re.match(r"^attack\.t(\d{4}(?:\.\d{3})?)$", str(tag), re.IGNORECASE)
        if m:
            ids.append(f"T{m.group(1)}")
    return ids


def scan_sigma(pack: Path) -> tuple[list[RuleEntry], list[str]]:
    """Scan sigma/ and return (rule entries, sorted unique ATT&CK technique IDs)."""
    sigma_dir = pack / "sigma"
    if not sigma_dir.is_dir():
        return [], []
    entries: list[RuleEntry] = []
    seen_ids: set[str] = set()
    attack_ids: set[str] = set()
    for path in sorted(sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            print(f"  Warning: skipping unparseable {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            continue
        rule_id = str(doc.get("id", "")).strip()
        if not rule_id or rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        title = str(doc.get("title", "")).strip()
        entries.append(RuleEntry(rule_id=rule_id, comment=title))
        attack_ids.update(_extract_attack_ids(doc.get("tags", [])))
    return entries, sorted(attack_ids)


def scan_ioc(pack: Path) -> list[RuleEntry]:
    """Parse IOC .txt files: each line format is  hash;rule=ID key=val comment=TEXT."""
    ioc_dir = pack / "ioc"
    if not ioc_dir.is_dir():
        return []
    seen: dict[str, str] = {}  # rule_id -> first comment seen
    for path in sorted(ioc_dir.rglob("*.txt")):
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            m_id = re.search(r"\brule=(\S+)", line)
            if not m_id:
                continue
            rule_id = m_id.group(1)
            if rule_id in seen:
                continue
            # comment= runs to end-of-line or next key=
            m_comment = re.search(r"\bcomment=(.+?)(?:\s+\w+=|$)", line)
            seen[rule_id] = m_comment.group(1).strip() if m_comment else ""
    return [RuleEntry(rule_id=k, comment=v) for k, v in seen.items()]


def scan_yara(pack: Path) -> list[RuleEntry]:
    """Extract rule names from .yar / .yara files."""
    yara_dir = pack / "yara"
    if not yara_dir.is_dir():
        return []
    entries: list[RuleEntry] = []
    seen: set[str] = set()
    patterns = [*sorted(yara_dir.rglob("*.yar")), *sorted(yara_dir.rglob("*.yara"))]
    for path in patterns:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*rule\s+(\w+)", text, re.MULTILINE):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            entries.append(RuleEntry(rule_id=name, comment=name))
    return entries


# --------------------------------------------------------------------------- #
# Global rule-pool scanning (rules/<type>/<os>/)
# --------------------------------------------------------------------------- #


def scan_global_sigma(os_name: str) -> dict[str, str]:
    """Return {rule_id: title} for all sigma rules in rules/sigma/<os_name>/."""
    sigma_dir = RULES_DIR / "sigma" / os_name
    if not sigma_dir.is_dir():
        return {}
    result: dict[str, str] = {}
    for path in sorted(sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            print(f"  Warning: skipping unparseable {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            continue
        rule_id = str(doc.get("id", "")).strip()
        if rule_id and rule_id not in result:
            result[rule_id] = str(doc.get("title", "")).strip()
    return result


def scan_global_ioc(os_name: str) -> dict[str, str]:
    """Return {rule_id: description} from rules/ioc/<os_name>/ and rules/ioc/common/."""
    result: dict[str, str] = {}
    for subdir in (os_name, "common"):
        ioc_dir = RULES_DIR / "ioc" / subdir
        if not ioc_dir.is_dir():
            continue
        for path in sorted(ioc_dir.rglob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                print(f"  Warning: skipping unparseable {path.relative_to(REPO_ROOT)}", file=sys.stderr)
                continue
            rule_id = str(doc.get("id", "")).strip()
            if rule_id and rule_id not in result:
                result[rule_id] = str(doc.get("description", "")).strip()
    return result


def scan_global_yara(os_name: str) -> set[str]:
    """Return all YARA rule names from rules/yara/<os_name>/."""
    yara_dir = RULES_DIR / "yara" / os_name
    if not yara_dir.is_dir():
        return set()
    names: set[str] = set()
    for path in [*sorted(yara_dir.rglob("*.yar")), *sorted(yara_dir.rglob("*.yara"))]:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*rule\s+(\w+)", text, re.MULTILINE):
            names.add(m.group(1))
    return names


def find_sigma_rule_paths(os_name: str) -> dict[str, Path]:
    """Return {rule_id: absolute_path} for every sigma rule in rules/sigma/<os_name>/."""
    sigma_dir = RULES_DIR / "sigma" / os_name
    result: dict[str, Path] = {}
    if not sigma_dir.is_dir():
        return result
    for path in sorted(sigma_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        rule_id = str(doc.get("id", "")).strip()
        if rule_id and rule_id not in result:
            result[rule_id] = path
    return result


def link_sigma_rules(pack: Path, os_name: str, rule_entries: list[RuleEntry]) -> None:
    """Replace sigma files in the pack with flat relative symlinks into rules/sigma/<os_name>/."""
    if not rule_entries:
        return

    sigma_dir = pack / "sigma"
    sigma_dir.mkdir(parents=True, exist_ok=True)

    rule_paths = find_sigma_rule_paths(os_name)
    symlinked_names: set[str] = set()

    for entry in rule_entries:
        source = rule_paths.get(entry.rule_id)
        if source is None:
            print(f"  Warning: rule {entry.rule_id} not found in rules/sigma/{os_name}/", file=sys.stderr)
            continue
        link_path = sigma_dir / source.name
        if link_path.is_symlink() or link_path.exists():
            link_path.unlink()
        rel = Path(os.path.relpath(source, link_path.parent))
        try:
            link_path.symlink_to(rel)
            symlinked_names.add(source.name)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                sys.exit(
                    "Error: creating symlinks requires Developer Mode or admin rights on Windows.\n"
                    "Enable Developer Mode in Settings → System → For developers, then retry."
                )
            raise

    if not symlinked_names:
        return

    # Remove actual (non-symlink) files in subdirectories that were replaced by flat symlinks
    for path in sorted(sigma_dir.rglob("*.yml")):
        if not path.is_symlink() and path.parent != sigma_dir and path.name in symlinked_names:
            path.unlink()

    # Remove empty directories left behind after cleanup
    for d in sorted(sigma_dir.rglob("*"), reverse=True):
        if d.is_dir() and d != sigma_dir:
            try:
                d.rmdir()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


def _read_existing(pack: Path) -> dict:
    p = pack / "pack.yml"
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        print(f"  Warning: could not parse existing pack.yml — {exc}", file=sys.stderr)
        return {}


def _build_meta(os_name: str, level: str, existing: dict) -> dict:
    meta = dict(existing)
    os_title = _OS_DISPLAY.get(os_name, os_name.title())
    meta.setdefault("name", f"{os_title} {level.title()}")
    meta.setdefault("id", f"{os_name}-{level}")
    meta.setdefault("description", f"TODO: describe {os_name}-{level} pack.")
    meta["os"] = os_name
    meta["level"] = level
    meta.setdefault("pack_schema_version", 1)
    meta.setdefault("requires_rustinel", ">=1.0.2")
    meta.setdefault("default", False)
    meta.setdefault("status", "experimental")
    meta.setdefault("license", "DRL-1.1")
    if "extends" not in meta:
        tmpl = _LEVEL_EXTENDS.get(level, [])
        meta["extends"] = [e.replace("{os}", os_name) for e in tmpl]
    meta.setdefault("test_status", "none")
    meta.setdefault("expected_false_positive_level", _FP_LEVEL.get(level, "medium"))
    return meta


# --------------------------------------------------------------------------- #
# YAML rendering
# --------------------------------------------------------------------------- #


def _wrap(text: str, width: int = 80, indent: int = 4) -> list[str]:
    prefix = " " * indent
    return [f"{prefix}{ln}" for ln in textwrap.fill(text.strip(), width - indent).split("\n")]


def _rule_lines(entries: list[RuleEntry]) -> list[str]:
    pad = max((len(e.rule_id) for e in entries), default=0) + 3
    lines = []
    for e in entries:
        base = f"          - {e.rule_id}"
        comment = f"  # {e.comment}" if e.comment else ""
        lines.append(f"{base:<{10 + 2 + pad}}{comment}".rstrip())
    return lines


def format_pack_yml(
    meta: dict,
    sigma: list[RuleEntry],
    ioc: list[RuleEntry],
    yara: list[RuleEntry],
    exclude_comments: dict[str, str] | None = None,
) -> str:
    out: list[str] = []

    def ln(s: str = "") -> None:
        out.append(s)

    # ── scalar metadata ────────────────────────────────────────────────────── #
    ln(f"name: {meta['name']}")
    ln(f"id: {meta['id']}")

    desc = str(meta.get("description", "")).strip()
    if len(desc) > 80:
        ln("description: >")
        out.extend(_wrap(desc))
    else:
        ln(f"description: {desc}")

    ln(f"os: {meta['os']}")
    ln(f"level: {meta['level']}")
    ln(f"pack_schema_version: {meta['pack_schema_version']}")
    ln(f'requires_rustinel: "{meta["requires_rustinel"]}"')
    ln(f"default: {'true' if meta['default'] else 'false'}")

    if "expected_false_positive_level" in meta:
        ln(f"expected_false_positive_level: {meta['expected_false_positive_level']}")

    ln(f"status: {meta['status']}")

    if "license" in meta:
        ln(f"license: {meta['license']}")

    # ── extends ───────────────────────────────────────────────────────────── #
    extends = meta.get("extends") or []
    if extends:
        ln("extends:")
        for ext in extends:
            ln(f"  - {ext}")
    else:
        ln("extends: []")

    # ── optional list fields ──────────────────────────────────────────────── #
    if meta.get("attack_coverage"):
        ln("attack_coverage:")
        for t in meta["attack_coverage"]:
            ln(f"  - {t}")

    if meta.get("telemetry_requirements"):
        ln("telemetry_requirements:")
        for t in meta["telemetry_requirements"]:
            ln(f"  - {t}")

    if "test_status" in meta:
        ln(f"test_status: {meta['test_status']}")

    # ── sources ───────────────────────────────────────────────────────────── #
    sources = meta.get("sources") or {}
    if sources:
        ln("sources:")
        for src_type, src_list in sources.items():
            ln(f"    {src_type}:")
            for src in src_list or []:
                ln(f"      - {src}")

    # ── rules ─────────────────────────────────────────────────────────────── #
    # rules.has is rebuilt from disk; rules.includes and rules.excludes are preserved.
    existing_rules = meta.get("rules") or {}
    includes = existing_rules.get("includes") or {}
    excludes = existing_rules.get("excludes") or {}

    has_content = bool(sigma or ioc or yara)
    has_inherited = any(
        (includes.get(k) or excludes.get(k)) for k in ("sigma", "yara", "ioc")
    )

    if has_content or has_inherited:
        ln("rules:")
        if has_content:
            ln("    has:")
            if sigma:
                ln("        sigma:")
                out.extend(_rule_lines(sigma))
            if yara:
                ln("        yara:")
                out.extend(_rule_lines(yara))
            if ioc:
                ln("        ioc:")
                out.extend(_rule_lines(ioc))

        def _section(key: str, data: dict) -> None:
            items_by_type = {t: data.get(t) or [] for t in ("sigma", "yara", "ioc")}
            if not any(items_by_type.values()):
                return
            ln(f"    {key}:")
            for rule_type, items in items_by_type.items():
                if items:
                    ln(f"        {rule_type}:")
                    if key == "excludes" and exclude_comments:
                        entries = [RuleEntry(rule_id=i, comment=exclude_comments.get(i, "")) for i in items]
                        out.extend(_rule_lines(entries))
                    else:
                        for item in items:
                            ln(f"          - {item}")

        _section("includes", includes)
        _section("excludes", excludes)

    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #


def build_pack(os_name: str, level: str, dry_run: bool) -> None:
    pack = _pack_path(os_name, level)
    label = f"{os_name}/{level}"
    print(f"\n{'-' * 60}")
    print(f"  Pack : {label}")
    print(f"  Path : {pack.relative_to(REPO_ROOT)}")
    print()

    existing = _read_existing(pack)
    meta = _build_meta(os_name, level, existing)

    sigma, attack_ids = scan_sigma(pack)
    ioc = scan_ioc(pack)
    yara = scan_yara(pack)

    if attack_ids:
        meta["attack_coverage"] = attack_ids

    # Compare pack rules against the global rules pool to compute excludes.
    global_sigma = scan_global_sigma(os_name)
    global_ioc = scan_global_ioc(os_name)
    global_yara = scan_global_yara(os_name)

    existing_has = (meta.get("rules") or {}).get("has") or {}

    # Build the full sigma list: disk scan results + any IDs only in pack.yml's rules.has.
    # This ensures pack.yml's sigma section is never silently zeroed out when rglob finds
    # only symlinks (or nothing) but pack.yml already tracks the authoritative list.
    disk_sigma_by_id = {e.rule_id: e for e in sigma}
    yml_only_ids = set(existing_has.get("sigma") or []) - disk_sigma_by_id.keys()
    extra_sigma = [RuleEntry(rule_id=rid, comment=global_sigma.get(rid, "")) for rid in sorted(yml_only_ids)]
    all_sigma = list(sigma) + extra_sigma

    pack_sigma_ids = {e.rule_id for e in all_sigma}
    pack_ioc_ids = {e.rule_id for e in ioc} | set(existing_has.get("ioc") or [])
    pack_yara_ids = {e.rule_id for e in yara} | set(existing_has.get("yara") or [])

    existing_excludes = (meta.get("rules") or {}).get("excludes") or {}
    merged_excludes: dict[str, list[str]] = {}
    for key, global_ids, pack_ids in [
        ("sigma", set(global_sigma), pack_sigma_ids),
        ("ioc", set(global_ioc), pack_ioc_ids),
        ("yara", global_yara, pack_yara_ids),
    ]:
        computed = global_ids - pack_ids
        manual = set(existing_excludes.get(key) or [])
        merged = sorted(computed | manual)
        if merged:
            merged_excludes[key] = merged

    if merged_excludes:
        if "rules" not in meta:
            meta["rules"] = {}
        meta["rules"]["excludes"] = merged_excludes

    exclude_comments: dict[str, str] = {**global_sigma, **global_ioc}
    exclude_comments.update({n: n for n in global_yara})

    exc = {k: len(v) for k, v in merged_excludes.items()}
    print(f"  sigma: {len(sigma):>4} on disk + {len(extra_sigma):>4} from pack.yml = {len(all_sigma):>4} total")
    print(f"  global sigma: {len(global_sigma):>4}   excluded: {exc.get('sigma', 0):>4}")
    if global_ioc or exc.get("ioc", 0):
        print(f"  global ioc:   {len(global_ioc):>4}   excluded: {exc.get('ioc', 0):>4}")
    if global_yara or exc.get("yara", 0):
        print(f"  global yara:  {len(global_yara):>4}   excluded: {exc.get('yara', 0):>4}")

    content = format_pack_yml(meta, all_sigma, ioc, yara, exclude_comments)
    dest = pack / "pack.yml"

    if dry_run:
        print(f"\n  -- dry-run preview: {dest.relative_to(REPO_ROOT)} --\n")
        for line in content.splitlines():
            print(f"  {line}")
    else:
        dest.write_text(content, encoding="utf-8")
        print(f"  Written: {dest.relative_to(REPO_ROOT)}")
        link_sigma_rules(pack, os_name, all_sigma)
        print(f"  Linked: {len(all_sigma)} sigma rule(s) as symlinks")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _interactive_select(packs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    print("Available packs:\n")
    for i, (os_name, level) in enumerate(packs, 1):
        print(f"  {i:2}.  {os_name}/{level}")
    print()
    print("Enter number(s) separated by spaces, or 'all':")
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
                print(f"  Warning: '{token}' is out of range — skipped.")
        except ValueError:
            print(f"  Warning: '{token}' is not a number — skipped.")
    return selected


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build or rebuild pack.yml from sigma/ioc/yara content in each pack directory."
    )
    parser.add_argument(
        "--pack",
        nargs="+",
        metavar="OS/LEVEL",
        help="Pack(s) to build, e.g. windows/hunting or linux/essential",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Build all discovered packs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without modifying any files",
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

    for os_name, level in selected:
        build_pack(os_name, level, dry_run=args.dry_run)

    print(f"\n{'-' * 60}")
    action = "dry-run preview" if args.dry_run else "build"
    print(f"Done. {action} complete for {len(selected)} pack(s).\n")


if __name__ == "__main__":
    main()
