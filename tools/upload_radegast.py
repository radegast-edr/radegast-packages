"""
Zips packs on-the-fly then uploads them to Radegast EDR via API.

Requires RADEGAST_API_KEY in .env (or the environment).
Optionally set RADEGAST_URL to override the default console endpoint.

Usage:
    # Upload a specific pack (or several)
    uv run python tools/upload_radegast.py --pack windows/essential
    uv run python tools/upload_radegast.py --pack windows/essential linux/advanced

    # Upload all discovered packs
    uv run python tools/upload_radegast.py --all

    # Interactive selection menu
    uv run python tools/upload_radegast.py
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from os import environ
from pathlib import Path
from typing import TypedDict

import yaml
from requests import get, post

# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------

DIR_ROOT = Path(__file__).resolve().parent.parent

def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        environ.setdefault(key, value)

_load_env(DIR_ROOT / ".env")

RADEGAST_URL = environ.get("RADEGAST_URL", "https://console.radegast.app")
RADEGAST_API_KEY = environ.get("RADEGAST_API_KEY", "")

# ---------------------------------------------------------------------------
# zip_pack imports
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent))
from zip_pack import _build_sigma_index, build_zip, discover_packs, PACKS_DIR  # noqa: E402


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class RadegastPack(TypedDict):
    id: int
    pack_id: str
    newest_version: str | None


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _raise(r) -> None:  # noqa: ANN001
    try:
        r.raise_for_status()
    except Exception as exc:
        raise SystemExit(f"HTTP {r.status_code}: {r.text}") from exc


def fetch_radegast_packs() -> list[RadegastPack]:
    r = get(f"{RADEGAST_URL}/api/v1/packs/", headers={"X-API-Key": RADEGAST_API_KEY})
    _raise(r)
    return [
        RadegastPack(
            id=x["id"],
            pack_id=x["pack_id"],
            newest_version=(x.get("latest") or {}).get("version"),
        )
        for x in r.json()
    ]


# ---------------------------------------------------------------------------
# Pack helpers
# ---------------------------------------------------------------------------


def _read_pack_meta(os_name: str, level: str) -> dict:
    pack_dir = PACKS_DIR / os_name / level
    doc = yaml.safe_load((pack_dir / "pack.yml").read_text(encoding="utf-8")) or {}
    raw_id = str(doc.get("id", f"{os_name}-{level}")).strip()
    safe_id = re.sub(r"[^a-z0-9-]", "-", raw_id.lower())
    safe_id = re.sub(r"-{2,}", "-", safe_id).strip("-")
    return {
        "raw_id": raw_id,
        "pack_id": f"radegast-{safe_id}",
        "pack_name": f"Radegast: {doc.get('name', f'{os_name}/{level}')}",
        "zip_path": pack_dir / f"{raw_id}.zip",
    }


# ---------------------------------------------------------------------------
# Upload logic
# ---------------------------------------------------------------------------


def _zip_without_description(zip_path: Path) -> io.BytesIO:
    """Return an in-memory zip identical to zip_path but with description stripped from pack.yml."""
    buf = io.BytesIO()
    with zipfile.ZipFile(zip_path, "r") as src, zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "pack.yml":
                doc = yaml.safe_load(data.decode("utf-8")) or {}
                doc.pop("description", None)
                data = yaml.dump(doc, allow_unicode=True, sort_keys=False).encode("utf-8")
            dst.writestr(item, data)
    buf.seek(0)
    return buf


def _bump_version(current: str | None) -> str:
    if current is None:
        return "1.0.0"
    parts = current.split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except (ValueError, IndexError):
        return "1.0.0"
    return ".".join(parts)


def upload_pack(
    os_name: str,
    level: str,
    remote_packs: list[RadegastPack],
    sigma_index: dict,
) -> None:
    meta = _read_pack_meta(os_name, level)

    # Always (re)build the zip, overwriting any existing file
    build_zip(os_name, level, sigma_index)

    zip_path: Path = meta["zip_path"]
    if not zip_path.exists():
        print(f"  ERROR: zip not found after build: {zip_path}", file=sys.stderr)
        return

    pack_id: str = meta["pack_id"]
    pack_name: str = meta["pack_name"]

    remote_pack = next((p for p in remote_packs if p["pack_id"] == pack_id), None)
    if remote_pack is None:
        print(f"[*] Creating new pack {pack_id} -- {pack_name}")
        r = post(
            f"{RADEGAST_URL}/api/v1/packs/",
            headers={"X-API-Key": RADEGAST_API_KEY},
            json={
                "pack_id": pack_id,
                "name": pack_name,
            },
        )
        _raise(r)
        body = r.json()
        remote_pack = RadegastPack(
            id=body["id"],
            pack_id=body["pack_id"],
            newest_version=None,
        )

    new_version = _bump_version(remote_pack["newest_version"])
    print(f"[*] Uploading {pack_id} version {new_version}")
    zip_buf = _zip_without_description(zip_path)
    r = post(
        f"{RADEGAST_URL}/api/v1/packs/{remote_pack['id']}/versions",
        headers={"X-API-Key": RADEGAST_API_KEY, "Authorization": RADEGAST_API_KEY},
        files={"file": (zip_path.name, zip_buf, "application/x-zip-compressed")},
        params={"version": new_version},
    )
    _raise(r)


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
        description="Zip and upload packs to Radegast EDR."
    )
    parser.add_argument(
        "--pack",
        nargs="+",
        metavar="OS/LEVEL",
        help="Pack(s) to upload, e.g. windows/essential or linux/advanced",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Upload all discovered packs",
    )
    return parser.parse_args()


def main() -> None:
    if not RADEGAST_API_KEY:
        sys.exit("ERROR: RADEGAST_API_KEY not set. Add it to .env or the environment.")

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

    print("[*] Fetching remote packs from Radegast...")
    remote_packs = fetch_radegast_packs()
    print(f"[*] Fetched {len(remote_packs)} remote packs")

    print("Building sigma index...")
    sigma_index = _build_sigma_index()
    print(f"  Indexed {len(sigma_index)} sigma rules.")

    for os_name, level in selected:
        upload_pack(os_name, level, remote_packs, sigma_index)

    print(f"\nDone. Processed {len(selected)} pack(s).")


if __name__ == "__main__":
    main()
