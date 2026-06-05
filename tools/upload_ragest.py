"""
Uploads built packages to Radegast EDR via API
"""

from json import loads
from typing import TypedDict
from os import environ
from pathlib import Path

from requests import get, post

RADEGAST_URL = environ.get("RADEGAST_URL", "https://console.radegast.app")
RADEGAST_API_KEY = environ["RADEGAST_API_KEY"]
DIR_ROOT = Path(__file__).parent.parent
DIR_DIST = DIR_ROOT / "dist"
FILE_INDEX = DIR_DIST / "index.json"


class RadegastPack(TypedDict):
    id: int
    pack_id: str
    newest_version: str | None


def fetch_radegast_packs() -> list[RadegastPack]:
    r = get(f"{RADEGAST_URL}/api/v1/packs/")
    r.raise_for_status()
    packs: list[RadegastPack] = [RadegastPack(
        id=x["id"],
        pack_id=x["pack_id"],
        newest_version=None
    ) for x in r.json()]
    for pack in packs:
        r = get(f"{RADEGAST_URL}/api/v1/packs/{pack['id']}/versions", headers={"X-API-Key": RADEGAST_API_KEY})
        r.raise_for_status()
        versions = r.json()
        for version in versions:
            pack["newest_version"] = version["version"]
            break
    return packs


def main() -> None:
    remote_packs = fetch_radegast_packs()
    print(f"[*] Fetched {len(remote_packs)} Radegast packs")

    packs = loads(FILE_INDEX.read_text())['packs']
    for pack in packs:
        pack_id = f"rustinel-{pack['id']}"
        pack_name = f"Rustinel: {pack['name']}"
        pack_version = pack['version']
        file_pack = DIR_DIST / f"{pack['artifact']}"
        assert file_pack.exists(), f"Pack file not found: {file_pack}"

        remote_pack = next((p for p in remote_packs if p['pack_id'] == pack_id), None)
        if remote_pack is None:
            print(f"[*] Creating new pack {pack_id} -- {pack_name}")
            r = post(
                f"{RADEGAST_URL}/api/v1/packs/",
                headers={"X-API-Key": RADEGAST_API_KEY},
                json={
                    "pack_id": pack_id,
                    "name": pack_name,
                    "description": f"Rustinel pack from https://github.com/Karib0u/rustinel-rules/",
                }
            )
            r.raise_for_status()
            remote_pack = RadegastPack(
                id=r.json()["id"],
                pack_id=r.json()["pack_id"],
                newest_version=None
            )

        if remote_pack["newest_version"] != pack_version:
            print(f"[*] Uploading pack {pack_id} version {pack_version} to Radegast")
            with file_pack.open("rb") as f:
                r = post(
                    f"{RADEGAST_URL}/api/v1/packs/{remote_pack['id']}/versions",
                    headers={"X-API-Key": RADEGAST_API_KEY},
                    files={"file": (file_pack.name, f, "application/zip")},
                    params={"version": pack_version},
                )
                r.raise_for_status()


if __name__ == "__main__":
    main()
