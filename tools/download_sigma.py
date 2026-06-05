"""Download Sigma rules from SigmaHQ/sigma into rules/sigma/.

Fetches rules from the windows/, linux/, and macos/ subfolders of
https://github.com/SigmaHQ/sigma/tree/master/rules and writes them into
the corresponding rules/sigma/{os}/ folders in this repo, preserving the
upstream subfolder structure.

Usage:
    python tools/download_sigma.py                   # download all
    python tools/download_sigma.py --os windows linux
    python tools/download_sigma.py --dry-run
    python tools/download_sigma.py --token ghp_...
    python tools/download_sigma.py --diff            # show missing rules by ID
    python tools/download_sigma.py --diff --os linux # diff a single OS

Set GITHUB_TOKEN env var or pass --token to avoid API rate limits (60 req/h
unauthenticated vs 5 000 req/h authenticated). The tree listing and zip
download each count as one request, so rate limits are rarely an issue here.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DEST = REPO_ROOT / "rules" / "sigma"

UPSTREAM_REPO = "SigmaHQ/sigma"
UPSTREAM_BRANCH = "master"
UPSTREAM_RULES_PREFIX = "rules"

GITHUB_API_TREE = (
    f"https://api.github.com/repos/{UPSTREAM_REPO}/git/trees/{UPSTREAM_BRANCH}?recursive=1"
)
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{UPSTREAM_BRANCH}"
GITHUB_ZIP_URL = (
    f"https://github.com/{UPSTREAM_REPO}/archive/refs/heads/{UPSTREAM_BRANCH}.zip"
)

ALL_TARGET_OS: tuple[str, ...] = ("windows", "linux", "macos")


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #


def _make_request(url: str, token: str | None) -> urllib.request.Request:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return req


def fetch_json(url: str, token: str | None = None) -> dict:
    req = _make_request(url, token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        sys.exit(f"GitHub API error {exc.code} for {url}: {exc.reason}")


def fetch_raw(url: str, token: str | None = None) -> bytes:
    req = _make_request(url, token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        sys.exit(f"Download error {exc.code} for {url}: {exc.reason}")


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #


def get_rule_entries(token: str | None, target_os: tuple[str, ...]) -> list[dict]:
    """Return tree entries for .yml files under rules/{os}/ for each target OS."""
    print(f"Fetching file tree from {UPSTREAM_REPO}…")
    tree_data = fetch_json(GITHUB_API_TREE, token)

    if tree_data.get("truncated"):
        print("Warning: upstream tree was truncated by GitHub — some files may be missing.")

    entries = []
    for item in tree_data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path: str = item["path"]
        parts = path.split("/")
        if (
            len(parts) >= 3
            and parts[0] == UPSTREAM_RULES_PREFIX
            and parts[1] in target_os
            and path.endswith(".yml")
        ):
            entries.append(item)

    return entries


def dest_path(upstream_path: str) -> Path:
    """Map upstream path (rules/windows/foo/bar.yml) -> local path under SIGMA_DEST."""
    rel = Path(upstream_path).relative_to(UPSTREAM_RULES_PREFIX)
    return SIGMA_DEST / rel


def download_rules(
    entries: list[dict],
    token: str | None,
    dry_run: bool,
    force: bool,
) -> tuple[int, int, int]:
    """Download entries. Returns (downloaded, skipped, total)."""
    total = len(entries)
    downloaded = 0
    skipped = 0

    for i, entry in enumerate(entries, 1):
        upstream_path: str = entry["path"]
        local = dest_path(upstream_path)
        label = f"[{i}/{total}] {upstream_path}"

        if local.exists() and not force:
            print(f"  skip  {label}")
            skipped += 1
            continue

        raw_url = f"{GITHUB_RAW_BASE}/{upstream_path}"

        if dry_run:
            print(f"  would download  {label}")
            downloaded += 1
            continue

        print(f"  fetch {label}")
        content = fetch_raw(raw_url, token)
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(content)
        downloaded += 1

        # Polite delay to avoid hammering raw.githubusercontent.com
        if i % 50 == 0:
            time.sleep(0.5)

    return downloaded, skipped, total


# --------------------------------------------------------------------------- #
# Diff helpers
# --------------------------------------------------------------------------- #


def load_local_ids(target_os: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Read local rules and return {os: {rule_id: rel_path}}.

    Skips files without a parseable `id` field and emits a warning.
    """
    result: dict[str, dict[str, str]] = {os_name: {} for os_name in target_os}
    for os_name in target_os:
        os_dir = SIGMA_DEST / os_name
        if not os_dir.is_dir():
            continue
        for path in sorted(os_dir.rglob("*.yml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                print(f"  Warning: could not parse {path.relative_to(REPO_ROOT)}")
                continue
            rule_id = str(doc.get("id", "")).strip()
            if not rule_id:
                print(f"  Warning: no id in {path.relative_to(REPO_ROOT)}")
                continue
            result[os_name][rule_id] = str(path.relative_to(REPO_ROOT))
    return result


def fetch_upstream_ids(target_os: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Download the upstream repo zip and return {os: {rule_id: upstream_path}}.

    Uses a single zip download instead of per-file requests. The zip is
    processed in memory; no files are written to disk.
    """
    print(f"Downloading upstream repo zip from {GITHUB_ZIP_URL} …")
    print("(This is a one-time download of the full repo — usually 30–80 MB.)")
    data = fetch_raw(GITHUB_ZIP_URL, token=None)
    print(f"Downloaded {len(data) / 1_048_576:.1f} MB. Parsing rules…")

    result: dict[str, dict[str, str]] = {os_name: {} for os_name in target_os}
    skipped_no_id = 0

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():
            if not member.endswith(".yml"):
                continue

            # Zip entries look like "sigma-master/rules/windows/proc_creation/foo.yml"
            # Find the "rules" segment regardless of the leading archive prefix.
            parts = member.split("/")
            try:
                rules_idx = parts.index(UPSTREAM_RULES_PREFIX)
            except ValueError:
                continue

            if rules_idx + 2 >= len(parts):
                continue

            os_name = parts[rules_idx + 1]
            if os_name not in target_os:
                continue

            try:
                content = zf.read(member).decode("utf-8", errors="replace")
                doc = yaml.safe_load(content) or {}
            except (yaml.YAMLError, Exception):
                continue

            rule_id = str(doc.get("id", "")).strip()
            if not rule_id:
                skipped_no_id += 1
                continue

            # Reconstruct the canonical upstream path: rules/{os}/...
            upstream_path = "/".join(parts[rules_idx:])
            result[os_name][rule_id] = upstream_path

    if skipped_no_id:
        print(f"  (skipped {skipped_no_id} upstream files with no id field)")

    return result


def show_diff(target_os: tuple[str, ...]) -> None:
    """Compare local rule IDs against upstream and report what is missing."""
    local = load_local_ids(target_os)
    upstream = fetch_upstream_ids(target_os)

    print()
    any_missing = False

    for os_name in target_os:
        local_ids = local[os_name]
        upstream_ids = upstream[os_name]

        missing = {
            rule_id: path
            for rule_id, path in upstream_ids.items()
            if rule_id not in local_ids
        }

        print(f"── {os_name} ────────────────────────────────────────────────")
        print(f"   local: {len(local_ids):>5} rules   upstream: {len(upstream_ids):>5} rules   missing: {len(missing):>5}")

        if missing:
            any_missing = True
            print()
            for rule_id, upstream_path in sorted(missing.items(), key=lambda kv: kv[1]):
                print(f"  MISSING  {rule_id}  ({upstream_path})")
        else:
            print("   All upstream rules are present locally.")
        print()

    if any_missing:
        print("Tip: run without --diff to download all missing rules.")
    else:
        print("Local rules are in sync with upstream for the selected OS targets.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download or diff Sigma rules from SigmaHQ/sigma into rules/sigma/."
    )
    parser.add_argument(
        "--os",
        nargs="+",
        choices=list(ALL_TARGET_OS),
        default=list(ALL_TARGET_OS),
        metavar="OS",
        help=f"Which OS rule sets to target (default: all). Choices: {', '.join(ALL_TARGET_OS)}",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token (default: $GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(download mode) Print what would be downloaded without writing files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="(download mode) Overwrite files that already exist locally",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help=(
            "Compare local rule IDs against upstream and report which rules are missing. "
            "Downloads the upstream repo as a single zip — no files are written."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target_os = tuple(args.os)

    if args.diff:
        show_diff(target_os)
        return

    if not args.token:
        print(
            "No GitHub token found. Unauthenticated requests are limited to 60/hour.\n"
            "Set GITHUB_TOKEN or pass --token to increase to 5 000/hour."
        )

    entries = get_rule_entries(args.token, target_os)
    print(f"Found {len(entries)} rules across: {', '.join(target_os)}\n")

    if not entries:
        print("Nothing to download.")
        return

    downloaded, skipped, total = download_rules(
        entries,
        token=args.token,
        dry_run=args.dry_run,
        force=args.force,
    )

    action = "would download" if args.dry_run else "downloaded"
    print(f"\nDone. {action} {downloaded}, skipped {skipped} (already exist), total {total}.")
    if args.dry_run:
        print("Re-run without --dry-run to write files.")


if __name__ == "__main__":
    main()
