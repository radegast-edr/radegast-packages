# radegast-packages

Detection packs for the [Radegast EDR](https://console.radegast.app) platform. Each pack bundles [Sigma](https://github.com/SigmaHQ/sigma) rules, YARA rules, and IOC (hash) lists for a specific OS and detection coverage level.

## Pack structure

Packs live under `packs/<os>/<level>/` and are defined by a `pack.yml` manifest:

```
packs/
  windows/
    essential/   # low-noise, high-confidence defaults
    advanced/    # extends essential, broader coverage
    hunting/     # extends advanced, higher FP tolerance
  linux/
    essential/
    advanced/
  macos/
    essential/
    advanced/
```

Each pack directory may contain:

| Subfolder | Content |
|-----------|---------|
| `sigma/`  | Sigma rule `.yml` files |
| `yara/`   | YARA rule `.yar` / `.yara` files |
| `ioc/`    | IOC hash lists as `.txt` files |

## Levels

| Level | Extends | False positive tolerance |
|-------|---------|--------------------------|
| `essential` | — | Low |
| `advanced`  | `<os>-essential` | Medium |
| `hunting`   | `<os>-advanced`  | High |

## Tools

All tools are in `tools/` and require Python 3.11+.

### `download_sigma.py` — fetch upstream rules

Downloads Sigma rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) into `rules/sigma/`.

```sh
python tools/download_sigma.py                        # download all OS targets
python tools/download_sigma.py --os windows linux     # specific OS(es)
python tools/download_sigma.py --diff                 # report missing rules vs upstream
python tools/download_sigma.py --force                # overwrite existing files
python tools/download_sigma.py --token ghp_...        # use a GitHub token (avoids rate limits)
```

Set `GITHUB_TOKEN` to avoid the 60 req/h unauthenticated rate limit.

### `populate_pack.py` — filter and sync sigma rules into a pack

Copies Sigma rules from `rules/sigma/<os>/` into a pack's `sigma/` folder based on filter criteria (level, MITRE tactic, description substring, or tag). Use `--sync` to make the pack match the criteria exactly — any rule already in the pack that does not satisfy the filters is removed.

```sh
python tools/populate_pack.py --os windows --level high critical --pack essential
python tools/populate_pack.py --os windows --level high critical --tactic execution persistence --pack essential
python tools/populate_pack.py --os windows --level high critical --tactic execution --pack essential --dry-run
python tools/populate_pack.py --os windows --level high critical --tactic execution --pack essential --sync
```

`--sync` is the key flag for a clean workflow: it ensures the pack on disk contains **only** the rules that match your current criteria, so the output of `build_packs.py` stays consistent.

### `build_packs.py` — rebuild pack manifests

Scans each pack's `sigma/`, `ioc/`, and `yara/` subdirectories and rewrites `pack.yml` with the rules found on disk. Preserves all existing metadata and computes `rules.excludes` from the global rules pool.

```sh
python tools/build_packs.py                           # interactive menu
python tools/build_packs.py --pack windows/hunting    # one pack
python tools/build_packs.py --all                     # every pack
python tools/build_packs.py --all --dry-run           # preview only
```

### `zip_pack.py` — create distributable archives

Reads `rules.has` from `pack.yml`, collects the referenced rule files, and writes a `.zip` next to the manifest.

```sh
python tools/zip_pack.py                              # interactive menu
python tools/zip_pack.py --pack windows/essential     # one pack
python tools/zip_pack.py --all                        # every pack
```

### `upload_radegast.py` — publish packs to Radegast EDR

Uploads built pack zips to the Radegast API. Creates the pack if it doesn't exist; uploads a new version only when the version string has changed.

```sh
RADEGAST_API_KEY=<key> python tools/upload_radegast.py
```

`RADEGAST_URL` defaults to `https://console.radegast.app`.

### `search_sigma.py` — search local Sigma rules

```sh
python tools/search_sigma.py --description "lateral movement"
python tools/search_sigma.py --description "WMI" --os windows
python tools/search_sigma.py --description "persistence" --show-path
```

### `link_packs.py` — migrate and symlink rules

Converts packs from the legacy list format to the current `rules.has` dict format, and creates relative symlinks from each pack directory into the shared `rules/` pool.

```sh
python tools/link_packs.py
```

## Typical workflow

```sh
# 1. Pull latest Sigma rules from upstream
python tools/download_sigma.py

# 2. Add/edit sigma, yara, or ioc files under packs/<os>/<level>/

# 3. Rebuild the pack.yml manifest
python tools/build_packs.py --pack windows/essential

# 4. Create the zip archive
python tools/zip_pack.py --pack windows/essential

# 5. Upload to Radegast
RADEGAST_API_KEY=<key> python tools/upload_radegast.py
```

## License

Packs are distributed under the [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License) license.
