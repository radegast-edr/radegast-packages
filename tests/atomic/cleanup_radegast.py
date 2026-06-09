"""
cleanup_radegast.py
===================
Uninstalls the Radegast agent from this machine and deregisters the device
from the Radegast API.

Prerequisites
-------------
- Python 3.7+
- RADEGAST_KEY environment variable must be set.
- install_radegast.py must have been run first — it writes .radegast_device_id
  next to this script, which contains the device ID needed to call the API.

Usage
-----
    python cleanup_radegast.py
"""

import os
import platform
import subprocess
import sys

try:
    import requests
except ImportError:
    print("Installing required dependency: requests...")
    subprocess.run(["uv", "add", "requests"], check=True)
    import requests


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICE_ID_FILE = os.path.join(SCRIPT_DIR, ".radegast_device_id")
API_BASE = "https://console-api.radegast.app/api/v1"


# ---------------------------------------------------------------------------
# 1. Read and validate the API key
# ---------------------------------------------------------------------------

api_key = os.environ.get("RADEGAST_KEY")
if not api_key:
    print(
        "Error: RADEGAST_KEY environment variable is not set.\n"
        "\n"
        "Windows (PowerShell):\n"
        '    $env:RADEGAST_KEY = "rg_..."\n'
        "    # or to persist: setx RADEGAST_KEY \"rg_...\"\n"
        "\n"
        "Linux / macOS:\n"
        '    export RADEGAST_KEY="rg_..."\n'
        "    # or add the line above to ~/.bashrc / ~/.zshrc for persistence"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# 2. Read the device ID written by install_radegast.py
# ---------------------------------------------------------------------------

if not os.path.exists(DEVICE_ID_FILE):
    print(
        f"Error: device ID file not found at {DEVICE_ID_FILE}.\n"
        "Run install_radegast.py first to install and register the device."
    )
    sys.exit(1)

with open(DEVICE_ID_FILE) as f:
    device_id = f.read().strip()

print(f"Found device ID: {device_id}")


# ---------------------------------------------------------------------------
# 3. Uninstall the Radegast agent from the host
# ---------------------------------------------------------------------------

current_os = platform.system()

if current_os == "Windows":
    print("Stopping and removing the Radegast service (Windows)...")
    subprocess.run(["sc", "stop", "radegast"], check=False)
    subprocess.run(["sc", "delete", "radegast"], check=False)
else:
    print("Stopping and removing the Radegast service (Linux)...")
    subprocess.run(["sudo", "systemctl", "stop", "radegast"], check=False)
    subprocess.run(["sudo", "systemctl", "disable", "radegast"], check=False)
    subprocess.run(["sudo", "rm", "-f", "/etc/systemd/system/radegast.service"], check=False)
    subprocess.run(["sudo", "systemctl", "daemon-reload"], check=False)


# ---------------------------------------------------------------------------
# 4. Deregister the device from the Radegast API
# ---------------------------------------------------------------------------

print(f"Deleting device {device_id} from Radegast API...")
response = requests.delete(
    f"{API_BASE}/devices/{device_id}",
    headers={
        "accept": "application/json",
        "X-API-Key": api_key,
        "Authorization": api_key,
    },
)
response.raise_for_status()
print(f"Device {device_id} deleted successfully.")


# ---------------------------------------------------------------------------
# 5. Remove the saved device ID file
# ---------------------------------------------------------------------------

os.remove(DEVICE_ID_FILE)
print(f"Removed {DEVICE_ID_FILE}.")
