"""
install_radegast.py
===================
Registers this machine as a Radegast device and runs the platform-specific
install script delivered by the Radegast API.

Prerequisites
-------------
- Python 3.7+
- The environment variable RADEGAST_KEY must be set to your Radegast API key
  before running this script.

  Setting RADEGAST_KEY
  ~~~~~~~~~~~~~~~~~~~~
  Windows (PowerShell — current session only):
      $env:RADEGAST_KEY = "rg_..."

  Windows (persist across sessions):
      setx RADEGAST_KEY "rg_..."
      # Open a new terminal after running setx for the value to take effect.

  Linux / macOS (current session only):
      export RADEGAST_KEY="rg_..."

  Linux / macOS (persist across sessions — add to shell profile):
      echo 'export RADEGAST_KEY="rg_..."' >> ~/.bashrc   # bash
      echo 'export RADEGAST_KEY="rg_..."' >> ~/.zshrc    # zsh
      source ~/.bashrc   # reload without restarting the terminal

  Note: Python's os.environ reads the process environment on both Windows and
  Linux, so the same script works unchanged on either platform.

Usage
-----
    python install_radegast.py

What this script does
---------------------
1. Reads RADEGAST_KEY from the environment and exits with a clear error if it
   is missing.
2. Calls the Radegast API to register this device and obtain a RADEGAST_TOKEN.
3. Persists RADEGAST_TOKEN for the current user:
     - Windows: via setx
     - Linux/macOS: appended to ~/.bashrc if not already present
4. Downloads the platform-specific install script from the Radegast API and
   executes it (a .bat file on Windows, a shell script via sudo on Linux).
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


# ---------------------------------------------------------------------------
# 1. Read and validate the API key from the environment
#    os.environ.get() works identically on Windows and Linux/macOS.
#    On Windows, environment variable names are case-insensitive, but using
#    the exact name "RADEGAST_KEY" ensures compatibility on all platforms.
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
# 2. Register this device and obtain the device token
# ---------------------------------------------------------------------------

print("Registering device with Radegast API...")
response = requests.post(
    "https://console-api.radegast.app/api/v1/devices/",
    headers={
        "accept": "application/json",
        "X-API-Key": api_key,
        "Authorization": api_key,
        "Content-Type": "application/json",
    },
    json={
        "name": "string",
        "group_id": 10,
    },
)
response.raise_for_status()

device = response.json()
print(f"Device registered: {device}")

radegast_token = device["token"]
print(f"RADEGAST_TOKEN: {radegast_token}")


# ---------------------------------------------------------------------------
# 3. Persist RADEGAST_TOKEN and run the platform-specific install script
# ---------------------------------------------------------------------------

current_os = platform.system()

if current_os == "Windows":
    # Persist the token for the current user across sessions
    subprocess.run(["setx", "RADEGAST_TOKEN", radegast_token], check=True)
    os.environ["RADEGAST_TOKEN"] = radegast_token

    print("Fetching Windows install script...")
    install_response = requests.get(
        "https://console-api.radegast.app/api/v1/device/install",
        params={"os": "windows"},
        headers={"accept": "application/json"},
    )
    install_response.raise_for_status()
    install_script = install_response.text

    bat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "radegast_install.bat")
    with open(bat_path, "w") as f:
        f.write(install_script)
    print(f"Install script saved to {bat_path}")
    print("Running Windows install script...")
    subprocess.run([bat_path], check=True)

else:
    print("Fetching Linux install script...")
    install_response = requests.get(
        "https://console-api.radegast.app/api/v1/device/install",
        params={"os": "linux"},
        headers={"accept": "application/json"},
    )
    install_response.raise_for_status()
    install_script = install_response.text

    # Persist the token for the current user across sessions
    shell_rc = os.path.expanduser("~/.bashrc")
    export_line = f'\nexport RADEGAST_TOKEN="{radegast_token}"\n'
    with open(shell_rc, "r") as f:
        contents = f.read()
    if "RADEGAST_TOKEN" not in contents:
        with open(shell_rc, "a") as f:
            f.write(export_line)
        print(f"RADEGAST_TOKEN written to {shell_rc} — restart your shell or run: source ~/.bashrc")

    print("Running Linux install script...")
    subprocess.run(
        ["sudo", f"RADEGAST_TOKEN={radegast_token}", "sh"],
        input=install_script,
        text=True,
        check=True,
    )
