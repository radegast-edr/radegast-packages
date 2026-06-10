import os
import sys
import base64
import platform
import urllib.request
import zipfile
import subprocess
import shutil
import time
from pathlib import Path


def run_cmd(cmd, check=True, show_output=False):
    """Helper to run shell commands. Shows output if explicitly requested."""
    stdout_dest = None if show_output else subprocess.DEVNULL
    stderr_dest = None if show_output else subprocess.DEVNULL
    try:
        subprocess.run(cmd, check=check, stdout=stdout_dest, stderr=stderr_dest)
    except subprocess.CalledProcessError as e:
        print(f"WARNING/ERROR executing {' '.join(cmd)}: {e}")


def main():
    print("=== Starting Radegast EDR Agent & Rustinel Windows Installation ===")

    # Check for administrative privileges and elevate if needed
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False

    if not is_admin:
        print("Requesting administrative privileges...")
        try:
            params = " ".join([f'"{arg}"' for arg in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}" {params}', None, 1)
            if ret > 32:
                sys.exit(0)
        except Exception as e:
            print(f"ERROR: Failed to elevate privileges: {e}", file=sys.stderr)
        sys.exit(1)

    # 0. Check RADEGAST_TOKEN environment variable
    token = os.environ.get("RADEGAST_TOKEN")
    if not token:
        print("ERROR: RADEGAST_TOKEN environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    # Base directory setup
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    radegast_dir = Path(program_files) / "Radegast"
    tools_dir = radegast_dir / ".tools"

    # New Agent Layout Subdirectories
    agent_dir = radegast_dir / "agent"
    agent_home_dir = agent_dir / "home"
    agent_service_dir = agent_dir / "service"
    rules_dir = agent_dir / "rules"
    ioc_dir = rules_dir / "ioc"
    logs_dir = agent_dir / "logs"
    state_dir = agent_dir / "state"
    cache_dir = agent_dir / ".cache"

    # New Rustinel Layout Subdirectories
    rustinel_dir = radegast_dir / "rustinel"
    rustinel_core_dir = rustinel_dir / "rustinel"
    rustinel_service_dir = rustinel_dir / "service"

    # Executable Target Paths
    python_exe_path = Path(sys.executable)
    python_dir = python_exe_path.parent
    rustinel_service_exe = rustinel_service_dir / "radegast-rustinel-service.exe"
    agent_service_exe = agent_service_dir / "radegast-agent-service.exe"

    # 1. Pre-Installation Cleanup (Unlock Files)
    print("Checking for existing services to stop and unlock files...")
    if rustinel_service_exe.exists():
        run_cmd([str(rustinel_service_exe), "stop"], check=False)
        run_cmd([str(rustinel_service_exe), "uninstall"], check=False)
    else:
        run_cmd(["net", "stop", "RadegastRustinel"], check=False)

    if agent_service_exe.exists():
        run_cmd([str(agent_service_exe), "stop"], check=False)
        run_cmd([str(agent_service_exe), "uninstall"], check=False)
    else:
        run_cmd(["net", "stop", "RadegastAgent"], check=False)

    run_cmd(["taskkill", "/f", "/im", "rustinel.exe"], check=False)
    run_cmd(["taskkill", "/f", "/im", "radegast-agent.exe"], check=False)
    time.sleep(2)

    # 2. Setup Directories
    print(f"Creating specialized application directory trees under {radegast_dir}...")
    dirs_to_create = [
        radegast_dir, tools_dir,
        agent_dir, agent_service_dir, rules_dir, ioc_dir, logs_dir, state_dir, cache_dir, agent_home_dir,
        rustinel_dir, rustinel_core_dir, rustinel_service_dir
    ]
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)

    for filename in ["hashes.txt", "ips.txt", "domains.txt", "paths_regex.txt"]:
        file_path = ioc_dir / filename
        if not file_path.exists():
            file_path.write_text("", encoding="utf-8")

    # 3. Get architecture and download rustinel
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        arch = "amd64"
        winsw_url = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
        winsw_url = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-arm64.exe"
    else:
        print(f"ERROR: Unsupported architecture: {machine}", file=sys.stderr)
        sys.exit(1)

    backend_url = "https://console-api.radegast.app"
    download_url = f"{backend_url}/api/v1/device/agent/download?os=windows&arch={arch}"
    zip_path = rustinel_core_dir / "rustinel.zip"

    print("Downloading rustinel...")
    try:
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        import ssl
        ssl_context = ssl._create_unverified_context() if hasattr(ssl, '_create_unverified_context') else None
        with urllib.request.urlopen(req, context=ssl_context) as response, open(zip_path, 'wb') as out_file:
            out_file.write(response.read())

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(rustinel_core_dir)
        if zip_path.exists():
            zip_path.unlink()
    except Exception as e:
        print(f"ERROR: Failed to download/extract rustinel: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Write configuration file config.toml
    config_b64 = "IyBSdXN0aW5lbCBDb25maWd1cmF0aW9uIEZpbGUgZm9yIFdpbmRvd3MKIyBUaGlzIGZpbGUgaXMgb3B0aW9uYWwgLSB0aGUgYWdlbnQgd2lsbCB1c2UgZGVmYXVsdHMgaWYgbm90IHByZXNlbnQKCiMgMS4gRmVhdHVyZSBUb2dnbGVzICYgUnVsZXMKW3NjYW5uZXJdCnNpZ21hX2VuYWJsZWQgPSB0cnVlCnNpZ21hX3J1bGVzX3BhdGggPSAiQzpcXFByb2dyYW0gRmlsZXNcXFJhZGVnYXN0XFxhZ2VudFxccnVsZXNcXHNpZ21hIgp5YXJhX2VuYWJsZWQgPSB0cnVlCnlhcmFfcnVsZXNfcGF0aCA9ICJDOlxcUHJvZ3JhbSBGaWxlc1xcUmFkZWdhc3RcXGFnZW50XFxydWxlc1xceWFyYSIKCltyZWxvYWRdCmVuYWJsZWQgPSB0cnVlCmRlYm91bmNlX21zID0gMjAwMCAgICAgICAgICAjIHBvbGwgY2FkZW5jZSBpcyBtYXgoZGVib3VuY2VfbXMsIDIwMDApCgojIFNoYXJlZCBhbGxvd2xpc3QgYXBwbGllZCB0bzoKIyAtIHJlc3BvbnNlLmFsbG93bGlzdF9wYXRocwojIC0gaW9jLmhhc2hfYWxsb3dsaXN0X3BhdGhzCiMgLSBzY2FubmVyLnlhcmFfYWxsb3dsaXN0X3BhdGhzCiMKIyBQbGF0Zm9ybSBkZWZhdWx0cyBhcmUgY29tcGlsZWQgaW4g4oCUIG9ubHkgc2V0IHRoaXMgdG8gb3ZlcnJpZGUgdGhlbS4KIwojIFdpbmRvd3MgZGVmYXVsdHM6CiMgICBDOlxXaW5kb3dzXCwgQzpcUHJvZ3JhbSBGaWxlc1wsIEM6XFByb2dyYW0gRmlsZXMgKHg4NilcCgojIDIuIE9wZXJhdGlvbmFsIExvZ2dpbmcgKFRoZSBBZ2VudCdzIGludGVybmFsIGhlYWx0aCkKIyAgICBXcml0ZXMgdG86IHtkaXJlY3Rvcnl9L3tmaWxlbmFtZX0uPGRhdGU+Cltsb2dnaW5nXQpsZXZlbCA9ICJpbmZvIiAgICAgICAgICAgICAgIyB0cmFjZSwgZGVidWcsIGluZm8sIHdhcm4sIGVycm9yCmRpcmVjdG9yeSA9ICJsb2dzIgpmaWxlbmFtZSA9ICJDOlxcUHJvZ3JhbSBGaWxlc1xcUmFkZWdhc3RcXGFnZW50XFxsb2dzXFxydXN0aW5lbC5sb2ciCmNvbnNvbGVfb3V0cHV0ID0gdHJ1ZSAgICAgICAjIElmIHRydWUsIGR1cGxpY2F0ZSBsb2dzIHRvIHN0ZG91dCAoZGV2IG1vZGUpCgojIDMuIFNlY3VyaXR5IEFsZXJ0cyAoVGhlIERldGVjdGlvbiBPdXRwdXQpCiMgICAgV3JpdGVzIHRvOiB7ZGlyZWN0b3J5fS97ZmlsZW5hbWV9LjxkYXRlPgpbYWxlcnRzXQpkaXJlY3RvcnkgPSAibG9ncyIKZmlsZW5hbWUgPSAiQzpcXFByb2dyYW0gRmlsZXNcXFJhZGVnYXN0XFxhZ2VudFxcbG9nc1xcYWxlcnRzLmpzb24iICAgICMgV2lsbCBjb250YWluIG5ld2xpbmUtZGVsaW1pdGVkIEpTT04gKE5ESlNPTikKbWF0Y2hfZGVidWcgPSAib2ZmIiAgICAgICAgICMgb2ZmIHwgc3VtbWFyeSB8IGZ1bGwgKGF0dGFjaCBtYXRjaCBkZXRhaWxzIHRvIGFsZXJ0cy5qc29uKQoKIyA0LiBBY3RpdmUgUmVzcG9uc2UgKE9wdGlvbmFsIFByZXZlbnRpb24pCltyZXNwb25zZV0KZW5hYmxlZCA9IGZhbHNlCnByZXZlbnRpb25fZW5hYmxlZCA9IGZhbHNlCm1pbl9zZXZlcml0eSA9ICJjcml0aWNhbCIgICAjIHNpZ21hOiBjcml0aWNhbCBvbmx5OyB5YXJhIGFsd2F5cyB0cmVhdGVkIGFzIGNyaXRpY2FsCmNoYW5uZWxfY2FwYWNpdHkgPSAxMjgKCiMgNS4gQXRvbWljIElPQyBEZXRlY3Rpb24gKEhhc2hlcywgSVBzLCBEb21haW5zLCBQYXRoIFJlZ2V4KQpbaW9jXQplbmFibGVkID0gdHJ1ZQpoYXNoZXNfcGF0aCA9ICJDOlxcUHJvZ3JhbSBGaWxlc1xcUmFkZWdhc3RcXGFnZW50XFxydWxlc1xcaW9jXFxoYXNoZXMudHh0IgppcHNfcGF0aCA9ICJDOlxcUHJvZ3JhbSBGaWxlc1xcUmFkZWdhc3RcXGFnZW50XFxydWxlc1xcaW9jXFxpcHMudHh0Igpkb21haW5zX3BhdGggPSAiQzpcXFByb2dyYW0gRmlsZXNcXFJhZGVnYXN0XFxhZ2VudFxccnVsZXNcXGlvY1xcZG9tYWlucy50eHQiCnBhdGhzX3JlZ2V4X3BhdGggPSAiQzpcXFByb2dyYW0gRmlsZXNcXFJhZGVnYXN0XFxhZ2VudFxccnVsZXNcXGlvY1xccGF0aHNfcmVnZXgudHh0IgpkZWZhdWx0X3NldmVyaXR5ID0gImhpZ2giCm1heF9maWxlX3NpemVfbWIgPSA1MA=="
    config_content = base64.b64decode(config_b64.encode("utf-8")).decode("utf-8")
    (rustinel_core_dir / "config.toml").write_text(config_content, encoding="utf-8")

    # 5. Install radegast-agent-python
    uv_exe = "C:/Users/lulvatar/.local/bin/uv.exe"
    agent_pyproject = agent_home_dir / "pyproject.toml"
    if agent_pyproject.exists():
        agent_pyproject.unlink()
    subprocess.run(
        [str(uv_exe), "init",  ".", "--python", python_exe_path],
        check=True,
        cwd=agent_home_dir
    )

    # 6. Download WinSW and Setup Service XMLs
    print("Downloading WinSW Wrapper...")
    winsw_bin = tools_dir / "winsw.exe"
    try:
        req = urllib.request.Request(winsw_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ssl_context) as response, open(winsw_bin, 'wb') as out_file:
            out_file.write(response.read())
    except Exception as e:
        print(f"ERROR: Failed to download WinSW: {e}", file=sys.stderr)
        sys.exit(1)

    shutil.copy(winsw_bin, rustinel_service_exe)
    shutil.copy(winsw_bin, agent_service_exe)

    # 7. Setup service XMLs
    rustinel_xml = f"""<service>
      <id>RadegastRustinel</id>
      <name>Radegast Rustinel Sensor</name>
      <description>Low-level sensor for the Radegast EDR.</description>
      <executable>{rustinel_core_dir}\\rustinel.exe</executable>
      <arguments>run</arguments>
      <workingdirectory>{rustinel_core_dir}</workingdirectory>
      <log mode="roll" logpath="{logs_dir}" />
      <onfailure action="restart" delay="5000" />
      <stopparentfirst>true</stopparentfirst>
      <serviceaccount>
        <domain>NT AUTHORITY</domain>
        <user>SYSTEM</user>
      </serviceaccount>
    </service>"""
    (rustinel_service_dir / "radegast-rustinel-service.xml").write_text(rustinel_xml, encoding="utf-8")

    agent_xml = f"""<service>
      <id>RadegastAgent</id>
      <name>Radegast EDR Agent</name>
      <description>Management agent for Radegast EDR communications.</description>
      <executable>{uv_exe}</executable>
      <arguments>run --with radegast-edr-agent --python "{python_exe_path}" radegast-edr-agent</arguments>
      <workingdirectory>{agent_home_dir}</workingdirectory>
      <env name="PYTHONUNBUFFERED" value="1" />
      <env name="RADEGAST_AGENT_BACKEND_URL" value="{backend_url}/api/v1" />
      <env name="RADEGAST_AGENT_DEVICE_TOKEN" value="{token}" />
      <env name="RADEGAST_AGENT_RUSTINEL_BINARY" value="{rustinel_core_dir}\\rustinel.exe" />
      <env name="RADEGAST_AGENT_RULES_DIR" value="{rules_dir}\\" />
      <env name="RADEGAST_AGENT_ALERTS_DIR" value="{logs_dir}\\" />
      <env name="RADEGAST_AGENT_STATE_DIR" value="{state_dir}\\" />
      <onfailure action="restart" delay="5000" />
      <stopparentfirst>true</stopparentfirst>
      <log mode="roll" logpath="{logs_dir}" />
      <serviceaccount>
        <domain>NT AUTHORITY</domain>
        <user>SYSTEM</user>
      </serviceaccount>
    </service>"""
    (agent_service_dir / "radegast-agent-service.xml").write_text(agent_xml, encoding="utf-8")

    # 8. Install Services FIRST
    print("Registering Windows Services...")
    subprocess.run([str(rustinel_service_exe), "install"], check=True)
    subprocess.run([str(agent_service_exe), "install"], check=True)

    print("Waiting for Service Manager to register identities...")
    time.sleep(3)

    # 9. Unblock Files
    print("Clearing Mark of the Web attributes from all files...")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"Get-ChildItem -Path '{radegast_dir}' -Recurse | Unblock-File"], check=True)

    # 10. Apply Strict NTFS ACLs via icacls
    print("Securing directories with strict layout isolation...")
    vsa_account = r"NT SERVICE\RadegastAgent"

    # A. Lock root directory exclusively to Administrators and SYSTEM
    run_cmd(["icacls", str(radegast_dir), "/inheritance:r", "/grant:r", "Administrators:(OI)(CI)F", "/grant:r",
             "SYSTEM:(OI)(CI)F"], show_output=True)

    # B.Grant the VSA traverse/read rights to the root folder ONLY (No inheritance)
    # Leaving out (OI)(CI) means this rule applies ONLY to the Radegast folder itself.
    # This allows the agent to resolve paths like \Radegast\rustinel\... without being blocked at the root.
    run_cmd(["icacls", str(radegast_dir), "/grant:r", f"{vsa_account}:RX"], show_output=True)

    # C. Grant Full Control exclusively to the requested Agent directory ecosystem
    run_cmd(["icacls", str(agent_dir), "/grant:r", f"{vsa_account}:(OI)(CI)F", "/T", "/Q"], show_output=True)

    # D. Grant Read & Execute (RX) to the Rustinel folder tree AND force it recursively (/T)
    # The /T flag ensures that the *already extracted* rustinel.exe binary instantly receives the RX permission.
    run_cmd(["icacls", str(rustinel_dir), "/grant:r", f"{vsa_account}:(OI)(CI)RX", "/T", "/Q"], show_output=True)

    # Secure global Python directory context to Read & Execute only for the VSA account
    if python_dir.exists():
        run_cmd(["icacls", str(python_dir), "/reset", "/T", "/Q"], show_output=True)
        run_cmd(["icacls", str(python_dir), "/grant:r", f"{vsa_account}:(OI)(CI)RX", "/T", "/Q"], show_output=True)

    # 11. Create Uninstaller Script
    uninstall_bat = radegast_dir / "uninstall.bat"
    uninstall_content = (
        "@echo off\r\n"
        "net session >nul 2>&1\r\n"
        "if errorlevel 1 (\r\n"
        "    echo Requesting administrative privileges...\r\n"
        "    powershell -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"\r\n"
        "    exit /b 0\r\n"
        ")\r\n"
        "echo WARNING: The signing key cannot be changed and must be backed-up manually if moving to another device.\r\n"
        "set /p \"confirm=Have you backed-up your device signing key manually? (y/n): \"\r\n"
        "if /i \"%confirm%\" neq \"y\" exit /b 1\r\n"
        "echo === Uninstalling Radegast Services ===\r\n"
        f"\"{agent_service_exe}\" stop >nul 2>&1\r\n"
        f"\"{rustinel_service_exe}\" stop >nul 2>&1\r\n"
        f"\"{agent_service_exe}\" uninstall >nul 2>&1\r\n"
        f"\"{rustinel_service_exe}\" uninstall >nul 2>&1\r\n"
        "taskkill /f /im rustinel.exe >nul 2>&1\r\n"
        "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Radegast /f >nul 2>&1\r\n"
        "echo === Removing Files ===\r\n"
        f"start /b \"\" cmd /c \"timeout /t 3 >nul & rmdir /s /q \"{radegast_dir}\" >nul 2>&1\"\r\n"
    )
    uninstall_bat.write_text(uninstall_content, encoding="utf-8")

    # 12. Start Services
    print("Starting Windows Services...")
    try:
        subprocess.run([str(rustinel_service_exe), "start"], check=True)
        subprocess.run([str(agent_service_exe), "start"], check=True)
        print("Services started successfully.")
    except Exception as e:
        print(f"ERROR: Failed to start services: {e}", file=sys.stderr)
        sys.exit(1)

    print("=== Radegast agent & rustinel Windows setup completed successfully ===")


if __name__ == "__main__":
    main()
