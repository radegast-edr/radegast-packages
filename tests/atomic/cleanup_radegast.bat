@echo off
@title radegast_cleanup
echo radegast_cleanup
echo ================================
echo.
set PYTHON_VERSION=3.14
set APP_DIR=%LOCALAPPDATA%\winpython-oneclick
set PYTHON_DIR=%APP_DIR%\python
set PYTHON_EXE=%PYTHON_DIR%\python.exe
set PYTHONW_EXE=%PYTHON_DIR%\pythonw.exe
set SCRIPTS_DIR=%PYTHON_DIR%\Scripts
set PYTHON_ZIP=%TEMP%\winpython_3_13.zip
set INSTALL_SCRIPT=%TEMP%\install_inline.py
set INSTALL_B64=%TEMP%\install_inline.b64
echo.

if exist "%PYTHON_EXE%" (
    echo Python already installed at %PYTHON_DIR%
    goto :install_uv
)

echo.
echo Downloading portable Python...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://cdn.adamhlavacek.com/winpython_3_13.zip' -OutFile $env:PYTHON_ZIP"
if errorlevel 1 (
    echo ERROR: Failed to download Python
    PAUSE
    exit /b 1
)
echo Download complete.
echo.
echo Extracting Python to %APP_DIR%...
if not exist "%APP_DIR%" mkdir "%APP_DIR%"
powershell -Command "Expand-Archive -Path $env:PYTHON_ZIP -DestinationPath $env:APP_DIR -Force"
if errorlevel 1 (
    echo ERROR: Failed to extract Python
    PAUSE
    exit /b 1
)
del "%PYTHON_ZIP%"
echo Python extracted successfully.
echo.
if not exist "%PYTHON_EXE%" (
    echo ERROR: Python executable not found at %PYTHON_EXE%
    PAUSE
    exit /b 1
)
echo.

:install_uv
echo Checking for uv...
set "UV_EXE=%SCRIPTS_DIR%\uv.exe"

rem 1. Install uv via pip if not found
if not exist "%UV_EXE%" (
    echo Installing uv via pip...
    "%PYTHON_EXE%" -m pip install uv
    if errorlevel 1 (
        echo ERROR: Failed to install uv
        PAUSE
        exit /b 1
    )
) else (
    echo uv is already installed.
)

rem 2. Add to Current Process PATH (So we can use it immediately below)
echo.
echo Configuring environment variables...
set "PATH=%SCRIPTS_DIR%;%PATH%"

rem 3. Add to Persistent User PATH (Safely using PowerShell to avoid duplicates)
powershell -Command "$targetPath = '%SCRIPTS_DIR%'; $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($currentPath -notlike '*' + $targetPath + '*') { [Environment]::SetEnvironmentVariable('Path', $currentPath + ';' + $targetPath, 'User'); Write-Host 'Added to User PATH.' } else { Write-Host 'Already in User PATH.' }"

:install_app
echo.
echo Writing installation script...
if exist "%INSTALL_B64%" del "%INSTALL_B64%"
if exist "%INSTALL_SCRIPT%" del "%INSTALL_SCRIPT%"
set SB=%INSTALL_B64%
set SO=%INSTALL_SCRIPT%
echo|set /p="IiIiCmNsZWFudXBfcmFkZWdhc3QucHkKPT09PT09PT09PT09PT09PT09PQpVbmluc3RhbGxzIHRoZSBSYWRlZ2FzdCBhZ2VudCBmcm9tIHRoaXMgbWFjaGluZSBhbmQgZGVyZWdpc3RlcnMgdGhlIGRldmljZQpmcm9tIHRoZSBSYWRlZ2FzdCBBUEkuCgpQcmVyZXF1aXNpdGVzCi0tLS0tLS0tLS0tLS0KLSBQeXRob24gMy43KwotIFJBREVHQVNUX0tFWSBlbnZpcm9ubWVudCB2YXJpYWJsZSBtdXN0IGJlIHNldC4KLSBpbnN0YWxsX3JhZGVnYXN0LnB5IG11c3QgaGF2ZSBiZWVuIHJ1biBmaXJzdCDigJQgaXQgd3JpdGVzIC5yYWRlZ2FzdF9kZXZpY2VfaWQKICBuZXh0IHRvIHRoaXMgc2NyaXB0LCB3aGljaCBjb250YWlucyB0aGUgZGV2aWNlIElEIG5lZWRlZCB0byBjYWxsIHRoZSBBUEkuCgpVc2FnZQotLS0tLQogICAgcHl0aG9uIGNsZWFudXBfcmFkZWdhc3QucHkKIiIiCgppbXBvcnQgb3MKaW1wb3J0IHBsYXRmb3JtCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCBzeXMKCnRyeToKICAgIGltcG9ydCByZXF1ZXN0cwpleGNlcHQgSW1wb3J0RXJyb3I6CiAgICBwcmludCgiSW5zdGFsbGluZyByZXF1aXJlZCBkZXBlbmRlbmN5OiByZXF1ZXN0cy4uLiIpCiAgICBzdWJwcm9jZXNzLnJ1bihbInV2IiwgImFkZCIsICJyZXF1ZXN0cyJdLCBjaGVjaz1UcnVlKQogICAgaW1wb3J0IHJlcXVlc3RzCgoKU0NSSVBUX0RJUiA9IG9zLnBhdGguZGlybmFtZShvcy5wYXRoLmFic3BhdGgoX19maWxlX18pKQpERVZJQ0VfSURfRklMRSA9IG9zLnBhdGguam9pbihTQ1JJUFRfRElSLCAiLnJhZGVnYXN0X2RldmljZV9pZCIpCkFQSV9CQVNFID0gImh0dHBzOi8vY29uc29sZS1hcGkucmFkZWdhc3QuYXBwL2FwaS92MSIKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDEuIFJlYWQgYW5kIHZhbGlkYXRlIHRoZSBBUEkga2V5CiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgphcGlfa2V5ID0gb3MuZW52aXJvbi5nZXQoIlJBREVHQVNUX0tFWSIpCmlmIG5vdCBhcGlfa2V5OgogICAgcHJpbnQoCiAgICAgICAgIkVycm9yOiBSQURFR0FTVF9LRVkgZW52aXJvbm1lbnQgdmFyaWFibGUgaXMgbm90IHNldC5cbiIKICAgICAgICAiXG4iCiAgICAgICAgIldpbmRvd3MgKFBvd2VyU2hlbGwpOlxuIgogICAgICAgICcgICAgJGVudjpSQURFR0FTVF9LRVkgPSAicmdfLi4uIlxuJwogICAgICAgICIgICAgIyBvciB0byBwZXJzaXN0OiBzZXR4IFJBREVHQVNUX0tFWSBcInJnXy4uLlwiXG4iCiAgICAgICAgIlxuIgogICAgICAgICJMaW51eCAvIG1hY09TOlxuIgogICAgICAgICcgICAgZXhwb3J0IFJBREVHQVNUX0tFWT0icmdfLi4uIlxuJwogICAgICAgICIgICAgIyBvciBhZGQgdGhlIGxpbmUgYWJvdmUgdG8gfi8uYmFzaHJjIC8gfi8uenNocmMgZm9yIHBlcnNpc3RlbmNlIgogICAgKQogICAgc3lzLmV4aXQoMSkKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDIuIFJlYWQgdGhlIGRldmljZSBJRCB3cml0dGVuIGJ5IGluc3RhbGxfcmFkZWdhc3QucHkKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmlmIG5vdCBvcy5wYXRoLmV4aXN0cyhERVZJQ0VfSURfRklMRSk6CiAgICBwcmludCgKICAgICAgICBmIkVycm9yOiBkZXZpY2UgSUQgZmlsZSBub3QgZm91bmQgYXQge0RFVklDRV9JRF9GSUxFfS5cbiIKICAgICAgICAiUnVuIGluc3RhbGxfcmFkZWdhc3QucHkgZmlyc3QgdG8gaW5zdGFsbCBhbmQgcmVnaXN0ZXIgdGhlIGRldmljZS4iCiAgICApCiAgICBzeXMuZXhpdCgxKQoKd2l0aCBvcGVuKERFVklDRV9JRF9GSUxFKSBhcyBmOgogICAgZGV2aWNlX2lkID0gZi5yZWFkKCkuc3RyaXAoKQoKcHJpbnQoZiJGb3VuZCBkZXZpY2UgSUQ6IHtkZXZpY2VfaWR9IikKCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQojIDMuIFVuaW5zdGFsbCB0aGUgUmFkZWdhc3QgYWdlbnQgZnJvbSB0aGUgaG9zdAojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKY3VycmVudF9vcyA9IHBsYXRmb3JtLnN5c3RlbSgpCgppZiBjdXJyZW50X29zID09ICJXaW5kb3dzIjoKICAgIHByaW50KCJTdG9wcGluZyBhbmQgcmVtb3ZpbmcgdGhlIFJhZGVnYXN0IHNlcnZpY2UgKFdpbmRvd3MpLi4uIikKICAgIHN1YnByb2Nlc3MucnVuKFsic2MiLCAic3RvcCIsICJyYWRlZ2FzdCJdLCBjaGVjaz1GYWxzZSkKICAgIHN1YnByb2Nlc3MucnVuKFsic2MiLCAiZGVsZXRlIiwgInJhZGVnYXN0Il0sIGNoZWNrPUZhbHNlKQplbHNlOgogICAgcHJpbnQoIlN0b3BwaW5nIGFuZCByZW1vdmluZyB0aGUgUmFkZWdhc3Qgc2VydmljZSAoTGludXgpLi4uIikKICAgIHN1YnByb2Nlc3MucnVuKFsic3VkbyIsICJzeXN0ZW1jdGwiLCAic3RvcCIsICJyYWRlZ2FzdCJdLCBjaGVjaz1GYWxzZSkKICAgIHN1YnByb2Nlc3MucnVuKFsic3VkbyIsICJzeXN0ZW1jdGwiLCAiZGlzYWJsZSIsICJyYWRlZ2FzdCJdLCBjaGVjaz1GYWxzZSkKICAgIHN1YnByb2Nlc3MucnVuKFsic3VkbyIsICJybSIsICItZiIsICIvZXRjL3N5c3RlbWQvc3lzdGVtL3JhZGVnYXN0LnNlcnZpY2UiXSwgY2hlY2s9RmFsc2UpCiAgICBzdWJwcm9jZXNzLnJ1bihbInN1ZG8iLCAic3lzdGVtY3RsIiwgImRhZW1vbi1yZWxvYWQiXSwgY2hlY2s9RmFsc2UpCgoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KIyA0LiBEZXJlZ2lzdGVyIHRoZSBkZXZpY2UgZnJvbSB0aGUgUmFkZWdhc3QgQVBJCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgpwcmludChmIkRlbGV0aW5nIGRldmljZSB7ZGV2aWNlX2lkfSBmcm9tIFJhZGVnYXN0IEFQSS4uLiIpCnJlc3BvbnNlID0gcmVxdWVzdHMuZGVsZXRlKAogICAgZiJ7QVBJX0JBU0V9L2RldmljZXMve2RldmljZV9pZH0iLAogICAgaGVhZGVycz17CiAgICAgICAgImFjY2VwdCI6ICJhcHBsaWNhdGlvbi9qc29uIiwKICAgICAgICAiWC1BUEktS2V5IjogYXBpX2tleSwKICAgICAgICAiQXV0aG9yaXphdGlvbiI6IGFwaV9rZXksCiAgICB9LAopCnJlc3BvbnNlLnJhaXNlX2Zvcl9zdGF0dXMoKQpwcmludChmIkRldmljZSB7ZGV2aWNlX2lkfSBkZWxldGVkIHN1Y2Nlc3NmdWxseS4iKQoKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiMgNS4gUmVtb3ZlIHRoZSBzYXZlZCBkZXZpY2UgSUQgZmlsZQojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKb3MucmVtb3ZlKERFVklDRV9JRF9GSUxFKQpwcmludChmIlJlbW92ZWQge0RFVklDRV9JRF9GSUxFfS4iKQo=" > "%SB%"
echo Decoding script: 1/1 (100%)
powershell -Command "$b = Get-Content -Path $env:SB -Raw; $x = [System.Convert]::FromBase64String($b); [System.IO.File]::WriteAllBytes($env:SO, $x)"

echo.

echo Running installation script with uv...
rem Executing using uv run
uv run --python=%PYTHON_VERSION% "%INSTALL_SCRIPT%"

if errorlevel 1 (
    echo ERROR: Installation script failed with error code %ERRORLEVEL%
) else (
    echo.
    echo Installation completed successfully!
)
echo.
del "%INSTALL_SCRIPT%" 2>nul
del "%INSTALL_B64%" 2>nul
PAUSE
