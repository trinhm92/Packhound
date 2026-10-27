# Build "Packhound" for Windows (folder app + zip, optional installer).
# Optional code signing: $env:SIGN_CERT_THUMBPRINT = "<thumbprint of your code-signing cert in CurrentUser\My>"
# Optional installer: install Inno Setup 6 (iscc.exe on PATH); packaging\windows-installer.iss is used.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$Root = Get-Location
$Build = Join-Path $Root "build\windows"
$Name = "Packhound"
# Python: $env:PYTHON if set (CI), else the py launcher. Use 64-bit Python 3.10+.
$Py = if ($env:PYTHON) { $env:PYTHON } else { (& py -3 -c "import sys; print(sys.executable)").Trim() }
$Version = (Select-String -Path scs\__init__.py -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value

if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
New-Item -ItemType Directory -Force $Build | Out-Null
& $Py -m venv "$Build\venv"
$VPy = "$Build\venv\Scripts\python.exe"
function Check([string]$What) { if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" } }
# Hash-locked: pip may install only the exact files recorded in packaging\locks (made by
# packaging/lock_build_deps.py with a release-age cooldown), and nothing else (--no-deps).
& $VPy -m pip install --quiet --require-hashes --no-deps --only-binary=:all: -r packaging\locks\build-windows.txt; Check "locked install"
# source-only packages, built with the locked setuptools instead of one fetched for the build
& $VPy -m pip install --quiet --require-hashes --no-deps --no-build-isolation -r packaging\locks\build-windows-sdist.txt; Check "locked source install"
& $VPy -m pip check; Check "pip check"
& $VPy -m pip freeze | Out-File -Encoding utf8 "$Build\build-requirements.lock.txt"
Write-Host "== checking the build environment (known-malicious/vulnerable packages, startup hooks)"
$env:PYTHONPATH = "$Root"
$extra = @(); if ($env:SCS_ALLOW_VULNERABLE) { $extra = @("--allow-vulnerable") }
& $Py -m scs fixer build-check --python $VPy @extra; Check "build-check"
Remove-Item Env:PYTHONPATH

& "$Build\venv\Scripts\pyinstaller.exe" --noconfirm --clean --distpath "$Build\dist" --workpath "$Build\work" packaging\scs-gui.spec; Check "pyinstaller"
$AppDir = Join-Path $Build "dist\$Name"
$Exe = Join-Path $AppDir "$Name.exe"

if ($env:SIGN_CERT_THUMBPRINT) {
  Write-Host "== signing"
  & signtool sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Exe
}

# SHA-256 of every file, checked by `scs self-check` and every scheduled run (after signing: signing changes the .exe)
$env:PYTHONPATH = "$Root"
& $Py -m scs self-check --write-manifest $AppDir; Check "manifest"
Remove-Item Env:PYTHONPATH

$Zip = Join-Path $Build "Packhound-$Version-windows.zip"
Compress-Archive -Path $AppDir -DestinationPath $Zip -Force
(Get-FileHash $Zip -Algorithm SHA256).Hash | Out-File -Encoding ascii "$Zip.sha256"
# Optional: sign the checksum with an SSH key ($env:SCS_SIGN_KEY), verifiable with `ssh-keygen -Y verify`
if ($env:SCS_SIGN_KEY) { & ssh-keygen -Y sign -f $env:SCS_SIGN_KEY -n scs-release "$Zip.sha256"; Check "checksum signing" }

if (Get-Command iscc.exe -ErrorAction SilentlyContinue) {
  & iscc.exe /DAppVersion=$Version /DSourceDir="$AppDir" /DOutputDir="$Build" packaging\windows-installer.iss
  $Setup = Join-Path $Build "Packhound-$Version-setup.exe"
  if ($env:SIGN_CERT_THUMBPRINT) { & signtool sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Setup }
}
Write-Host "built: $AppDir"
Write-Host "       $Zip"
if (-not $env:SIGN_CERT_THUMBPRINT) { Write-Host "note: unsigned build - SmartScreen will warn on first run." }
