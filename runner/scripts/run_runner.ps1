$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "Virtualenv não encontrada. Execute scripts\install_runner.ps1 primeiro." }
& $Python -m magi_runner --config settings.json
