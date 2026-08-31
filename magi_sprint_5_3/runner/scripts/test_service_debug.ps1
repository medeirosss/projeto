param(
    [string]$InstallDir = "C:\Program Files\Magi\Runner"
)
$ErrorActionPreference = "Stop"
$Python = Join-Path $InstallDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "Python da venv não encontrado: $Python" }
$env:MAGI_RUNNER_HOME = $InstallDir
$env:MAGI_RUNNER_CONFIG = Join-Path $InstallDir "settings.json"
Push-Location $InstallDir
try {
    & $Python -m magi_runner.service.windows_service debug
} finally {
    Pop-Location
}
