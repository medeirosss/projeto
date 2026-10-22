$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\Magi\Runner"
$Python = Join-Path $InstallDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "Python da venv não encontrado: $Python" }
$env:MAGI_RUNNER_HOME = $InstallDir
$env:MAGI_RUNNER_CONFIG = Join-Path $InstallDir "settings.json"
$env:PYTHONPATH = $InstallDir
Push-Location $InstallDir
try {
    & $Python -c "import sys, os; print(sys.executable); print(os.getcwd()); import magi_runner; print('magi_runner import OK'); import magi_runner.service.windows_service as s; print('windows_service import OK')"
    & $Python -m magi_runner --config settings.json --doctor
}
finally { Pop-Location }
