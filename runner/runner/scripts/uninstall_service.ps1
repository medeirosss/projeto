param([string]$ServiceName = "MagiRunnerV2")
$ErrorActionPreference = "Stop"
if ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
}
$python = ".venv\Scripts\python.exe"
if (Test-Path $python) {
    & $python -m magi_runner.service.windows_service remove
} else {
    sc.exe delete $ServiceName | Out-Null
}
Write-Host "Service removed: $ServiceName"
