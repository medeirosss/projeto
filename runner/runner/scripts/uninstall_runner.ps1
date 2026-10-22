param([string]$InstallDir = "C:\Program Files\Magi\Runner")
$ErrorActionPreference = "Stop"
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force; Write-Host "Magi Runner removido de $InstallDir" -ForegroundColor Green } else { Write-Host "Diretório não encontrado: $InstallDir" -ForegroundColor Yellow }
