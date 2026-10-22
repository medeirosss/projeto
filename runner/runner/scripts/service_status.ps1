param([string]$ServiceName = "MagiRunnerV2")
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) { Write-Host "Service not installed: $ServiceName" -ForegroundColor Yellow; exit 1 }
$svc | Format-Table -AutoSize
$home = [Environment]::GetEnvironmentVariable("MAGI_RUNNER_HOME", "Machine")
if ($home) {
    $health = Join-Path $home "runner_data\health.json"
    if (Test-Path $health) {
        Write-Host ""
        Write-Host "health.json:" -ForegroundColor Cyan
        Get-Content $health -Raw
    }
}
