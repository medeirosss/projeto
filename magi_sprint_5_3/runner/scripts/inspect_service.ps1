param(
    [string]$ServiceName = "MagiRunnerV2",
    [string]$InstallDir = "C:\Program Files\Magi\Runner"
)
Write-Host "== Service" -ForegroundColor Cyan
Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-List *
Write-Host "== Registry" -ForegroundColor Cyan
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $reg) { Get-ItemProperty $reg | Format-List ImagePath,PythonClass,PythonPath,Environment,ObjectName,Start,Type }
Write-Host "== Logs" -ForegroundColor Cyan
$boot = Join-Path $InstallDir "runner_data\logs\service_boot.log"
$runner = Join-Path $InstallDir "runner_data\logs\runner.log"
if (Test-Path $boot) { Get-Content $boot -Tail 120 } else { Write-Host "Sem service_boot.log" -ForegroundColor Yellow }
if (Test-Path $runner) { Get-Content $runner -Tail 120 } else { Write-Host "Sem runner.log" -ForegroundColor Yellow }
Write-Host "== Event Viewer" -ForegroundColor Cyan
Get-EventLog -LogName Application -Newest 50 | ? { $_.Source -like '*Python*' -or $_.Source -like '*Magi*' -or $_.Message -like '*MagiRunnerV2*' } | Format-List TimeGenerated,Source,EntryType,Message

Write-Host "`n== Pywin32 Registry Details" -ForegroundColor Cyan
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $svcKey) {
    Get-ItemProperty $svcKey | Format-List *
}
$pyKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\PythonClass"
if (Test-Path $pyKey) {
    Write-Host "`nPythonClass subkey:" -ForegroundColor Cyan
    Get-ItemProperty $pyKey | Format-List *
}
