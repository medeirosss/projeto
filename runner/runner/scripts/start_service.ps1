param([string]$ServiceName = "MagiRunnerV2")
Start-Service -Name $ServiceName
Get-Service -Name $ServiceName
