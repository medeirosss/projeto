param([string]$ServiceName = "MagiRunnerV2")
Stop-Service -Name $ServiceName
Get-Service -Name $ServiceName
