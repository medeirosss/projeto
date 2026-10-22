param([string]$ServerUrl, [string]$RunnerName, [switch]$Online, [switch]$Offline, [switch]$InsecureNoTlsVerify)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
function Read-Default([string]$Prompt, [string]$Default) { $value = Read-Host "$Prompt [$Default]"; if ([string]::IsNullOrWhiteSpace($value)) { return $Default }; return $value.Trim() }
function Read-YesNo([string]$Prompt, [bool]$DefaultYes = $true) { $suffix = if ($DefaultYes) { "S/n" } else { "s/N" }; $value = Read-Host "$Prompt [$suffix]"; if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultYes }; return @("s","sim","y","yes") -contains $value.Trim().ToLowerInvariant() }
function Write-Utf8NoBom([string]$Path, [string]$Content) { $encoding = New-Object System.Text.UTF8Encoding($false); [System.IO.File]::WriteAllText($Path, $Content, $encoding) }
if (-not (Test-Path ".\settings.json")) { Copy-Item ".\settings.example.json" ".\settings.json" }
$cfg = Get-Content ".\settings.json" -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $Online -and -not $Offline) { $Offline = Read-YesNo "Executar em modo offline/lab?" $false; $Online = -not $Offline }
if ($Offline) { $cfg.offline_mode = $true } else {
    if (-not $ServerUrl) { $hostValue = Read-Default "IP/FQDN do servidor Magi" "127.0.0.1"; $portValue = Read-Default "Porta da API do Magi" "8000"; $httpsChoice = Read-YesNo "Usar HTTPS?" $false; $scheme = if ($httpsChoice) { "https" } else { "http" }; if ($hostValue -match '^https?://') { $ServerUrl = $hostValue.TrimEnd('/') } else { $ServerUrl = "${scheme}://${hostValue}:${portValue}" } }
    $cfg.server_url = $ServerUrl.TrimEnd('/'); $cfg.offline_mode = $false
}
if (-not $RunnerName) { $RunnerName = Read-Default "Nome do Runner" $cfg.runner_name }
if ($RunnerName) { $cfg.runner_name = $RunnerName }
if ($InsecureNoTlsVerify) { $cfg.verify_tls = $false }
Write-Utf8NoBom -Path ".\settings.json" -Content ($cfg | ConvertTo-Json -Depth 30)
Write-Host "settings.json atualizado." -ForegroundColor Green
