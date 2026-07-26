<#
.SYNOPSIS
  Magi Runner v2 console/lab Windows installer.
.DESCRIPTION
  Installs Magi Runner v2 into Program Files, creates a Python virtual environment,
  installs dependencies, and runs an interactive configuration wizard.
  This version does NOT install a Windows Service.
#>
param(
    [string]$InstallDir = "C:\Program Files\Magi\Runner",
    [switch]$NonInteractive,
    [string]$ServerUrl,
    [string]$RunnerName,
    [switch]$UseHttps,
    [switch]$Offline,
    [switch]$InsecureNoTlsVerify,
    [switch]$Force
)
$ErrorActionPreference = "Stop"
function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer as Administrator, or change -InstallDir to a user-writable folder."
    }
}
function Write-Step([string]$Message) { Write-Host ""; Write-Host "==> $Message" -ForegroundColor Cyan }
function Read-Default([string]$Prompt, [string]$Default) { $value = Read-Host "$Prompt [$Default]"; if ([string]::IsNullOrWhiteSpace($value)) { return $Default }; return $value.Trim() }
function Read-YesNo([string]$Prompt, [bool]$DefaultYes = $true) {
    $suffix = if ($DefaultYes) { "S/n" } else { "s/N" }
    while ($true) {
        $value = Read-Host "$Prompt [$suffix]"
        if ([string]::IsNullOrWhiteSpace($value)) { return $DefaultYes }
        switch ($value.Trim().ToLowerInvariant()) {
            "s" { return $true }; "sim" { return $true }; "y" { return $true }; "yes" { return $true }
            "n" { return $false }; "nao" { return $false }; "não" { return $false }; "no" { return $false }
            default { Write-Host "Responda S ou N." -ForegroundColor Yellow }
        }
    }
}
function Resolve-Python {
    $candidates = @("py", "python")
    foreach ($cmd in $candidates) { $resolved = Get-Command $cmd -ErrorAction SilentlyContinue; if ($resolved) { return $resolved.Source } }
    throw "Python não encontrado. Instale Python 3.10+ e marque a opção 'Add python.exe to PATH'."
}
function Write-Utf8NoBom([string]$Path, [string]$Content) { $encoding = New-Object System.Text.UTF8Encoding($false); [System.IO.File]::WriteAllText($Path, $Content, $encoding) }
Assert-Admin
$SourceRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $SourceRoot "magi_runner"))) { throw "Execute este script a partir da pasta scripts do pacote do Magi Runner." }
Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host "     Magi Runner v2 Console Windows Setup    " -ForegroundColor DarkCyan
Write-Host "============================================" -ForegroundColor DarkCyan
Write-Host "Esta versão NÃO instala serviço Windows." -ForegroundColor Yellow
if (-not $NonInteractive) {
    $InstallDir = Read-Default "Diretório de instalação" $InstallDir
    $OfflineChoice = Read-YesNo "Executar em modo offline/lab?" $false
    if ($OfflineChoice) { $Offline = $true } else {
        if (-not $ServerUrl) {
            $hostValue = Read-Default "IP/FQDN do servidor Magi" "127.0.0.1"
            $portValue = Read-Default "Porta da API do Magi" "8000"
            $httpsChoice = Read-YesNo "Usar HTTPS?" $false
            $scheme = if ($httpsChoice) { "https" } else { "http" }
            if ($hostValue -match '^https?://') { $ServerUrl = $hostValue.TrimEnd('/') } else { $ServerUrl = "${scheme}://${hostValue}:${portValue}" }
        }
        if (-not $RunnerName) { $RunnerName = Read-Default "Nome do Runner" "magi-runner-$env:COMPUTERNAME" }
        if ($ServerUrl -like "https://*") { if (Read-YesNo "Desabilitar validação TLS? Use somente em laboratório/certificado self-signed" $false) { $InsecureNoTlsVerify = $true } }
    }
}
Write-Step "Preparando diretório de instalação"
if (Test-Path $InstallDir) {
    if (-not $Force) { Write-Host "O diretório já existe: $InstallDir" -ForegroundColor Yellow; if (-not (Read-YesNo "Sobrescrever arquivos do Runner?" $true)) { throw "Instalação cancelada pelo usuário." } }
} else { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
$excludeNames = @("runner_data", ".venv", "__pycache__")
Get-ChildItem -Path $SourceRoot -Force | Where-Object { $excludeNames -notcontains $_.Name } | ForEach-Object {
    $target = Join-Path $InstallDir $_.Name
    if ($_.PSIsContainer) { Copy-Item $_.FullName $target -Recurse -Force } else { Copy-Item $_.FullName $target -Force }
}
Push-Location $InstallDir
try {
    Write-Step "Validando Python e criando ambiente virtual"
    $PythonCmd = Resolve-Python
    if ($PythonCmd -match "py.exe$" -or $PythonCmd -eq "py") { & $PythonCmd -3 -m venv .venv } else { & $PythonCmd -m venv .venv }
    if ($LASTEXITCODE -ne 0) { throw "Falha ao criar virtualenv." }
    $VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
    $VenvPip = Join-Path $InstallDir ".venv\Scripts\pip.exe"
    Write-Step "Instalando dependências"
    & $VenvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "Falha ao atualizar pip." }
    & $VenvPip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar requirements.txt." }
    Write-Step "Instalando pacote local do Runner na venv"
    & $VenvPip install -e .
    if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar pacote local magi-runner na venv." }
    foreach ($d in @("runner_data", "runner_data\logs", "runner_data\jobs", "runner_data\spool", "runner_data\state")) { New-Item -ItemType Directory -Path (Join-Path $InstallDir $d) -Force | Out-Null }
    Write-Step "Criando settings.json"
    if (-not (Test-Path ".\settings.json")) { Copy-Item ".\settings.example.json" ".\settings.json" }
    $cfg = Get-Content ".\settings.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($RunnerName) { $cfg.runner_name = $RunnerName }
    if ($Offline) { $cfg.offline_mode = $true } else { if (-not $ServerUrl) { throw "ServerUrl é obrigatório quando Offline não está habilitado." }; $cfg.server_url = $ServerUrl.TrimEnd('/'); $cfg.offline_mode = $false }
    if ($InsecureNoTlsVerify) { $cfg.verify_tls = $false }
    Write-Utf8NoBom -Path ".\settings.json" -Content ($cfg | ConvertTo-Json -Depth 30)
    Write-Step "Executando validação local"
    & $VenvPython -m magi_runner --config settings.json --doctor
    if ($LASTEXITCODE -ne 0) { throw "Doctor falhou. Corrija os itens indicados antes de executar o Runner." }
    Write-Step "Instalação concluída"
    Write-Host "Instalado em: $InstallDir"
    Write-Host "Configuração: $(Join-Path $InstallDir 'settings.json')"
    Write-Host "Logs/dados: $(Join-Path $InstallDir 'runner_data')"
    Write-Host ""
    Write-Host "Para executar agora:" -ForegroundColor Green
    Write-Host "  cd `"$InstallDir`""
    Write-Host "  .\scripts\run_runner.ps1"
    Write-Host ""
    Write-Host "Para alterar o IP/FQDN depois:" -ForegroundColor Green
    Write-Host "  .\scripts\configure_runner.ps1"
}
finally { Pop-Location }
