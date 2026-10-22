param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [string]$RegistrationToken,
  [switch]$Online,
  [switch]$InsecureNoTlsVerify
)
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (!(Test-Path $Python)) { $Python = "python" }
$ArgsList = @("-m", "magi_runner", "--config", "settings.json", "--set-server-url", $ServerUrl)
if ($RegistrationToken) { $ArgsList += @("--set-registration-token", $RegistrationToken) }
if ($Online) { $ArgsList += "--online" }
Push-Location $Root
try {
  & $Python @ArgsList
  if ($InsecureNoTlsVerify) {
    $cfg = Get-Content .\settings.json -Raw | ConvertFrom-Json
    $cfg.verify_tls = $false
    $cfg | ConvertTo-Json -Depth 20 | Set-Content .\settings.json -Encoding UTF8
    Write-Host "verify_tls disabled. Use only in lab/self-signed certificate environments."
  }
} finally { Pop-Location }
