param(
    [string]$InstallDir = "$PSScriptRoot",
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if ([string]::IsNullOrWhiteSpace($Version)) {
    Write-Host "[MAGI] Consultando release oficial mais recente do Nuclei..."
    $release = Invoke-RestMethod -UseBasicParsing -Headers @{"User-Agent"="MAGI-Runner"} -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
    $Version = [string]$release.tag_name
    $Version = $Version.TrimStart("v")
}
$assetName = "nuclei_${Version}_windows_amd64.zip"
$url = "https://github.com/projectdiscovery/nuclei/releases/download/v$Version/$assetName"
$zip = Join-Path $env:TEMP "magi-$assetName"

Write-Host "[MAGI] Baixando Nuclei v$Version..."
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -Force -Path $zip -DestinationPath $InstallDir
Remove-Item -Force $zip -ErrorAction SilentlyContinue

$exe = Join-Path $InstallDir "nuclei.exe"
if (-not (Test-Path $exe)) { throw "nuclei.exe não encontrado após extração em $InstallDir" }

$templates = Join-Path $InstallDir "templates"
New-Item -ItemType Directory -Force -Path $templates | Out-Null

Write-Host "[MAGI] Provisionando nuclei-templates em $templates..."
& $exe -ut -ud $templates -duc
if ($LASTEXITCODE -ne 0) { throw "Falha ao provisionar nuclei-templates (exit=$LASTEXITCODE)." }

Write-Host "[MAGI] Runtime pronto:"
& $exe -version
Write-Host "[MAGI] Engine: $exe"
Write-Host "[MAGI] Templates: $templates"
