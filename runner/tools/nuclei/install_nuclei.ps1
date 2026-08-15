param([string]$Version="3.8.0",[string]$InstallDir="$PSScriptRoot")
$ErrorActionPreference="Stop"; $ProgressPreference="SilentlyContinue"
New-Item -ItemType Directory -Force -Path $InstallDir|Out-Null
$zip=Join-Path $env:TEMP "magi-nuclei-$Version.zip"
$url="https://github.com/projectdiscovery/nuclei/releases/download/v$Version/nuclei_${Version}_windows_amd64.zip"
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
Expand-Archive -Force -Path $zip -DestinationPath $InstallDir
Remove-Item -Force $zip -ErrorAction SilentlyContinue
$exe=Join-Path $InstallDir "nuclei.exe"; if(-not(Test-Path $exe)){throw "nuclei.exe ausente após extração."}
$templates=Join-Path $InstallDir "templates"; New-Item -ItemType Directory -Force -Path $templates|Out-Null
& $exe -ut -ud $templates -duc
if($LASTEXITCODE -ne 0){throw "Falha ao provisionar nuclei-templates."}
& $exe -version
