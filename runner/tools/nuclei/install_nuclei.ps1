$ErrorActionPreference="Stop"
$Root=$PSScriptRoot
$Exe=Join-Path $Root "nuclei.exe"
$Templates=Join-Path $Root "templates"
$Manifest=Join-Path $Root "runtime-manifest.json"
if(-not(Test-Path $Exe)){throw "Runtime Nuclei bundled ausente: $Exe"}
if(-not(Test-Path $Templates)){throw "Templates Nuclei bundled ausentes: $Templates"}
if(-not(Test-Path $Manifest)){throw "Manifesto do runtime ausente: $Manifest"}
Write-Host "[MAGI] Runtime Nuclei bundled detectado."
& $Exe -version
Write-Host "[MAGI] Atualização automática DESABILITADA por política da Sprint 4.2."
