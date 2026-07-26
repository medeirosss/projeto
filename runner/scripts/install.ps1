$ErrorActionPreference = "Stop"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\pip.exe install -r requirements.txt
if (!(Test-Path .\settings.json)) { Copy-Item .\settings.example.json .\settings.json }
Write-Host "Magi Runner v2 installed. Edit settings.json and run scripts\run.ps1"
