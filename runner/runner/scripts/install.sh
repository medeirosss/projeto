#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
[ -f settings.json ] || cp settings.example.json settings.json
echo "Magi Runner v2 installed. Edit settings.json and run scripts/run.sh"
