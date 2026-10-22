#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m magi_runner --security-report --config ./settings.json
