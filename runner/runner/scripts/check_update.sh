#!/usr/bin/env bash
set -euo pipefail
python3 -m magi_runner --config settings.json --check-update
