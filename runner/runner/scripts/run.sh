#!/usr/bin/env bash
set -euo pipefail
./.venv/bin/python -m magi_runner --config ./settings.json --once
