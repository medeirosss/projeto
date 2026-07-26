#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then PY="python3"; fi
if [ $# -lt 1 ]; then
  echo "Usage: scripts/configure_server.sh <server_url> [registration_token]"
  exit 1
fi
cd "$ROOT"
ARGS=("-m" "magi_runner" "--config" "settings.json" "--set-server-url" "$1" "--online")
if [ $# -ge 2 ]; then ARGS+=("--set-registration-token" "$2"); fi
"$PY" "${ARGS[@]}"
