#!/usr/bin/env bash
set -euo pipefail

RUNNER_HOME="${1:-/opt/magi-runner-v2}"
SERVICE_USER="magi-runner"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./scripts/install_systemd.sh"
  exit 1
fi

id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home "$RUNNER_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$RUNNER_HOME"
rsync -a --exclude '.venv' --exclude 'runner_data' ./ "$RUNNER_HOME"/
chown -R "$SERVICE_USER:$SERVICE_USER" "$RUNNER_HOME"

python3 -m venv "$RUNNER_HOME/.venv"
"$RUNNER_HOME/.venv/bin/python" -m pip install --upgrade pip
"$RUNNER_HOME/.venv/bin/python" -m pip install -r "$RUNNER_HOME/requirements.txt"

cp "$RUNNER_HOME/deploy/systemd/magi-runner-v2.service" /etc/systemd/system/magi-runner-v2.service
systemctl daemon-reload
systemctl enable magi-runner-v2.service

echo "Installed magi-runner-v2.service"
echo "Start with: sudo systemctl start magi-runner-v2"
