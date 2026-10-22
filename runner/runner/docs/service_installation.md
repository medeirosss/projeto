# Service Installation

## Windows

The Windows service entry point is:

```text
magi_runner.service.windows_service
```

Default service name:

```text
MagiRunnerV2
```

The service reads these machine environment variables:

```text
MAGI_RUNNER_HOME
MAGI_RUNNER_CONFIG
```

The installer script persists both variables and configures basic service recovery using `sc.exe failure`.

## Linux

The systemd unit runs as the `magi-runner` system user and uses:

```text
/opt/magi-runner-v2/.venv/bin/python -m magi_runner --config /opt/magi-runner-v2/settings.json
```

Systemd recovery is handled by:

```text
Restart=always
RestartSec=10
```

## Health file

The local watchdog writes:

```text
runner_data/health.json
```

Fields include PID, current status and loop age in seconds.
