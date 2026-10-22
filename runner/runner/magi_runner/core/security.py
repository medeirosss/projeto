from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = {"registration_token", "runner_secret", "api_key", "token", "secret"}
_ALLOWED_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,80}$")


@dataclass
class HardeningFinding:
    level: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


def redact(value: Any) -> Any:
    if value in (None, ""):
        return value
    text = str(value)
    if len(text) <= 6:
        return "***"
    return f"{text[:2]}***{text[-2:]}"


def redact_config(raw: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in raw.items():
        if key.lower() in SENSITIVE_KEYS or any(s in key.lower() for s in ("token", "secret", "password")):
            safe[key] = redact(value)
        else:
            safe[key] = value
    return safe


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_config_file(path: Path) -> list[HardeningFinding]:
    findings: list[HardeningFinding] = []
    if not path.exists():
        return [HardeningFinding("error", "CONFIG_MISSING", f"Config file not found: {path}")]
    try:
        raw = read_json(path)
    except Exception as exc:
        return [HardeningFinding("error", "CONFIG_INVALID_JSON", f"Invalid JSON config: {exc}")]

    name = str(raw.get("runner_name", ""))
    if not _ALLOWED_NAME.match(name):
        findings.append(HardeningFinding("error", "RUNNER_NAME_INVALID", "runner_name must use only letters, numbers, spaces, dot, dash or underscore and be <= 80 chars."))

    server_url = str(raw.get("server_url", ""))
    offline = bool(raw.get("offline_mode", False))
    if not offline and not server_url.startswith("https://"):
        findings.append(HardeningFinding("warning", "TLS_NOT_ENFORCED", "server_url should use HTTPS outside lab/offline tests."))
    if raw.get("verify_tls") is False and not offline:
        findings.append(HardeningFinding("warning", "TLS_VERIFY_DISABLED", "verify_tls=false should not be used in production."))

    if not offline and not raw.get("registration_token") and not raw.get("runner_secret"):
        findings.append(HardeningFinding("error", "AUTH_MISSING", "registration_token or runner_secret is required for online mode."))

    allowed = raw.get("allowed_executors", [])
    if not isinstance(allowed, list) or not allowed:
        findings.append(HardeningFinding("error", "EXECUTORS_EMPTY", "allowed_executors must be a non-empty list."))
    if "python" in allowed:
        findings.append(HardeningFinding("warning", "PYTHON_EXECUTOR_ENABLED", "Python executor is powerful; keep enabled only where explicitly needed."))
    if "atomic" in allowed:
        findings.append(HardeningFinding("info", "ATOMIC_ENABLED", "Atomic executor enabled. Ensure Atomic tests are approved by the Magi admin before dispatch."))

    for key in ("poll_interval_seconds", "heartbeat_interval_seconds", "default_timeout_seconds", "max_concurrent_jobs"):
        try:
            value = int(raw.get(key))
        except Exception:
            findings.append(HardeningFinding("error", f"{key.upper()}_INVALID", f"{key} must be an integer."))
            continue
        if value <= 0:
            findings.append(HardeningFinding("error", f"{key.upper()}_INVALID", f"{key} must be greater than zero."))

    return findings


def secure_file_best_effort(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def security_report(config_path: Path) -> dict[str, Any]:
    findings = validate_config_file(config_path)
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            raw = redact_config(read_json(config_path))
        except Exception:
            raw = {}
    errors = sum(1 for f in findings if f.level == "error")
    warnings = sum(1 for f in findings if f.level == "warning")
    return {
        "status": "failed" if errors else ("warning" if warnings else "ok"),
        "errors": errors,
        "warnings": warnings,
        "config": raw,
        "findings": [f.as_dict() for f in findings],
    }
