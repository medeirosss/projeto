from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from magi_runner.core.security import validate_config_file, secure_file_best_effort


@dataclass
class RunnerConfig:
    runner_name: str
    server_url: str
    registration_token: str
    runner_id: str | None = None
    runner_secret: str | None = None
    verify_tls: bool = True
    offline_mode: bool = False
    poll_interval_seconds: int = 5
    heartbeat_interval_seconds: int = 30
    max_concurrent_jobs: int = 1
    default_timeout_seconds: int = 120
    data_dir: str = "./runner_data"
    log_level: str = "INFO"
    allowed_executors: list[str] = field(default_factory=lambda: ["cmd", "powershell", "python", "atomic", "nmap_discovery", "service_discovery", "credential_validate", "deep_inventory", "security_check", "nuclei", "attack_simulation"])
    nmap_path: str | None = None
    offline_jobs_file: str = "./offline_jobs.json"
    update_enabled: bool = False
    update_manifest_url: str | None = None
    update_check_interval_seconds: int = 3600
    update_auto_apply: bool = False
    update_download_timeout_seconds: int = 120

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).resolve()


def load_config(path: str | os.PathLike[str]) -> RunnerConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    findings = validate_config_file(config_path)
    errors = [f for f in findings if f.level == "error"]
    if errors:
        details = "; ".join(f"{f.code}: {f.message}" for f in errors)
        raise ValueError(f"Invalid runner configuration: {details}")

    secure_file_best_effort(config_path)
    with config_path.open("r", encoding="utf-8-sig") as fh:
        raw: dict[str, Any] = json.load(fh)

    # Forward-compatible executor migration for existing 2.11.x settings.json.
    allowed = list(raw.get("allowed_executors") or [])
    if "nmap_discovery" in allowed and "service_discovery" not in allowed:
        allowed.append("service_discovery")
    if "service_discovery" in allowed and "credential_validate" not in allowed:
        allowed.append("credential_validate")
    if "credential_validate" in allowed and "deep_inventory" not in allowed:
        allowed.append("deep_inventory")
    if "deep_inventory" in allowed and "security_check" not in allowed:
        allowed.append("security_check")
    if "security_check" in allowed and "nuclei" not in allowed:
        allowed.append("nuclei")
    if "nuclei" in allowed and "attack_simulation" not in allowed:
        allowed.append("attack_simulation")
    raw["allowed_executors"] = allowed

    return RunnerConfig(**raw)



def read_config_raw(path: str | os.PathLike[str]) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def write_config_raw(path: str | os.PathLike[str], data: dict[str, Any]) -> None:
    config_path = Path(path)
    with config_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    secure_file_best_effort(config_path)


def update_config_values(path: str | os.PathLike[str], **values: Any) -> dict[str, Any]:
    raw = read_config_raw(path)
    raw.update(values)
    write_config_raw(path, raw)
    return raw


def persist_runner_credentials(path: str | os.PathLike[str], runner_id: str, runner_secret: str) -> None:
    update_config_values(path, runner_id=runner_id, runner_secret=runner_secret)
