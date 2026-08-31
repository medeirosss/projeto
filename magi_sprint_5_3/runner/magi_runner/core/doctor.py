from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from magi_runner.core.security import security_report
from magi_runner.core.version import __version__
from magi_runner.executors.nmap_discovery import nmap_capability
from magi_runner.core.nuclei_capability import nuclei_capability


def _exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_doctor(config_path: Path) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add("python_version", sys.version_info >= (3, 10), platform.python_version())
    add("psutil", importlib.util.find_spec("psutil") is not None, "required for host inventory")
    add("requests", importlib.util.find_spec("requests") is not None, "required for online API mode")
    add("powershell", _exists("powershell") or _exists("pwsh"), "required for PowerShell executor on Windows/Linux")
    add("cmd", True if platform.system() != "Windows" else _exists("cmd"), "required for CMD executor on Windows")
    add("config_file", config_path.exists(), str(config_path))
    nmap = nmap_capability()
    add("nmap", bool(nmap.get("available")), nmap.get("path") or nmap.get("message", ""))
    nuclei = nuclei_capability()
    add("nuclei_engine", bool(nuclei.get("engine_available")), nuclei.get("binary_path") or "searched: " + "; ".join(nuclei.get("searched_paths", [])))
    add("nuclei_templates", bool(nuclei.get("templates_available")), nuclei.get("templates_path", ""))
    integrity=nuclei.get("runtime_integrity") or {}
    add("nuclei_runtime_integrity", integrity.get("status")=="ok", integrity.get("status","unknown"))

    sec = security_report(config_path)
    add("config_hardening", sec["status"] != "failed", sec["status"])

    failures = [c for c in checks if not c["ok"]]
    return {
        "runner_version": __version__,
        "status": "failed" if failures else "ok",
        "platform": platform.platform(),
        "checks": checks,
        "security": sec,
    }


def print_doctor(config_path: Path) -> None:
    print(json.dumps(run_doctor(config_path), indent=2, ensure_ascii=False))
