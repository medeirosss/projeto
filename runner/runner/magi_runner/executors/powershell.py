from __future__ import annotations

import shutil

from .base import ExecutionResult
from .process import run_subprocess


class PowerShellExecutor:
    name = "powershell"

    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        command = job.get("command") or job.get("payload", {}).get("command")
        if not command:
            raise ValueError("PowerShell job requires 'command'")
        exe = shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")
        if not exe:
            raise RuntimeError("PowerShell executable not found")
        return run_subprocess([exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], workdir, timeout_seconds)
