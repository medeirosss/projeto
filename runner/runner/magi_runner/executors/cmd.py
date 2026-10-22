from __future__ import annotations

import platform

from .base import ExecutionResult
from .process import run_subprocess


class CmdExecutor:
    name = "cmd"

    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        command = job.get("command") or job.get("payload", {}).get("command")
        if not command:
            raise ValueError("CMD job requires 'command'")
        if platform.system().lower() == "windows":
            return run_subprocess(["cmd.exe", "/c", command], workdir, timeout_seconds)
        return run_subprocess(["/bin/sh", "-lc", command], workdir, timeout_seconds)
