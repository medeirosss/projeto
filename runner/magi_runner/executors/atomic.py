from __future__ import annotations

from .base import ExecutionResult
from .powershell import PowerShellExecutor


class AtomicExecutor:
    name = "atomic"

    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        payload = job.get("payload", {})
        technique_id = job.get("technique_id") or payload.get("technique_id")
        test_number = (
            job.get("test_number")
            or payload.get("test_number")
            or payload.get("atomic_test_number")
            or 1
        )
        get_prereqs = bool(payload.get("get_prereqs", False))
        cleanup = bool(payload.get("cleanup", False))
        if not technique_id:
            raise ValueError("Atomic job requires technique_id")
        action = "-GetPrereqs" if get_prereqs else ("-Cleanup" if cleanup else "")
        command = f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} {action}".strip()
        return PowerShellExecutor().run({"command": command}, workdir, timeout_seconds)
