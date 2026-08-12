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
        result = PowerShellExecutor().run({"command": command}, workdir, timeout_seconds)

        # Sprint 4.0.3: execution evidence must distinguish command execution from
        # post-execution confirmation. Atomic is currently executed on the Runner
        # host; target_host remains a requested/logical target until a remote
        # execution transport is explicitly implemented.
        metadata = dict(result.metadata or {})
        metadata.update({
            "atomic_technique_id": technique_id,
            "atomic_test_number": int(test_number),
            "atomic_action": "get_prereqs" if get_prereqs else ("cleanup" if cleanup else "execute"),
            "executed_real_test": not get_prereqs and not cleanup,
            "confirmation_status": "executed_unverified" if (not get_prereqs and not cleanup and result.status == "success") else None,
            "execution_scope": "runner_local",
            "execution_host": "runner",
            "requested_target": job.get("target") or payload.get("target_host"),
            "command": command,
        })
        result.metadata = metadata
        return result
