from __future__ import annotations

import re

from .base import ExecutionResult
from .powershell import PowerShellExecutor

_PREVENTION_PATTERNS = (
    ("antimalware", r"virus|vírus|software possivelmente indesejado|potentially unwanted|malware"),
    ("security_block", r"blocked by|foi bloquead|security policy|antivirus|anti-virus|windows defender"),
)
_EXECUTION_ERROR_PATTERNS = (
    r"fullyqualifiederrorid", r"write-error", r"permissiondenied",
    r"unauthorizedaccessexception", r"methodinvocationexception",
    r"cannot find path", r"não foi possível concluir a operação",
)

def _classify_atomic_outcome(result: ExecutionResult, real_execution: bool):
    if not real_execution:
        return None, []
    status = str(result.status or "").lower()
    if status in {"failed", "error", "timeout", "blocked"}:
        return "error", [f"runner_status:{status}"]
    combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    signals=[]
    for label, pattern in _PREVENTION_PATTERNS:
        if re.search(pattern, combined, flags=re.IGNORECASE): signals.append(label)
    if signals:
        return "prevented", signals
    if any(re.search(pattern, combined, flags=re.IGNORECASE) for pattern in _EXECUTION_ERROR_PATTERNS):
        return "not_confirmed", ["execution_error_in_output"]
    if status == "success":
        return "executed_unverified", []
    return "error", [f"runner_status:{status or 'unknown'}"]

class AtomicExecutor:
    name = "atomic"
    def run(self, job: dict, workdir: str, timeout_seconds: int) -> ExecutionResult:
        payload=job.get("payload", {})
        technique_id=job.get("technique_id") or payload.get("technique_id")
        test_number=job.get("test_number") or payload.get("test_number") or payload.get("atomic_test_number") or 1
        get_prereqs=bool(payload.get("get_prereqs", False)); cleanup=bool(payload.get("cleanup", False))
        if not technique_id: raise ValueError("Atomic job requires technique_id")
        action="-GetPrereqs" if get_prereqs else ("-Cleanup" if cleanup else "")
        command=f"Invoke-AtomicTest {technique_id} -TestNumbers {test_number} {action}".strip()
        result=PowerShellExecutor().run({"command":command}, workdir, timeout_seconds)
        real_execution=not get_prereqs and not cleanup
        confirmation_status,outcome_signals=_classify_atomic_outcome(result,real_execution)
        metadata=dict(result.metadata or {})
        metadata.update({
            "atomic_technique_id":technique_id,"atomic_test_number":int(test_number),
            "atomic_action":"get_prereqs" if get_prereqs else ("cleanup" if cleanup else "execute"),
            "executed_real_test":real_execution,"confirmation_status":confirmation_status,
            "outcome_signals":outcome_signals,"execution_scope":"runner_local",
            "execution_host":"runner","requested_target":job.get("target") or payload.get("target_host"),
            "command":command})
        result.metadata=metadata
        return result
