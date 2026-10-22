from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from magi_runner.collectors.artifacts import ArtifactManager, sha256_file
from magi_runner.collectors.evidence import EvidenceCollector
from magi_runner.core.config import RunnerConfig
from magi_runner.core.state import LocalState
from magi_runner.executors.registry import ExecutorRegistry



def _secret_values_from_job(job: dict[str, Any]) -> list[str]:
    payload = job.get("payload") or {}
    values: list[str] = []
    credential = payload.get("credential")
    if isinstance(credential, dict):
        for key in ("secret", "password", "community", "auth_key", "priv_key", "token"):
            value = credential.get(key)
            if value:
                values.append(str(value))
    for key in ("password", "community", "secret", "token"):
        value = payload.get(key)
        if value:
            values.append(str(value))
    # Longest first prevents partial redaction from exposing a suffix/prefix.
    return sorted(set(values), key=len, reverse=True)


def redact_sensitive_text(text: str | None, job: dict[str, Any]) -> str:
    import re
    safe = str(text or "")
    for secret in _secret_values_from_job(job):
        if secret:
            safe = safe.replace(secret, "********")
    # Provider output may echo values independently of our exact secret lookup.
    safe = re.sub(r"(?im)^(\s*(?:PASSWORD|PASS|COMMUNITY|TOKEN|SECRET)\s*=>\s*).+$", r"\1********", safe)
    safe = re.sub(r'(?i)(with password\s+)(\S+)', r'\1********', safe)
    # Kerberos/credential material is evidence that a credential artifact was produced,
    # but persisting the material itself is unnecessary and unsafe.
    safe = re.sub(r'(?i)(Hash:\s*)\$krb5[^\r\n]+', r'\1[REDACTED_KERBEROS_MATERIAL]', safe)
    return safe


def redact_result_metadata(metadata: dict[str, Any] | None, job: dict[str, Any]) -> dict[str, Any]:
    import copy
    safe = copy.deepcopy(metadata or {})
    # Never allow raw credential material in normalized evidence.
    def scrub(value):
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if str(k).lower() in {"password","secret","community","token","hash","ticket","credential_material"}:
                    out[k] = "********"
                else:
                    out[k] = scrub(v)
            return out
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, str):
            return redact_sensitive_text(value, job)
        return value
    return scrub(safe)

def redact_job(job: dict[str, Any]) -> dict[str, Any]:
    import copy
    safe=copy.deepcopy(job)
    payload=safe.get("payload") or {}
    cred=payload.get("credential")
    if isinstance(cred,dict):
        for key in ("secret","password","community","auth_key","priv_key"):
            if key in cred: cred[key]="********"
    return safe


class JobScheduler:
    def __init__(self, config: RunnerConfig, state: LocalState, logger: logging.Logger) -> None:
        self.config = config
        self.state = state
        self.logger = logger.getChild("scheduler")
        self.registry = ExecutorRegistry(config.allowed_executors)
        self.artifacts = ArtifactManager(config.data_path)
        self.evidence = EvidenceCollector()
        self.semaphore = threading.Semaphore(config.max_concurrent_jobs)
        self.active_jobs = 0
        self.active_lock = threading.Lock()

    def run_job(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job.get("job_id") or job.get("id"))
        if not job_id or job_id == "None":
            raise ValueError("Job requires job_id")
        if self.state.is_completed(job_id):
            return {"job_id": job_id, "status": "skipped", "reason": "already completed locally"}

        with self.semaphore:
            with self.active_lock:
                self.active_jobs += 1
            try:
                return self._execute(job_id, job)
            finally:
                with self.active_lock:
                    self.active_jobs -= 1

    def _execute(self, job_id: str, job: dict[str, Any]) -> dict[str, Any]:
        job_dir = self.artifacts.create_job_dir(job_id)
        executor_name = str(job.get("executor") or job.get("type") or "cmd").lower()
        timeout = int(job.get("timeout_seconds") or self.config.default_timeout_seconds)
        self.logger.info("Executing job %s with executor %s", job_id, executor_name)

        executor = self.registry.get(executor_name)
        try:
            result = executor.run(job, str(job_dir), timeout)
            evidence = self.evidence.collect(job.get("collect") or {}, job_dir)
            safe_stdout = redact_sensitive_text(result.stdout, job)
            safe_stderr = redact_sensitive_text(result.stderr, job)
            safe_metadata = redact_result_metadata(result.metadata, job)
            self.artifacts.write_text(job_dir, "stdout.txt", safe_stdout)
            self.artifacts.write_text(job_dir, "stderr.txt", safe_stderr)
            self.artifacts.write_json(job_dir, "job.json", redact_job(job))
            self.artifacts.write_json(job_dir, "evidence.json", evidence)
            summary = {
                "job_id": job_id,
                "executor": executor_name,
                "status": result.status,
                "exit_code": result.exit_code,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "duration_seconds": result.duration_seconds,
                "metadata": safe_metadata,
                "stdout": safe_stdout,
                "stderr": safe_stderr,
                "executed_real_test": bool((safe_metadata or {}).get("executed_real_test")),
                "confirmation_status": (safe_metadata or {}).get("confirmation_status"),
                "execution_scope": (safe_metadata or {}).get("execution_scope"),
                "requested_target": (safe_metadata or {}).get("requested_target"),
                "evidence_summary": summarize_evidence(evidence),
            }
            self.artifacts.write_json(job_dir, "metadata.json", summary)
            zip_path = self.artifacts.zip_job_dir(job_dir)
            summary["artifact_zip"] = str(zip_path)
            summary["artifact_sha256"] = sha256_file(Path(zip_path))
            self.artifacts.write_json(job_dir, "result.json", summary)
            return summary
        except Exception as exc:
            self.logger.exception("Job %s failed before normal result generation", job_id)
            failed = {"job_id": job_id, "status": "error", "error": str(exc)}
            self.artifacts.write_json(job_dir, "result.json", failed)
            return failed


def summarize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, list):
            summary[key] = {"count": len(value)}
        elif isinstance(value, dict):
            summary[key] = {"keys": list(value.keys())}
        else:
            summary[key] = str(type(value))
    return summary
