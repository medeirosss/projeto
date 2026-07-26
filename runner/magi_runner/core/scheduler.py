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
            self.artifacts.write_text(job_dir, "stdout.txt", result.stdout)
            self.artifacts.write_text(job_dir, "stderr.txt", result.stderr)
            self.artifacts.write_json(job_dir, "job.json", job)
            self.artifacts.write_json(job_dir, "evidence.json", evidence)
            summary = {
                "job_id": job_id,
                "executor": executor_name,
                "status": result.status,
                "exit_code": result.exit_code,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "duration_seconds": result.duration_seconds,
                "metadata": result.metadata,
                "evidence_summary": summarize_evidence(evidence),
            }
            self.artifacts.write_json(job_dir, "metadata.json", summary)
            zip_path = self.artifacts.zip_job_dir(job_dir)
            summary["artifact_zip"] = str(zip_path)
            summary["artifact_sha256"] = sha256_file(Path(zip_path))
            self.artifacts.write_json(job_dir, "result.json", summary)
            self.state.mark_completed(job_id)
            return summary
        except Exception as exc:
            self.logger.exception("Job %s failed before normal result generation", job_id)
            failed = {"job_id": job_id, "status": "error", "error": str(exc)}
            self.artifacts.write_json(job_dir, "result.json", failed)
            self.state.mark_completed(job_id)
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
