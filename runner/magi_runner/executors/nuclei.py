from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import ExecutionResult
from magi_runner.core.nuclei_capability import nuclei_capability


def _find_nuclei(payload: dict[str, Any]) -> str | None:
    cap = nuclei_capability(payload.get("nuclei_path"))
    return cap.get("binary_path")


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return rows


class NucleiExecutor:
    name = "nuclei"

    def run(self, job: dict[str, Any], workdir: str, timeout_seconds: int) -> ExecutionResult:
        started = datetime.now(timezone.utc)
        payload = job.get("payload") or {}
        target = str(payload.get("target") or job.get("target") or "").strip()
        template = str(payload.get("template") or payload.get("template_id") or "").strip()
        template_root = str(payload.get("nuclei_templates_path") or os.environ.get("MAGI_NUCLEI_TEMPLATES") or r"C:\Program Files\Magi\Runner\tools\nuclei\templates")
        if not target:
            raise ValueError("nuclei requer target")
        if not template:
            raise ValueError("nuclei requer template/template_id")

        binary = _find_nuclei(payload)
        capability = nuclei_capability(payload.get("nuclei_path"), template_root)
        if not binary:
            finished = datetime.now(timezone.utc)
            message = "Nuclei Engine indisponível no Runner."
            metadata = {
                "finding": {"detected": None, "status": "not_evaluated", "message": message},
                "evidence": {"provider": "nuclei", "target": target, "template_id": template, "reason": "engine_unavailable", "infrastructure_status": "engine_unavailable", "searched_paths": capability.get("searched_paths", [])},
                "message": message,
                "confirmation_status": "not_evaluated",
                "execution_scope": "runner_to_target",
                "requested_target": target,
                "executed_real_test": False,
            }
            return ExecutionResult(
                status="failed", exit_code=127, stdout="", stderr=message,
                started_at=started.isoformat(), finished_at=finished.isoformat(),
                duration_seconds=(finished-started).total_seconds(), metadata=metadata
            )

        template_path = Path(template)
        if not template_path.is_absolute():
            template_path = Path(template_root) / template
        if not template_path.exists():
            finished = datetime.now(timezone.utc)
            message = f"Template Nuclei indisponível no Runner: {template}"
            metadata = {
                "finding": {"detected": None, "status": "not_evaluated", "message": message},
                "evidence": {"provider": "nuclei", "target": target, "template_id": template, "reason": "template_unavailable", "template_path": str(template_path), "infrastructure_status": "template_unavailable"},
                "message": message, "confirmation_status": "not_evaluated",
                "execution_scope": "runner_to_target", "requested_target": target, "executed_real_test": False,
            }
            return ExecutionResult(status="failed",exit_code=66,stdout="",stderr=message,
                started_at=started.isoformat(),finished_at=finished.isoformat(),
                duration_seconds=(finished-started).total_seconds(),metadata=metadata)
        args = [binary, "-u", target, "-t", str(template_path), "-jsonl", "-silent", "-no-color", "-duc"]
        severity = payload.get("severity")
        if severity:
            args += ["-severity", str(severity)]
        started_mono = time.monotonic()
        try:
            cp = subprocess.run(
                args, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=max(5, int(timeout_seconds))
            )
            rows = _parse_jsonl(cp.stdout)
            detected = bool(rows)
            status = "success" if cp.returncode == 0 else "failed"
            finding_status = "detected" if detected else ("not_detected" if status == "success" else "error")
            message = (
                f"Nuclei confirmou {len(rows)} ocorrência(s) para {template} em {target}."
                if detected else
                f"Nuclei não confirmou {template} em {target}."
                if status == "success" else
                f"Nuclei falhou ao avaliar {template} em {target}."
            )
            evidence = {
                "provider": "nuclei", "target": target, "template_id": template,
                "matches": rows[:100], "match_count": len(rows),
                "exit_code": cp.returncode,
            }
            metadata = {
                "finding": {"detected": detected if status == "success" else None, "status": finding_status, "message": message},
                "evidence": evidence, "message": message,
                "confirmation_status": finding_status,
                "execution_scope": "runner_to_target",
                "requested_target": target,
                "executed_real_test": True,
            }
            finished = datetime.now(timezone.utc)
            Path(workdir, "nuclei.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
            return ExecutionResult(
                status=status, exit_code=cp.returncode, stdout=cp.stdout, stderr=cp.stderr,
                started_at=started.isoformat(), finished_at=finished.isoformat(),
                duration_seconds=round(time.monotonic()-started_mono, 3), metadata=metadata
            )
        except subprocess.TimeoutExpired as exc:
            finished = datetime.now(timezone.utc)
            message = f"Nuclei excedeu timeout ao avaliar {target}."
            metadata = {
                "finding": {"detected": None, "status": "error", "message": message},
                "evidence": {"provider": "nuclei", "target": target, "template_id": template, "reason": "timeout"},
                "message": message, "confirmation_status": "error",
                "execution_scope": "runner_to_target", "requested_target": target, "executed_real_test": True,
            }
            return ExecutionResult(
                status="timeout", exit_code=124, stdout=exc.stdout or "", stderr=exc.stderr or "",
                started_at=started.isoformat(), finished_at=finished.isoformat(),
                duration_seconds=(finished-started).total_seconds(), metadata=metadata
            )
