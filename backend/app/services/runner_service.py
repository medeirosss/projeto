from __future__ import annotations

from datetime import datetime
from sqlalchemy import text

from app.database.connection import SessionLocal
from app.repositories.atomic_repository import update_atomic_execution_from_runner_job
from app.repositories.runner_repository import (
    create_runner_job,
    create_validation_job,
    get_pending_jobs,
    register_runner,
    save_job_result,
    update_heartbeat,
    update_validation_from_runner_job,
)


def register_runner_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    register_runner(
        runner_id=runner_id,
        name=data.get("name"),
        hostname=data.get("hostname"),
    )

    return {"success": True, "runner_id": runner_id, "status": "registered"}


def heartbeat_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    update_heartbeat(runner_id)
    return {"success": True, "runner_id": runner_id, "status": "online"}


def list_jobs_service(runner_id: str):
    if not runner_id:
        raise ValueError("runner_id is required")

    jobs = get_pending_jobs(runner_id)
    return {"success": True, "runner_id": runner_id, "jobs": jobs}


def create_job_service(data: dict):
    job_type = data.get("job_type")
    if not job_type:
        raise ValueError("job_type is required")

    payload = data.get("payload") or {}
    job = create_runner_job(
        runner_id=data.get("runner_id"),
        job_type=job_type,
        target=data.get("target"),
        payload=payload,
    )

    validation = None
    if job_type == "validation":
        validation_type = payload.get("validation_type")
        if not validation_type:
            raise ValueError("payload.validation_type is required for validation jobs")

        validation = create_validation_job(
            runner_job_id=job["id"],
            runner_id=data.get("runner_id"),
            validation_type=validation_type,
            target=data.get("target"),
            expected_state=payload.get("expected_state"),
            alert_id=payload.get("alert_id"),
            status="queued",
        )

    return {"success": True, "job": job, "validation": validation}


def _connectivity_status_from_result(status: str, result: dict | None) -> tuple[str, str]:
    result = result or {}

    if status == "success" and bool(result.get("reachable")):
        return "reachable", "Host alcançável."

    if status in ["success", "failed"]:
        return "unreachable", "Host não alcançável."

    return "check_failed", "Falha ao validar conectividade."


def _update_alert_connectivity_status_by_db_id(
    alert_db_id: int,
    connectivity_status: str,
    connectivity_message: str,
):
    """Atualiza somente os campos de conectividade.

    Importante:
    - Não atualiza automation_status.
    - Não recalcula recommended_actions aqui para evitar quebrar o retorno do Runner.
    - Contexto e recomendações podem ser recalculados em uma etapa posterior, de forma controlada.
    """
    with SessionLocal() as db:
        row = db.execute(
            text(
                """
                UPDATE alerts
                SET connectivity_status = :connectivity_status,
                    connectivity_message = :connectivity_message,
                    connectivity_at = :connectivity_at
                WHERE id = :alert_db_id
                RETURNING id, alert_uuid, connectivity_status, connectivity_message, connectivity_at, automation_status
                """
            ),
            {
                "alert_db_id": alert_db_id,
                "connectivity_status": connectivity_status,
                "connectivity_message": connectivity_message,
                "connectivity_at": datetime.utcnow(),
            },
        ).mappings().first()
        db.commit()
        return dict(row) if row else None


def job_result_service(job_id: int, data: dict):
    runner_id = data.get("runner_id")
    status = data.get("status")

    if not runner_id:
        raise ValueError("runner_id is required")

    if status not in ["success", "failed", "error"]:
        raise ValueError("status must be success, failed or error")

    result_payload = data.get("result") or {}

    result = save_job_result(
        job_id=job_id,
        runner_id=runner_id,
        status=status,
        result=result_payload,
        error=data.get("error"),
    )

    if not result:
        raise ValueError("job not found or not assigned to this runner")

    validation = update_validation_from_runner_job(
        runner_job_id=job_id,
        status=status,
        result=result_payload,
        error=data.get("error"),
    )

    atomic_execution = None
    if result and result.get("job_type") == "atomic_validation":
        atomic_execution = update_atomic_execution_from_runner_job(
            runner_job_id=job_id,
            runner_id=runner_id,
            status=status,
            result=result_payload,
            error=data.get("error"),
        )

    connectivity = None

    if validation and validation.get("validation_type") == "host_reachable" and validation.get("alert_id"):
        connectivity_status, connectivity_message = _connectivity_status_from_result(status, result_payload)
        connectivity = _update_alert_connectivity_status_by_db_id(
            alert_db_id=int(validation.get("alert_id")),
            connectivity_status=connectivity_status,
            connectivity_message=connectivity_message,
        )

    return {
        "success": True,
        "job": result,
        "validation": validation,
        "atomic_execution": atomic_execution,
        "connectivity": connectivity,
    }
