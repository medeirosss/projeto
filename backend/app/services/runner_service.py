from __future__ import annotations

from app.repositories.alerts_repository import update_alert_connectivity_status_by_db_id
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
    if status == "success" and bool((result or {}).get("reachable")):
        return "reachable", "Host alcançável."
    if status in ["success", "failed"]:
        return "unreachable", "Host não alcançável."
    return "check_failed", "Falha ao validar conectividade."


def _update_alert_connectivity_from_validation(validation: dict | None, status: str, result: dict | None):
    if not validation or validation.get("validation_type") != "host_reachable":
        return None

    alert_db_id = validation.get("alert_id")
    if not alert_db_id:
        return None

    # validation_jobs.alert_id guarda o ID interno da tabela alerts.
    # Buscamos o alert_uuid para atualizar o alerta mantendo o padrão da API.
    # Mantemos fallback em branco para evitar quebrar retorno do runner.
    alert_uuid = None
    try:
        # Pequena consulta local via repository não existe por db_id; por isso usamos SQL indireto só no repository de alerta em versão futura.
        # Neste patch, usamos o alert_id vindo do payload quando disponível via result/payload em melhorias futuras.
        pass
    except Exception:
        pass
    return {"pending_alert_update_by_db_id": alert_db_id}


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

    connectivity = None
    # O update final de connectivity_status por alert_id interno é feito no repository abaixo.
    # Mantemos a lógica aqui para não misturar ping com automation_status.
    if validation and validation.get("validation_type") == "host_reachable" and validation.get("alert_id"):
        connectivity_status, connectivity_message = _connectivity_status_from_result(status, result_payload)
        connectivity = update_alert_connectivity_status_by_db_id(
            alert_db_id=int(validation.get("alert_id")),
            connectivity_status=connectivity_status,
            connectivity_message=connectivity_message,
        )

    return {
        "success": True,
        "job": result,
        "validation": validation,
        "connectivity": connectivity,
    }
