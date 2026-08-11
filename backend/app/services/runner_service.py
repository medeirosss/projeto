from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import text

from app.database.connection import SessionLocal
from app.repositories.atomic_repository import update_atomic_execution_from_runner_job
from app.services.target_service import ingest_runner_discovery_result
from app.services.service_discovery_service import ingest_runner_service_result
from app.services.credential_engine_service import ingest_runner_credential_result
from app.services.deep_inventory_service import ingest_runner_deep_result
from app.repositories.runner_repository import (
    create_runner_job,
    create_runner_registration,
    create_validation_job,
    get_next_job,
    get_pending_jobs,
    list_runners,
    register_runner,
    save_job_result,
    update_heartbeat,
    update_validation_from_runner_job,
    validate_runner_secret,
)


def _flatten_host_info(host_info: dict[str, Any] | None) -> dict[str, Any]:
    host_info = host_info or {}
    metadata = dict(host_info)
    # Common Runner v2 keys are preserved, but also normalized for existing UI.
    if host_info.get("platform") and not metadata.get("os"):
        metadata["os"] = host_info.get("platform")
    if host_info.get("hostname") and not metadata.get("hostname"):
        metadata["hostname"] = host_info.get("hostname")
    if host_info.get("primary_ip") and not metadata.get("ip_address"):
        metadata["ip_address"] = host_info.get("primary_ip")
    return metadata


def _auth_runner_from_headers(headers) -> str:
    runner_id = headers.get("x-runner-id") or headers.get("X-Runner-ID")
    runner_secret = headers.get("x-runner-secret") or headers.get("X-Runner-Secret")
    if not runner_id:
        raise ValueError("X-Runner-ID header is required")
    if not validate_runner_secret(runner_id, runner_secret):
        raise PermissionError("invalid runner credentials")
    return runner_id


def register_runner_v2_service(data: dict, remote_addr: str | None = None):
    host_info = data.get("host_info") or {}
    metadata = _flatten_host_info(host_info)
    if remote_addr:
        metadata["remote_addr"] = remote_addr
    if data.get("registration_token"):
        # Kept only for traceability in the first v1.0 registration model.
        metadata["registration_token_present"] = True

    runner_name = data.get("runner_name") or data.get("name") or host_info.get("hostname")
    hostname = host_info.get("hostname") or data.get("hostname")
    created = create_runner_registration(runner_name=runner_name, hostname=hostname, metadata=metadata)
    return {
        "success": True,
        "status": "registered",
        "runner_id": created["runner_id"],
        "runner_secret": created["runner_secret"],
    }


def heartbeat_v2_service(data: dict, headers, remote_addr: str | None = None):
    runner_id = _auth_runner_from_headers(headers)
    metadata = _flatten_host_info(data.get("host_info") or {})
    if data.get("runner_version"):
        metadata["runner_version"] = data.get("runner_version")
    if data.get("status"):
        metadata["reported_status"] = data.get("status")
    if remote_addr:
        metadata["remote_addr"] = remote_addr
    row = update_heartbeat(runner_id, metadata=metadata)
    if not row:
        raise ValueError("runner not found or disabled")
    return {"success": True, "runner_id": runner_id, "status": "online"}


def get_next_job_v2_service(headers):
    runner_id = _auth_runner_from_headers(headers)
    job = get_next_job(runner_id)
    if job and job.get("job_type") in {"credential_validate","deep_inventory"}:
        # Inject plaintext only into the transient HTTP response. runner_jobs stores only credential_id.
        from app.services.credentials_service import get_credential_by_id
        payload = dict(job.get("payload") or {})
        cred = get_credential_by_id(payload.get("credential_id"), include_secret=True)
        if not cred or not cred.get("password"):
            # Do not strand a job in running when a credential was removed after scheduling.
            failed = save_job_result(int(job["job_id"]), runner_id, "failed", {"status":"failed","error":"Credencial indisponível."}, "Credencial indisponível.")
            if failed:
                ingest_runner_credential_result(int(job["job_id"]), runner_id, "failed", {"status":"failed","error":"Credencial indisponível."}, "Credencial indisponível.")
            return {"success": True, "runner_id": runner_id, "job": None}
        payload["credential"] = {
            "id": cred.get("id"), "name": cred.get("name"), "type": cred.get("type"),
            "username": cred.get("username"), "domain": cred.get("domain"),
            "secret": cred.get("password"), "metadata": cred.get("metadata") or {},
        }
        job = dict(job); job["payload"] = payload
    return {"success": True, "runner_id": runner_id, "job": job}


def job_result_v2_service(job_id: int, data: dict, headers):
    runner_id = _auth_runner_from_headers(headers)
    status = data.get("status")
    if status not in ["success", "failed", "error", "timeout"]:
        raise ValueError("status must be success, failed, error or timeout")
    result = save_job_result(
        job_id=int(job_id),
        runner_id=runner_id,
        status=status,
        result=data,
        error=data.get("error") or data.get("stderr"),
    )
    if not result:
        raise ValueError("job not found or not assigned to this runner")
    validation = update_validation_from_runner_job(int(job_id), status=status, result=data, error=data.get("error"))
    atomic_execution = None
    if result and result.get("job_type") == "atomic_validation":
        atomic_execution = update_atomic_execution_from_runner_job(
            runner_job_id=int(job_id), runner_id=runner_id, status=status, result=data, error=data.get("error"),
        )
    discovery = None
    service_discovery = None
    credential_engine = None
    deep_inventory = None
    security_check = None
    if result and result.get("job_type") == "nmap_discovery":
        discovery = ingest_runner_discovery_result(int(job_id), runner_id, status, data, data.get("error"))
    if result and result.get("job_type") == "service_discovery":
        service_discovery = ingest_runner_service_result(int(job_id), runner_id, status, data, data.get("error"))
    if result and result.get("job_type") == "credential_validate":
        credential_engine = ingest_runner_credential_result(int(job_id), runner_id, status, data, data.get("error"))
    if result and result.get("job_type") == "deep_inventory":
        deep_inventory = ingest_runner_deep_result(int(job_id), runner_id, status, data, data.get("error"))
    if result and result.get("job_type") == "security_check":
        from app.repositories.validation_repository import ingest_execution_result
        security_check = ingest_execution_result(int(job_id), status, data, data.get("error"))
    return {"success": True, "job": result, "validation": validation, "atomic_execution": atomic_execution, "discovery": discovery, "service_discovery": service_discovery, "credential_engine": credential_engine, "deep_inventory": deep_inventory, "security_check": security_check}


# Legacy /api/runner compatibility used by previous Magi builds.
def register_runner_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    metadata = data.get("metadata") or {}
    for key in ["ip_address", "os", "runner_version", "atomic_mode", "remote_addr"]:
        if data.get(key) is not None:
            metadata[key] = data.get(key)

    register_runner(
        runner_id=runner_id,
        name=data.get("name"),
        hostname=data.get("hostname"),
        metadata=metadata,
    )

    return {"success": True, "runner_id": runner_id, "status": "registered"}


def heartbeat_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    metadata = data.get("metadata") or {}
    for key in ["ip_address", "os", "runner_version", "atomic_mode", "remote_addr"]:
        if data.get(key) is not None:
            metadata[key] = data.get(key)

    update_heartbeat(runner_id, metadata=metadata)
    return {"success": True, "runner_id": runner_id, "status": "online"}


def list_runners_service(include_disabled: bool = False):
    return {"success": True, "runners": list_runners(include_disabled=include_disabled)}


def list_jobs_service(runner_id: str):
    if not runner_id:
        raise ValueError("runner_id is required")

    jobs = get_pending_jobs(runner_id)
    return {"success": True, "runner_id": runner_id, "jobs": jobs}


def create_job_service(data: dict):
    job_type = data.get("job_type") or data.get("executor") or data.get("type")
    if not job_type:
        raise ValueError("job_type is required")

    payload = data.get("payload") or {}
    if data.get("executor") and not payload.get("executor"):
        payload["executor"] = data.get("executor")
    if data.get("command") and not payload.get("command"):
        payload["command"] = data.get("command")

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

    if status not in ["success", "failed", "error", "timeout"]:
        raise ValueError("status must be success, failed, error or timeout")

    result_payload = data.get("result") or data

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
