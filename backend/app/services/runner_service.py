from __future__ import annotations

from app.repositories.runner_repository import (
    create_runner_job,
    create_validation_job,
    get_pending_jobs,
    mark_validation_running,
    register_runner,
    save_job_result,
    update_heartbeat,
    update_validation_from_runner_job,
)


VALID_JOB_STATUSES = ["success", "failed", "error"]


def register_runner_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    register_runner(
        runner_id=runner_id,
        name=data.get("name"),
        hostname=data.get("hostname"),
    )

    return {
        "success": True,
        "runner_id": runner_id,
        "status": "registered",
    }


def heartbeat_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    update_heartbeat(runner_id)

    return {
        "success": True,
        "runner_id": runner_id,
        "status": "online",
    }


def list_jobs_service(runner_id: str):
    if not runner_id:
        raise ValueError("runner_id is required")

    jobs = get_pending_jobs(runner_id)

    for job in jobs:
        if job.get("job_type") == "validation":
            mark_validation_running(job["id"])

    return {
        "success": True,
        "runner_id": runner_id,
        "jobs": jobs,
    }


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
        )

    return {
        "success": True,
        "job": job,
        "validation": validation,
    }


def job_result_service(job_id: int, data: dict):
    runner_id = data.get("runner_id")
    status = data.get("status")

    if not runner_id:
        raise ValueError("runner_id is required")

    if status not in VALID_JOB_STATUSES:
        raise ValueError("status must be success, failed or error")

    result = save_job_result(
        job_id=job_id,
        runner_id=runner_id,
        status=status,
        result=data.get("result"),
        error=data.get("error"),
    )

    if not result:
        raise ValueError("job not found or not assigned to this runner")

    validation = update_validation_from_runner_job(
        runner_job_id=job_id,
        status=status,
        result=data.get("result"),
        error=data.get("error"),
    )

    return {
        "success": True,
        "job": result,
        "validation": validation,
    }
