from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.services.runner_service import (
    create_job_service,
    get_next_job_v2_service,
    heartbeat_service,
    heartbeat_v2_service,
    job_result_service,
    job_result_v2_service,
    list_jobs_service,
    list_runners_service,
    register_runner_service,
    register_runner_v2_service,
)

router = APIRouter()


def _handle(exc: Exception):
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=401, detail=str(exc))
    raise HTTPException(status_code=400, detail=str(exc))


@router.get("/ping")
def runner_ping():
    return {"success": True, "service": "magi-runner-api", "status": "ok"}


# Runner v2 endpoints. Used by Magi Runner v2.10+.
@router.post("/register")
def register_runner(data: dict, request: Request):
    try:
        return register_runner_v2_service(data or {}, request.client.host if request.client else None)
    except Exception as exc:
        _handle(exc)


@router.post("/heartbeat")
def runner_heartbeat(data: dict, request: Request):
    try:
        return heartbeat_v2_service(data or {}, request.headers, request.client.host if request.client else None)
    except Exception as exc:
        _handle(exc)


@router.get("/jobs/next")
def runner_next_job(request: Request):
    try:
        return get_next_job_v2_service(request.headers)
    except Exception as exc:
        _handle(exc)


@router.post("/jobs/{job_id}/result")
def runner_job_result(job_id: int, data: dict, request: Request):
    try:
        return job_result_v2_service(job_id, data or {}, request.headers)
    except Exception as exc:
        _handle(exc)


# Administrative/testing endpoints. These are reused by current Magi UI/tests.
@router.get("/runners")
def list_registered_runners(include_disabled: bool = Query(False)):
    try:
        return list_runners_service(include_disabled=include_disabled)
    except Exception as exc:
        _handle(exc)


@router.post("/jobs")
def create_runner_job(data: dict):
    try:
        return create_job_service(data or {})
    except Exception as exc:
        _handle(exc)


@router.get("/jobs")
def list_runner_jobs(runner_id: str = Query(...)):
    try:
        return list_jobs_service(runner_id)
    except Exception as exc:
        _handle(exc)


# Legacy compatibility endpoint. Old runners send runner_id in body.
@router.post("/legacy/register")
def legacy_register_runner(data: dict, request: Request):
    try:
        data = data or {}
        data.setdefault("remote_addr", request.client.host if request.client else None)
        return register_runner_service(data)
    except Exception as exc:
        _handle(exc)


@router.post("/legacy/heartbeat")
def legacy_runner_heartbeat(data: dict, request: Request):
    try:
        data = data or {}
        data.setdefault("remote_addr", request.client.host if request.client else None)
        return heartbeat_service(data)
    except Exception as exc:
        _handle(exc)


@router.post("/legacy/jobs/{job_id}/result")
def legacy_runner_job_result(job_id: int, data: dict):
    try:
        return job_result_service(job_id, data or {})
    except Exception as exc:
        _handle(exc)
