from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from app.services.runner_service import (
    create_job_service,
    heartbeat_service,
    job_result_service,
    list_jobs_service,
    list_runners_service,
    register_runner_service,
)

router = APIRouter()


@router.post("/register")
def register_runner(data: dict, request: Request):
    try:
        data = data or {}
        data.setdefault("remote_addr", request.client.host if request.client else None)
        return register_runner_service(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/heartbeat")
def runner_heartbeat(data: dict, request: Request):
    try:
        data = data or {}
        data.setdefault("remote_addr", request.client.host if request.client else None)
        return heartbeat_service(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))




@router.get("/runners")
def list_registered_runners(include_disabled: bool = Query(False)):
    try:
        return list_runners_service(include_disabled=include_disabled)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/jobs")
def create_runner_job(data: dict):
    try:
        return create_job_service(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/jobs")
def list_runner_jobs(runner_id: str = Query(...)):
    try:
        return list_jobs_service(runner_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/jobs/{job_id}/result")
def runner_job_result(job_id: int, data: dict):
    try:
        return job_result_service(job_id, data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
