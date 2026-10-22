from app.services.runner_service import create_job_service
from fastapi import APIRouter, HTTPException, Query
from app.services.runner_service import (
    register_runner_service,
    heartbeat_service,
    list_jobs_service,
    job_result_service,
)

router = APIRouter()


@router.post("/register")
def register_runner(data: dict):
    try:
        return register_runner_service(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/heartbeat")
def runner_heartbeat(data: dict):
    try:
        return heartbeat_service(data)
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
@router.post("/jobs")
def create_runner_job(data: dict):
    try:
        return create_job_service(data)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))