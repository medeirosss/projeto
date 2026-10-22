from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

try:
    from app.database import get_db
except Exception:
    from database import get_db  # type: ignore

from app.models.runner_v2 import Runner, RunnerJob
from app.schemas.runner_v2 import (
    RunnerCreateJobRequest,
    RunnerHeartbeatRequest,
    RunnerInfoResponse,
    RunnerJobInfoResponse,
    RunnerJobResponse,
    RunnerJobResultRequest,
    RunnerRegisterRequest,
    RunnerRegisterResponse,
)
from app.services.runner_v2_security import (
    get_registration_token,
    hash_secret,
    new_job_uuid,
    new_runner_secret,
    new_runner_uuid,
    verify_secret,
)

router = APIRouter(prefix="/api/runners", tags=["Runner v2"])


@router.get("/ping")
def ping_runner_api():
    return {"ok": True, "service": "magi-runner-api", "version": "2.9"}



def _extract_host_field(host_info: dict, *names: str) -> str | None:
    for name in names:
        value = host_info.get(name)
        if value:
            return str(value)
    return None


def _runner_to_response(runner: Runner) -> RunnerInfoResponse:
    return RunnerInfoResponse(
        runner_id=runner.runner_uuid,
        runner_name=runner.runner_name,
        runner_group=runner.runner_group,
        status=runner.status,
        version=runner.version,
        hostname=runner.hostname,
        os_name=runner.os_name,
        ip_address=runner.ip_address,
        last_heartbeat_at=runner.last_heartbeat_at,
        created_at=runner.created_at,
    )


def _job_to_response(job: RunnerJob) -> RunnerJobInfoResponse:
    return RunnerJobInfoResponse(
        job_id=job.job_uuid,
        runner_id=job.runner_uuid,
        runner_group=job.runner_group,
        job_type=job.job_type,
        status=job.status,
        priority=job.priority,
        exit_code=job.exit_code,
        error=job.error,
        created_at=job.created_at,
        claimed_at=job.claimed_at,
        finished_at=job.finished_at,
    )


def authenticate_runner(
    db: Session,
    x_runner_id: Annotated[str | None, Header()] = None,
    x_runner_secret: Annotated[str | None, Header()] = None,
) -> Runner:
    if not x_runner_id or not x_runner_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Runner credentials are required")
    runner = db.query(Runner).filter(Runner.runner_uuid == x_runner_id).first()
    if not runner or not verify_secret(x_runner_secret, runner.runner_secret_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid runner credentials")
    return runner


@router.post("/register", response_model=RunnerRegisterResponse)
def register_runner(payload: RunnerRegisterRequest, request: Request, db: Session = Depends(get_db)):
    expected_token = get_registration_token()
    if expected_token == "CHANGE_ME":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MAGI_RUNNER_REGISTRATION_TOKEN is not configured on backend",
        )
    if payload.registration_token != expected_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid registration token")

    host_info = payload.host_info or {}
    runner_uuid = new_runner_uuid()
    runner_secret = new_runner_secret()
    runner = Runner(
        runner_uuid=runner_uuid,
        runner_name=payload.runner_name,
        runner_group=payload.runner_group or "default",
        runner_secret_hash=hash_secret(runner_secret),
        status="registered",
        hostname=_extract_host_field(host_info, "hostname", "fqdn"),
        os_name=_extract_host_field(host_info, "os", "os_name"),
        ip_address=request.client.host if request.client else None,
        host_info=host_info,
    )
    db.add(runner)
    db.commit()
    return RunnerRegisterResponse(runner_id=runner_uuid, runner_secret=runner_secret)


@router.post("/heartbeat")
def heartbeat(
    payload: RunnerHeartbeatRequest,
    db: Session = Depends(get_db),
    x_runner_id: Annotated[str | None, Header()] = None,
    x_runner_secret: Annotated[str | None, Header()] = None,
):
    runner = authenticate_runner(db, x_runner_id, x_runner_secret)
    host_info = payload.host_info or {}
    runner.status = payload.status or "online"
    runner.version = payload.runner_version
    runner.host_info = host_info
    runner.hostname = _extract_host_field(host_info, "hostname", "fqdn") or runner.hostname
    runner.os_name = _extract_host_field(host_info, "os", "os_name") or runner.os_name
    runner.last_heartbeat_at = datetime.utcnow()
    runner.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "runner_id": runner.runner_uuid, "status": runner.status}


@router.get("/jobs/next", response_model=RunnerJobResponse)
def next_job(
    db: Session = Depends(get_db),
    x_runner_id: Annotated[str | None, Header()] = None,
    x_runner_secret: Annotated[str | None, Header()] = None,
):
    runner = authenticate_runner(db, x_runner_id, x_runner_secret)
    job = (
        db.query(RunnerJob)
        .filter(RunnerJob.status == "queued")
        .filter((RunnerJob.runner_uuid == runner.runner_uuid) | ((RunnerJob.runner_uuid.is_(None)) & (RunnerJob.runner_group == runner.runner_group)))
        .order_by(RunnerJob.priority.asc(), RunnerJob.created_at.asc())
        .first()
    )
    if not job:
        return RunnerJobResponse()
    job.status = "claimed"
    job.runner_uuid = runner.runner_uuid
    job.claimed_at = datetime.utcnow()
    job.updated_at = datetime.utcnow()
    db.commit()
    return RunnerJobResponse(
        job_id=job.job_uuid,
        job_type=job.job_type,
        command=job.command,
        payload=job.payload or {},
        timeout_seconds=job.timeout_seconds,
    )


@router.post("/jobs/{job_id}/result")
def job_result(
    job_id: str,
    payload: RunnerJobResultRequest,
    db: Session = Depends(get_db),
    x_runner_id: Annotated[str | None, Header()] = None,
    x_runner_secret: Annotated[str | None, Header()] = None,
):
    runner = authenticate_runner(db, x_runner_id, x_runner_secret)
    job = db.query(RunnerJob).filter(RunnerJob.job_uuid == job_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    if job.runner_uuid != runner.runner_uuid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Job belongs to another runner")
    payload_status = (payload.status or "").lower()
    success = payload.success if payload.success is not None else payload_status in {"success", "finished", "ok"}
    job.status = "finished" if success else "failed"
    job.finished_at = datetime.utcnow()
    job.result = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
    job.stdout = payload.stdout
    job.stderr = payload.stderr
    job.exit_code = payload.exit_code
    job.error = payload.error
    job.updated_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "job_id": job.job_uuid, "status": job.status}


# Admin endpoints. Protect them with the existing Magi auth dependency when wiring into production.
@router.get("", response_model=list[RunnerInfoResponse])
def list_runners(db: Session = Depends(get_db)):
    runners = db.query(Runner).order_by(Runner.created_at.desc()).limit(200).all()
    return [_runner_to_response(r) for r in runners]


@router.get("/jobs", response_model=list[RunnerJobInfoResponse])
def list_jobs(db: Session = Depends(get_db)):
    jobs = db.query(RunnerJob).order_by(RunnerJob.created_at.desc()).limit(200).all()
    return [_job_to_response(j) for j in jobs]


@router.post("/jobs", response_model=RunnerJobInfoResponse)
def create_job(payload: RunnerCreateJobRequest, db: Session = Depends(get_db)):
    job = RunnerJob(
        job_uuid=new_job_uuid(),
        runner_uuid=payload.runner_id,
        runner_group=payload.runner_group or "default",
        job_type=payload.job_type,
        command=payload.command,
        payload=payload.payload or {},
        priority=payload.priority,
        timeout_seconds=payload.timeout_seconds,
        status="queued",
        created_by=payload.created_by,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _job_to_response(job)
