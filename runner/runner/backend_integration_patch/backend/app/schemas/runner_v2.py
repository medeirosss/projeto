from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class RunnerRegisterRequest(BaseModel):
    runner_name: str = Field(min_length=1, max_length=255)
    runner_group: str = Field(default="default", max_length=120)
    registration_token: str = Field(min_length=1)
    host_info: dict[str, Any] = Field(default_factory=dict)


class RunnerRegisterResponse(BaseModel):
    runner_id: str
    runner_secret: str


class RunnerHeartbeatRequest(BaseModel):
    runner_id: str | None = None
    status: str = "online"
    runner_version: str | None = None
    host_info: dict[str, Any] = Field(default_factory=dict)


class RunnerJobResponse(BaseModel):
    job_id: str | None = None
    job_type: str | None = None
    command: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int | None = None


class RunnerJobResultRequest(BaseModel):
    success: bool | None = None
    status: str | None = None
    executor: str | None = None
    artifact_zip: str | None = None
    artifact_sha256: str | None = None
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    error: str | None = None
    duration_seconds: float | None = None
    started_at: str | None = None
    finished_at: str | None = None
    job_id: str | None = None
    job_type: str | None = None


class RunnerCreateJobRequest(BaseModel):
    runner_id: str | None = None
    runner_group: str = "default"
    job_type: Literal["cmd", "powershell", "python", "atomic"]
    command: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    priority: int = 100
    timeout_seconds: int = 300
    created_by: str | None = None


class RunnerInfoResponse(BaseModel):
    runner_id: str
    runner_name: str
    runner_group: str
    status: str
    version: str | None = None
    hostname: str | None = None
    os_name: str | None = None
    ip_address: str | None = None
    last_heartbeat_at: datetime | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class RunnerJobInfoResponse(BaseModel):
    job_id: str
    runner_id: str | None = None
    runner_group: str
    job_type: str
    status: str
    priority: int
    exit_code: int | None = None
    error: str | None = None
    created_at: datetime
    claimed_at: datetime | None = None
    finished_at: datetime | None = None

    class Config:
        from_attributes = True
