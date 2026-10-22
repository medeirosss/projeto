from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB

try:
    from app.database import Base
except Exception:  # fallback for projects that expose Base elsewhere
    from database import Base  # type: ignore


class Runner(Base):
    __tablename__ = "runners"

    id = Column(Integer, primary_key=True, index=True)
    runner_uuid = Column(String(64), unique=True, nullable=False, index=True)
    runner_name = Column(String(255), nullable=False)
    runner_group = Column(String(120), nullable=False, default="default", index=True)
    runner_secret_hash = Column(String(255), nullable=False)
    status = Column(String(40), nullable=False, default="registered", index=True)
    version = Column(String(80), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_name = Column(String(120), nullable=True)
    ip_address = Column(String(80), nullable=True)
    host_info = Column(JSONB, nullable=False, default=dict)
    last_heartbeat_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class RunnerJob(Base):
    __tablename__ = "runner_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_uuid = Column(String(64), unique=True, nullable=False, index=True)
    runner_uuid = Column(String(64), ForeignKey("runners.runner_uuid", ondelete="SET NULL"), nullable=True, index=True)
    runner_group = Column(String(120), nullable=False, default="default", index=True)
    job_type = Column(String(60), nullable=False)
    command = Column(Text, nullable=False)
    payload = Column(JSONB, nullable=False, default=dict)
    status = Column(String(40), nullable=False, default="queued", index=True)
    priority = Column(Integer, nullable=False, default=100)
    timeout_seconds = Column(Integer, nullable=False, default=300)
    claimed_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    result = Column(JSONB, nullable=True)
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    created_by = Column(String(120), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
