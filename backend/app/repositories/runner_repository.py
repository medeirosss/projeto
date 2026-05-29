from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.database.connection import SessionLocal


def _json(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def register_runner(runner_id: str, name: str | None, hostname: str | None, metadata: dict | None = None):
    metadata = metadata or {}
    with SessionLocal() as db:
        db.execute(text("""
            INSERT INTO runners (runner_id, name, hostname, status, last_heartbeat, enabled, metadata, created_at, updated_at)
            VALUES (:runner_id, :name, :hostname, 'online', :now, TRUE, CAST(:metadata AS JSONB), :now, :now)
            ON CONFLICT (runner_id)
            DO UPDATE SET
                name = COALESCE(EXCLUDED.name, runners.name),
                hostname = COALESCE(EXCLUDED.hostname, runners.hostname),
                status = 'online',
                last_heartbeat = EXCLUDED.last_heartbeat,
                metadata = COALESCE(runners.metadata, '{}'::jsonb) || EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
        """), {
            "runner_id": runner_id,
            "name": name,
            "hostname": hostname,
            "metadata": _json(metadata),
            "now": datetime.utcnow()
        })
        db.commit()


def update_heartbeat(runner_id: str, metadata: dict | None = None):
    metadata = metadata or {}
    with SessionLocal() as db:
        db.execute(text("""
            UPDATE runners
            SET status = 'online',
                last_heartbeat = :now,
                metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:metadata AS JSONB),
                updated_at = :now
            WHERE runner_id = :runner_id AND enabled = TRUE
        """), {"runner_id": runner_id, "metadata": _json(metadata), "now": datetime.utcnow()})
        db.commit()


def get_pending_jobs(runner_id: str):
    with SessionLocal() as db:
        rows = db.execute(text("""
            UPDATE runner_jobs
            SET status = 'running', started_at = :now, runner_id = COALESCE(runner_id, :runner_id)
            WHERE id IN (
                SELECT id
                FROM runner_jobs
                WHERE status = 'pending'
                  AND (runner_id = :runner_id OR runner_id IS NULL)
                ORDER BY created_at ASC
                LIMIT 5
            )
            RETURNING id, runner_id, job_type, target, payload, status
        """), {"runner_id": runner_id, "now": datetime.utcnow()}).mappings().all()
        db.commit()
        return [dict(row) for row in rows]


def create_runner_job(runner_id: str | None, job_type: str, target: str | None, payload: dict | None):
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO runner_jobs (runner_id, job_type, target, payload, status, created_at)
            VALUES (:runner_id, :job_type, :target, CAST(:payload AS JSONB), 'pending', :now)
            RETURNING id, status, job_type, payload
        """), {
            "runner_id": runner_id,
            "job_type": job_type,
            "target": target,
            "payload": _json(payload),
            "now": datetime.utcnow()
        }).mappings().first()
        db.commit()
        return dict(row)


def save_job_result(job_id: int, runner_id: str, status: str, result: dict | None, error: str | None):
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE runner_jobs
            SET status = :status,
                result = CAST(:result AS JSONB),
                error = :error,
                finished_at = :now
            WHERE id = :job_id
              AND (runner_id = :runner_id OR runner_id IS NULL)
            RETURNING id, status, job_type, payload
        """), {
            "job_id": job_id,
            "runner_id": runner_id,
            "status": status,
            "result": _json(result),
            "error": error,
            "now": datetime.utcnow()
        }).mappings().first()
        db.commit()
        return dict(row) if row else None


def create_validation_job(
    runner_job_id: int | None,
    runner_id: str | None,
    validation_type: str,
    target: str | None,
    expected_state: dict | None,
    alert_id: int | None = None,
    status: str = "pending_manual",
):
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO validation_jobs (
                runner_job_id, runner_id, validation_type, target, expected_state, status, created_at, alert_id
            )
            VALUES (
                :runner_job_id, :runner_id, :validation_type, :target,
                CAST(:expected_state AS JSONB), :status, :now, :alert_id
            )
            RETURNING id, alert_id, runner_job_id, status
        """), {
            "runner_job_id": runner_job_id,
            "runner_id": runner_id,
            "validation_type": validation_type,
            "target": target,
            "expected_state": _json(expected_state),
            "status": status,
            "alert_id": alert_id,
            "now": datetime.utcnow()
        }).mappings().first()
        db.commit()
        return dict(row)


def get_latest_validation_for_alert(alert_db_id: int, validation_type: str):
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT id, alert_id, runner_job_id, validation_type, target, status
            FROM validation_jobs
            WHERE alert_id = :alert_id
              AND validation_type = :validation_type
            ORDER BY id DESC
            LIMIT 1
        """), {"alert_id": alert_db_id, "validation_type": validation_type}).mappings().first()
        return dict(row) if row else None


def link_validation_to_runner_job(validation_id: int, runner_job_id: int, status: str = "queued"):
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE validation_jobs
            SET runner_job_id = :runner_job_id, status = :status, started_at = NULL, finished_at = NULL
            WHERE id = :validation_id
            RETURNING id, alert_id, runner_job_id, validation_type, target, status
        """), {
            "validation_id": validation_id,
            "runner_job_id": runner_job_id,
            "status": status,
        }).mappings().first()
        db.commit()
        return dict(row) if row else None


def update_validation_from_runner_job(runner_job_id: int, status: str, result: dict | None, error: str | None):
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE validation_jobs
            SET status = :status,
                result = CAST(:result AS JSONB),
                details = :error,
                finished_at = :now
            WHERE runner_job_id = :runner_job_id
            RETURNING id, alert_id, validation_type, target, status, result
        """), {
            "runner_job_id": runner_job_id,
            "status": status,
            "result": _json(result),
            "error": error,
            "now": datetime.utcnow()
        }).mappings().first()
        db.commit()
        return dict(row) if row else None


def list_runners(include_disabled: bool = False) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
            SELECT
                runner_id,
                name,
                hostname,
                CASE
                  WHEN enabled IS NOT TRUE THEN 'disabled'
                  WHEN last_heartbeat IS NULL THEN 'offline'
                  WHEN last_heartbeat < (now() AT TIME ZONE 'UTC') - interval '2 minutes' THEN 'offline'
                  ELSE status
                END AS status,
                last_heartbeat,
                enabled,
                metadata,
                metadata->>'ip_address' AS ip_address,
                metadata->>'os' AS os,
                metadata->>'runner_version' AS runner_version,
                metadata->>'atomic_mode' AS atomic_mode,
                (SELECT COUNT(*) FROM runner_jobs j WHERE j.runner_id = runners.runner_id AND j.status IN ('pending','running')) AS open_jobs,
                (SELECT COUNT(*) FROM runner_jobs j WHERE j.runner_id = runners.runner_id) AS total_jobs,
                created_at,
                updated_at
            FROM runners
            WHERE (:include_disabled = TRUE OR enabled = TRUE)
            ORDER BY last_heartbeat DESC NULLS LAST, runner_id ASC
        """), {"include_disabled": include_disabled}).mappings().all()
        return [dict(row) for row in rows]
