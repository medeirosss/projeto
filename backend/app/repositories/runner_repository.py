from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.database.connection import SessionLocal


def register_runner(runner_id: str, name: str | None, hostname: str | None) -> None:
    with SessionLocal() as db:
        db.execute(text("""
            INSERT INTO runners (runner_id, name, hostname, status, last_heartbeat, enabled, created_at)
            VALUES (:runner_id, :name, :hostname, 'online', :now, TRUE, :now)
            ON CONFLICT (runner_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                hostname = EXCLUDED.hostname,
                status = 'online',
                last_heartbeat = EXCLUDED.last_heartbeat
        """), {
            "runner_id": runner_id,
            "name": name,
            "hostname": hostname,
            "now": datetime.utcnow(),
        })
        db.commit()


def update_heartbeat(runner_id: str) -> None:
    with SessionLocal() as db:
        db.execute(text("""
            UPDATE runners
            SET status = 'online', last_heartbeat = :now
            WHERE runner_id = :runner_id AND enabled = TRUE
        """), {
            "runner_id": runner_id,
            "now": datetime.utcnow(),
        })
        db.commit()


def get_pending_jobs(runner_id: str) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
            UPDATE runner_jobs
            SET status = 'running', started_at = :now
            WHERE id IN (
                SELECT id
                FROM runner_jobs
                WHERE status = 'pending'
                  AND (runner_id = :runner_id OR runner_id IS NULL)
                ORDER BY created_at ASC
                LIMIT 5
            )
            RETURNING id, runner_id, job_type, target, payload, status
        """), {
            "runner_id": runner_id,
            "now": datetime.utcnow(),
        }).mappings().all()

        db.commit()
        return [dict(row) for row in rows]


def create_runner_job(
    runner_id: str | None,
    job_type: str,
    target: str | None,
    payload: dict | None,
) -> dict[str, Any]:
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO runner_jobs (
                runner_id,
                job_type,
                target,
                payload,
                status,
                created_at
            )
            VALUES (
                :runner_id,
                :job_type,
                :target,
                CAST(:payload AS JSONB),
                'pending',
                :now
            )
            RETURNING id, runner_id, job_type, target, payload, status
        """), {
            "runner_id": runner_id,
            "job_type": job_type,
            "target": target,
            "payload": json.dumps(payload or {}),
            "now": datetime.utcnow(),
        }).mappings().first()

        db.commit()
        return dict(row) if row else {}


def resolve_alert_db_id(alert_ref: int | str | None) -> int | None:
    if alert_ref in (None, ""):
        return None

    if isinstance(alert_ref, int):
        return alert_ref

    text_ref = str(alert_ref).strip()
    if text_ref.isdigit():
        return int(text_ref)

    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT id
            FROM alerts
            WHERE alert_uuid = :alert_uuid
            LIMIT 1
        """), {"alert_uuid": text_ref}).mappings().first()

        return int(row["id"]) if row else None


def create_validation_job(
    runner_job_id: int,
    runner_id: str | None,
    validation_type: str,
    target: str | None,
    expected_state: dict | None,
    alert_id: int | str | None = None,
    action_execution_id: int | None = None,
) -> dict[str, Any] | None:
    alert_db_id = resolve_alert_db_id(alert_id)

    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO validation_jobs (
                runner_job_id,
                alert_id,
                action_execution_id,
                runner_id,
                validation_type,
                target,
                expected_state,
                status,
                created_at
            )
            VALUES (
                :runner_job_id,
                :alert_id,
                :action_execution_id,
                :runner_id,
                :validation_type,
                :target,
                CAST(:expected_state AS JSONB),
                'pending',
                :now
            )
            RETURNING id, alert_id, runner_job_id, status
        """), {
            "runner_job_id": runner_job_id,
            "alert_id": alert_db_id,
            "action_execution_id": action_execution_id,
            "runner_id": runner_id,
            "validation_type": validation_type,
            "target": target,
            "expected_state": json.dumps(expected_state or {}),
            "now": datetime.utcnow(),
        }).mappings().first()

        db.commit()
        return dict(row) if row else None


def save_job_result(
    job_id: int,
    runner_id: str,
    status: str,
    result: dict | None,
    error: str | None,
) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE runner_jobs
            SET status = :status,
                result = CAST(:result AS JSONB),
                error = :error,
                finished_at = :now
            WHERE id = :job_id
              AND (runner_id = :runner_id OR runner_id IS NULL)
            RETURNING id, status
        """), {
            "job_id": job_id,
            "runner_id": runner_id,
            "status": status,
            "result": json.dumps(result or {}),
            "error": error,
            "now": datetime.utcnow(),
        }).mappings().first()

        db.commit()
        return dict(row) if row else None


def update_validation_from_runner_job(
    runner_job_id: int,
    status: str,
    result: dict | None,
    error: str | None,
) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("""
            WITH updated AS (
                UPDATE validation_jobs
                SET status = :status,
                    result = CAST(:result AS JSONB),
                    details = :error,
                    finished_at = :now
                WHERE runner_job_id = :runner_job_id
                RETURNING id, alert_id, runner_job_id, status
            )
            SELECT
                updated.id,
                updated.alert_id,
                alerts.alert_uuid,
                updated.runner_job_id,
                updated.status
            FROM updated
            LEFT JOIN alerts ON alerts.id = updated.alert_id
        """), {
            "runner_job_id": runner_job_id,
            "status": status,
            "result": json.dumps(result or {}),
            "error": error,
            "now": datetime.utcnow(),
        }).mappings().first()

        db.commit()
        return dict(row) if row else None
