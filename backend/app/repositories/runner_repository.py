from datetime import datetime
from sqlalchemy import text
from app.database import SessionLocal


def register_runner(runner_id: str, name: str | None, hostname: str | None):
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
            "now": datetime.utcnow()
        })
        db.commit()


def update_heartbeat(runner_id: str):
    with SessionLocal() as db:
        db.execute(text("""
            UPDATE runners
            SET status = 'online', last_heartbeat = :now
            WHERE runner_id = :runner_id AND enabled = TRUE
        """), {
            "runner_id": runner_id,
            "now": datetime.utcnow()
        })
        db.commit()


def get_pending_jobs(runner_id: str):
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
            "now": datetime.utcnow()
        }).mappings().all()

        db.commit()
        return [dict(row) for row in rows]


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
            RETURNING id, status
        """), {
            "job_id": job_id,
            "runner_id": runner_id,
            "status": status,
            "result": result or {},
            "error": error,
            "now": datetime.utcnow()
        }).mappings().first()

        db.commit()
        return dict(row) if row else None