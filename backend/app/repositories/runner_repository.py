from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.database.connection import SessionLocal


def _json(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def ensure_runner_schema() -> None:
    """Creates/normalizes the Runner v2 tables.

    This is intentionally idempotent because some Magi environments are being
    upgraded from previous validation-engine builds with slightly different
    runner table definitions.
    """
    with SessionLocal() as db:
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS runners (
            id SERIAL PRIMARY KEY,
            runner_id VARCHAR(100) UNIQUE NOT NULL,
            name VARCHAR(150),
            hostname VARCHAR(255),
            status VARCHAR(50) NOT NULL DEFAULT 'offline',
            last_heartbeat TIMESTAMP,
            token_hash TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS runner_jobs (
            id SERIAL PRIMARY KEY,
            runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
            job_type VARCHAR(100) NOT NULL,
            target VARCHAR(255),
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            status VARCHAR(50) NOT NULL DEFAULT 'pending',
            result JSONB,
            error TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            finished_at TIMESTAMP
        );
        """))
        db.execute(text("ALTER TABLE runners ALTER COLUMN name DROP NOT NULL;"))
        db.execute(text("ALTER TABLE runners ADD COLUMN IF NOT EXISTS token_hash TEXT;"))
        db.execute(text("ALTER TABLE runners ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;"))
        db.execute(text("ALTER TABLE runners ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;"))
        db.execute(text("ALTER TABLE runners ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;"))
        db.execute(text("ALTER TABLE runner_jobs ADD COLUMN IF NOT EXISTS result JSONB;"))
        db.execute(text("ALTER TABLE runner_jobs ADD COLUMN IF NOT EXISTS error TEXT;"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_runner_jobs_status ON runner_jobs(status);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_runner_jobs_runner_status ON runner_jobs(runner_id, status);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_runner_jobs_created_at ON runner_jobs(created_at DESC);"))
        db.commit()


def register_runner(runner_id: str, name: str | None, hostname: str | None, metadata: dict | None = None, runner_secret: str | None = None):
    metadata = metadata or {}
    token_hash = _hash_secret(runner_secret) if runner_secret else None
    with SessionLocal() as db:
        db.execute(text("""
            INSERT INTO runners (runner_id, name, hostname, status, last_heartbeat, enabled, token_hash, metadata, created_at, updated_at)
            VALUES (:runner_id, :name, :hostname, 'online', :now, TRUE, :token_hash, CAST(:metadata AS JSONB), :now, :now)
            ON CONFLICT (runner_id)
            DO UPDATE SET
                name = COALESCE(EXCLUDED.name, runners.name),
                hostname = COALESCE(EXCLUDED.hostname, runners.hostname),
                status = 'online',
                last_heartbeat = EXCLUDED.last_heartbeat,
                token_hash = COALESCE(EXCLUDED.token_hash, runners.token_hash),
                metadata = COALESCE(runners.metadata, '{}'::jsonb) || EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at
        """), {
            "runner_id": runner_id,
            "name": name,
            "hostname": hostname,
            "metadata": _json(metadata),
            "token_hash": token_hash,
            "now": datetime.utcnow()
        })
        db.commit()


def create_runner_registration(runner_name: str | None, hostname: str | None, metadata: dict | None = None) -> dict[str, str]:
    runner_id = f"runner-{uuid.uuid4().hex[:12]}"
    runner_secret = secrets.token_urlsafe(32)
    register_runner(runner_id=runner_id, name=runner_name or hostname or runner_id, hostname=hostname, metadata=metadata, runner_secret=runner_secret)
    return {"runner_id": runner_id, "runner_secret": runner_secret}


def validate_runner_secret(runner_id: str, runner_secret: str | None) -> bool:
    if not runner_id or not runner_secret:
        return False
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT token_hash, enabled
            FROM runners
            WHERE runner_id = :runner_id
            LIMIT 1
        """), {"runner_id": runner_id}).mappings().first()
        if not row or not row.get("enabled") or not row.get("token_hash"):
            return False
        return secrets.compare_digest(str(row["token_hash"]), _hash_secret(runner_secret))


def update_heartbeat(runner_id: str, metadata: dict | None = None):
    metadata = metadata or {}
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE runners
            SET status = 'online',
                last_heartbeat = :now,
                metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:metadata AS JSONB),
                updated_at = :now
            WHERE runner_id = :runner_id AND enabled = TRUE
            RETURNING runner_id, status, last_heartbeat
        """), {"runner_id": runner_id, "metadata": _json(metadata), "now": datetime.utcnow()}).mappings().first()
        db.commit()
        return dict(row) if row else None



def get_single_online_runner() -> dict[str, Any] | None:
    """Returns the most recently active enabled Runner. Golden Image 1.0 uses one Runner."""
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT runner_id, name, hostname, last_heartbeat, metadata
            FROM runners
            WHERE enabled = TRUE
              AND last_heartbeat IS NOT NULL
              AND last_heartbeat >= (now() AT TIME ZONE 'UTC') - interval '2 minutes'
              AND status = 'online'
            ORDER BY last_heartbeat DESC
            LIMIT 1
        """)).mappings().first()
        return dict(row) if row else None

def get_next_job(runner_id: str):
    with SessionLocal() as db:
        row = db.execute(text("""
            UPDATE runner_jobs
            SET status = 'running', started_at = :now, runner_id = COALESCE(runner_id, :runner_id)
            WHERE id = (
                SELECT id
                FROM runner_jobs
                WHERE status = 'pending'
                  AND (runner_id = :runner_id OR runner_id IS NULL)
                  AND NOT (
                    job_type IN ('campaign_probe','credential_validate')
                    AND COALESCE(payload->'campaign_context'->>'campaign_uuid','') <> ''
                    AND EXISTS (
                      SELECT 1 FROM attack_campaigns c
                      WHERE c.campaign_uuid = payload->'campaign_context'->>'campaign_uuid'
                        AND (c.enabled=FALSE OR c.status IN ('paused','cancelled','completed'))
                    )
                  )
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, runner_id, job_type, target, payload, status
        """), {"runner_id": runner_id, "now": datetime.utcnow()}).mappings().first()
        db.commit()
        if not row:
            return None
        job = dict(row)
        payload = job.get("payload") or {}

        # Keep the execution view synchronized with the actual queue state.
        if job.get("job_type") == "atomic_validation":
            db.execute(text("""
                UPDATE atomic_execution_jobs
                SET status = 'running',
                    started_at = COALESCE(started_at, :now)
                WHERE runner_job_id = :runner_job_id
                  AND status = 'queued'
            """), {"runner_job_id": int(job["id"]), "now": datetime.utcnow()})
            db.commit()

        if job.get("job_type") == "nmap_discovery":
            db.execute(text("""
                UPDATE discovery_runs
                SET status = 'running', pipeline_status = 'running'
                WHERE runner_job_id = :runner_job_id
                  AND status = 'queued'
            """), {"runner_job_id": int(job["id"])})
            db.commit()

        if job.get("job_type") == "service_discovery":
            db.execute(text("""UPDATE service_discovery_jobs SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:runner_job_id"""), {"runner_job_id": int(job["id"]), "now": datetime.utcnow()})
            db.commit()
        if job.get("job_type") == "credential_validate":
            db.execute(text("""UPDATE credential_attempts SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:runner_job_id"""), {"runner_job_id": int(job["id"]), "now": datetime.utcnow()})
            db.commit()
        if job.get("job_type") == "deep_inventory":
            db.execute(text("""UPDATE deep_inventory_jobs SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:runner_job_id"""), {"runner_job_id": int(job["id"]), "now": datetime.utcnow()})
            db.commit()
        if job.get("job_type") in {"security_check", "nuclei", "attack_simulation"}:
            from app.repositories.validation_repository import mark_execution_running
            mark_execution_running(int(job["id"]))

        executor = payload.get("executor") or payload.get("type")
        if not executor:
            executor = "atomic" if job.get("job_type") == "atomic_validation" else job.get("job_type")

        # Normalize the Atomic payload expected by Runner v2.
        if executor == "atomic":
            payload = dict(payload)
            if payload.get("atomic_test_number") is not None and payload.get("test_number") is None:
                payload["test_number"] = payload.get("atomic_test_number")

        # Runner v2 expects job_id and executor.
        return {
            "job_id": str(job["id"]),
            "id": job["id"],
            "runner_id": job.get("runner_id"),
            "job_type": job.get("job_type"),
            "executor": executor,
            "type": executor,
            "target": job.get("target"),
            "payload": payload,
            "timeout_seconds": payload.get("timeout_seconds"),
        }


def get_pending_jobs(runner_id: str):
    job = get_next_job(runner_id)
    return [job] if job else []


def create_runner_job(runner_id: str | None, job_type: str, target: str | None, payload: dict | None):
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO runner_jobs (runner_id, job_type, target, payload, status, created_at)
            VALUES (:runner_id, :job_type, :target, CAST(:payload AS JSONB), 'pending', :now)
            RETURNING id, runner_id, status, job_type, target, payload, created_at
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
              AND status <> 'cancelled'
            RETURNING id, status, job_type, payload, result, error, finished_at
        """), {
            "job_id": int(job_id),
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



def clear_runner_jobs(runner_id: str, reason: str = "Runner limpo manualmente em Configurações") -> dict[str, int]:
    """Cancel all outstanding jobs assigned to one Runner without deleting history.

    Completed/failed/timeout jobs are preserved for audit. Campaign paths linked to
    cancelled jobs are also terminally cancelled so the Campaign UI cannot remain
    stuck in queued/running after an administrative Runner cleanup.
    """
    now = datetime.utcnow()
    with SessionLocal() as db:
        exists = db.execute(text("SELECT 1 FROM runners WHERE runner_id=:runner_id"), {"runner_id": runner_id}).first()
        if not exists:
            raise ValueError("Runner não encontrado.")

        rows = db.execute(text("""
            SELECT id FROM runner_jobs
            WHERE (runner_id=:runner_id OR (runner_id IS NULL AND status='pending'))
              AND status IN ('pending','running')
            FOR UPDATE
        """), {"runner_id": runner_id}).all()
        job_ids = [int(r[0]) for r in rows]
        if not job_ids:
            return {"jobs_cancelled": 0, "campaign_paths_cancelled": 0}

        cancelled_jobs = db.execute(text("""
            UPDATE runner_jobs
            SET status='cancelled', error=:reason, finished_at=:now
            WHERE id = ANY(:ids) AND status IN ('pending','running')
        """), {"ids": job_ids, "reason": reason, "now": now}).rowcount or 0

        cancelled_paths = db.execute(text("""
            UPDATE attack_campaign_paths
            SET status='cancelled', result='runner_cleared', finished_at=:now,
                evidence=COALESCE(evidence,'{}'::jsonb) || CAST(:evidence AS JSONB)
            WHERE runner_job_id = ANY(:ids) AND status IN ('queued','running')
        """), {
            "ids": job_ids,
            "now": now,
            "evidence": _json({"cancellation_reason": reason, "runner_id": runner_id}),
        }).rowcount or 0

        # Keep common execution mirrors from remaining visually queued/running.
        sync_tables = [
            ("credential_attempts", "runner_job_id"),
            ("service_discovery_jobs", "runner_job_id"),
            ("deep_inventory_jobs", "runner_job_id"),
            ("discovery_runs", "runner_job_id"),
            ("validation_task_executions", "runner_job_id"),
            ("atomic_execution_jobs", "runner_job_id"),
        ]
        for table, column in sync_tables:
            present = db.execute(text("SELECT to_regclass(:name)"), {"name": table}).scalar()
            if not present:
                continue
            db.execute(text(f"""
                UPDATE {table}
                SET status='cancelled', finished_at=COALESCE(finished_at,:now)
                WHERE {column} = ANY(:ids) AND status IN ('pending','queued','running')
            """), {"ids": job_ids, "now": now})

        db.commit()
        return {
            "jobs_cancelled": int(cancelled_jobs),
            "campaign_paths_cancelled": int(cancelled_paths),
        }

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
                COALESCE(metadata->>'ip_address', metadata->>'primary_ip', metadata->>'remote_addr') AS ip_address,
                COALESCE(metadata->>'os', metadata->>'platform') AS os,
                COALESCE(metadata->>'runner_version', metadata->>'version') AS runner_version,
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


def get_online_runner_with_capability(capability: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("""
            SELECT runner_id, name, hostname, last_heartbeat, metadata
            FROM runners
            WHERE enabled = TRUE
              AND status = 'online'
              AND last_heartbeat >= (now() AT TIME ZONE 'UTC') - interval '2 minutes'
              AND COALESCE((metadata->'capabilities'->'nmap_discovery'->>'available')::boolean, FALSE) = TRUE
            ORDER BY COALESCE((metadata->>'active_jobs')::int,0) ASC, last_heartbeat DESC
            LIMIT 1
        """), {"capability": capability}).mappings().first()
        return dict(row) if row else None
