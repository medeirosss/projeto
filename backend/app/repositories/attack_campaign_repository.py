from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _json(v: Any) -> str:
    return json.dumps(v if v is not None else {}, ensure_ascii=False, default=str)


def ensure_attack_campaign_schema() -> None:
    with SessionLocal() as db:
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS attack_campaigns (
          id SERIAL PRIMARY KEY,
          campaign_uuid VARCHAR(48) UNIQUE NOT NULL,
          name VARCHAR(180) NOT NULL,
          description TEXT,
          scope_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb,
          initial_seeds JSONB NOT NULL DEFAULT '[]'::jsonb,
          credential_id INTEGER,
          runner_id VARCHAR(100),
          start_at TIMESTAMP NOT NULL,
          end_at TIMESTAMP NOT NULL,
          daily_start TIME NOT NULL DEFAULT '08:00',
          daily_end TIME NOT NULL DEFAULT '18:00',
          cycle_interval_minutes INTEGER NOT NULL DEFAULT 15,
          cycle_timeout_minutes INTEGER NOT NULL DEFAULT 15,
          recurrence_days INTEGER,
          max_seeds_per_cycle INTEGER NOT NULL DEFAULT 3,
          branch_policy JSONB NOT NULL DEFAULT '[10,5,1,0]'::jsonb,
          max_paths_per_cycle INTEGER NOT NULL DEFAULT 60,
          max_outstanding_jobs INTEGER NOT NULL DEFAULT 5,
          snapshot_retention INTEGER NOT NULL DEFAULT 10,
          status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_by VARCHAR(160),
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS attack_campaign_executions (
          id SERIAL PRIMARY KEY,
          campaign_id INTEGER NOT NULL REFERENCES attack_campaigns(id) ON DELETE CASCADE,
          execution_number INTEGER NOT NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
          scheduled_start TIMESTAMP NOT NULL,
          scheduled_end TIMESTAMP NOT NULL,
          started_at TIMESTAMP,
          finished_at TIMESTAMP,
          next_cycle_at TIMESTAMP,
          stop_reason VARCHAR(80),
          stats JSONB NOT NULL DEFAULT '{}'::jsonb,
          final_snapshot JSONB,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(campaign_id, execution_number)
        );
        CREATE TABLE IF NOT EXISTS attack_campaign_cycles (
          id SERIAL PRIMARY KEY,
          execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,
          cycle_number INTEGER NOT NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
          scheduled_at TIMESTAMP NOT NULL,
          started_at TIMESTAMP,
          deadline_at TIMESTAMP,
          finished_at TIMESTAMP,
          seeds JSONB NOT NULL DEFAULT '[]'::jsonb,
          frontier JSONB NOT NULL DEFAULT '[]'::jsonb,
          stats JSONB NOT NULL DEFAULT '{}'::jsonb,
          stop_reason VARCHAR(80),
          UNIQUE(execution_id, cycle_number)
        );
        CREATE TABLE IF NOT EXISTS attack_campaign_assets (
          id SERIAL PRIMARY KEY,
          execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,
          address VARCHAR(255) NOT NULL,
          hostname VARCHAR(255),
          fqdn VARCHAR(255),
          state VARCHAR(40) NOT NULL DEFAULT 'discovered',
          access_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
          seed_count INTEGER NOT NULL DEFAULT 0,
          inventory JSONB NOT NULL DEFAULT '{}'::jsonb,
          first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(execution_id, address)
        );
        CREATE TABLE IF NOT EXISTS attack_campaign_paths (
          id SERIAL PRIMARY KEY,
          execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,
          cycle_id INTEGER NOT NULL REFERENCES attack_campaign_cycles(id) ON DELETE CASCADE,
          origin VARCHAR(255) NOT NULL,
          target VARCHAR(255) NOT NULL,
          depth INTEGER NOT NULL DEFAULT 0,
          status VARCHAR(50) NOT NULL DEFAULT 'queued',
          runner_job_id INTEGER,
          validation_execution_id INTEGER,
          result VARCHAR(80),
          evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          finished_at TIMESTAMP,
          UNIQUE(execution_id, origin, target)
        );
        CREATE INDEX IF NOT EXISTS idx_attack_campaign_status ON attack_campaigns(status,enabled);
        CREATE INDEX IF NOT EXISTS idx_attack_campaign_exec_status ON attack_campaign_executions(status,scheduled_start,scheduled_end);
        CREATE INDEX IF NOT EXISTS idx_attack_campaign_cycle_status ON attack_campaign_cycles(status,scheduled_at);
        CREATE INDEX IF NOT EXISTS idx_attack_campaign_path_job ON attack_campaign_paths(runner_job_id);
        """))
        db.commit()


def create_campaign(data: dict[str, Any], created_by: str) -> dict[str, Any]:
    campaign_uuid = f"camp-{uuid.uuid4().hex[:12]}"
    with SessionLocal() as db:
        row = db.execute(text("""
          INSERT INTO attack_campaigns(
            campaign_uuid,name,description,scope_cidrs,initial_seeds,credential_id,runner_id,
            start_at,end_at,daily_start,daily_end,cycle_interval_minutes,cycle_timeout_minutes,
            recurrence_days,max_seeds_per_cycle,branch_policy,max_paths_per_cycle,max_outstanding_jobs,
            snapshot_retention,status,created_by,updated_at)
          VALUES(:uuid,:name,:description,CAST(:scope AS JSONB),CAST(:seeds AS JSONB),:credential_id,:runner_id,
            :start_at,:end_at,CAST(:daily_start AS TIME),CAST(:daily_end AS TIME),:interval,:timeout,
            :recurrence,:max_seeds,CAST(:policy AS JSONB),:max_paths,:max_jobs,:retention,'scheduled',:created_by,:now)
          RETURNING *
        """), {
            "uuid": campaign_uuid, "name": data["name"], "description": data.get("description"),
            "scope": _json(data["scope_cidrs"]), "seeds": _json(data["initial_seeds"]),
            "credential_id": data.get("credential_id"), "runner_id": data.get("runner_id"),
            "start_at": data["start_at"], "end_at": data["end_at"],
            "daily_start": data.get("daily_start", "08:00"), "daily_end": data.get("daily_end", "18:00"),
            "interval": int(data.get("cycle_interval_minutes", 15)), "timeout": int(data.get("cycle_timeout_minutes", 15)),
            "recurrence": data.get("recurrence_days"), "max_seeds": int(data.get("max_seeds_per_cycle", 3)),
            "policy": _json(data.get("branch_policy") or [10,5,1,0]), "max_paths": int(data.get("max_paths_per_cycle",60)),
            "max_jobs": int(data.get("max_outstanding_jobs",5)), "retention": int(data.get("snapshot_retention",10)),
            "created_by": created_by, "now": datetime.utcnow(),
        }).mappings().first()
        db.execute(text("""
          INSERT INTO attack_campaign_executions(campaign_id,execution_number,status,scheduled_start,scheduled_end,next_cycle_at)
          VALUES(:campaign_id,1,'scheduled',:start_at,:end_at,:start_at)
        """), {"campaign_id": row["id"], "start_at": data["start_at"], "end_at": data["end_at"]})
        db.commit()
        return dict(row)


def list_campaigns() -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
          SELECT c.*, e.id AS execution_id,e.execution_number,e.status AS execution_status,e.scheduled_start,e.scheduled_end,
                 e.stats AS execution_stats,e.stop_reason,e.next_cycle_at
          FROM attack_campaigns c
          LEFT JOIN LATERAL (
            SELECT * FROM attack_campaign_executions x WHERE x.campaign_id=c.id ORDER BY execution_number DESC LIMIT 1
          ) e ON TRUE
          ORDER BY c.created_at DESC
        """)).mappings().all()
        return [dict(r) for r in rows]


def get_campaign(campaign_uuid: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        c = db.execute(text("SELECT * FROM attack_campaigns WHERE campaign_uuid=:u"), {"u": campaign_uuid}).mappings().first()
        if not c: return None
        out = dict(c)
        executions = db.execute(text("SELECT * FROM attack_campaign_executions WHERE campaign_id=:id ORDER BY execution_number DESC"), {"id": c["id"]}).mappings().all()
        out["executions"] = [dict(x) for x in executions]
        if executions:
            eid = executions[0]["id"]
            out["assets"] = [dict(x) for x in db.execute(text("SELECT * FROM attack_campaign_assets WHERE execution_id=:e ORDER BY address"), {"e":eid}).mappings().all()]
            out["paths"] = [dict(x) for x in db.execute(text("SELECT * FROM attack_campaign_paths WHERE execution_id=:e ORDER BY id DESC LIMIT 500"), {"e":eid}).mappings().all()]
            out["cycles"] = [dict(x) for x in db.execute(text("SELECT * FROM attack_campaign_cycles WHERE execution_id=:e ORDER BY cycle_number DESC LIMIT 100"), {"e":eid}).mappings().all()]
        return out


def set_campaign_status(campaign_uuid: str, status: str, enabled: bool | None = None) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("""UPDATE attack_campaigns SET status=:s,enabled=COALESCE(:enabled,enabled),updated_at=:now WHERE campaign_uuid=:u RETURNING *"""),
                         {"s":status,"enabled":enabled,"now":datetime.utcnow(),"u":campaign_uuid}).mappings().first()
        db.commit(); return dict(row) if row else None


def delete_campaign(campaign_uuid: str) -> bool:
    with SessionLocal() as db:
        r=db.execute(text("DELETE FROM attack_campaigns WHERE campaign_uuid=:u RETURNING id"),{"u":campaign_uuid}).first(); db.commit(); return bool(r)


def db_session():
    return SessionLocal()
