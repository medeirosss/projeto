from __future__ import annotations
import json
from datetime import datetime
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _json(v: Any) -> str:
    return json.dumps(v if v is not None else {}, ensure_ascii=False)


def ensure_validation_schema() -> None:
    # Safety net for installations that start before Alembic is executed.
    with SessionLocal() as db:
        db.execute(text("""CREATE TABLE IF NOT EXISTS validation_repositories (id SERIAL PRIMARY KEY,repository_key VARCHAR(80) UNIQUE NOT NULL,name VARCHAR(160) NOT NULL,provider VARCHAR(80) NOT NULL,description TEXT,enabled BOOLEAN NOT NULL DEFAULT TRUE,available BOOLEAN NOT NULL DEFAULT TRUE,source_path TEXT,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,last_sync_at TIMESTAMP,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"""))
        db.execute(text("""CREATE TABLE IF NOT EXISTS validation_tasks (id SERIAL PRIMARY KEY,repository_key VARCHAR(80) NOT NULL,task_key VARCHAR(160) UNIQUE NOT NULL,name VARCHAR(255) NOT NULL,description TEXT,category VARCHAR(100),platform VARCHAR(80),executor VARCHAR(80) NOT NULL,impact VARCHAR(30) NOT NULL DEFAULT 'low',requires_admin BOOLEAN NOT NULL DEFAULT FALSE,approved BOOLEAN NOT NULL DEFAULT TRUE,enabled BOOLEAN NOT NULL DEFAULT TRUE,detection JSONB NOT NULL DEFAULT '{}'::jsonb,remediation TEXT,"references" JSONB NOT NULL DEFAULT '[]'::jsonb,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"""))
        db.execute(text("""CREATE TABLE IF NOT EXISTS validation_task_executions (id SERIAL PRIMARY KEY,execution_uuid UUID NOT NULL DEFAULT gen_random_uuid(),validation_task_id INTEGER REFERENCES validation_tasks(id) ON DELETE SET NULL,repository_key VARCHAR(80) NOT NULL,task_key VARCHAR(160) NOT NULL,runner_id VARCHAR(100),runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL,target VARCHAR(255) NOT NULL,requested_by VARCHAR(160),status VARCHAR(50) NOT NULL DEFAULT 'queued',impact VARCHAR(30),plan JSONB NOT NULL DEFAULT '{}'::jsonb,evidence JSONB NOT NULL DEFAULT '{}'::jsonb,finding_status VARCHAR(30),finding_message TEXT,remediation TEXT,error TEXT,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,started_at TIMESTAMP,finished_at TIMESTAMP)"""))
        db.commit()


def upsert_repository(item: dict[str, Any]) -> None:
    with SessionLocal() as db:
        db.execute(text("""INSERT INTO validation_repositories(repository_key,name,provider,description,enabled,available,source_path,metadata,last_sync_at,updated_at) VALUES(:key,:name,:provider,:description,:enabled,:available,:source_path,CAST(:metadata AS JSONB),:now,:now) ON CONFLICT(repository_key) DO UPDATE SET name=EXCLUDED.name,provider=EXCLUDED.provider,description=EXCLUDED.description,available=EXCLUDED.available,source_path=EXCLUDED.source_path,metadata=EXCLUDED.metadata,last_sync_at=EXCLUDED.last_sync_at,updated_at=EXCLUDED.updated_at"""), {"key":item["repository_key"],"name":item["name"],"provider":item["provider"],"description":item.get("description"),"enabled":item.get("enabled",True),"available":item.get("available",True),"source_path":item.get("source_path"),"metadata":_json(item.get("metadata") or {}),"now":datetime.utcnow()})
        db.commit()


def upsert_task(item: dict[str, Any]) -> None:
    with SessionLocal() as db:
        db.execute(text("""INSERT INTO validation_tasks(repository_key,task_key,name,description,category,platform,executor,impact,requires_admin,approved,enabled,detection,remediation,"references",metadata,updated_at) VALUES(:repo,:key,:name,:description,:category,:platform,:executor,:impact,:requires_admin,:approved,:enabled,CAST(:detection AS JSONB),:remediation,CAST(:references AS JSONB),CAST(:metadata AS JSONB),:now) ON CONFLICT(task_key) DO UPDATE SET repository_key=EXCLUDED.repository_key,name=EXCLUDED.name,description=EXCLUDED.description,category=EXCLUDED.category,platform=EXCLUDED.platform,executor=EXCLUDED.executor,impact=EXCLUDED.impact,requires_admin=EXCLUDED.requires_admin,detection=EXCLUDED.detection,remediation=EXCLUDED.remediation,"references"=EXCLUDED."references",metadata=EXCLUDED.metadata,updated_at=EXCLUDED.updated_at"""), {"repo":item["repository_key"],"key":item["task_key"],"name":item["name"],"description":item.get("description"),"category":item.get("category"),"platform":item.get("platform"),"executor":item["executor"],"impact":item.get("impact","low"),"requires_admin":item.get("requires_admin",False),"approved":item.get("approved",True),"enabled":item.get("enabled",True),"detection":_json(item.get("detection") or {}),"remediation":item.get("remediation"),"references":json.dumps(item.get("references") or [],ensure_ascii=False),"metadata":_json(item.get("metadata") or {}),"now":datetime.utcnow()})
        db.commit()


def list_repositories():
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT r.*, (SELECT COUNT(*) FROM validation_tasks t WHERE t.repository_key=r.repository_key) task_count FROM validation_repositories r ORDER BY r.name""")).mappings().all()
        return [dict(x) for x in rows]


def list_tasks(repository_key=None, search=None, category=None, limit=300):
    q=f"%{(search or '').lower().strip()}%"
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT * FROM validation_tasks WHERE (:repo IS NULL OR repository_key=:repo) AND (:category IS NULL OR category=:category) AND (:search='' OR lower(task_key) LIKE :q OR lower(name) LIKE :q OR lower(COALESCE(description,'')) LIKE :q) ORDER BY repository_key,category,name LIMIT :limit"""),{"repo":repository_key,"category":category,"search":(search or '').strip(),"q":q,"limit":limit}).mappings().all()
        return [dict(x) for x in rows]


def get_task(task_id:int):
    with SessionLocal() as db:
        row=db.execute(text("SELECT * FROM validation_tasks WHERE id=:id"),{"id":task_id}).mappings().first()
        return dict(row) if row else None


def create_execution(task:dict, runner_id:str, runner_job_id:int, target:str, requested_by:str, plan:dict):
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO validation_task_executions(validation_task_id,repository_key,task_key,runner_id,runner_job_id,target,requested_by,status,impact,plan,remediation) VALUES(:task_id,:repo,:key,:runner,:job,:target,:requested,'queued',:impact,CAST(:plan AS JSONB),:remediation) RETURNING *"""),{"task_id":task["id"],"repo":task["repository_key"],"key":task["task_key"],"runner":runner_id,"job":runner_job_id,"target":target,"requested":requested_by,"impact":task.get("impact"),"plan":_json(plan),"remediation":task.get("remediation")}).mappings().first(); db.commit(); return dict(row)


def mark_execution_running(runner_job_id:int):
    with SessionLocal() as db:
        db.execute(text("UPDATE validation_task_executions SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:job AND status='queued'"),{"job":runner_job_id,"now":datetime.utcnow()}); db.commit()


def ingest_execution_result(runner_job_id:int,status:str,result:dict,error:str|None=None):
    meta=(result or {}).get('metadata') or {}; finding=meta.get('finding') or {}; evidence=meta.get('evidence') or meta
    finding_status=finding.get('status') or ('detected' if finding.get('detected') else 'not_detected' if status=='success' else 'error')
    message=finding.get('message') or meta.get('message')
    with SessionLocal() as db:
        row=db.execute(text("""UPDATE validation_task_executions SET status=:status,evidence=CAST(:evidence AS JSONB),finding_status=:finding_status,finding_message=:message,error=:error,finished_at=:now WHERE runner_job_id=:job RETURNING *"""),{"status":status,"evidence":_json(evidence),"finding_status":finding_status,"message":message,"error":error,"now":datetime.utcnow(),"job":runner_job_id}).mappings().first(); db.commit(); return dict(row) if row else None


def list_executions(limit=100):
    with SessionLocal() as db:
        rows=db.execute(text("SELECT * FROM validation_task_executions ORDER BY id DESC LIMIT :limit"),{"limit":limit}).mappings().all(); return [dict(x) for x in rows]
