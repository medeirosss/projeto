from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _now():
    return datetime.utcnow()


def create_attempt_link(discovery_run_id:int,target_id:int,credential_id:int,runner_job_id:int,runner_id:str,target_ip:str,protocol:str)->dict:
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO credential_attempts
            (discovery_run_id,target_id,credential_id,runner_job_id,runner_id,target_ip,protocol,status,attempts_used,created_at)
            VALUES(:run,:target,:cred,:job,:runner,:ip,:protocol,'queued',0,:now)
            ON CONFLICT(runner_job_id) DO NOTHING
            RETURNING *"""),{"run":discovery_run_id,"target":target_id,"cred":credential_id,"job":runner_job_id,"runner":runner_id,"ip":target_ip,"protocol":protocol,"now":_now()}).mappings().first()
        db.commit(); return dict(row) if row else {}


def has_attempts_for_run(discovery_run_id:int)->bool:
    with SessionLocal() as db:
        return bool(db.execute(text("SELECT 1 FROM credential_attempts WHERE discovery_run_id=:id LIMIT 1"),{"id":discovery_run_id}).first())


def get_run_credential_config(discovery_run_id:int)->dict|None:
    with SessionLocal() as db:
        row=db.execute(text("""SELECT r.id AS discovery_run_id,r.scan_id,s.credential_id
            FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id
            WHERE r.id=:id"""),{"id":discovery_run_id}).mappings().first()
        return dict(row) if row and row.get('credential_id') else None


def set_run_credential_totals(discovery_run_id:int,total:int):
    with SessionLocal() as db:
        db.execute(text("""UPDATE discovery_runs SET credential_jobs_total=:total,credential_jobs_completed=0,
            credential_jobs_failed=0,credential_jobs_success=0,
            pipeline_status=CASE WHEN :total>0 THEN 'credential_engine' ELSE 'completed' END
            WHERE id=:id"""),{"id":discovery_run_id,"total":total})
        db.commit()


def mark_attempt_running(runner_job_id:int):
    with SessionLocal() as db:
        db.execute(text("UPDATE credential_attempts SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:id"),{"id":runner_job_id,"now":_now()})
        db.commit()


def get_attempt_by_runner_job(runner_job_id:int)->dict|None:
    with SessionLocal() as db:
        row=db.execute(text("SELECT * FROM credential_attempts WHERE runner_job_id=:id"),{"id":runner_job_id}).mappings().first()
        return dict(row) if row else None


def targets_for_run(discovery_run_id:int)->list[dict[str,Any]]:
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT DISTINCT t.id,t.target_uuid,t.hostname,host(t.ip_address) AS ip_address,t.asset_type
            FROM enrichment_events e JOIN targets t ON t.id=e.target_id
            WHERE e.discovery_run_id=:id AND t.deleted_at IS NULL"""),{"id":discovery_run_id}).mappings().all()
        return [dict(r) for r in rows]


def ingest_attempt_result(*,runner_job_id:int,runner_id:str,status:str,result:dict,error:str|None=None)->dict|None:
    job=get_attempt_by_runner_job(runner_job_id)
    if not job: return None
    meta=(result or {}).get('metadata') or {}
    auth_ok=bool(meta.get('authenticated')) and status=='success'
    hostname=(meta.get('hostname') or '').strip() or None
    attempts_used=max(0,min(2,int(meta.get('attempts_used') or 0)))
    protocol=str(meta.get('protocol') or job.get('protocol') or '')[:30]
    final_status='success' if auth_ok else ('timeout' if status=='timeout' else 'failed')
    message=error or result.get('error') or result.get('stderr') or meta.get('message')
    with SessionLocal() as db:
        db.execute(text("""UPDATE credential_attempts SET status=:status,attempts_used=:attempts,hostname_result=:hostname,
            error=:error,finished_at=:now,protocol=:protocol WHERE runner_job_id=:job"""),
            {"status":final_status,"attempts":attempts_used,"hostname":hostname,"error":str(message)[:2000] if message else None,"now":_now(),"protocol":protocol,"job":runner_job_id})
        if auth_ok:
            db.execute(text("""INSERT INTO asset_credentials(target_id,credential_id,protocol,last_success_at,hostname_result,runner_id)
                VALUES(:tid,:cid,:protocol,:now,:hostname,:runner)
                ON CONFLICT(target_id,credential_id,protocol) DO UPDATE SET last_success_at=EXCLUDED.last_success_at,
                hostname_result=EXCLUDED.hostname_result,runner_id=EXCLUDED.runner_id"""),
                {"tid":job['target_id'],"cid":job['credential_id'],"protocol":protocol,"now":_now(),"hostname":hostname,"runner":runner_id})
            # Only enrich hostname when the inventory has no hostname yet.
            if hostname:
                db.execute(text("""UPDATE targets SET hostname=:hostname,hostname_normalized=lower(:hostname),
                    display_name=CASE WHEN COALESCE(NULLIF(display_name,''),host(ip_address))=host(ip_address) OR display_name IS NULL THEN :hostname ELSE display_name END,
                    hostname_source=COALESCE(hostname_source,'credential'),updated_at=:now
                    WHERE id=:tid AND (hostname IS NULL OR btrim(hostname)='')"""),{"hostname":hostname,"tid":job['target_id'],"now":_now()})
        totals=db.execute(text("""SELECT COUNT(*) AS total,
            COUNT(*) FILTER(WHERE status='success') AS ok,
            COUNT(*) FILTER(WHERE status IN ('failed','error','timeout')) AS failed
            FROM credential_attempts WHERE discovery_run_id=:run"""),{"run":job['discovery_run_id']}).mappings().first()
        completed=int(totals['ok'])+int(totals['failed'])
        # Deep Inventory, when enabled, is enqueued after each successful credential.
        # Do not close the pipeline here if at least one Deep Inventory job is expected.
        cfg=db.execute(text("""SELECT s.deep_inventory_enabled FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id WHERE r.id=:run"""),{"run":job['discovery_run_id']}).mappings().first()
        deep_enabled=bool(cfg and cfg.get('deep_inventory_enabled'))
        pipeline=('deep_inventory' if deep_enabled and auth_ok else ('completed' if completed>=int(totals['total']) else 'credential_engine'))
        db.execute(text("""UPDATE discovery_runs SET credential_jobs_total=:total,credential_jobs_completed=:done,
            credential_jobs_failed=:failed,credential_jobs_success=:ok,pipeline_status=:pipeline WHERE id=:run"""),
            {"total":int(totals['total']),"done":completed,"failed":int(totals['failed']),"ok":int(totals['ok']),"pipeline":pipeline,"run":job['discovery_run_id']})
        db.commit()
    return {"discovery_run_id":job['discovery_run_id'],"target_id":job['target_id'],"credential_id":job['credential_id'],"target_ip":str(job['target_ip']),"protocol":protocol,"status":final_status,"authenticated":auth_ok,"hostname":hostname,"attempts_used":attempts_used,"pipeline_status":pipeline}
