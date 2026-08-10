from __future__ import annotations
import json
from datetime import datetime
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _now(): return datetime.utcnow()
def _json(v): return json.dumps(v if v is not None else {}, ensure_ascii=False, default=str)

def get_scan_service_enabled(scan_id:int|None) -> bool:
    if not scan_id: return False
    with SessionLocal() as db:
        row=db.execute(text("SELECT service_discovery_enabled FROM discovery_scans WHERE id=:id"),{"id":scan_id}).mappings().first()
        return bool(row and row.get("service_discovery_enabled"))

def create_service_job_link(discovery_run_id:int,target_id:int,runner_job_id:int,runner_id:str,target_ip:str)->dict:
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO service_discovery_jobs(discovery_run_id,target_id,runner_job_id,runner_id,target_ip,status,created_at)
            VALUES(:run,:target,:job,:runner,:ip,'queued',:now) RETURNING *"""),{"run":discovery_run_id,"target":target_id,"job":runner_job_id,"runner":runner_id,"ip":target_ip,"now":_now()}).mappings().first()
        db.commit(); return dict(row)

def mark_service_job_running(runner_job_id:int):
    with SessionLocal() as db:
        db.execute(text("UPDATE service_discovery_jobs SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:id"),{"id":runner_job_id,"now":_now()}); db.commit()

def get_service_job_by_runner_job(runner_job_id:int)->dict|None:
    with SessionLocal() as db:
        r=db.execute(text("SELECT * FROM service_discovery_jobs WHERE runner_job_id=:id"),{"id":runner_job_id}).mappings().first(); return dict(r) if r else None

def set_run_service_totals(discovery_run_id:int,total:int):
    with SessionLocal() as db:
        db.execute(text("""UPDATE discovery_runs SET service_jobs_total=:total,service_jobs_completed=0,service_jobs_failed=0,services_found_count=0,new_services_count=0,
            pipeline_status=CASE WHEN :total>0 THEN 'service_discovery' ELSE 'completed' END WHERE id=:id"""),{"id":discovery_run_id,"total":total}); db.commit()

def ingest_services(*,runner_job_id:int,runner_id:str,status:str,services:list[dict],error:str|None=None,raw_xml:str|None=None)->dict|None:
    job=get_service_job_by_runner_job(runner_job_id)
    if not job: return None
    new_count=0; found=0
    with SessionLocal() as db:
        if status=='success':
            # Current-state view: services not observed in this successful pass become inactive,
            # while history remains in asset_service_observations.
            db.execute(text("UPDATE asset_services SET active=FALSE WHERE target_id=:tid"), {"tid": job['target_id']})
            for svc in services:
                if str(svc.get('state') or '').lower()!='open': continue
                port=int(svc.get('port') or 0)
                if port<=0: continue
                protocol=str(svc.get('protocol') or 'tcp').lower()[:10]
                existing=db.execute(text("SELECT id FROM asset_services WHERE target_id=:tid AND port=:port AND protocol=:proto"),{"tid":job['target_id'],"port":port,"proto":protocol}).first()
                if not existing: new_count+=1
                db.execute(text("""INSERT INTO asset_services(target_id,port,protocol,service_name,friendly_name,category,product,version,extra_info,banner,os_type,cpe,service_fingerprint,tunnel,detection_method,detection_confidence,state,first_seen_at,last_seen_at,runner_id,last_discovery_run_id,active)
                    VALUES(:tid,:port,:proto,:service,:friendly,:category,:product,:version,:extra,:banner,:os_type,CAST(:cpe AS jsonb),:servicefp,:tunnel,:method,:conf,:state,:now,:now,:runner,:run,TRUE)
                    ON CONFLICT(target_id,port,protocol) DO UPDATE SET service_name=EXCLUDED.service_name,friendly_name=EXCLUDED.friendly_name,category=EXCLUDED.category,
                    product=EXCLUDED.product,version=EXCLUDED.version,extra_info=EXCLUDED.extra_info,banner=EXCLUDED.banner,os_type=EXCLUDED.os_type,cpe=EXCLUDED.cpe,service_fingerprint=EXCLUDED.service_fingerprint,tunnel=EXCLUDED.tunnel,detection_method=EXCLUDED.detection_method,detection_confidence=EXCLUDED.detection_confidence,state=EXCLUDED.state,last_seen_at=EXCLUDED.last_seen_at,
                    runner_id=EXCLUDED.runner_id,last_discovery_run_id=EXCLUDED.last_discovery_run_id,active=TRUE"""),{
                    "tid":job['target_id'],"port":port,"proto":protocol,"service":svc.get('service_name'),"friendly":svc.get('friendly_name'),"category":svc.get('category'),
                    "product":svc.get('product'),"version":svc.get('version'),"extra":svc.get('extra_info'),"banner":svc.get('banner'),"os_type":svc.get('os_type'),"cpe":json.dumps(svc.get('cpe') or []),"servicefp":svc.get('service_fingerprint'),"tunnel":svc.get('tunnel'),"method":svc.get('method'),"conf":int(svc.get('conf')) if str(svc.get('conf') or "").isdigit() else None,"state":svc.get('state') or 'open',
                    "now":_now(),"runner":runner_id,"run":job['discovery_run_id']})
                db.execute(text("""INSERT INTO asset_service_observations(discovery_run_id,target_id,port,protocol,state,service_name,friendly_name,category,product,version,is_new,observed_at)
                    VALUES(:run,:tid,:port,:proto,:state,:service,:friendly,:category,:product,:version,:is_new,:now)"""),{
                    "run":job['discovery_run_id'],"tid":job['target_id'],"port":port,"proto":protocol,"state":svc.get('state') or 'open',"service":svc.get('service_name'),
                    "friendly":svc.get('friendly_name'),"category":svc.get('category'),"product":svc.get('product'),"version":svc.get('version'),"is_new":not bool(existing),"now":_now()})
                found+=1
        db.execute(text("""UPDATE service_discovery_jobs SET status=:status,error=:error,raw_output=:raw,service_count=:count,new_service_count=:new_count,finished_at=:now
            WHERE runner_job_id=:job"""),{"status":status,"error":error,"raw":raw_xml,"count":found,"new_count":new_count,"now":_now(),"job":runner_job_id})
        totals=db.execute(text("""SELECT discovery_run_id,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status='success') AS success_count,
            COUNT(*) FILTER (WHERE status IN ('failed','error','timeout')) AS failed_count,
            COALESCE(SUM(service_count),0) AS service_count,
            COALESCE(SUM(new_service_count),0) AS new_count
            FROM service_discovery_jobs WHERE discovery_run_id=:run GROUP BY discovery_run_id"""),{"run":job['discovery_run_id']}).mappings().first()
        completed=int(totals['success_count'])+int(totals['failed_count'])
        pipeline='completed' if completed>=int(totals['total']) else 'service_discovery'
        db.execute(text("""UPDATE discovery_runs SET service_jobs_total=:total,service_jobs_completed=:done,service_jobs_failed=:failed,services_found_count=:services,new_services_count=:new,pipeline_status=:pipeline
            WHERE id=:run"""),{"total":int(totals['total']),"done":completed,"failed":int(totals['failed_count']),"services":int(totals['service_count']),"new":int(totals['new_count']),"pipeline":pipeline,"run":job['discovery_run_id']})
        db.commit()
    if status == 'success':
        try:
            from app.repositories.exposure_repository import evaluate_target
            evaluate_target(int(job['target_id']))
        except Exception:
            pass
    return {"discovery_run_id":job['discovery_run_id'],"services_found":found,"new_services":new_count,"pipeline_completed": completed>=int(totals['total'])}

def list_asset_services(target_id:int,include_inactive:bool=False)->list[dict[str,Any]]:
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT id,port,protocol,service_name,friendly_name,category,product,version,extra_info,banner,os_type,cpe,service_fingerprint,tunnel,detection_method,detection_confidence,state,first_seen_at,last_seen_at,runner_id,active
            FROM asset_services WHERE target_id=:id AND (:all=TRUE OR active=TRUE) ORDER BY port,protocol"""),{"id":target_id,"all":include_inactive}).mappings().all()
        out=[]
        for r in rows:
            d=dict(r)
            for k,v in list(d.items()):
                if hasattr(v,'isoformat'): d[k]=v.isoformat()
            out.append(d)
        return out

def service_count_by_target_ids(target_ids:list[int])->dict[int,int]:
    if not target_ids:return {}
    with SessionLocal() as db:
        rows=db.execute(text("SELECT target_id,COUNT(*) AS c FROM asset_services WHERE active=TRUE AND target_id = ANY(:ids) GROUP BY target_id"),{"ids":target_ids}).mappings().all()
        return {int(r['target_id']):int(r['c']) for r in rows}
