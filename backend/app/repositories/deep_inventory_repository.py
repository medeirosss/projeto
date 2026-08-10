from __future__ import annotations
import json
from datetime import datetime, timedelta
from sqlalchemy import text
from app.database.connection import SessionLocal


def _now(): return datetime.utcnow()
def _j(v): return json.dumps(v if v is not None else [], ensure_ascii=False, default=str)
def _ser(r):
    r=dict(r)
    for k,v in list(r.items()):
        if hasattr(v,'isoformat'): r[k]=v.isoformat()
    return r


def get_process_rules(enabled_only:bool=False):
    with SessionLocal() as db:
        q="SELECT * FROM process_knowledge_rules" + (" WHERE enabled=TRUE" if enabled_only else "") + " ORDER BY severity DESC,name"
        return [_ser(r) for r in db.execute(text(q)).mappings().all()]


def save_process_rule(payload:dict):
    name=str(payload.get('name') or '').strip()[:120]; process=str(payload.get('process_name') or '').strip()[:255]
    if not name or not process: raise ValueError('Nome da regra e processo são obrigatórios.')
    category=str(payload.get('category') or 'non_authorized').strip().lower()
    severity=str(payload.get('severity') or 'medium').strip().lower()
    if category not in {'malware_known','suspicious','non_authorized','p2p','admin_tool','allowed'}: raise ValueError('Categoria inválida.')
    if severity not in {'low','medium','high','critical'}: raise ValueError('Severidade inválida.')
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO process_knowledge_rules(name,process_name,category,severity,description,enabled,created_at,updated_at)
        VALUES(:name,:process,:cat,:sev,:desc,:enabled,:now,:now)
        ON CONFLICT(process_name) DO UPDATE SET name=EXCLUDED.name,category=EXCLUDED.category,severity=EXCLUDED.severity,description=EXCLUDED.description,enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at RETURNING *"""),
        {'name':name,'process':process,'cat':category,'sev':severity,'desc':str(payload.get('description') or '')[:2000] or None,'enabled':bool(payload.get('enabled',True)),'now':_now()}).mappings().first(); db.commit(); return _ser(row)


def delete_process_rule(rule_id:int):
    with SessionLocal() as db:
        row=db.execute(text("DELETE FROM process_knowledge_rules WHERE id=:id RETURNING id"),{'id':rule_id}).first(); db.commit(); return bool(row)


def get_snapshot(target_id:int):
    with SessionLocal() as db:
        r=db.execute(text("SELECT * FROM asset_inventory_snapshot WHERE target_id=:id"),{'id':target_id}).mappings().first(); return _ser(r) if r else None


def list_hardware_changes(target_id:int,limit:int=100):
    with SessionLocal() as db:
        return [_ser(r) for r in db.execute(text("SELECT * FROM asset_hardware_changes WHERE target_id=:id ORDER BY detected_at DESC LIMIT :lim"),{'id':target_id,'lim':limit}).mappings().all()]


def list_process_findings(target_id:int):
    with SessionLocal() as db:
        return [_ser(r) for r in db.execute(text("SELECT * FROM asset_process_findings WHERE target_id=:id ORDER BY currently_detected DESC,last_seen_at DESC"),{'id':target_id}).mappings().all()]


def create_deep_job_link(discovery_run_id,scan_id,target_id,credential_id,runner_job_id,runner_id):
    with SessionLocal() as db:
        db.execute(text("""INSERT INTO deep_inventory_jobs(discovery_run_id,scan_id,target_id,credential_id,runner_job_id,runner_id,status,created_at)
        VALUES(:run,:scan,:target,:cred,:job,:runner,'queued',:now) ON CONFLICT(runner_job_id) DO NOTHING"""),
        {'run':discovery_run_id,'scan':scan_id,'target':target_id,'cred':credential_id,'job':runner_job_id,'runner':runner_id,'now':_now()}); db.commit()


def mark_deep_running(runner_job_id:int):
    with SessionLocal() as db:
        db.execute(text("UPDATE deep_inventory_jobs SET status='running',started_at=COALESCE(started_at,:now) WHERE runner_job_id=:id"),{'id':runner_job_id,'now':_now()}); db.commit()


def deep_enabled_for_run(discovery_run_id:int):
    with SessionLocal() as db:
        r=db.execute(text("""SELECT r.scan_id,s.deep_inventory_enabled,s.deep_inventory_interval_minutes FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id WHERE r.id=:id"""),{'id':discovery_run_id}).mappings().first(); return dict(r) if r else None


def set_run_deep_total(discovery_run_id:int, delta:int=1):
    with SessionLocal() as db:
        db.execute(text("UPDATE discovery_runs SET deep_jobs_total=deep_jobs_total+:d,pipeline_status='deep_inventory' WHERE id=:id"),{'d':delta,'id':discovery_run_id}); db.commit()


def finalize_run_if_no_deep(discovery_run_id:int):
    with SessionLocal() as db:
        row=db.execute(text("SELECT credential_jobs_total,credential_jobs_completed,deep_jobs_total,deep_jobs_completed FROM discovery_runs WHERE id=:id"),{'id':discovery_run_id}).mappings().first()
        if row and int(row['credential_jobs_completed'] or 0)>=int(row['credential_jobs_total'] or 0) and int(row['deep_jobs_completed'] or 0)>=int(row['deep_jobs_total'] or 0):
            db.execute(text("UPDATE discovery_runs SET pipeline_status='completed' WHERE id=:id"),{'id':discovery_run_id}); db.commit()


def _norm_disk(d):
    return {k:d.get(k) for k in ('device','model','serial','size','interface') if d.get(k) not in (None,'')}


def ingest_deep_result(runner_job_id:int,runner_id:str,status:str,result:dict,error=None):
    meta=(result or {}).get('metadata') or {}; inv=meta.get('inventory') or {}; matches=meta.get('process_matches') or []
    with SessionLocal() as db:
        job=db.execute(text("SELECT * FROM deep_inventory_jobs WHERE runner_job_id=:id"),{'id':runner_job_id}).mappings().first()
        if not job: return None
        target_id=int(job['target_id']); old=db.execute(text("SELECT * FROM asset_inventory_snapshot WHERE target_id=:id"),{'id':target_id}).mappings().first()
        changes=[]
        if status=='success':
            fields=[('hardware','manufacturer','manufacturer'),('hardware','model','model'),('hardware','serial_number','serial_number'),('hardware','cpu_model','cpu_model'),('hardware','cpu_cores','cpu_cores'),('hardware','cpu_logical','cpu_logical'),('hardware','memory_bytes','memory_bytes')]
            if old:
                for component,key,col in fields:
                    nv=inv.get(key); ov=old.get(col)
                    if nv not in (None,'') and str(nv)!=str(ov if ov is not None else ''):
                        changes.append((component,key,ov,nv))
                old_disks=old.get('disks') or []; new_disks=[_norm_disk(x) for x in (inv.get('disks') or [])]
                if new_disks and json.dumps(old_disks,sort_keys=True,default=str)!=json.dumps(new_disks,sort_keys=True,default=str): changes.append(('hardware','disks',old_disks,new_disks))
            for component,key,ov,nv in changes:
                db.execute(text("INSERT INTO asset_hardware_changes(target_id,component,field_name,old_value,new_value,runner_id,credential_id,detected_at) VALUES(:t,:c,:f,:o,:n,:r,:cred,:now)"),{'t':target_id,'c':component,'f':key,'o':json.dumps(ov,ensure_ascii=False,default=str) if isinstance(ov,(list,dict)) else (str(ov) if ov is not None else None),'n':json.dumps(nv,ensure_ascii=False,default=str) if isinstance(nv,(list,dict)) else str(nv),'r':runner_id,'cred':job['credential_id'],'now':_now()})
            vals={k:inv.get(k) for k in ['hostname','os_name','os_version','os_build','domain_name','manufacturer','model','serial_number','cpu_model','cpu_cores','cpu_logical','memory_bytes','uptime_seconds']}
            vals.update({'target':target_id,'disks':_j([_norm_disk(x) for x in (inv.get('disks') or [])]),'runner':runner_id,'cred':job['credential_id'],'now':_now()})
            db.execute(text("""INSERT INTO asset_inventory_snapshot(target_id,hostname,os_name,os_version,os_build,domain_name,manufacturer,model,serial_number,cpu_model,cpu_cores,cpu_logical,memory_bytes,disks,uptime_seconds,runner_id,credential_id,collected_at,updated_at)
            VALUES(:target,:hostname,:os_name,:os_version,:os_build,:domain_name,:manufacturer,:model,:serial_number,:cpu_model,:cpu_cores,:cpu_logical,:memory_bytes,CAST(:disks AS JSONB),:uptime_seconds,:runner,:cred,:now,:now)
            ON CONFLICT(target_id) DO UPDATE SET hostname=EXCLUDED.hostname,os_name=EXCLUDED.os_name,os_version=EXCLUDED.os_version,os_build=EXCLUDED.os_build,domain_name=EXCLUDED.domain_name,manufacturer=EXCLUDED.manufacturer,model=EXCLUDED.model,serial_number=EXCLUDED.serial_number,cpu_model=EXCLUDED.cpu_model,cpu_cores=EXCLUDED.cpu_cores,cpu_logical=EXCLUDED.cpu_logical,memory_bytes=EXCLUDED.memory_bytes,disks=EXCLUDED.disks,uptime_seconds=EXCLUDED.uptime_seconds,runner_id=EXCLUDED.runner_id,credential_id=EXCLUDED.credential_id,collected_at=EXCLUDED.collected_at,updated_at=EXCLUDED.updated_at"""),vals)
            db.execute(text("UPDATE asset_process_findings SET currently_detected=FALSE WHERE target_id=:id"),{'id':target_id})
            for m in matches:
                rid=m.get('rule_id')
                db.execute(text("""INSERT INTO asset_process_findings(target_id,rule_id,process_name,process_path,pid,sha256,publisher,signed,category,severity,first_seen_at,last_seen_at,currently_detected)
                VALUES(:t,:rid,:name,:path,:pid,:sha,:pub,:signed,:cat,:sev,:now,:now,TRUE)
                ON CONFLICT(target_id,rule_id) DO UPDATE SET process_name=EXCLUDED.process_name,process_path=EXCLUDED.process_path,pid=EXCLUDED.pid,sha256=EXCLUDED.sha256,publisher=EXCLUDED.publisher,signed=EXCLUDED.signed,category=EXCLUDED.category,severity=EXCLUDED.severity,last_seen_at=EXCLUDED.last_seen_at,currently_detected=TRUE"""),{'t':target_id,'rid':rid,'name':m.get('process_name'),'path':m.get('process_path'),'pid':m.get('pid'),'sha':m.get('sha256'),'pub':m.get('publisher'),'signed':m.get('signed'),'cat':m.get('category'),'sev':m.get('severity'),'now':_now()})
            if inv.get('hostname'):
                db.execute(text("UPDATE targets SET hostname=COALESCE(NULLIF(hostname,''),:h),display_name=CASE WHEN display_name IS NULL OR display_name=host(ip_address) THEN :h ELSE display_name END,updated_at=:now WHERE id=:id"),{'h':inv['hostname'],'now':_now(),'id':target_id})
        final='success' if status=='success' else ('timeout' if status=='timeout' else 'failed')
        db.execute(text("UPDATE deep_inventory_jobs SET status=:s,hardware_changes=:hc,process_findings=:pf,error=:e,finished_at=:now WHERE runner_job_id=:job"),{'s':final,'hc':len(changes),'pf':len(matches),'e':str(error or result.get('stderr') or '')[:2000] or None,'now':_now(),'job':runner_job_id})
        if job.get('discovery_run_id'):
            db.execute(text("""UPDATE discovery_runs SET deep_jobs_completed=deep_jobs_completed+1,deep_jobs_success=deep_jobs_success+:ok,deep_jobs_failed=deep_jobs_failed+:fail,hardware_changes_count=hardware_changes_count+:hc,process_findings_count=process_findings_count+:pf WHERE id=:run"""),{'ok':1 if final=='success' else 0,'fail':0 if final=='success' else 1,'hc':len(changes),'pf':len(matches),'run':job['discovery_run_id']})
        db.commit()
    if job.get('discovery_run_id'): finalize_run_if_no_deep(int(job['discovery_run_id']))
    return {'target_id':target_id,'status':final,'hardware_changes':len(changes),'process_findings':len(matches),'discovery_run_id':job.get('discovery_run_id')}


def due_targets(limit:int=20):
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT DISTINCT ON (dst.target_id) dst.target_id,dst.scan_id,s.deep_inventory_interval_minutes,ac.credential_id,ac.protocol,t.runner_id AS runner_id,host(t.ip_address) AS target_ip,COALESCE(i.collected_at, TIMESTAMP '1970-01-01') AS last_collected
        FROM discovery_scan_targets dst JOIN discovery_scans s ON s.id=dst.scan_id AND s.deep_inventory_enabled=TRUE JOIN targets t ON t.id=dst.target_id AND t.active_in_inventory=TRUE JOIN asset_credentials ac ON ac.target_id=t.id LEFT JOIN asset_inventory_snapshot i ON i.target_id=t.id
        WHERE COALESCE(i.collected_at, TIMESTAMP '1970-01-01') <= (now() AT TIME ZONE 'UTC') - (s.deep_inventory_interval_minutes || ' minutes')::interval
          AND NOT EXISTS (SELECT 1 FROM deep_inventory_jobs dj WHERE dj.target_id=t.id AND dj.status IN ('queued','running'))
        ORDER BY dst.target_id,ac.last_success_at DESC LIMIT :lim"""),{'lim':limit}).mappings().all(); return [dict(r) for r in rows]
