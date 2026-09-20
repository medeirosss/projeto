from __future__ import annotations
import json
from sqlalchemy import text
from app.database.connection import SessionLocal
from app.services.target_service import execute_scan

def rescan_asset(target:dict, origin_scan:dict)->dict:
    """5.6.4.1 Scan Now: dispatch a real host-only Runner discovery job.
    Identity remains conservative: the rescan may refresh the known asset only after normal identity resolution.
    """
    tid=int(target['id']); hostname=(target.get('dns_name') or target.get('hostname') or '').strip(); mac=(target.get('mac_address') or '').strip()
    target_spec=str(target.get('ip_address') or hostname).strip()
    if not target_spec: raise ValueError('Ativo não possui IP/hostname utilizável para Scan Now.')
    # Never mutate the saved scan scope. This copy is a one-host execution only.
    host_scan={**origin_scan,'target_spec':target_spec,'target_type':'host','is_running':True}
    result=execute_scan(host_scan,'asset_rescan')
    job_id=result.get('runner_job_id'); run_uuid=result.get('run_uuid')
    details={'hostname':hostname,'mac':mac,'policy':'identity_required','runner_job_id':job_id,'run_uuid':run_uuid,'target_spec':target_spec}
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO asset_rescan_history(target_id,scan_id,status,identity_status,located_by,old_ip,details)
          VALUES(:t,:s,'QUEUED','PENDING',:by,CAST(:ip AS inet),CAST(:d AS jsonb)) RETURNING id"""),
          {'t':tid,'s':origin_scan['id'],'by':'hostname' if hostname else 'last_ip','ip':target.get('ip_address'),'d':json.dumps(details)}).mappings().first()
        db.execute(text("UPDATE discovery_scan_targets SET last_rescan_at=CURRENT_TIMESTAMP WHERE target_id=:t AND scan_id=:s"),{'t':tid,'s':origin_scan['id']})
        db.commit()
    return {'status':'QUEUED','target_uuid':target['target_uuid'],'asset_id':target['target_uuid'],'origin_scan':origin_scan['scan_uuid'],'runner_job_id':job_id,'run_uuid':run_uuid,'rescan_history_id':row['id'] if row else None,'identity_policy':{'ip_only':'NEVER_CONFIRMED','hostname_and_mac':'MATCH_CONFIRMED','conflict':'DO_NOT_UPDATE'},'message':'Scan Now enviado ao Runner como descoberta host-only.'}
