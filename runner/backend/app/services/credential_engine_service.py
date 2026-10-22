from __future__ import annotations
from app.repositories.runner_repository import create_runner_job
from app.repositories import credential_engine_repository as repo
from app.repositories.credentials_repository import get_stored_credential_by_id

def _protocol_for_type(t):
    v=(t or '').lower()
    if v in {'windows','wmi','winrm','windows_local','windows_domain'}: return 'windows'
    if v in {'ssh','linux'}: return 'ssh'
    if v in {'snmp','snmp_v2c','snmpv2c'}: return 'snmp_v2c'
    return v or 'unknown'

def _compatible(cred,target):
    p=_protocol_for_type(cred.get('credential_type')); at=(target.get('asset_type') or 'unknown').lower()
    if p=='windows' and at in {'network','network_node','router','switch'}: return False
    if p=='snmp_v2c' and at in {'endpoint','windows','server','workstation'}: return False
    return True

def _enqueue_one(run_id,runner_id,target,cred):
    cid=int(cred['id'] if 'id' in cred else cred['credential_id']); ip=str(target.get('ip_address') or '')
    protocol=_protocol_for_type(cred.get('credential_type'))
    payload={'executor':'credential_validate','target':ip,'timeout_seconds':45,'credential_id':cid,'credential_type':cred.get('credential_type'),'protocol':protocol,'max_attempts':1,'discovery_run_id':run_id,'target_id':int(target['id'])}
    job=create_runner_job(runner_id=runner_id,job_type='credential_validate',target=ip,payload=payload)
    repo.create_attempt_link(run_id,int(target['id']),cid,int(job['id']),runner_id,ip,protocol); return job

def _ordered_credentials(run_id,target):
    cfg=repo.credentials_for_run(run_id); attempted=repo.attempted_credentials(run_id,int(target['id']))
    # Last successful credential for this asset/scan is naturally promoted when available.
    preferred=[]
    try:
        from app.database.connection import SessionLocal
        from sqlalchemy import text
        with SessionLocal() as db:
            c=db.execute(text("SELECT dst.last_successful_credential_id FROM discovery_scan_targets dst JOIN discovery_runs r ON r.scan_id=dst.scan_id WHERE r.id=:r AND dst.target_id=:t"),{'r':run_id,'t':target['id']}).scalar()
        if c: preferred=[int(c)]
    except Exception: pass
    cfg.sort(key=lambda x:(0 if int(x['credential_id']) in preferred else 1,int(x['priority'])))
    out=[]
    for x in cfg:
        cid=int(x['credential_id'])
        if cid in attempted: continue
        full=get_stored_credential_by_id(cid)
        if full and _compatible(full,target): out.append(full)
    return out

def enqueue_for_discovery_run(discovery_run_id:int,runner_id:str)->dict:
    if repo.has_attempts_for_run(discovery_run_id): return {'enabled':True,'queued':0,'already_queued':True}
    cfg=repo.credentials_for_run(discovery_run_id)
    if not cfg: repo.set_run_credential_totals(discovery_run_id,0); return {'enabled':False,'queued':0}
    queued=0
    for target in repo.targets_for_run(discovery_run_id):
        choices=_ordered_credentials(discovery_run_id,target)
        if choices: _enqueue_one(discovery_run_id,runner_id,target,choices[0]); queued+=1
    repo.set_run_credential_totals(discovery_run_id,queued)
    return {'enabled':True,'queued':queued,'credential_count':len(cfg)}

def ingest_runner_credential_result(job_id:int,runner_id:str,status:str,result:dict,error:str|None=None):
    out=repo.ingest_attempt_result(runner_job_id=job_id,runner_id=runner_id,status=status,result=result,error=error)
    if not out:return out
    if out.get('authenticated'):
        repo.remember_scan_credential(int(out['discovery_run_id']),int(out['target_id']),int(out['credential_id']),str(out.get('protocol') or ''))
        from app.services.deep_inventory_service import maybe_enqueue_after_credential
        deep=maybe_enqueue_after_credential(out,runner_id,True)
        if deep: out['deep_inventory_job_id']=deep.get('id')
    else:
        target=next((x for x in repo.targets_for_run(int(out['discovery_run_id'])) if int(x['id'])==int(out['target_id'])),None)
        choices=_ordered_credentials(int(out['discovery_run_id']),target or {'id':out['target_id'],'ip_address':out['target_ip'],'asset_type':'unknown'})
        if choices:
            j=_enqueue_one(int(out['discovery_run_id']),runner_id,target or {'id':out['target_id'],'ip_address':out['target_ip']},choices[0]); out['next_credential_job_id']=j.get('id')
        else:
            from app.repositories.deep_inventory_repository import finalize_run_if_no_deep
            finalize_run_if_no_deep(int(out['discovery_run_id']))
    return out
