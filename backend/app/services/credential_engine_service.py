from __future__ import annotations

from app.repositories.runner_repository import create_runner_job
from app.repositories import credential_engine_repository as repo
from app.repositories.credentials_repository import get_stored_credential_by_id


def _protocol_for_type(credential_type:str)->str:
    value=(credential_type or '').lower()
    if value in {'windows','wmi','winrm'}: return 'windows'
    if value in {'ssh','linux'}: return 'ssh'
    if value in {'snmp','snmp_v2c','snmpv2c'}: return 'snmp_v2c'
    return value or 'unknown'


def enqueue_for_discovery_run(discovery_run_id:int,runner_id:str)->dict:
    if repo.has_attempts_for_run(discovery_run_id):
        return {'enabled':True,'queued':0,'already_queued':True}
    cfg=repo.get_run_credential_config(discovery_run_id)
    if not cfg:
        repo.set_run_credential_totals(discovery_run_id,0)
        return {'enabled':False,'queued':0}
    credential=get_stored_credential_by_id(cfg['credential_id'])
    if not credential:
        repo.set_run_credential_totals(discovery_run_id,0)
        return {'enabled':False,'queued':0,'error':'Credencial selecionada não existe ou está desabilitada.'}
    protocol=_protocol_for_type(credential.get('credential_type'))
    queued=0
    for target in repo.targets_for_run(discovery_run_id):
        ip=str(target.get('ip_address') or '')
        if not ip: continue
        # Secret is NOT stored in runner_jobs. It is injected transiently by /jobs/next.
        payload={'executor':'credential_validate','target':ip,'timeout_seconds':45,'credential_id':int(cfg['credential_id']),
                 'credential_type':credential.get('credential_type'),'protocol':protocol,'max_attempts':2,
                 'discovery_run_id':discovery_run_id,'target_id':int(target['id'])}
        job=create_runner_job(runner_id=runner_id,job_type='credential_validate',target=ip,payload=payload)
        repo.create_attempt_link(discovery_run_id,int(target['id']),int(cfg['credential_id']),int(job['id']),runner_id,ip,protocol)
        queued+=1
    repo.set_run_credential_totals(discovery_run_id,queued)
    return {'enabled':True,'queued':queued,'credential_id':int(cfg['credential_id'])}


def ingest_runner_credential_result(job_id:int,runner_id:str,status:str,result:dict,error:str|None=None):
    return repo.ingest_attempt_result(runner_job_id=job_id,runner_id=runner_id,status=status,result=result,error=error)
