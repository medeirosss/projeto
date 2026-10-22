from __future__ import annotations
from app.repositories.runner_repository import create_runner_job, get_single_online_runner, is_runner_queue_paused
from app.repositories import deep_inventory_repository as repo


def _rules_payload():
    return [{'id':r['id'],'process_name':r['process_name'],'category':r['category'],'severity':r['severity']} for r in repo.get_process_rules(True)]


def enqueue_for_target(*,target_id:int,target_ip:str,credential_id:int,runner_id:str,discovery_run_id:int|None=None,scan_id:int|None=None,protocol:str|None=None):
    payload={'executor':'deep_inventory','target':target_ip,'target_id':target_id,'credential_id':credential_id,'protocol':protocol,'timeout_seconds':90,'process_rules':_rules_payload(),'discovery_run_id':discovery_run_id,'scan_id':scan_id}
    job=create_runner_job(runner_id=runner_id,job_type='deep_inventory',target=target_ip,payload=payload)
    repo.create_deep_job_link(discovery_run_id,scan_id,target_id,credential_id,int(job['id']),runner_id)
    if discovery_run_id: repo.set_run_deep_total(discovery_run_id,1)
    return job


def maybe_enqueue_after_credential(attempt:dict,runner_id:str,authenticated:bool):
    if not authenticated: return None
    run_id=attempt.get('discovery_run_id'); cfg=repo.deep_enabled_for_run(int(run_id)) if run_id else None
    if not cfg or not cfg.get('deep_inventory_enabled'): return None
    return enqueue_for_target(target_id=int(attempt['target_id']),target_ip=str(attempt['target_ip']),credential_id=int(attempt['credential_id']),runner_id=runner_id,discovery_run_id=int(run_id),scan_id=cfg.get('scan_id'),protocol=attempt.get('protocol'))


def enqueue_due_periodic(limit:int=20):
    runner=get_single_online_runner()
    if not runner: return 0
    if is_runner_queue_paused(runner['runner_id']): return 0
    n=0
    for item in repo.due_targets(limit):
        enqueue_for_target(target_id=int(item['target_id']),target_ip=str(item['target_ip']),credential_id=int(item['credential_id']),runner_id=runner['runner_id'],scan_id=int(item['scan_id']),protocol=item.get('protocol'))
        n+=1
    return n


def ingest_runner_deep_result(job_id:int,runner_id:str,status:str,result:dict,error=None):
    return repo.ingest_deep_result(job_id,runner_id,status,result,error)
