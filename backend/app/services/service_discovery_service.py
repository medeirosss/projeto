from __future__ import annotations
from app.repositories.runner_repository import create_runner_job
from app.repositories import service_discovery_repository as repo


def enqueue_for_discovery_run(run:dict,targets:list[dict],runner_id:str)->dict:
    run_id=int(run['id'])
    if not repo.get_scan_service_enabled(run.get('scan_id')):
        repo.set_run_service_totals(run_id,0)
        return {"enabled":False,"queued":0}
    queued=0
    for target in targets:
        ip=str(target.get('ip_address') or '')
        target_id=target.get('id')
        if not ip or not target_id: continue
        payload={"executor":"service_discovery","target":ip,"timeout_seconds":120,"profile":"top1000","version_intensity":"normal","discovery_run_id":run_id,"target_id":int(target_id)}
        job=create_runner_job(runner_id=runner_id,job_type='service_discovery',target=ip,payload=payload)
        repo.create_service_job_link(run_id,int(target_id),int(job['id']),runner_id,ip)
        queued+=1
    repo.set_run_service_totals(run_id,queued)
    return {"enabled":True,"queued":queued}


def ingest_runner_service_result(job_id:int,runner_id:str,status:str,result:dict,error:str|None=None):
    from app.services.service_knowledge import lookup_service
    metadata=(result or {}).get('metadata') or {}
    services=[]
    for raw in metadata.get('services') or []:
        item=dict(raw); item.update(lookup_service(int(item.get('port') or 0),str(item.get('protocol') or 'tcp'),item.get('service_name'))); services.append(item)
    out=repo.ingest_services(runner_job_id=job_id,runner_id=runner_id,status=status,services=services,error=error or result.get('error') or result.get('stderr'),raw_xml=metadata.get('raw_xml'))
    if out and out.get('pipeline_completed'):
        from app.services.credential_engine_service import enqueue_for_discovery_run
        out['credential_engine']=enqueue_for_discovery_run(int(out['discovery_run_id']),runner_id)
    return out
