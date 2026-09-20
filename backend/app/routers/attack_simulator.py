from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Request

from app.services.attack_simulator_service import attack_catalog, attack_history, sync_attack_simulator, provider_status, attack_execution_log
from app.services.validation_engine_service import execute_task, plan_task

router = APIRouter(prefix="/api/attack-simulator", tags=["attack-simulator"])


@router.get("/summary")
def summary():
    data = attack_catalog()
    sims = data.get("simulations") or []
    categories: dict[str, int] = {}
    for item in sims:
        key = item.get("category") or "Other"
        categories[key] = categories.get(key, 0) + 1
    return {
        "success": True,
        "version": "5.6.3",
        "safe_mode": True,
        "destructive": False,
        "credential_execution": True,
        "simulations": len(sims),
        "categories": categories,
    }




@router.get("/providers")
def providers():
    return provider_status()

@router.post("/sync")
def sync():
    return sync_attack_simulator()


@router.get("/catalog")
def catalog(search: str | None = None, category: str | None = None):
    return attack_catalog(search=search, category=category)


@router.post("/simulations/{task_id}/plan")
def plan(task_id: int, payload: dict = Body(...)):
    try:
        result = plan_task(task_id, payload.get("target"), options=payload)
        if result.get("task", {}).get("repository_key") != "magi_attack":
            raise ValueError("A tarefa informada não pertence ao MAGI Attack Simulator.")
        return result
    except Exception as exc:
        raise HTTPException(400, str(exc))


@router.post("/simulations/{task_id}/execute")
def execute(task_id: int, request: Request, payload: dict = Body(...)):
    try:
        planned = plan_task(task_id, payload.get("target"), options=payload)
        if planned.get("task", {}).get("repository_key") != "magi_attack":
            raise ValueError("A tarefa informada não pertence ao MAGI Attack Simulator.")
        u = getattr(request.state, "user", {}) or {}
        requested = u.get("sub") or u.get("username") or "ui"
        return execute_task(task_id, payload.get("target"), requested, options=payload)
    except Exception as exc:
        raise HTTPException(400, str(exc))


@router.get("/history")
def history(limit: int = 100):
    return attack_history(limit=max(1, min(limit, 500)))


@router.get("/history/{execution_id}/log")
def history_log(execution_id: int):
    try:
        return attack_execution_log(execution_id)
    except Exception as exc:
        raise HTTPException(404, str(exc))

@router.get('/correlation/targets')
def correlation_targets():
    from app.repositories.target_repository import list_targets
    rows=list_targets(limit=1000)
    items=rows.get('items',[]) if isinstance(rows,dict) else rows
    return {'items':[{'target_uuid':x.get('target_uuid'),'name':x.get('display_name') or x.get('hostname') or x.get('ip_address'),'ip_address':x.get('ip_address'),'asset_type':x.get('asset_type')} for x in items]}

@router.get('/correlation/{target_uuid}/plan')
def correlation_plan(target_uuid:str):
    from app.repositories import target_repository as tr
    from app.services.attack_exposure_service import correlate_target
    t=tr.get_target(target_uuid)
    if not t: raise HTTPException(404,'Ativo não encontrado.')
    c=correlate_target(int(t['id'])); sims=[]; seen=set()
    for a in c.get('attacks',[]):
        for s in a.get('simulations',[]):
            k=s.get('technique_key')
            if not k or k in seen: continue
            seen.add(k); sims.append({**s,'attack_name':a.get('name'),'impact':s.get('simulation_impact') or a.get('impact'),'state':a.get('state'),'confidence':a.get('match_confidence'),'reason':a.get('match_reason')})
    return {'target':{'target_uuid':target_uuid,'name':t.get('display_name') or t.get('hostname') or t.get('ip_address'),'ip_address':t.get('ip_address'),'asset_type':t.get('asset_type')},'simulations':sims,'total':len(sims)}

@router.post('/correlation/{target_uuid}/execute')
def correlation_execute(target_uuid:str,request:Request,payload:dict=Body(...)):
    from app.repositories import target_repository as tr
    from app.repositories.validation_repository import list_tasks
    from app.services.validation_engine_service import execute_task
    t=tr.get_target(target_uuid)
    if not t: raise HTTPException(404,'Ativo não encontrado.')
    selected=set(payload.get('techniques') or [])
    plan=correlation_plan(target_uuid); allowed={x['technique_key'] for x in plan['simulations']}
    selected &= allowed
    if not selected: raise HTTPException(400,'Selecione ao menos uma simulação correlacionada.')
    tasks={x.get('task_key'):x for x in list_tasks('magi_attack',limit=1000)}
    results=[]
    for key in selected:
        task=tasks.get(key)
        if not task: results.append({'technique_key':key,'status':'SKIPPED','message':'Técnica não instalada.'}); continue
        meta=task.get('metadata') or {}; opts={}
        if meta.get('credential_required'):
            detection=task.get('detection') or {}; typ=str(detection.get('type') or '').lower()
            required='snmp' if 'snmp' in typ else 'ssh' if 'ssh' in typ else 'windows'
            def comp(c):
                ct=str(c.get('credential_type') or '').lower()
                return (required=='windows' and ct in {'windows','windows_domain','windows_local','wmi','winrm'}) or (required=='snmp' and ct in {'snmp','snmp_v2c','snmpv2c'}) or (required=='ssh' and ct in {'ssh','linux'})
            creds=[c for c in (t.get('credentials') or []) if comp(c)]
            cid=creds[0].get('credential_id') if creds else None
            if not cid:
                scans=tr.origin_scans_for_target(int(t['id'])); cid=next((x.get('last_successful_credential_id') for x in scans if x.get('last_successful_credential_id')),None)
            if not cid: results.append({'technique_key':key,'status':'CREDENTIAL_REQUIRED','message':'Nenhuma credencial compatível confirmada no ativo.'}); continue
            opts['credential_id']=cid
        try:
            r=execute_task(int(task['id']),str(t.get('ip_address') or t.get('hostname')),'correlation-ui',options=opts)
            results.append({'technique_key':key,'status':'QUEUED','execution':r})
        except Exception as exc: results.append({'technique_key':key,'status':'ERROR','message':str(exc)})
    return {'target_uuid':target_uuid,'requested':len(selected),'results':results}
