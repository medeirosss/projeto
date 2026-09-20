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
        "version": "5.6.3.1",
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
    from app.services.web_asset_service import list_assets as list_web_assets
    rows=list_targets(limit=1000)
    items=rows.get('items',[]) if isinstance(rows,dict) else rows
    out=[{'asset_id':x.get('target_uuid'),'target_uuid':x.get('target_uuid'),'name':x.get('display_name') or x.get('hostname') or x.get('ip_address'),'address':x.get('ip_address'),'ip_address':x.get('ip_address'),'asset_type':x.get('asset_type') or 'Host','asset_source':'target'} for x in items]
    for w in list_web_assets():
        out.append({'asset_id':w.get('web_uuid'),'target_uuid':w.get('web_uuid'),'name':w.get('name') or w.get('hostname') or w.get('normalized_url'),'address':w.get('normalized_url') or w.get('original_url'),'ip_address':w.get('normalized_url') or w.get('original_url'),'asset_type':'Web','asset_source':'web','status':w.get('status')})
    return {'items':out}

def _web_correlation_plan(web_uuid:str):
    from app.services.web_asset_service import list_assets
    from app.repositories.validation_repository import list_tasks
    w=next((x for x in list_assets() if x.get('web_uuid')==web_uuid),None)
    if not w: raise HTTPException(404,'Web Asset não encontrado.')
    scheme=str(w.get('scheme') or '').lower(); reachable=str(w.get('status') or '').lower()=='reachable'
    tasks=list_tasks('magi_attack',limit=1000); sims=[]
    for task in tasks:
        if str(task.get('category') or '').lower()!='application': continue
        meta=task.get('metadata') or {}; det=task.get('detection') or {}; key=task.get('task_key')
        if not key or meta.get('credential_required'): continue
        tls=det.get('tls'); port=det.get('port')
        # Correlation is evidence-driven: do not propose HTTPS-only tests to an HTTP asset or vice versa.
        if tls is True and scheme!='https': continue
        if tls is False and scheme=='https' and key!='MAGI-M-ATK-APP-001': continue
        if port==443 and scheme!='https': continue
        if port==80 and scheme=='https' and key!='MAGI-M-ATK-APP-001': continue
        if not reachable: continue
        sims.append({'technique_key':key,'attack_name':task.get('name'),'impact':str(task.get('impact') or 'safe').upper(),'state':'AVAILABLE','confidence':100,'credential_requirement':'NONE','remote_evidence':str(meta.get('remote_evidence') or 'NOT_SUPPORTED'),'reason':{'checks':[{'type':'web_asset','value':w.get('normalized_url'),'matched':True},{'type':'scheme','value':scheme,'matched':True},{'type':'http_status','value':w.get('http_status'),'matched':True}]}})
    return {'target':{'target_uuid':web_uuid,'name':w.get('name') or w.get('hostname'),'ip_address':w.get('normalized_url') or w.get('original_url'),'asset_type':'Web','asset_source':'web'},'simulations':sims,'total':len(sims)}

@router.get('/correlation/{target_uuid}/plan')
def correlation_plan(target_uuid:str):
    if target_uuid.upper().startswith('WEB-'):
        return _web_correlation_plan(target_uuid)
    from app.repositories import target_repository as tr
    from app.services.attack_exposure_service import correlate_target
    t=tr.get_target(target_uuid)
    if not t: raise HTTPException(404,'Ativo não encontrado.')
    from app.repositories.validation_repository import list_tasks
    task_map={x.get('task_key'):x for x in list_tasks('magi_attack',limit=1000)}
    c=correlate_target(int(t['id'])); sims=[]; seen=set()
    for a in c.get('attacks',[]):
        for sim in a.get('simulations',[]):
            k=sim.get('technique_key')
            if not k or k in seen: continue
            seen.add(k); tm=(task_map.get(k) or {}).get('metadata') or {}; req=str(tm.get('credential_requirement') or ('REQUIRED' if tm.get('credential_required') else 'NONE')).upper(); sims.append({**sim,'attack_name':a.get('name'),'impact':sim.get('simulation_impact') or a.get('impact'),'state':a.get('state'),'confidence':a.get('match_confidence'),'reason':a.get('match_reason'),'credential_requirement':req,'remote_evidence':str(tm.get('remote_evidence') or 'NOT_SUPPORTED')})
    return {'target':{'target_uuid':target_uuid,'name':t.get('display_name') or t.get('hostname') or t.get('ip_address'),'ip_address':t.get('ip_address'),'asset_type':t.get('asset_type'),'asset_source':'target'},'simulations':sims,'total':len(sims)}

@router.post('/correlation/{target_uuid}/execute')
def correlation_execute(target_uuid:str,request:Request,payload:dict=Body(...)):
    from app.repositories.validation_repository import list_tasks
    from app.services.validation_engine_service import execute_task
    selected=set(payload.get('techniques') or [])
    evidence_requested=bool(payload.get('create_benign_evidence'))
    plan=correlation_plan(target_uuid); allowed={x['technique_key'] for x in plan['simulations']}
    selected &= allowed
    if not selected: raise HTTPException(400,'Selecione ao menos uma simulação correlacionada.')
    tasks={x.get('task_key'):x for x in list_tasks('magi_attack',limit=1000)}
    results=[]
    if target_uuid.upper().startswith('WEB-'):
        target=plan['target']['ip_address']
        for key in selected:
            task=tasks.get(key)
            if not task: results.append({'technique_key':key,'status':'SKIPPED','message':'Técnica não instalada.'}); continue
            try:
                r=execute_task(int(task['id']),str(target),'correlation-ui',options={'asset_ref':target_uuid}) # Zero-Credential Guarantee: Web correlation never injects credentials for NONE tasks)
                results.append({'technique_key':key,'status':'QUEUED','execution':r})
            except Exception as exc: results.append({'technique_key':key,'status':'ERROR','message':str(exc)})
        return {'target_uuid':target_uuid,'asset_type':'Web','requested':len(selected),'results':results}
    from app.repositories import target_repository as tr
    t=tr.get_target(target_uuid)
    if not t: raise HTTPException(404,'Ativo não encontrado.')
    for key in selected:
        task=tasks.get(key)
        if not task: results.append({'technique_key':key,'status':'SKIPPED','message':'Técnica não instalada.'}); continue
        meta=task.get('metadata') or {}; req=str(meta.get('credential_requirement') or ('REQUIRED' if meta.get('credential_required') else 'NONE')).upper(); opts={}
        if req=='REQUIRED':
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
        # NONE must remain credential-free even when the asset has confirmed credentials.
        if req=='NONE': opts.pop('credential_id',None)
        if evidence_requested and str(meta.get('remote_evidence') or '')=='SUPPORTED':
            opts['create_benign_evidence']=True
            opts['evidence_path']=rf'C:\MAGI\Evidence\{target_uuid}\{key}.txt'
            opts['evidence_context']={'asset_ref':target_uuid,'technique_key':key,'source':'correlation'}
        try:
            r=execute_task(int(task['id']),str(t.get('ip_address') or t.get('hostname')),'correlation-ui',options=opts)
            results.append({'technique_key':key,'status':'QUEUED','execution':r})
        except Exception as exc: results.append({'technique_key':key,'status':'ERROR','message':str(exc)})
    return {'target_uuid':target_uuid,'requested':len(selected),'results':results}
