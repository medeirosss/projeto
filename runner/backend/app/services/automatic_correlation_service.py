from __future__ import annotations
from app.services.attack_exposure_service import correlate_target
from app.repositories.validation_repository import list_tasks


def _req(meta:dict)->str:
    return str(meta.get('credential_requirement') or ('REQUIRED' if meta.get('credential_required') else 'NONE')).upper()


def build_plan(target:dict)->dict:
    """Evidence-driven planner. Knowledge decides applicability; catalog decides executability.
    No technique allowlist lives in Correlation."""
    exposure=correlate_target(int(target['id']))
    tasks={x.get('task_key'):x for x in list_tasks('magi_attack',limit=2000) if x.get('task_key')}
    simulations=[]; seen=set()
    for attack in exposure.get('attacks',[]):
        for mapping in attack.get('simulations',[]):
            key=mapping.get('technique_key'); task=tasks.get(key)
            if not key or key in seen or not task or not task.get('enabled',True): continue
            seen.add(key)
            meta=task.get('metadata') or {}
            simulations.append({**mapping,
                'technique_key':key,'technique_name':task.get('name'),
                'attack_name':attack.get('name'),'attack_uuid':attack.get('attack_uuid'),
                'impact':mapping.get('simulation_impact') or task.get('impact') or attack.get('impact'),
                'state':attack.get('state'),'confidence':attack.get('match_confidence'),
                'reason':attack.get('match_reason'),'credential_requirement':_req(meta),
                'remote_evidence':str(meta.get('remote_evidence') or 'NOT_SUPPORTED'),
                'automatic':True})
    # Deterministic planner: zero-credential validations first, then authenticated ones.
    simulations.sort(key=lambda x:(0 if x['credential_requirement']=='NONE' else 1, x.get('attack_name') or '', x['technique_key']))
    return {'simulations':simulations,'total':len(simulations),'attack_count':exposure.get('attack_count',0),'planner':'automatic-v2'}
