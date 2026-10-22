from __future__ import annotations
import json, uuid
from datetime import datetime
from sqlalchemy import text
from app.database.connection import SessionLocal

EVENTS={'ENTERED','ACTION_STARTED','ACTION_COMPLETED','EVIDENCE_CREATED','RELAY_STARTED','RELAY_RETURNED','EXITED','FAILED','RETURN_CONFIRMED'}
STATES={'POSSIBLE','VALIDATABLE','EXECUTING','REACHED','CONFIRMED','RETURN_CONFIRMED','BLOCKED','STALE'}

def _clean_payload(v):
    # Telemetry is intentionally metadata-only: never accept arbitrary command output or secrets.
    allowed={'message','reason','evidence_ref','runner_job_id','protocol','latency_ms'}
    return {k:v[k] for k in allowed if k in (v or {})}

def list_runs():
    with SessionLocal() as db:
        rows=db.execute(text("SELECT path_uuid,status,metadata,created_at,started_at,finished_at FROM attack_path_runs ORDER BY id DESC LIMIT 100")).mappings().all()
        return [dict(r) for r in rows]

def create_run(data,user='ui'):
    path_uuid='PATH-'+uuid.uuid4().hex[:12].upper()
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO attack_path_runs(path_uuid,campaign_execution_id,origin_target_id,status,requested_by,metadata)
          VALUES(:u,:c,:o,'planned',:by,CAST(:m AS JSONB)) RETURNING *"""),{'u':path_uuid,'c':data.get('campaign_execution_id'),'o':data.get('origin_target_id'),'by':user,'m':json.dumps(data.get('metadata') or {})}).mappings().first()
        db.commit(); return dict(row)

def get_run(path_uuid):
    with SessionLocal() as db:
        run=db.execute(text("SELECT * FROM attack_path_runs WHERE path_uuid=:u"),{'u':path_uuid}).mappings().first()
        if not run: raise ValueError('Attack Path não encontrado.')
        edges=db.execute(text("SELECT * FROM attack_path_edges WHERE path_run_id=:i ORDER BY hop,id"),{'i':run['id']}).mappings().all()
        events=db.execute(text("SELECT * FROM attack_path_telemetry WHERE path_run_id=:i ORDER BY sequence_no,id"),{'i':run['id']}).mappings().all()
        return {'run':dict(run),'edges':[dict(x) for x in edges],'telemetry':[dict(x) for x in events]}

def telemetry(path_uuid,data):
    event=str(data.get('event_type') or '').upper()
    if event not in EVENTS: raise ValueError('Evento de telemetria inválido.')
    node=str(data.get('node_address') or '').strip()
    if not node: raise ValueError('node_address é obrigatório.')
    ev_uuid=str(data.get('event_uuid') or ('EVT-'+uuid.uuid4().hex.upper()))[:64]
    with SessionLocal() as db:
        run=db.execute(text("SELECT * FROM attack_path_runs WHERE path_uuid=:u FOR UPDATE"),{'u':path_uuid}).mappings().first()
        if not run: raise ValueError('Attack Path não encontrado.')
        seq=int(data.get('sequence_no') or (db.execute(text('SELECT COALESCE(MAX(sequence_no),0)+1 FROM attack_path_telemetry WHERE path_run_id=:i'),{'i':run['id']}).scalar() or 1))
        payload=_clean_payload(data.get('payload') or {})
        db.execute(text("""INSERT INTO attack_path_telemetry(path_run_id,edge_id,event_uuid,sequence_no,node_target_id,node_address,parent_address,hop,event_type,technique_key,result,transport,relay_depth,payload,event_at)
          VALUES(:r,:e,:u,:s,:n,:a,:p,:h,:t,:k,:result,:transport,:depth,CAST(:payload AS JSONB),:at)
          ON CONFLICT(event_uuid) DO NOTHING"""),{'r':run['id'],'e':data.get('edge_id'),'u':ev_uuid,'s':seq,'n':data.get('node_target_id'),'a':node,'p':data.get('parent_address'),'h':int(data.get('hop') or 0),'t':event,'k':data.get('technique_key'),'result':data.get('result'),'transport':str(data.get('transport') or 'relay')[:20],'depth':int(data.get('relay_depth') or 0),'payload':json.dumps(payload),'at':data.get('event_at') or datetime.utcnow()})
        if event in {'ENTERED','ACTION_STARTED'}: db.execute(text("UPDATE attack_path_runs SET status='executing',started_at=COALESCE(started_at,CURRENT_TIMESTAMP) WHERE id=:i"),{'i':run['id']})
        db.commit()
    return {'success':True,'path_uuid':path_uuid,'event_uuid':ev_uuid,'sequence_no':seq}

def ingest_relay(path_uuid,bundle):
    # A child returns a compact envelope to its parent; each parent may append its own event.
    events=bundle.get('events') or []
    if not isinstance(events,list) or len(events)>100: raise ValueError('Relay bundle inválido ou excede 100 eventos.')
    out=[]
    for idx,e in enumerate(events):
        x=dict(e or {}); x['transport']='relay'; x['relay_depth']=int(x.get('relay_depth') or 0)+1
        out.append(telemetry(path_uuid,x))
    return {'success':True,'path_uuid':path_uuid,'accepted':len(out),'events':out}

def create_from_campaign(campaign_uuid,user='ui'):
    """Snapshot latest Campaign execution into the 5.7 graph.
    Existing Campaign access is VALIDATABLE unless evidence explicitly proves remote-origin execution.
    This prevents Runner->target validation from being mislabeled as a lateral hop.
    """
    path_uuid='PATH-'+uuid.uuid4().hex[:12].upper()
    with SessionLocal() as db:
        camp=db.execute(text('SELECT id,name FROM attack_campaigns WHERE campaign_uuid=:u'),{'u':campaign_uuid}).mappings().first()
        if not camp: raise ValueError('Campaign não encontrada.')
        ex=db.execute(text('SELECT id,execution_number FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1'),{'c':camp['id']}).mappings().first()
        if not ex: raise ValueError('Campaign ainda não possui execução.')
        run=db.execute(text("""INSERT INTO attack_path_runs(path_uuid,campaign_execution_id,status,requested_by,metadata)
          VALUES(:u,:e,'planned',:by,CAST(:m AS JSONB)) RETURNING id"""),{'u':path_uuid,'e':ex['id'],'by':user,'m':json.dumps({'source':'campaign','campaign_uuid':campaign_uuid,'campaign_name':camp['name'],'execution_number':ex['execution_number']})}).mappings().first()
        paths=db.execute(text("SELECT * FROM attack_campaign_paths WHERE execution_id=:e ORDER BY hop,id"),{'e':ex['id']}).mappings().all()
        for p in paths:
            ev=p.get('evidence') or {}; explicit=bool(ev.get('remote_origin_confirmed') or ev.get('lateral_execution_confirmed') or ev.get('path_telemetry_confirmed'))
            status=str(p.get('status') or '').lower(); result=str(p.get('result') or '')
            if explicit: state='CONFIRMED'
            elif status in {'failed','error','timeout','cancelled'}: state='BLOCKED'
            elif status=='confirmed' or result=='access_confirmed': state='VALIDATABLE'
            else: state='POSSIBLE'
            db.execute(text("""INSERT INTO attack_path_edges(path_run_id,origin_address,target_address,hop,protocol,state,evidence)
              VALUES(:r,:o,:t,:h,:p,:s,CAST(:e AS JSONB))"""),{'r':run['id'],'o':p.get('origin_address') or p.get('origin'),'t':p.get('target_address') or p.get('target'),'h':int(p.get('hop') or p.get('depth') or 0),'p':p.get('protocol'),'s':state,'e':json.dumps({'campaign_path_id':p.get('id'),'runner_job_id':p.get('runner_job_id'),'campaign_status':p.get('status'),'campaign_result':p.get('result'),'remote_origin_proven':explicit})})
        db.commit()
    return get_run(path_uuid)

# 5.7.1 — Campaign integration + controlled WinRM path validation.
def sync_from_campaign(campaign_uuid: str, campaign_path_id: int | None = None, queue_winrm: bool = True):
    """Keep one PATH-* per Campaign execution and mirror Campaign facts into it.

    Runner->target credential validation is never promoted to CONFIRMED. For a
    WinRM access relation A->B, a separate END-101 job is queued to prove that
    Host A actually initiated the B session. That job is the only automatic
    source of CONFIRMED/RETURN_CONFIRMED in 5.7.1.
    """
    from app.repositories.runner_repository import create_runner_job
    from app.repositories.validation_repository import create_execution
    with SessionLocal() as db:
        camp=db.execute(text('SELECT * FROM attack_campaigns WHERE campaign_uuid=:u'),{'u':campaign_uuid}).mappings().first()
        if not camp: return None
        ex=db.execute(text('SELECT * FROM attack_campaign_executions WHERE campaign_id=:c ORDER BY execution_number DESC LIMIT 1'),{'c':camp['id']}).mappings().first()
        if not ex: return None
        run=db.execute(text('SELECT * FROM attack_path_runs WHERE campaign_execution_id=:e ORDER BY id DESC LIMIT 1'),{'e':ex['id']}).mappings().first()
        if not run:
            pu='PATH-'+uuid.uuid4().hex[:12].upper()
            run=db.execute(text("""INSERT INTO attack_path_runs(path_uuid,campaign_execution_id,status,requested_by,metadata)
              VALUES(:u,:e,'planned','campaign',CAST(:m AS JSONB)) RETURNING *"""),{'u':pu,'e':ex['id'],'m':json.dumps({'source':'campaign','campaign_uuid':campaign_uuid,'campaign_name':camp['name'],'execution_number':ex['execution_number'],'telemetry_version':'5.7.1'})}).mappings().first()
        q="SELECT p.*,j.payload AS runner_payload FROM attack_campaign_paths p LEFT JOIN runner_jobs j ON j.id=p.runner_job_id WHERE p.execution_id=:e"
        params={'e':ex['id']}
        if campaign_path_id:
            q += ' AND p.id=:pid'; params['pid']=int(campaign_path_id)
        paths=db.execute(text(q+' ORDER BY p.id'),params).mappings().all()
        for p0 in paths:
            p=dict(p0); ev=dict(p.get('evidence') or {})
            status=str(p.get('status') or '').lower(); result=str(p.get('result') or '')
            state='BLOCKED' if status in {'failed','error','timeout','cancelled','not_confirmed','cycle_timeout'} else ('VALIDATABLE' if status=='confirmed' or result=='access_confirmed' else 'POSSIBLE')
            edge=db.execute(text("SELECT * FROM attack_path_edges WHERE path_run_id=:r AND (evidence->>'campaign_path_id')=:pid LIMIT 1"),{'r':run['id'],'pid':str(p['id'])}).mappings().first()
            edge_ev={'campaign_path_id':p['id'],'runner_job_id':p.get('runner_job_id'),'campaign_status':p.get('status'),'campaign_result':p.get('result'),'remote_origin_proven':False}
            if edge:
                db.execute(text("UPDATE attack_path_edges SET state=:s,protocol=:p,evidence=CAST(:ev AS JSONB),updated_at=CURRENT_TIMESTAMP WHERE id=:id"),{'s':state,'p':p.get('protocol'),'ev':json.dumps(edge_ev),'id':edge['id']})
                edge_id=edge['id']
            else:
                edge_id=db.execute(text("""INSERT INTO attack_path_edges(path_run_id,origin_address,target_address,hop,protocol,state,evidence)
                  VALUES(:r,:o,:t,:h,:p,:s,CAST(:ev AS JSONB)) RETURNING id"""),{'r':run['id'],'o':p.get('origin'),'t':p.get('target'),'h':int(p.get('depth') or 0),'p':p.get('protocol'),'s':state,'ev':json.dumps(edge_ev)}).scalar()
            # Direct Campaign validation telemetry is useful, but explicitly not lateral proof.
            if status=='confirmed' and p.get('target'):
                event_uuid=f"EVT-CAMP-{ex['id']}-{p['id']}-REACHED"
                db.execute(text("""INSERT INTO attack_path_telemetry(path_run_id,edge_id,event_uuid,sequence_no,node_address,parent_address,hop,event_type,technique_key,result,transport,relay_depth,payload)
                  VALUES(:r,:edge,:u,(SELECT COALESCE(MAX(sequence_no),0)+1 FROM attack_path_telemetry WHERE path_run_id=:r),:node,:parent,:hop,'ENTERED',NULL,'reached','runner_direct',0,CAST(:payload AS JSONB)) ON CONFLICT(event_uuid) DO NOTHING"""),{'r':run['id'],'edge':edge_id,'u':event_uuid,'node':p.get('target'),'parent':p.get('origin'),'hop':int(p.get('depth') or 0),'payload':json.dumps({'message':'Campaign direct validation reached target; lateral origin not yet proven.','runner_job_id':p.get('runner_job_id'),'protocol':p.get('protocol')})})
            # Only WinRM access gets automatic real A->B proof in 5.7.1. SSH intentionally excluded.
            if not queue_winrm or p.get('protocol')!='winrm' or str(p.get('relation_type') or '')!='access' or status!='confirmed':
                continue
            origin=str(p.get('origin') or '').strip(); target=str(p.get('target') or '').strip()
            if not origin or not target or origin.lower()=='runner' or origin==target: continue
            current=db.execute(text("SELECT evidence FROM attack_path_edges WHERE id=:id"),{'id':edge_id}).scalar() or {}
            if current.get('path_validation_job_id'): continue
            credential_id=(p.get('runner_payload') or {}).get('credential_id')
            if not credential_id or not camp.get('runner_id'): continue
            payload={'executor':'attack_simulation','task_key':'MAGI-ATK-END-101','scenario_name':'WinRM Lateral Movement Path Validation','attack_category':'Endpoint','host_b':target,
                     'credential_id':credential_id,'scope':{'allowed_hosts':[origin,target],'max_hops':1,'hard_max_hops':5},
                     'simulation':{'type':'winrm_lateral_path','port':5985},'timeout_seconds':90,
                     'path_context':{'path_uuid':run['path_uuid'],'edge_id':edge_id,'campaign_uuid':campaign_uuid,'campaign_path_id':p['id'],'origin':origin,'target':target,'hop':int(p.get('depth') or 0)}}
            job=create_runner_job(camp['runner_id'],'attack_simulation',origin,payload)
            task=db.execute(text("SELECT * FROM validation_tasks WHERE task_key='MAGI-ATK-END-101' LIMIT 1")).mappings().first()
            if task:
                try:create_execution(dict(task),camp['runner_id'],job['id'],origin,f"campaign-path:{campaign_uuid}",{'ready':True,'runner_id':camp['runner_id'],'executor':'attack_simulation','target':origin,'task_id':task['id'],'task_key':task['task_key'],'repository':'magi_attack','credential_id':credential_id,'secondary_target':target,'path_uuid':run['path_uuid']})
                except Exception: pass
            current.update({'path_validation_job_id':job['id'],'path_validation_technique':'MAGI-ATK-END-101'})
            db.execute(text("UPDATE attack_path_edges SET state='EXECUTING',technique_key='MAGI-ATK-END-101',evidence=CAST(:ev AS JSONB),updated_at=CURRENT_TIMESTAMP WHERE id=:id"),{'ev':json.dumps(current),'id':edge_id})
            db.execute(text("UPDATE attack_path_runs SET status='executing',started_at=COALESCE(started_at,CURRENT_TIMESTAMP) WHERE id=:id"),{'id':run['id']})
        db.commit()
        return {'path_uuid':run['path_uuid'],'campaign_execution_id':ex['id']}

def ingest_path_validation_result(job_id: int, status: str, data: dict):
    """Translate END-101 result into path telemetry without carrying command output/secrets."""
    with SessionLocal() as db:
        job=db.execute(text('SELECT payload FROM runner_jobs WHERE id=:j'),{'j':int(job_id)}).mappings().first()
        ctx=((job or {}).get('payload') or {}).get('path_context') or {}
        if not ctx: return None
        run=db.execute(text('SELECT * FROM attack_path_runs WHERE path_uuid=:u FOR UPDATE'),{'u':ctx.get('path_uuid')}).mappings().first()
        edge=db.execute(text('SELECT * FROM attack_path_edges WHERE id=:i AND path_run_id=:r FOR UPDATE'),{'i':ctx.get('edge_id'),'r':run['id'] if run else -1}).mappings().first() if run else None
        if not run or not edge: return None
        meta=(data or {}).get('metadata') or {}; confirmed=str(meta.get('lateral_movement_status') or '')=='confirmed' or str(meta.get('attack_result') or '')=='lateral_movement_confirmed'
        origin=ctx.get('origin'); target=ctx.get('target'); hop=int(ctx.get('hop') or 0)
        base=int(db.execute(text('SELECT COALESCE(MAX(sequence_no),0) FROM attack_path_telemetry WHERE path_run_id=:r'),{'r':run['id']}).scalar() or 0)
        events=[(origin,None,'ENTERED','origin_reached','relay'),(origin,None,'ACTION_STARTED','lateral_validation_started','relay')]
        if confirmed:
            events += [(target,origin,'ENTERED','lateral_target_reached','relay'),(target,origin,'ACTION_COMPLETED','lateral_movement_confirmed','relay'),(target,origin,'RELAY_STARTED','telemetry_return_started','relay'),(origin,None,'RELAY_RETURNED','child_signal_returned','relay'),(target,origin,'RETURN_CONFIRMED','return_confirmed','relay')]
        else:
            events += [(target,origin,'FAILED',str(meta.get('confirmation_status') or 'lateral_movement_not_confirmed'),'relay')]
        for i,(node,parent,etype,res,transport) in enumerate(events,1):
            eu=f"EVT-PATH-{job_id}-{i}"
            db.execute(text("""INSERT INTO attack_path_telemetry(path_run_id,edge_id,event_uuid,sequence_no,node_address,parent_address,hop,event_type,technique_key,result,transport,relay_depth,payload)
              VALUES(:r,:e,:u,:seq,:node,:parent,:hop,:etype,'MAGI-ATK-END-101',:result,:transport,:depth,CAST(:payload AS JSONB)) ON CONFLICT(event_uuid) DO NOTHING"""),{'r':run['id'],'e':edge['id'],'u':eu,'seq':base+i,'node':node,'parent':parent,'hop':hop+(1 if node==target else 0),'etype':etype,'result':res,'transport':transport,'depth':1 if node==target else 0,'payload':json.dumps({'runner_job_id':job_id,'protocol':'winrm','message':'Controlled path telemetry; no secret or command output stored.'})})
        new_state='RETURN_CONFIRMED' if confirmed else 'BLOCKED'
        ev=dict(edge.get('evidence') or {}); ev.update({'remote_origin_proven':confirmed,'path_telemetry_confirmed':confirmed,'path_validation_job_id':job_id,'path_validation_result':meta.get('attack_result') or status})
        db.execute(text('UPDATE attack_path_edges SET state=:s,evidence=CAST(:ev AS JSONB),updated_at=CURRENT_TIMESTAMP WHERE id=:id'),{'s':new_state,'ev':json.dumps(ev),'id':edge['id']})
        db.execute(text("UPDATE attack_path_runs SET status=:s,finished_at=CASE WHEN :done THEN CURRENT_TIMESTAMP ELSE finished_at END WHERE id=:id"),{'s':'confirmed' if confirmed else 'executing','done':confirmed,'id':run['id']})
        db.commit(); return {'path_uuid':run['path_uuid'],'edge_id':edge['id'],'state':new_state,'confirmed':confirmed}
