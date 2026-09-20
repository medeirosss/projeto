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
