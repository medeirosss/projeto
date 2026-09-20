from __future__ import annotations
import json
from pathlib import Path
from sqlalchemy import text
from app.database.connection import get_db_session

SCHEMA_VERSION=1
MAGI_VERSION='5.6.3.1'
BUNDLED=Path(__file__).resolve().parents[1]/'data'/'attack_knowledge_2026.09.002.json'


def _validate(snapshot:dict)->dict:
    m=snapshot.get('manifest') or {}
    if int(m.get('knowledge_schema',0))!=SCHEMA_VERSION: raise ValueError('Knowledge Schema incompatível.')
    if not m.get('full_snapshot'): raise ValueError('A 5.6.1 aceita somente Knowledge full snapshot cumulativo.')
    if not m.get('knowledge_version'): raise ValueError('knowledge_version ausente.')
    ids=[a.get('attack_uuid') for a in snapshot.get('attacks') or []]
    if not ids or any(not x for x in ids) or len(ids)!=len(set(ids)): raise ValueError('Attack Knowledge inválido ou com IDs duplicados.')
    return m


def import_snapshot(snapshot:dict, source:str|None=None)->dict:
    m=_validate(snapshot); version=str(m['knowledge_version']); source=source or str(m.get('source') or 'offline_update')
    attacks=snapshot.get('attacks') or []
    with get_db_session() as db:
        old=db.execute(text('SELECT knowledge_version FROM knowledge_state ORDER BY id DESC LIMIT 1')).scalar()
        inserted=updated=deprecated=0; present=[]
        for a in attacks:
            uid=a['attack_uuid']; present.append(uid)
            row=db.execute(text('SELECT id FROM attack_knowledge WHERE attack_uuid=:u'),{'u':uid}).scalar()
            payload={'u':uid,'n':a['name'],'d':a.get('description',''),'c':a.get('category','Other'),'i':str(a.get('impact','SAFE')).upper(),'s':source,'v':version,'m':json.dumps(a.get('metadata') or {})}
            if row:
                db.execute(text("UPDATE attack_knowledge SET name=:n,description=:d,category=:c,impact=:i,status='active',source=:s,knowledge_version=:v,metadata=CAST(:m AS jsonb),updated_at=CURRENT_TIMESTAMP,deprecated_at=NULL WHERE attack_uuid=:u"),payload); aid=row; updated+=1
                for t in ('attack_conditions','attack_cve_mappings','attack_references','attack_technique_mappings'): db.execute(text(f'DELETE FROM {t} WHERE attack_id=:id'),{'id':aid})
            else:
                aid=db.execute(text("INSERT INTO attack_knowledge(attack_uuid,name,description,category,impact,status,source,knowledge_version,metadata) VALUES(:u,:n,:d,:c,:i,'active',:s,:v,CAST(:m AS jsonb)) RETURNING id"),payload).scalar(); inserted+=1
            for cond in a.get('conditions') or []:
                db.execute(text("INSERT INTO attack_conditions(attack_id,condition_type,operator,value,required) VALUES(:id,:t,:o,CAST(:v AS jsonb),:r)"),{'id':aid,'t':cond['type'],'o':cond.get('operator','eq'),'v':json.dumps(cond.get('value')),'r':bool(cond.get('required',True))})
            for cve in a.get('cves') or []: db.execute(text('INSERT INTO attack_cve_mappings(attack_id,cve_id) VALUES(:id,:c)'),{'id':aid,'c':cve})
            for ref in a.get('references') or []: db.execute(text('INSERT INTO attack_references(attack_id,reference_type,reference_id,url) VALUES(:id,:t,:r,:u)'),{'id':aid,'t':ref.get('type','other'),'r':ref.get('id',''),'u':ref.get('url')})
            for tech in a.get('techniques') or []:
                db.execute(text('INSERT INTO attack_technique_mappings(attack_id,technique_key,provider,executable,simulation_impact) VALUES(:id,:k,:p,:e,:i)'),{'id':aid,'k':tech['technique_key'],'p':tech.get('provider','magi_native'),'e':bool(tech.get('executable')),'i':tech.get('simulation_impact')})
        if present:
            result=db.execute(text("UPDATE attack_knowledge SET status='deprecated',deprecated_at=COALESCE(deprecated_at,CURRENT_TIMESTAMP),updated_at=CURRENT_TIMESTAMP WHERE status<>'deprecated' AND NOT (attack_uuid = ANY(:ids))"),{'ids':present}); deprecated=result.rowcount or 0
        db.execute(text('DELETE FROM knowledge_state'))
        db.execute(text('INSERT INTO knowledge_state(knowledge_schema,knowledge_version,source,full_snapshot,minimum_magi_version) VALUES(:ks,:kv,:s,TRUE,:mv)'),{'ks':SCHEMA_VERSION,'kv':version,'s':source,'mv':m.get('minimum_magi_version',MAGI_VERSION)})
        db.execute(text('INSERT INTO knowledge_sync_history(from_version,to_version,source,status,inserted,updated,deprecated,message) VALUES(:f,:t,:s,\'SUCCESS\',:i,:u,:d,:m)'),{'f':old,'t':version,'s':source,'i':inserted,'u':updated,'d':deprecated,'m':'Full cumulative snapshot applied transactionally.'})
    return {'success':True,'from_version':old,'knowledge_version':version,'inserted':inserted,'updated':updated,'deprecated':deprecated,'source':source,'full_snapshot':True}


def ensure_bundled_knowledge()->dict:
    snapshot=json.loads(BUNDLED.read_text(encoding='utf-8')); target=snapshot['manifest']['knowledge_version']
    try:
        with get_db_session() as db: current=db.execute(text('SELECT knowledge_version FROM knowledge_state ORDER BY id DESC LIMIT 1')).scalar()
    except Exception:
        return {'success':False,'message':'Knowledge schema ainda não disponível; execute Alembic upgrade.'}
    if current == target: return {'success':True,'knowledge_version':current,'changed':False}
    # Bundled snapshots are cumulative; jump directly to the newest bundled version.
    if current and str(current) > str(target): return {'success':True,'knowledge_version':current,'changed':False}
    r=import_snapshot(snapshot,'bundled'); r['changed']=True; return r


def knowledge_status()->dict:
    with get_db_session() as db:
        state=db.execute(text('SELECT knowledge_schema,knowledge_version,source,full_snapshot,minimum_magi_version,applied_at FROM knowledge_state ORDER BY id DESC LIMIT 1')).mappings().first()
        counts=db.execute(text("SELECT count(*) total,count(*) FILTER(WHERE status='active') active,count(*) FILTER(WHERE status='deprecated') deprecated FROM attack_knowledge")).mappings().one()
    return {'success':True,'magi_version':MAGI_VERSION,'state':dict(state) if state else None,'attacks':dict(counts)}


def knowledge_catalog(category:str|None=None, impact:str|None=None, status:str='active')->dict:
    q="SELECT id,attack_uuid,name,description,category,impact,status,source,knowledge_version,metadata FROM attack_knowledge WHERE status=:s"; p={'s':status}
    if category: q+=' AND lower(category)=lower(:c)'; p['c']=category
    if impact: q+=' AND upper(impact)=upper(:i)'; p['i']=impact
    q+=' ORDER BY category,name'
    with get_db_session() as db:
        rows=[dict(x) for x in db.execute(text(q),p).mappings().all()]
        for r in rows:
            r['conditions']=[dict(x) for x in db.execute(text('SELECT condition_type,operator,value,required FROM attack_conditions WHERE attack_id=:id ORDER BY id'),{'id':r['id']}).mappings().all()]
            r['simulations']=[dict(x) for x in db.execute(text('SELECT technique_key,provider,executable,simulation_impact FROM attack_technique_mappings WHERE attack_id=:id ORDER BY id'),{'id':r['id']}).mappings().all()]
    return {'success':True,'attacks':rows}


def sync_history(limit:int=50)->dict:
    with get_db_session() as db: rows=[dict(x) for x in db.execute(text('SELECT * FROM knowledge_sync_history ORDER BY id DESC LIMIT :n'),{'n':limit}).mappings().all()]
    return {'success':True,'history':rows}
