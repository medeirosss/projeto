from __future__ import annotations
import json, uuid
from datetime import datetime
from pathlib import Path
from typing import Any
import yaml
from sqlalchemy import text
from app.database.connection import SessionLocal

ROOT = Path(__file__).resolve().parents[2]
KB_PATH = ROOT / "config" / "exposure_knowledge.yaml"


def _now(): return datetime.utcnow()
def _uuid(): return f"EXP-{uuid.uuid4().hex[:12].upper()}"
def _ser(row):
    if not row: return None
    d=dict(row)
    for k,v in list(d.items()):
        if hasattr(v,"isoformat"): d[k]=v.isoformat()
    return d

def load_knowledge() -> dict:
    try:
        return yaml.safe_load(KB_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}

def _upsert(db, *, target_id:int, rule_id:str, source_type:str, source_key:str, title:str, category:str, severity:str, evidence:dict):
    now=_now()
    row=db.execute(text("SELECT status FROM exposure_findings WHERE target_id=:t AND source_type=:st AND source_key=:sk"),{"t":target_id,"st":source_type,"sk":source_key}).mappings().first()
    status='ignored' if row and row.get('status')=='ignored' else 'open'
    db.execute(text("""INSERT INTO exposure_findings(finding_uuid,target_id,rule_id,source_type,source_key,title,category,severity,status,evidence,first_seen_at,last_seen_at,resolved_at,updated_at)
        VALUES(:u,:t,:r,:st,:sk,:title,:cat,:sev,:status,CAST(:ev AS JSONB),:now,:now,NULL,:now)
        ON CONFLICT(target_id,source_type,source_key) DO UPDATE SET rule_id=EXCLUDED.rule_id,title=EXCLUDED.title,category=EXCLUDED.category,severity=EXCLUDED.severity,
        status=CASE WHEN exposure_findings.status='ignored' THEN 'ignored' ELSE 'open' END,evidence=EXCLUDED.evidence,last_seen_at=EXCLUDED.last_seen_at,resolved_at=NULL,updated_at=EXCLUDED.updated_at"""),
        {"u":_uuid(),"t":target_id,"r":rule_id,"st":source_type,"sk":source_key,"title":title,"cat":category,"sev":severity,"status":status,"ev":json.dumps(evidence,ensure_ascii=False,default=str),"now":now})

def evaluate_target(target_id:int) -> dict:
    kb=load_knowledge(); observed:set[tuple[str,str]]=set(); now=_now()
    with SessionLocal() as db:
        services=db.execute(text("SELECT * FROM asset_services WHERE target_id=:t AND active=TRUE"),{"t":target_id}).mappings().all()
        for svc in services:
            port=int(svc.get('port') or 0); proto=str(svc.get('protocol') or 'tcp').lower()
            matched=False
            for rule in kb.get('service_rules') or []:
                if int(rule.get('port') or -1)==port and str(rule.get('protocol') or 'tcp').lower()==proto:
                    sk=f"{proto}:{port}:{rule['id']}"; observed.add(('service',sk)); matched=True
                    _upsert(db,target_id=target_id,rule_id=rule['id'],source_type='service',source_key=sk,title=rule['title'],category=rule['category'],severity=rule['severity'],evidence={"port":port,"protocol":proto,"service":svc.get('friendly_name') or svc.get('service_name'),"product":svc.get('product'),"version":svc.get('version'),"detected_by":"Service Discovery","last_observed":svc.get('last_seen_at')})
            unknown=kb.get('unknown_service') or {}
            name=str(svc.get('service_name') or '').lower()
            if unknown.get('enabled') and (name in {'','unknown'}):
                sk=f"{proto}:{port}:UNKNOWN_SERVICE"; observed.add(('service',sk))
                _upsert(db,target_id=target_id,rule_id='UNKNOWN_SERVICE',source_type='service',source_key=sk,title=unknown.get('title','Serviço desconhecido exposto'),category=unknown.get('category','Unknown Service'),severity=unknown.get('severity','info'),evidence={"port":port,"protocol":proto,"service":svc.get('service_name') or 'unknown',"tunnel":svc.get('tunnel'),"detected_by":"Service Discovery","last_observed":svc.get('last_seen_at')})
        processes=db.execute(text("SELECT * FROM asset_process_findings WHERE target_id=:t AND currently_detected=TRUE"),{"t":target_id}).mappings().all()
        for p in processes:
            rid=p.get('rule_id') or p.get('process_name'); sk=f"process:{rid}"; observed.add(('process',sk))
            _upsert(db,target_id=target_id,rule_id=f"PROCESS_{rid}",source_type='process',source_key=sk,title=f"Processo de interesse: {p.get('process_name')}",category=str(p.get('category') or 'Process Intelligence'),severity=str(p.get('severity') or 'medium'),evidence={"process":p.get('process_name'),"path":p.get('process_path'),"sha256":p.get('sha256'),"publisher":p.get('publisher'),"signed":p.get('signed'),"detected_by":"Deep Inventory / Process Knowledge Base","last_observed":p.get('last_seen_at')})
        existing=db.execute(text("SELECT id,source_type,source_key,status FROM exposure_findings WHERE target_id=:t AND status IN ('open','ignored')"),{"t":target_id}).mappings().all()
        for f in existing:
            if (f['source_type'],f['source_key']) not in observed:
                db.execute(text("UPDATE exposure_findings SET status='resolved',resolved_at=:now,updated_at=:now WHERE id=:id"),{"id":f['id'],"now":now})
        db.commit()
    return summary(target_id=target_id)

def list_findings(*,status:str|None=None,severity:str|None=None,search:str|None=None,target_id:int|None=None,limit:int=500):
    clauses=["1=1"]; params={"limit":limit}
    if status: clauses.append("ef.status=:status"); params['status']=status
    if severity: clauses.append("ef.severity=:severity"); params['severity']=severity
    if target_id: clauses.append("ef.target_id=:target_id"); params['target_id']=target_id
    if search:
        clauses.append("(lower(ef.title) LIKE :search OR lower(COALESCE(t.display_name,'')) LIKE :search OR host(t.ip_address) LIKE :search)"); params['search']=f"%{search.lower()}%"
    with SessionLocal() as db:
        rows=db.execute(text(f"""SELECT ef.*,t.target_uuid,t.display_name,t.hostname,host(t.ip_address) AS ip_address FROM exposure_findings ef JOIN targets t ON t.id=ef.target_id WHERE {' AND '.join(clauses)} ORDER BY CASE ef.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, ef.last_seen_at DESC LIMIT :limit"""),params).mappings().all()
        return [_ser(r) for r in rows]

def summary(target_id:int|None=None):
    params={}; where=""
    if target_id: where="WHERE target_id=:target_id"; params['target_id']=target_id
    with SessionLocal() as db:
        rows=db.execute(text(f"SELECT severity,status,COUNT(*) c FROM exposure_findings {where} GROUP BY severity,status"),params).mappings().all()
    out={"severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0},"status":{"open":0,"resolved":0,"ignored":0},"total":0}
    for r in rows:
        sev=str(r['severity'] or 'info').lower(); st=str(r['status'] or 'open').lower(); c=int(r['c'])
        out['severity'][sev]=out['severity'].get(sev,0)+c; out['status'][st]=out['status'].get(st,0)+c; out['total']+=c
    return out

def set_status(finding_uuid:str,status:str,reason:str|None=None):
    if status not in {'open','ignored'}: raise ValueError('Status permitido: open ou ignored.')
    now=_now()
    with SessionLocal() as db:
        row=db.execute(text("""UPDATE exposure_findings SET status=:s,ignored_at=CASE WHEN :s='ignored' THEN :now ELSE NULL END,ignored_reason=CASE WHEN :s='ignored' THEN :reason ELSE NULL END,resolved_at=NULL,updated_at=:now WHERE finding_uuid=:u RETURNING *"""),{"s":status,"now":now,"reason":reason,"u":finding_uuid}).mappings().first(); db.commit(); return _ser(row) if row else None

def get_target_id(target_uuid:str):
    with SessionLocal() as db:
        return db.execute(text("SELECT id FROM targets WHERE target_uuid=:u"),{"u":target_uuid}).scalar_one_or_none()

def rebuild_all():
    with SessionLocal() as db:
        ids=[int(x[0]) for x in db.execute(text("SELECT id FROM targets WHERE deleted_at IS NULL")).all()]
    for tid in ids: evaluate_target(tid)
    return {"targets_processed":len(ids),"summary":summary()}
