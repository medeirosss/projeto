from __future__ import annotations
from sqlalchemy import text
from app.database.connection import SessionLocal

def _match(cond, ports, services, findings, cred_types):
    t=cond['condition_type']; v=cond['value']
    if t=='tcp_port': return ('tcp',int(v)) in ports
    if t=='udp_port': return ('udp',int(v)) in ports
    if t=='tcp_port_any': return any(('tcp',int(x)) in ports for x in (v or []))
    if t in {'service','service_name','deep_inventory_service'}:
        wanted=str(v).lower()
        return wanted in services or any(wanted in x for x in services)
    if t=='finding': return str(v).lower() in findings
    if t=='credential_type': return str(v).lower() in cred_types
    return False

def correlate_target(target_id:int)->dict:
    with SessionLocal() as db:
        svc=db.execute(text("SELECT protocol,port,lower(coalesce(service_name,'')) service_name FROM asset_services WHERE target_id=:t AND active=TRUE"),{'t':target_id}).mappings().all()
        ports={(str(x['protocol']).lower(),int(x['port'])) for x in svc}; services={x['service_name'] for x in svc if x['service_name']}
        findings={str(x[0]).lower() for x in db.execute(text("SELECT source_key FROM exposure_findings WHERE target_id=:t AND status='open'"),{'t':target_id}).all()}
        cred_types={str(x[0]).lower() for x in db.execute(text("SELECT DISTINCT c.credential_type FROM asset_credentials ac JOIN stored_credentials c ON c.id=ac.credential_id WHERE ac.target_id=:t"),{'t':target_id}).all()}
        attacks=db.execute(text("SELECT id,attack_uuid,name,description,category,impact FROM attack_knowledge WHERE status='active' ORDER BY category,name")).mappings().all()
        out=[]
        for a in attacks:
            conds=[dict(x) for x in db.execute(text("SELECT condition_type,operator,value,required FROM attack_conditions WHERE attack_id=:a ORDER BY id"),{'a':a['id']}).mappings().all()]
            checks=[(_match(c,ports,services,findings,cred_types),c) for c in conds]
            required=[ok for ok,c in checks if c.get('required',True)]
            # Partial required evidence is POSSIBLE; all required conditions = AVAILABLE relation.
            matched=sum(1 for ok,c in checks if ok); req_total=len(required)
            if not matched: continue
            state='AVAILABLE' if (not required or all(required)) else 'POSSIBLE'
            sims=[dict(x) for x in db.execute(text("SELECT technique_key,provider,executable,simulation_impact FROM attack_technique_mappings WHERE attack_id=:a AND executable=TRUE"),{'a':a['id']}).mappings().all()]
            confidence=100 if state=='AVAILABLE' else max(20,int(100*matched/max(1,len(checks))))
            reason={'matched':matched,'conditions':len(checks),'checks':[{'type':c['condition_type'],'value':c['value'],'required':c.get('required',True),'matched':ok} for ok,c in checks]}
            db.execute(text("""INSERT INTO asset_attack_exposure(target_id,attack_id,state,match_confidence,match_reason) VALUES(:t,:a,:s,:c,CAST(:r AS jsonb)) ON CONFLICT(target_id,attack_id) DO UPDATE SET state=EXCLUDED.state,match_confidence=EXCLUDED.match_confidence,match_reason=EXCLUDED.match_reason,last_seen_at=CURRENT_TIMESTAMP"""),{'t':target_id,'a':a['id'],'s':state,'c':confidence,'r':__import__('json').dumps(reason)})
            d=dict(a); d.update({'state':state,'match_confidence':confidence,'match_reason':reason,'simulations':sims}); out.append(d)
        db.commit()
    return {'target_id':target_id,'attacks':out,'attack_count':len(out),'simulation_count':sum(len(a['simulations']) for a in out)}
