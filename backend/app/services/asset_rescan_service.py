from __future__ import annotations
from sqlalchemy import text
from app.database.connection import SessionLocal

def rescan_asset(target:dict, origin_scan:dict)->dict:
    """Identity-first contract for Scan Now. Never rebinds an asset by IP alone.
    5.6.2 intentionally refuses unsafe overwrite when hostname/MAC evidence is unavailable.
    """
    tid=int(target['id']); hostname=(target.get('dns_name') or target.get('hostname') or '').strip(); mac=(target.get('mac_address') or '').strip()
    with SessionLocal() as db:
        # This endpoint records intent and returns the safe lookup plan; runner execution uses the same origin scan credentials.
        db.execute(text("INSERT INTO asset_rescan_history(target_id,scan_id,status,identity_status,located_by,old_ip,details) VALUES(:t,:s,'QUEUED','PENDING',:by,CAST(:ip AS inet),CAST(:d AS jsonb))"),{'t':tid,'s':origin_scan['id'],'by':'hostname' if hostname else 'last_ip','ip':target.get('ip_address'),'d':__import__('json').dumps({'hostname':hostname,'mac':mac,'policy':'hostname_first_ip_fallback_identity_required'})})
        db.execute(text("UPDATE discovery_scan_targets SET last_rescan_at=CURRENT_TIMESTAMP WHERE target_id=:t AND scan_id=:s"),{'t':tid,'s':origin_scan['id']})
        db.commit()
    return {'status':'QUEUED','target_uuid':target['target_uuid'],'asset_id':target['target_uuid'],'origin_scan':origin_scan['scan_uuid'],'lookup_order':['hostname/fqdn','last_ip'],'identity_policy':{'ip_only':'NEVER_CONFIRMED','hostname_and_mac':'MATCH_CONFIRMED','conflict':'DO_NOT_UPDATE'},'message':'Asset Rescan registrado. Atualização do TGT exige validação de identidade; IP isolado nunca sobrescreve o ativo.'}
