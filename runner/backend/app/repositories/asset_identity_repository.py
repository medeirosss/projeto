from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import text


def _now():
    return datetime.utcnow()


def _norm(value: Any) -> str | None:
    if value is None:
        return None
    v=str(value).strip().lower()
    return v or None


def record_identifier(db, target_id:int, identifier_type:str, value:Any, *, source:str, confidence:int=50, is_current:bool=True) -> None:
    value=_norm(value)
    if not value:
        return
    now=_now()
    if is_current:
        db.execute(text("""UPDATE asset_identifiers SET is_current=FALSE,last_seen_at=:now
            WHERE target_id=:target AND identifier_type=:kind AND identifier_value<>:value AND is_current=TRUE"""),
            {"target":target_id,"kind":identifier_type,"value":value,"now":now})
    db.execute(text("""INSERT INTO asset_identifiers(target_id,identifier_type,identifier_value,source,confidence,first_seen_at,last_seen_at,is_current)
        VALUES(:target,:kind,:value,:source,:confidence,:now,:now,:current)
        ON CONFLICT(target_id,identifier_type,identifier_value) DO UPDATE SET
          source=EXCLUDED.source,confidence=GREATEST(asset_identifiers.confidence,EXCLUDED.confidence),
          last_seen_at=EXCLUDED.last_seen_at,is_current=EXCLUDED.is_current"""),
        {"target":target_id,"kind":identifier_type,"value":value,"source":source,"confidence":confidence,"now":now,"current":is_current})


def record_identity_event(db, target_id:int, status:str, confidence:int, reason:str, evidence:dict|None=None) -> None:
    import json
    db.execute(text("""INSERT INTO asset_identity_events(target_id,match_status,confidence,reason,evidence,observed_at)
        VALUES(:target,:status,:confidence,:reason,CAST(:evidence AS JSONB),:now)"""),
        {"target":target_id,"status":status,"confidence":confidence,"reason":reason,
         "evidence":json.dumps(evidence or {},ensure_ascii=False,default=str),"now":_now()})
    db.execute(text("""UPDATE targets SET identity_status=:status,identity_confidence=:confidence,
        identity_reason=:reason,identity_evaluated_at=:now WHERE id=:target"""),
        {"target":target_id,"status":status,"confidence":confidence,"reason":reason,"now":_now()})


def resolve_discovered_target(db, *, hostname_normalized:str|None, ip_address:str, mac_normalized:str|None, dns_name:str|None=None) -> dict:
    """Deterministic identity resolver for Build 5.6.0.

    IP is continuity evidence, never confirmed identity by itself. Strong conflicts
    deliberately produce NEW_ASSET instead of merging histories.
    """
    hn=_norm(hostname_normalized); mac=_norm(mac_normalized); dns=_norm(dns_name)
    if mac:
        rows=db.execute(text("SELECT * FROM targets WHERE mac_normalized=:m AND deleted_at IS NULL ORDER BY last_seen_at DESC"),{"m":mac}).mappings().all()
        if len(rows)==1:
            r=rows[0]
            existing_h=_norm(r.get('hostname_normalized'))
            if hn and existing_h and hn!=existing_h:
                return {"target":None,"status":"IDENTITY_CONFLICT","confidence":95,"reason":"MAC_MATCH_HOSTNAME_CONFLICT","evidence":{"mac":mac,"incoming_hostname":hn,"existing_target_uuid":r.get('target_uuid'),"existing_hostname":existing_h}}
            return {"target":r,"status":"MATCH_CONFIRMED","confidence":95,"reason":"MAC_MATCH","evidence":{"mac":mac}}
        if len(rows)>1:
            return {"target":None,"status":"IDENTITY_CONFLICT","confidence":100,"reason":"MAC_COLLISION","evidence":{"mac":mac,"matches":len(rows)}}
    if hn:
        rows=db.execute(text("SELECT * FROM targets WHERE hostname_normalized=:h AND deleted_at IS NULL ORDER BY last_seen_at DESC"),{"h":hn}).mappings().all()
        if len(rows)==1:
            r=rows[0]; existing_mac=_norm(r.get('mac_normalized'))
            if mac and existing_mac and mac!=existing_mac:
                return {"target":None,"status":"IDENTITY_CONFLICT","confidence":95,"reason":"HOSTNAME_MATCH_MAC_CONFLICT","evidence":{"hostname":hn,"incoming_mac":mac,"existing_target_uuid":r.get('target_uuid'),"existing_mac":existing_mac}}
            return {"target":r,"status":"MATCH_PROBABLE","confidence":80,"reason":"HOSTNAME_MATCH","evidence":{"hostname":hn}}
        if len(rows)>1:
            return {"target":None,"status":"IDENTITY_CONFLICT","confidence":90,"reason":"HOSTNAME_COLLISION","evidence":{"hostname":hn,"matches":len(rows)}}
    if dns:
        rows=db.execute(text("SELECT * FROM targets WHERE lower(dns_name)=:d AND deleted_at IS NULL ORDER BY last_seen_at DESC"),{"d":dns}).mappings().all()
        if len(rows)==1:
            return {"target":rows[0],"status":"MATCH_PROBABLE","confidence":85,"reason":"FQDN_MATCH","evidence":{"fqdn":dns}}
    rows=db.execute(text("SELECT * FROM targets WHERE ip_address=CAST(:ip AS INET) AND deleted_at IS NULL ORDER BY last_seen_at DESC"),{"ip":ip_address}).mappings().all()
    if len(rows)==1:
        return {"target":rows[0],"status":"MATCH_PROBABLE","confidence":35,"reason":"IP_CONTINUITY_ONLY","evidence":{"ip":ip_address,"warning":"IP alone does not confirm asset identity"}}
    if len(rows)>1:
        return {"target":None,"status":"IDENTITY_CONFLICT","confidence":20,"reason":"IP_REUSED_OR_COLLISION","evidence":{"ip":ip_address,"matches":len(rows)}}
    return {"target":None,"status":"NEW_ASSET","confidence":0,"reason":"NO_IDENTITY_MATCH","evidence":{"ip":ip_address,"hostname":hn,"mac":mac,"fqdn":dns}}


def resolve_target_id(db, target:str|None) -> int|None:
    """Best-effort correlation for executions. Never creates an asset."""
    raw=str(target or '').strip()
    if not raw:
        return None
    # Exact current IP is safe as an execution correlation hint; identity remains governed separately.
    row=db.execute(text("SELECT id FROM targets WHERE ip_address=CAST(:value AS INET) AND deleted_at IS NULL ORDER BY last_seen_at DESC LIMIT 1"),{"value":raw}).first() if all(c.isdigit() or c=='.' for c in raw) else None
    if row:
        return int(row[0])
    key=raw.lower().rstrip('.')
    rows=db.execute(text("SELECT id FROM targets WHERE deleted_at IS NULL AND (hostname_normalized=:v OR lower(COALESCE(dns_name,''))=:v) ORDER BY last_seen_at DESC LIMIT 2"),{"v":key}).all()
    return int(rows[0][0]) if len(rows)==1 else None
