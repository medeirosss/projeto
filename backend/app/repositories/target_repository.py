from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _now(): return datetime.utcnow()
def _uuid(prefix: str): return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"

def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, default=str)


def ensure_target_schema() -> None:
    with SessionLocal() as db:
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS targets (
            id SERIAL PRIMARY KEY, target_uuid VARCHAR(40) UNIQUE NOT NULL,
            hostname VARCHAR(255), hostname_normalized VARCHAR(255), ip_address INET NOT NULL,
            mac_address VARCHAR(17), mac_normalized VARCHAR(12), vendor VARCHAR(255), dns_name VARCHAR(255), hostname_source VARCHAR(30),
            display_name VARCHAR(255), asset_type VARCHAR(50) NOT NULL DEFAULT 'unknown', fingerprint_confidence INTEGER NOT NULL DEFAULT 0, fingerprint_rule VARCHAR(100), fingerprint_reasons TEXT, fingerprinted_at TIMESTAMP, notes TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'online', discovery_source VARCHAR(50) NOT NULL DEFAULT 'nmap',
            last_scan_id INTEGER, runner_id VARCHAR(80),
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS target_addresses (
            id SERIAL PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            ip_address INET NOT NULL, first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, is_current BOOLEAN NOT NULL DEFAULT TRUE,
            UNIQUE(target_id, ip_address)
        );
        CREATE TABLE IF NOT EXISTS discovery_scans (
            id SERIAL PRIMARY KEY, scan_uuid VARCHAR(40) UNIQUE NOT NULL, name VARCHAR(150) NOT NULL,
            target_spec VARCHAR(255) NOT NULL, target_type VARCHAR(20) NOT NULL,
            schedule_type VARCHAR(20) NOT NULL DEFAULT 'manual', interval_minutes INTEGER,
            is_enabled BOOLEAN NOT NULL DEFAULT FALSE, is_running BOOLEAN NOT NULL DEFAULT FALSE,
            last_run_at TIMESTAMP, next_run_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS discovery_runs (
            id SERIAL PRIMARY KEY, run_uuid VARCHAR(40) UNIQUE NOT NULL,
            scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL,
            target_spec VARCHAR(255) NOT NULL, execution_mode VARCHAR(30) NOT NULL DEFAULT 'local',
            trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual', status VARCHAR(30) NOT NULL DEFAULT 'running',
            addresses_checked INTEGER NOT NULL DEFAULT 0, discovered_count INTEGER NOT NULL DEFAULT 0,
            error TEXT, started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS discovery_scan_targets (
            scan_id INTEGER NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
            target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consecutive_misses INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(scan_id, target_id)
        );
        CREATE TABLE IF NOT EXISTS asset_compliance_rules (
            id SERIAL PRIMARY KEY,
            asset_type VARCHAR(30) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            starts_with VARCHAR(80), contains_text VARCHAR(80), ends_with VARCHAR(80),
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS enrichment_events (
            id SERIAL PRIMARY KEY,
            discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE SET NULL,
            target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            is_new BOOLEAN NOT NULL DEFAULT FALSE,
            stages JSONB NOT NULL DEFAULT '{}'::jsonb,
            evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
            classification VARCHAR(50), confidence INTEGER NOT NULL DEFAULT 0,
            error_summary TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS asset_services (
            id SERIAL PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            port INTEGER NOT NULL, protocol VARCHAR(10) NOT NULL DEFAULT 'tcp', service_name VARCHAR(100), friendly_name VARCHAR(120), category VARCHAR(100),
            product VARCHAR(255), version VARCHAR(120), extra_info VARCHAR(255), banner TEXT, os_type VARCHAR(80), cpe JSONB NOT NULL DEFAULT '[]'::jsonb, service_fingerprint TEXT, tunnel VARCHAR(30), detection_method VARCHAR(30), detection_confidence INTEGER, state VARCHAR(30) NOT NULL DEFAULT 'open',
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, runner_id VARCHAR(80),
            last_discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE SET NULL, active BOOLEAN NOT NULL DEFAULT TRUE,
            UNIQUE(target_id,port,protocol)
        );
        CREATE TABLE IF NOT EXISTS asset_service_observations (
            id SERIAL PRIMARY KEY, discovery_run_id INTEGER REFERENCES discovery_runs(id) ON DELETE SET NULL, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            port INTEGER NOT NULL, protocol VARCHAR(10) NOT NULL, state VARCHAR(30), service_name VARCHAR(100), friendly_name VARCHAR(120), category VARCHAR(100), product VARCHAR(255), version VARCHAR(120),
            is_new BOOLEAN NOT NULL DEFAULT FALSE, observed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS service_discovery_jobs (
            id SERIAL PRIMARY KEY, discovery_run_id INTEGER NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            runner_job_id INTEGER UNIQUE NOT NULL REFERENCES runner_jobs(id) ON DELETE CASCADE, runner_id VARCHAR(80), target_ip INET NOT NULL, status VARCHAR(30) NOT NULL DEFAULT 'queued',
            service_count INTEGER NOT NULL DEFAULT 0, new_service_count INTEGER NOT NULL DEFAULT 0, error TEXT, raw_output TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, started_at TIMESTAMP, finished_at TIMESTAMP
        );
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS dns_name VARCHAR(255);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS hostname_source VARCHAR(30);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) NOT NULL DEFAULT 'unknown';
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS fingerprint_confidence INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS fingerprint_rule VARCHAR(100);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS fingerprint_reasons TEXT;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS fingerprinted_at TIMESTAMP;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS notes TEXT;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'online';
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS active_in_inventory BOOLEAN NOT NULL DEFAULT TRUE;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS retired_at TIMESTAMP;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS retired_reason VARCHAR(80);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS consecutive_misses INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS confidence_details JSONB NOT NULL DEFAULT '[]'::jsonb;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_enrichment_status VARCHAR(30);
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS os_type VARCHAR(80);
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS cpe JSONB NOT NULL DEFAULT '[]'::jsonb;
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS service_fingerprint TEXT;
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS tunnel VARCHAR(30);
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS detection_method VARCHAR(30);
        ALTER TABLE asset_services ADD COLUMN IF NOT EXISTS detection_confidence INTEGER;
        ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS cleanup_enabled BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS service_discovery_enabled BOOLEAN NOT NULL DEFAULT FALSE;
        ALTER TABLE discovery_scans ADD COLUMN IF NOT EXISTS cleanup_missed_scans INTEGER NOT NULL DEFAULT 10;
        ALTER TABLE discovery_scan_targets ADD COLUMN IF NOT EXISTS consecutive_misses INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual';
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS addresses_checked INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS provider VARCHAR(20) NOT NULL DEFAULT 'runner';
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS raw_output TEXT;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS new_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS updated_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS dns_success_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS dns_failed_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS fingerprint_success_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS fingerprint_failed_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS classified_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS unknown_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS pipeline_status VARCHAR(30);
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS service_jobs_total INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS service_jobs_completed INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS service_jobs_failed INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS services_found_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS new_services_count INTEGER NOT NULL DEFAULT 0;
        UPDATE targets SET display_name=COALESCE(NULLIF(hostname,''),NULLIF(dns_name,''),host(ip_address)) WHERE display_name IS NULL OR display_name='';
        CREATE INDEX IF NOT EXISTS idx_targets_last_seen_at ON targets(last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS idx_targets_inventory_active ON targets(active_in_inventory) WHERE active_in_inventory=TRUE;
        CREATE INDEX IF NOT EXISTS idx_discovery_scans_next_run ON discovery_scans(next_run_at) WHERE is_enabled = TRUE;
        CREATE INDEX IF NOT EXISTS idx_discovery_runs_started_at ON discovery_runs(started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_enrichment_events_run ON enrichment_events(discovery_run_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_asset_services_target ON asset_services(target_id,active,port);
        CREATE INDEX IF NOT EXISTS idx_service_discovery_jobs_run ON service_discovery_jobs(discovery_run_id,status);
        """))
        db.commit()


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("ip_address",):
        if row.get(key) is not None: row[key] = str(row[key])
    for key, value in list(row.items()):
        if hasattr(value, "isoformat"): row[key] = value.isoformat()
    return row


def create_scan(name: str, target_spec: str, target_type: str, schedule_type: str, interval_minutes: int | None, is_enabled: bool, cleanup_enabled: bool=False, cleanup_missed_scans: int=10, service_discovery_enabled: bool=False) -> dict:
    now = _now(); next_run = now + timedelta(minutes=interval_minutes) if is_enabled and schedule_type == "interval" and interval_minutes else None
    with SessionLocal() as db:
        row = db.execute(text("""INSERT INTO discovery_scans
        (scan_uuid,name,target_spec,target_type,schedule_type,interval_minutes,is_enabled,next_run_at,cleanup_enabled,cleanup_missed_scans,service_discovery_enabled,created_at,updated_at)
        VALUES(:uuid,:name,:spec,:type,:sched,:interval,:enabled,:next,:cleanup_enabled,:cleanup_missed,:service_enabled,:now,:now) RETURNING *"""),
        {"uuid":_uuid("SCN"),"name":name,"spec":target_spec,"type":target_type,"sched":schedule_type,"interval":interval_minutes,"enabled":is_enabled,"next":next_run,"cleanup_enabled":cleanup_enabled,"cleanup_missed":cleanup_missed_scans,"service_enabled":service_discovery_enabled,"now":now}).mappings().first()
        db.commit(); return _serialize(dict(row))


def list_scans() -> list[dict]:
    with SessionLocal() as db:
        rows=db.execute(text("SELECT * FROM discovery_scans ORDER BY created_at DESC")).mappings().all()
        return [_serialize(dict(x)) for x in rows]


def get_scan(scan_uuid: str) -> dict | None:
    with SessionLocal() as db:
        row=db.execute(text("SELECT * FROM discovery_scans WHERE scan_uuid=:u"),{"u":scan_uuid}).mappings().first()
        return _serialize(dict(row)) if row else None


def update_scan(scan_uuid: str, **fields) -> dict | None:
    allowed={"name","target_spec","target_type","schedule_type","interval_minutes","is_enabled","cleanup_enabled","cleanup_missed_scans","service_discovery_enabled"}
    values={k:v for k,v in fields.items() if k in allowed}
    current=get_scan(scan_uuid)
    if not current: return None
    if not values: return current
    effective={**current,**values}
    interval=effective.get("interval_minutes")
    next_run=_now()+timedelta(minutes=int(interval)) if effective.get("is_enabled") and effective.get("schedule_type")=="interval" and interval else None
    values["next_run_at"]=next_run; values["u"]=scan_uuid; values["now"]=_now()
    sets=", ".join(f"{k}=:{k}" for k in values if k in allowed or k=="next_run_at")
    with SessionLocal() as db:
        row=db.execute(text(f"UPDATE discovery_scans SET {sets}, updated_at=:now WHERE scan_uuid=:u RETURNING *"),values).mappings().first()
        db.commit(); return _serialize(dict(row)) if row else None


def delete_scan(scan_uuid: str, remove_exclusive_targets: bool=False) -> bool:
    with SessionLocal() as db:
        scan=db.execute(text("SELECT id FROM discovery_scans WHERE scan_uuid=:u"),{"u":scan_uuid}).mappings().first()
        if not scan: return False
        sid=scan["id"]
        running=db.execute(text("SELECT 1 FROM discovery_runs WHERE scan_id=:sid AND status IN ('queued','running') LIMIT 1"),{"sid":sid}).first()
        if running:
            raise ValueError("Este scan possui uma execução em andamento. Aguarde a conclusão antes de excluir.")
        if remove_exclusive_targets:
            db.execute(text("""UPDATE targets SET active_in_inventory=FALSE,retired_at=:now,retired_reason='scan_removed',updated_at=:now WHERE id IN (
                SELECT dst.target_id FROM discovery_scan_targets dst WHERE dst.scan_id=:sid
                AND NOT EXISTS (SELECT 1 FROM discovery_scan_targets other WHERE other.target_id=dst.target_id AND other.scan_id<>:sid)
            )"""),{"sid":sid,"now":_now()})
        db.execute(text("DELETE FROM discovery_scans WHERE id=:sid"),{"sid":sid}); db.commit(); return True


def claim_due_scans(limit:int=2) -> list[dict]:
    now=_now()
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT * FROM discovery_scans WHERE is_enabled=TRUE AND is_running=FALSE
        AND next_run_at IS NOT NULL AND next_run_at<=:now ORDER BY next_run_at LIMIT :limit FOR UPDATE SKIP LOCKED"""),{"now":now,"limit":limit}).mappings().all()
        ids=[r["id"] for r in rows]
        if ids: db.execute(text("UPDATE discovery_scans SET is_running=TRUE WHERE id = ANY(:ids)"),{"ids":ids})
        db.commit(); return [_serialize(dict(r)) for r in rows]


def mark_scan_running(scan_uuid:str) -> bool:
    with SessionLocal() as db:
        row=db.execute(text("UPDATE discovery_scans SET is_running=TRUE WHERE scan_uuid=:u AND is_running=FALSE RETURNING id"),{"u":scan_uuid}).first(); db.commit(); return bool(row)


def release_scan(scan_id:int, interval_minutes:int|None):
    now=_now(); nxt=now+timedelta(minutes=interval_minutes) if interval_minutes else None
    with SessionLocal() as db:
        db.execute(text("UPDATE discovery_scans SET is_running=FALSE,last_run_at=:now,next_run_at=:next,updated_at=:now WHERE id=:id"),{"id":scan_id,"now":now,"next":nxt}); db.commit()


def create_discovery_run(target_spec: str, scan_id:int|None=None, trigger_type:str="manual", addresses_checked:int=0) -> dict:
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO discovery_runs(run_uuid,scan_id,target_spec,trigger_type,status,addresses_checked,started_at,pipeline_status)
        VALUES(:u,:sid,:spec,:trigger,'running',:checked,:now,'running') RETURNING *"""),{"u":_uuid("DSC"),"sid":scan_id,"spec":target_spec,"trigger":trigger_type,"checked":addresses_checked,"now":_now()}).mappings().first(); db.commit(); return _serialize(dict(row))


def finish_discovery_run(run_uuid:str,status:str,count:int,error:str|None=None):
    with SessionLocal() as db:
        db.execute(text("UPDATE discovery_runs SET status=:s,discovered_count=:c,error=:e,finished_at=:n,pipeline_status=:p WHERE run_uuid=:u"),{"s":status,"c":count,"e":error,"n":_now(),"p":"completed" if status=="success" else status,"u":run_uuid}); db.commit()


def _find_existing(db, hostname_normalized, ip_address, mac_normalized):
    if mac_normalized:
        r=db.execute(text("SELECT * FROM targets WHERE mac_normalized=:m LIMIT 1"),{"m":mac_normalized}).mappings().first()
        if r:return r
    if hostname_normalized:
        r=db.execute(text("SELECT * FROM targets WHERE hostname_normalized=:h ORDER BY last_seen_at DESC LIMIT 1"),{"h":hostname_normalized}).mappings().first()
        if r:return r
    return db.execute(text("SELECT * FROM targets WHERE ip_address=CAST(:ip AS INET) ORDER BY last_seen_at DESC LIMIT 1"),{"ip":ip_address}).mappings().first()


def upsert_discovered_target(*,hostname,hostname_normalized,ip_address,mac_address,mac_normalized,vendor=None,status="online",source="nmap",scan_id=None,runner_id=None,dns_name=None,hostname_source=None)->dict:
    now=_now()
    with SessionLocal() as db:
        existing=_find_existing(db,hostname_normalized,ip_address,mac_normalized)
        is_new = existing is None
        if existing:
            tid=existing["id"]
            if str(existing["ip_address"])!=ip_address: db.execute(text("UPDATE target_addresses SET is_current=FALSE WHERE target_id=:id"),{"id":tid})
            row=db.execute(text("""UPDATE targets SET hostname=COALESCE(:h,hostname),hostname_normalized=COALESCE(:hn,hostname_normalized),
            dns_name=COALESCE(:dns,dns_name),hostname_source=COALESCE(:hostname_source,hostname_source),
            display_name=COALESCE(:display_name,display_name),ip_address=CAST(:ip AS INET),mac_address=COALESCE(:m,mac_address),mac_normalized=COALESCE(:mn,mac_normalized),
            vendor=COALESCE(:vendor,vendor),status=:status,discovery_source=:src,last_scan_id=COALESCE(:sid,last_scan_id),
            runner_id=COALESCE(:runner_id,runner_id),last_seen_at=:n,deleted_at=NULL,active_in_inventory=TRUE,retired_at=NULL,retired_reason=NULL,consecutive_misses=0,updated_at=:n WHERE id=:id RETURNING *"""),
            {"h":hostname,"hn":hostname_normalized,"dns":dns_name or hostname,"hostname_source":hostname_source,"display_name":hostname or dns_name or ip_address,"ip":ip_address,"m":mac_address,"mn":mac_normalized,"vendor":vendor,"status":status,"src":source,"sid":scan_id,"runner_id":runner_id,"n":now,"id":tid}).mappings().first()
        else:
            row=db.execute(text("""INSERT INTO targets(target_uuid,hostname,hostname_normalized,dns_name,hostname_source,display_name,asset_type,ip_address,mac_address,mac_normalized,vendor,status,discovery_source,last_scan_id,runner_id,first_seen_at,last_seen_at,active_in_inventory,consecutive_misses,created_at,updated_at)
            VALUES(:u,:h,:hn,:dns,:hostname_source,:display_name,'unknown',CAST(:ip AS INET),:m,:mn,:vendor,:status,:src,:sid,:runner_id,:n,:n,TRUE,0,:n,:n) RETURNING *"""),
            {"u":_uuid("TGT"),"h":hostname,"hn":hostname_normalized,"dns":dns_name or hostname,"hostname_source":hostname_source,"display_name":hostname or dns_name or ip_address,"ip":ip_address,"m":mac_address,"mn":mac_normalized,"vendor":vendor,"status":status,"src":source,"sid":scan_id,"runner_id":runner_id,"n":now}).mappings().first(); tid=row["id"]
        db.execute(text("""INSERT INTO target_addresses(target_id,ip_address,first_seen_at,last_seen_at,is_current) VALUES(:id,CAST(:ip AS INET),:n,:n,TRUE)
        ON CONFLICT(target_id,ip_address) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at,is_current=TRUE"""),{"id":tid,"ip":ip_address,"n":now})
        if scan_id:
            db.execute(text("""INSERT INTO discovery_scan_targets(scan_id,target_id,first_seen_at,last_seen_at,consecutive_misses) VALUES(:sid,:tid,:n,:n,0)
            ON CONFLICT(scan_id,target_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at,consecutive_misses=0"""),{"sid":scan_id,"tid":tid,"n":now})
        db.commit()
        result=_serialize(dict(row)); result["_is_new"]=is_new
        return result


def get_compliance_rules() -> list[dict]:
    with SessionLocal() as db:
        rows=db.execute(text("SELECT * FROM asset_compliance_rules ORDER BY CASE asset_type WHEN 'server' THEN 1 WHEN 'workstation' THEN 2 WHEN 'network_device' THEN 3 ELSE 9 END")).mappings().all()
        return [_serialize(dict(r)) for r in rows]


def save_compliance_rules(rules: list[dict]) -> list[dict]:
    allowed={"server","workstation","network_device"}
    if len(rules)>3: raise ValueError("Esta versão permite no máximo 3 regras de compliance.")
    seen=set()
    with SessionLocal() as db:
        for item in rules:
            asset_type=str(item.get("asset_type") or "").strip().lower()
            if asset_type not in allowed: raise ValueError("Tipo de compliance inválido.")
            if asset_type in seen: raise ValueError("Cada tipo pode possuir apenas uma regra nesta versão.")
            seen.add(asset_type)
            values={
                "asset_type":asset_type,
                "name":str(item.get("name") or asset_type).strip()[:100],
                "starts_with":str(item.get("starts_with") or "").strip()[:80] or None,
                "contains_text":str(item.get("contains_text") or "").strip()[:80] or None,
                "ends_with":str(item.get("ends_with") or "").strip()[:80] or None,
                "enabled":bool(item.get("enabled",True)),
                "now":_now(),
            }
            db.execute(text("""INSERT INTO asset_compliance_rules(asset_type,name,starts_with,contains_text,ends_with,enabled,created_at,updated_at)
                VALUES(:asset_type,:name,:starts_with,:contains_text,:ends_with,:enabled,:now,:now)
                ON CONFLICT(asset_type) DO UPDATE SET name=EXCLUDED.name,starts_with=EXCLUDED.starts_with,contains_text=EXCLUDED.contains_text,ends_with=EXCLUDED.ends_with,enabled=EXCLUDED.enabled,updated_at=EXCLUDED.updated_at"""),values)
        for missing in ({"server","workstation","network_device"} - seen):
            db.execute(text("DELETE FROM asset_compliance_rules WHERE asset_type=:asset_type"), {"asset_type": missing})
        if not seen:
            db.execute(text("DELETE FROM asset_compliance_rules"))
        db.commit()
    return get_compliance_rules()


def update_target_fingerprint(target_id:int, asset_type:str, confidence:int, rule_id:str|None, reasons:list[str], fingerprinted_at:datetime, evidence:list[dict]|None=None, enrichment_status:str|None=None)->dict|None:
    with SessionLocal() as db:
        row=db.execute(text("""UPDATE targets SET asset_type=:asset_type,fingerprint_confidence=:confidence,fingerprint_rule=:rule_id,
            fingerprint_reasons=:reasons,fingerprinted_at=:fingerprinted_at,confidence_details=CAST(:evidence AS JSONB),last_enrichment_status=:enrichment_status,updated_at=:fingerprinted_at WHERE id=:id RETURNING *"""),
            {"asset_type":asset_type,"confidence":confidence,"rule_id":rule_id,"reasons":"; ".join(reasons),"fingerprinted_at":fingerprinted_at,"evidence":_json(evidence or []),"enrichment_status":enrichment_status,"id":target_id}).mappings().first()
        db.commit(); return _serialize(dict(row)) if row else None


def record_enrichment_event(discovery_run_id:int|None,target_id:int,is_new:bool,stages:dict,evidence:list[dict],classification:str,confidence:int,error_summary:str|None=None)->dict:
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO enrichment_events(discovery_run_id,target_id,is_new,stages,evidence,classification,confidence,error_summary,created_at)
            VALUES(:run_id,:target_id,:is_new,CAST(:stages AS JSONB),CAST(:evidence AS JSONB),:classification,:confidence,:error_summary,:now) RETURNING *"""),
            {"run_id":discovery_run_id,"target_id":target_id,"is_new":is_new,"stages":_json(stages),"evidence":_json(evidence),"classification":classification,"confidence":confidence,"error_summary":error_summary,"now":_now()}).mappings().first()
        db.commit(); return _serialize(dict(row))


def enrich_target(target:dict, discovery_run_id:int|None=None, host_context:dict|None=None)->dict:
    from app.services.enrichment_engine import fingerprint_asset
    compliance=get_compliance_rules()
    host_context=host_context or {}
    stages={
        "discovery":{"status":"success","message":"Ativo confirmado pelo Nmap."},
        "dns":{"status":"pending","message":"Aguardando resolução."},
        "fingerprint":{"status":"pending","message":"Aguardando análise."},
        "classification":{"status":"pending","message":"Aguardando classificação."},
        "inventory":{"status":"success","message":"Ativo persistido no inventário."},
    }
    if host_context.get("dns_name") or host_context.get("hostname"):
        stages["dns"]={"status":"success","message":f"Nome identificado por {host_context.get('hostname_source') or 'Nmap/DNS'}."}
    elif host_context.get("dns_error"):
        stages["dns"]={"status":"failed","message":str(host_context.get("dns_error"))[:300]}
    else:
        stages["dns"]={"status":"inconclusive","message":"Nenhum nome DNS/PTR foi encontrado."}
    try:
        result=fingerprint_asset(target, compliance_rules=compliance)
        stages["fingerprint"]={"status":"success" if result.internal_rule_id else "inconclusive","message":f"Regra {result.internal_rule_id} compatível." if result.internal_rule_id else "Nenhuma regra interna conclusiva."}
        stages["classification"]={"status":"success" if result.asset_type!="unknown" else "inconclusive","message":f"Classificado como {result.asset_type}." if result.asset_type!="unknown" else "Ativo permaneceu sem classificação."}
        final_status="success" if result.asset_type!="unknown" else "partial"
        updated=update_target_fingerprint(int(target["id"]),result.asset_type,result.confidence,result.rule_id,result.reasons,result.fingerprinted_at,result.evidence,final_status) or target
        record_enrichment_event(discovery_run_id,int(target["id"]),bool(target.get("_is_new")),stages,result.evidence,result.asset_type,result.confidence,None)
        updated["_is_new"]=bool(target.get("_is_new"))
        return updated
    except Exception as exc:
        stages["fingerprint"]={"status":"failed","message":str(exc)[:300]}
        stages["classification"]={"status":"skipped","message":"Classificação não executada devido à falha anterior."}
        update_target_fingerprint(int(target["id"]),target.get("asset_type") or "unknown",int(target.get("fingerprint_confidence") or 0),target.get("fingerprint_rule"),[],_now(),target.get("confidence_details") or [],"failed")
        record_enrichment_event(discovery_run_id,int(target["id"]),bool(target.get("_is_new")),stages,[],target.get("asset_type") or "unknown",int(target.get("fingerprint_confidence") or 0),str(exc)[:1000])
        target["_is_new"]=bool(target.get("_is_new"))
        return target


def apply_scan_cleanup(scan_id:int, seen_target_ids:list[int]) -> dict:
    with SessionLocal() as db:
        scan=db.execute(text("SELECT cleanup_enabled,cleanup_missed_scans FROM discovery_scans WHERE id=:id"),{"id":scan_id}).mappings().first()
        if not scan: return {"missed":0,"retired":0}
        ids=seen_target_ids or [-1]
        missed=db.execute(text("""UPDATE discovery_scan_targets dst SET consecutive_misses=dst.consecutive_misses+1
            WHERE dst.scan_id=:sid AND NOT (dst.target_id = ANY(:seen))
            RETURNING dst.target_id,dst.consecutive_misses"""),{"sid":scan_id,"seen":ids}).mappings().all()
        # Keep the target-level counter as a convenient summary, while the source
        # of truth remains per scan association.
        db.execute(text("""UPDATE targets t SET consecutive_misses=COALESCE((SELECT MAX(dst.consecutive_misses) FROM discovery_scan_targets dst WHERE dst.target_id=t.id),0),updated_at=:now
            WHERE t.id IN (SELECT target_id FROM discovery_scan_targets WHERE scan_id=:sid)"""),{"sid":scan_id,"now":_now()})
        retired=[]
        if scan["cleanup_enabled"]:
            threshold=max(3,int(scan["cleanup_missed_scans"] or 10))
            retired=db.execute(text("""UPDATE targets t SET active_in_inventory=FALSE,retired_at=:now,retired_reason='discovery_cleanup',updated_at=:now
                WHERE t.active_in_inventory=TRUE
                  AND t.id IN (SELECT target_id FROM discovery_scan_targets WHERE scan_id=:sid AND consecutive_misses>=:threshold)
                  AND NOT EXISTS (SELECT 1 FROM discovery_scan_targets other WHERE other.target_id=t.id AND other.scan_id<>:sid AND other.consecutive_misses=0)
                RETURNING t.id"""),{"sid":scan_id,"threshold":threshold,"now":_now()}).all()
        db.commit(); return {"missed":len(missed),"retired":len(retired)}


def update_run_pipeline_summary(run_id:int, finalize:bool=True) -> None:
    with SessionLocal() as db:
        rows=db.execute(text("SELECT is_new,stages,classification FROM enrichment_events WHERE discovery_run_id=:id"),{"id":run_id}).mappings().all()
        def stage_status(row,name):
            value=row.get("stages") or {}; return (value.get(name) or {}).get("status")
        counts={
            "new_count":sum(1 for r in rows if r["is_new"]),
            "updated_count":sum(1 for r in rows if not r["is_new"]),
            "dns_success_count":sum(1 for r in rows if stage_status(r,"dns")=="success"),
            "dns_failed_count":sum(1 for r in rows if stage_status(r,"dns") in {"failed","inconclusive"}),
            "fingerprint_success_count":sum(1 for r in rows if stage_status(r,"fingerprint")=="success"),
            "fingerprint_failed_count":sum(1 for r in rows if stage_status(r,"fingerprint") in {"failed","inconclusive"}),
            "classified_count":sum(1 for r in rows if str(r.get("classification") or "unknown")!="unknown"),
            "unknown_count":sum(1 for r in rows if str(r.get("classification") or "unknown")=="unknown"),
        }
        db.execute(text("""UPDATE discovery_runs SET new_count=:new_count,updated_count=:updated_count,dns_success_count=:dns_success_count,dns_failed_count=:dns_failed_count,
            fingerprint_success_count=:fingerprint_success_count,fingerprint_failed_count=:fingerprint_failed_count,classified_count=:classified_count,unknown_count=:unknown_count,pipeline_status=:pipeline_status
            WHERE id=:id"""),{**counts,"id":run_id,"pipeline_status":"completed" if finalize else "enrichment_complete"})
        db.commit()


def list_targets(search=None,limit=200,offset=0):
    s=f"%{(search or '').strip().lower()}%"
    where="WHERE t.deleted_at IS NULL AND t.active_in_inventory=TRUE AND (:s='%%' OR lower(COALESCE(t.display_name,'')) LIKE :s OR lower(COALESCE(t.hostname,'')) LIKE :s OR lower(COALESCE(t.dns_name,'')) LIKE :s OR host(t.ip_address) LIKE :s OR lower(COALESCE(t.mac_address,'')) LIKE :s OR lower(COALESCE(t.vendor,'')) LIKE :s OR lower(COALESCE(t.runner_id,'')) LIKE :s OR lower(COALESCE(r.name,'')) LIKE :s)"
    with SessionLocal() as db:
        rows=db.execute(text(f"""SELECT t.*, COALESCE(NULLIF(r.name,''),NULLIF(r.hostname,''),t.runner_id) AS runner_name,
            'detected' AS lifecycle_status,
            (SELECT COUNT(*) FROM asset_services svc WHERE svc.target_id=t.id AND svc.active=TRUE) AS service_count
            FROM targets t LEFT JOIN runners r ON r.runner_id=t.runner_id
            {where} ORDER BY t.last_seen_at DESC LIMIT :l OFFSET :o"""),{"s":s,"l":limit,"o":offset}).mappings().all()
        total=db.execute(text(f"SELECT COUNT(*) FROM targets t LEFT JOIN runners r ON r.runner_id=t.runner_id {where}"),{"s":s}).scalar_one()
        return {"items":[_serialize(dict(r)) for r in rows],"total":int(total),"limit":limit,"offset":offset}


def list_new_assets_latest_run(limit:int=500) -> dict:
    with SessionLocal() as db:
        run=db.execute(text("""SELECT id,run_uuid,started_at,finished_at FROM discovery_runs
            WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1""")).mappings().first()
        if not run: return {"items":[],"total":0,"run":None}
        rows=db.execute(text("""SELECT t.*,COALESCE(NULLIF(r.name,''),NULLIF(r.hostname,''),t.runner_id) AS runner_name,e.stages,e.evidence,e.confidence,
            (SELECT COUNT(*) FROM asset_services svc WHERE svc.target_id=t.id AND svc.active=TRUE) AS service_count
            FROM enrichment_events e JOIN targets t ON t.id=e.target_id LEFT JOIN runners r ON r.runner_id=t.runner_id
            WHERE e.discovery_run_id=:rid AND e.is_new=TRUE AND t.active_in_inventory=TRUE AND t.deleted_at IS NULL
            ORDER BY e.created_at DESC LIMIT :limit"""),{"rid":run["id"],"limit":limit}).mappings().all()
        return {"items":[_serialize(dict(x)) for x in rows],"total":len(rows),"run":_serialize(dict(run))}


def get_target(target_uuid):
    with SessionLocal() as db:
        r=db.execute(text("""SELECT t.*,COALESCE(NULLIF(rn.name,''),NULLIF(rn.hostname,''),t.runner_id) AS runner_name
            FROM targets t LEFT JOIN runners rn ON rn.runner_id=t.runner_id WHERE t.target_uuid=:u"""),{"u":target_uuid}).mappings().first()
        if not r:return None
        result=_serialize(dict(r))
        ev=db.execute(text("SELECT * FROM enrichment_events WHERE target_id=:id ORDER BY created_at DESC LIMIT 1"),{"id":r["id"]}).mappings().first()
        result["latest_enrichment"]=_serialize(dict(ev)) if ev else None
        from app.repositories.service_discovery_repository import list_asset_services
        result["services"]=list_asset_services(int(r["id"]))
        result["service_count"]=len(result["services"])
        return result


def delete_target(target_uuid:str)->bool:
    with SessionLocal() as db:
        r=db.execute(text("""UPDATE targets SET active_in_inventory=FALSE,retired_at=:n,retired_reason='manual',updated_at=:n
            WHERE target_uuid=:u AND active_in_inventory=TRUE RETURNING id"""),{"n":_now(),"u":target_uuid}).first(); db.commit(); return bool(r)


def list_discovery_runs(limit=50):
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT r.*,s.scan_uuid,s.name AS scan_name FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id
        ORDER BY r.started_at DESC LIMIT :l"""),{"l":limit}).mappings().all(); return [_serialize(dict(r)) for r in rows]


def get_discovery_run(run_uuid:str) -> dict|None:
    with SessionLocal() as db:
        row=db.execute(text("""SELECT r.*,s.scan_uuid,s.name AS scan_name FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id WHERE r.run_uuid=:u"""),{"u":run_uuid}).mappings().first()
        if not row:return None
        result=_serialize(dict(row))
        events=db.execute(text("""SELECT e.*,t.target_uuid,t.display_name,t.hostname,host(t.ip_address) AS ip_address,t.mac_address,
            sdj.status AS service_status,sdj.service_count,sdj.new_service_count,sdj.error AS service_error
            FROM enrichment_events e JOIN targets t ON t.id=e.target_id
            LEFT JOIN service_discovery_jobs sdj ON sdj.discovery_run_id=e.discovery_run_id AND sdj.target_id=e.target_id
            WHERE e.discovery_run_id=:rid ORDER BY e.created_at"""),{"rid":row["id"]}).mappings().all()
        result["assets"]=[_serialize(dict(e)) for e in events]
        return result


def clear_discovery_runs():
    with SessionLocal() as db: db.execute(text("DELETE FROM discovery_runs")); db.commit()


def create_queued_discovery_run(target_spec: str, scan_id: int | None, trigger_type: str, addresses_checked: int, runner_id: str, runner_job_id: int, provider: str = "runner") -> dict:
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO discovery_runs(run_uuid,scan_id,target_spec,execution_mode,trigger_type,status,addresses_checked,runner_id,runner_job_id,provider,started_at,pipeline_status)
            VALUES(:u,:sid,:spec,:provider,:trigger,'queued',:checked,:runner_id,:job_id,:provider,:now,'queued') RETURNING *
        """), {"u":_uuid("DSC"),"sid":scan_id,"spec":target_spec,"provider":provider,"trigger":trigger_type,"checked":addresses_checked,"runner_id":runner_id,"job_id":runner_job_id,"now":_now()}).mappings().first()
        db.commit(); return _serialize(dict(row))


def get_discovery_run_by_job(job_id: int) -> dict | None:
    with SessionLocal() as db:
        row=db.execute(text("SELECT * FROM discovery_runs WHERE runner_job_id=:id"),{"id":job_id}).mappings().first()
        return _serialize(dict(row)) if row else None


def update_discovery_run_from_runner(job_id:int, status:str, count:int, error:str|None=None, raw_output:str|None=None, runner_id:str|None=None):
    with SessionLocal() as db:
        row=db.execute(text("""UPDATE discovery_runs SET status=:status,discovered_count=:count,error=:error,raw_output=:raw,runner_id=COALESCE(:runner_id,runner_id),
            finished_at=:now,pipeline_status=:pipeline WHERE runner_job_id=:job_id RETURNING *"""),
            {"status":status,"count":count,"error":error,"raw":raw_output,"runner_id":runner_id,"now":_now(),"pipeline":"completed" if status=="success" else status,"job_id":job_id}).mappings().first()
        db.commit(); return _serialize(dict(row)) if row else None


def release_scan_by_run(run:dict):
    sid=run.get("scan_id")
    if not sid:return
    with SessionLocal() as db:
        scan=db.execute(text("SELECT interval_minutes,is_enabled FROM discovery_scans WHERE id=:id"),{"id":sid}).mappings().first()
    release_scan(int(sid),int(scan["interval_minutes"]) if scan and scan["is_enabled"] and scan["interval_minutes"] else None)
