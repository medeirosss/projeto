from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any
from sqlalchemy import text
from app.database.connection import SessionLocal


def _now(): return datetime.utcnow()
def _uuid(prefix: str): return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def ensure_target_schema() -> None:
    with SessionLocal() as db:
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS targets (
            id SERIAL PRIMARY KEY, target_uuid VARCHAR(40) UNIQUE NOT NULL,
            hostname VARCHAR(255), hostname_normalized VARCHAR(255), ip_address INET NOT NULL,
            mac_address VARCHAR(17), mac_normalized VARCHAR(12), vendor VARCHAR(255), dns_name VARCHAR(255), hostname_source VARCHAR(30),
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
            PRIMARY KEY(scan_id, target_id)
        );
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS dns_name VARCHAR(255);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS hostname_source VARCHAR(30);
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'online';
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
        ALTER TABLE targets ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual';
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS addresses_checked INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL;
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS provider VARCHAR(20) NOT NULL DEFAULT 'runner';
        ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS raw_output TEXT;
        CREATE INDEX IF NOT EXISTS idx_targets_last_seen_at ON targets(last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS idx_discovery_scans_next_run ON discovery_scans(next_run_at) WHERE is_enabled = TRUE;
        CREATE INDEX IF NOT EXISTS idx_discovery_runs_started_at ON discovery_runs(started_at DESC);
        """))
        db.commit()


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("ip_address",):
        if row.get(key) is not None: row[key] = str(row[key])
    for key, value in list(row.items()):
        if hasattr(value, "isoformat"): row[key] = value.isoformat()
    return row


def create_scan(name: str, target_spec: str, target_type: str, schedule_type: str, interval_minutes: int | None, is_enabled: bool) -> dict:
    now = _now(); next_run = now + timedelta(minutes=interval_minutes) if is_enabled and schedule_type == "interval" and interval_minutes else None
    with SessionLocal() as db:
        row = db.execute(text("""INSERT INTO discovery_scans
        (scan_uuid,name,target_spec,target_type,schedule_type,interval_minutes,is_enabled,next_run_at,created_at,updated_at)
        VALUES(:uuid,:name,:spec,:type,:sched,:interval,:enabled,:next,:now,:now) RETURNING *"""),
        {"uuid":_uuid("SCN"),"name":name,"spec":target_spec,"type":target_type,"sched":schedule_type,"interval":interval_minutes,"enabled":is_enabled,"next":next_run,"now":now}).mappings().first()
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
    allowed={"name","target_spec","target_type","schedule_type","interval_minutes","is_enabled"}
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
        if remove_exclusive_targets:
            db.execute(text("""UPDATE targets SET deleted_at=:now, updated_at=:now WHERE id IN (
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
        row=db.execute(text("""INSERT INTO discovery_runs(run_uuid,scan_id,target_spec,trigger_type,status,addresses_checked,started_at)
        VALUES(:u,:sid,:spec,:trigger,'running',:checked,:now) RETURNING *"""),{"u":_uuid("DSC"),"sid":scan_id,"spec":target_spec,"trigger":trigger_type,"checked":addresses_checked,"now":_now()}).mappings().first(); db.commit(); return _serialize(dict(row))


def finish_discovery_run(run_uuid:str,status:str,count:int,error:str|None=None):
    with SessionLocal() as db:
        db.execute(text("UPDATE discovery_runs SET status=:s,discovered_count=:c,error=:e,finished_at=:n WHERE run_uuid=:u"),{"s":status,"c":count,"e":error,"n":_now(),"u":run_uuid}); db.commit()


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
        if existing:
            tid=existing["id"]
            if str(existing["ip_address"])!=ip_address: db.execute(text("UPDATE target_addresses SET is_current=FALSE WHERE target_id=:id"),{"id":tid})
            row=db.execute(text("""UPDATE targets SET hostname=COALESCE(:h,hostname),hostname_normalized=COALESCE(:hn,hostname_normalized),
            dns_name=COALESCE(:dns,dns_name),hostname_source=COALESCE(:hostname_source,hostname_source),ip_address=CAST(:ip AS INET),mac_address=COALESCE(:m,mac_address),mac_normalized=COALESCE(:mn,mac_normalized),
            vendor=COALESCE(:vendor,vendor),status=:status,discovery_source=:src,last_scan_id=COALESCE(:sid,last_scan_id),
            runner_id=COALESCE(:runner_id,runner_id),last_seen_at=:n,deleted_at=NULL,updated_at=:n WHERE id=:id RETURNING *"""),
            {"h":hostname,"hn":hostname_normalized,"dns":dns_name or hostname,"hostname_source":hostname_source,"ip":ip_address,"m":mac_address,"mn":mac_normalized,"vendor":vendor,"status":status,"src":source,"sid":scan_id,"runner_id":runner_id,"n":now,"id":tid}).mappings().first()
        else:
            row=db.execute(text("""INSERT INTO targets(target_uuid,hostname,hostname_normalized,dns_name,hostname_source,ip_address,mac_address,mac_normalized,vendor,status,discovery_source,last_scan_id,runner_id,first_seen_at,last_seen_at,created_at,updated_at)
            VALUES(:u,:h,:hn,:dns,:hostname_source,CAST(:ip AS INET),:m,:mn,:vendor,:status,:src,:sid,:runner_id,:n,:n,:n,:n) RETURNING *"""),
            {"u":_uuid("TGT"),"h":hostname,"hn":hostname_normalized,"dns":dns_name or hostname,"hostname_source":hostname_source,"ip":ip_address,"m":mac_address,"mn":mac_normalized,"vendor":vendor,"status":status,"src":source,"sid":scan_id,"runner_id":runner_id,"n":now}).mappings().first(); tid=row["id"]
        db.execute(text("""INSERT INTO target_addresses(target_id,ip_address,first_seen_at,last_seen_at,is_current) VALUES(:id,CAST(:ip AS INET),:n,:n,TRUE)
        ON CONFLICT(target_id,ip_address) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at,is_current=TRUE"""),{"id":tid,"ip":ip_address,"n":now})
        if scan_id:
            db.execute(text("""INSERT INTO discovery_scan_targets(scan_id,target_id,first_seen_at,last_seen_at) VALUES(:sid,:tid,:n,:n)
            ON CONFLICT(scan_id,target_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at"""),{"sid":scan_id,"tid":tid,"n":now})
        db.commit(); return _serialize(dict(row))


def list_targets(search=None,limit=200,offset=0):
    s=f"%{(search or '').strip().lower()}%"
    where="WHERE deleted_at IS NULL AND (:s='%%' OR lower(COALESCE(hostname,'')) LIKE :s OR lower(COALESCE(dns_name,'')) LIKE :s OR host(ip_address) LIKE :s OR lower(COALESCE(mac_address,'')) LIKE :s OR lower(COALESCE(vendor,'')) LIKE :s OR lower(COALESCE(runner_id,'')) LIKE :s)"
    with SessionLocal() as db:
        rows=db.execute(text(f"SELECT * FROM targets {where} ORDER BY last_seen_at DESC LIMIT :l OFFSET :o"),{"s":s,"l":limit,"o":offset}).mappings().all()
        total=db.execute(text(f"SELECT COUNT(*) FROM targets {where}"),{"s":s}).scalar_one()
        return {"items":[_serialize(dict(r)) for r in rows],"total":int(total),"limit":limit,"offset":offset}


def get_target(target_uuid):
    with SessionLocal() as db:
        r=db.execute(text("SELECT * FROM targets WHERE target_uuid=:u"),{"u":target_uuid}).mappings().first(); return _serialize(dict(r)) if r else None


def delete_target(target_uuid:str)->bool:
    with SessionLocal() as db:
        r=db.execute(text("UPDATE targets SET deleted_at=:n,updated_at=:n WHERE target_uuid=:u AND deleted_at IS NULL RETURNING id"),{"n":_now(),"u":target_uuid}).first(); db.commit(); return bool(r)


def list_discovery_runs(limit=50):
    with SessionLocal() as db:
        rows=db.execute(text("""SELECT r.*,s.scan_uuid,s.name AS scan_name FROM discovery_runs r LEFT JOIN discovery_scans s ON s.id=r.scan_id
        ORDER BY r.started_at DESC LIMIT :l"""),{"l":limit}).mappings().all(); return [_serialize(dict(r)) for r in rows]


def clear_discovery_runs():
    with SessionLocal() as db: db.execute(text("DELETE FROM discovery_runs")); db.commit()


def create_queued_discovery_run(target_spec: str, scan_id: int | None, trigger_type: str, addresses_checked: int, runner_id: str, runner_job_id: int, provider: str = "runner") -> dict:
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO discovery_runs(run_uuid,scan_id,target_spec,execution_mode,trigger_type,status,addresses_checked,runner_id,runner_job_id,provider,started_at)
            VALUES(:u,:sid,:spec,:provider,:trigger,'queued',:checked,:runner_id,:job_id,:provider,:now) RETURNING *
        """), {"u":_uuid("DSC"),"sid":scan_id,"spec":target_spec,"provider":provider,"trigger":trigger_type,"checked":addresses_checked,"runner_id":runner_id,"job_id":runner_job_id,"now":_now()}).mappings().first()
        db.commit(); return _serialize(dict(row))

def get_discovery_run_by_job(job_id: int) -> dict | None:
    with SessionLocal() as db:
        row=db.execute(text("SELECT * FROM discovery_runs WHERE runner_job_id=:id"),{"id":job_id}).mappings().first()
        return _serialize(dict(row)) if row else None

def update_discovery_run_from_runner(job_id:int, status:str, count:int, error:str|None=None, raw_output:str|None=None, runner_id:str|None=None):
    with SessionLocal() as db:
        row=db.execute(text("""UPDATE discovery_runs SET status=:status,discovered_count=:count,error=:error,raw_output=:raw,runner_id=COALESCE(:runner_id,runner_id),finished_at=:now WHERE runner_job_id=:job_id RETURNING *"""),
            {"status":status,"count":count,"error":error,"raw":raw_output,"runner_id":runner_id,"now":_now(),"job_id":job_id}).mappings().first()
        db.commit(); return _serialize(dict(row)) if row else None

def release_scan_by_run(run:dict):
    if not run or not run.get("scan_id"): return
    with SessionLocal() as db:
        scan=db.execute(text("SELECT interval_minutes,is_enabled FROM discovery_scans WHERE id=:id"),{"id":run["scan_id"]}).mappings().first()
    release_scan(int(run["scan_id"]), int(scan["interval_minutes"]) if scan and scan["is_enabled"] and scan["interval_minutes"] else None)
