from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import text

from app.database.connection import SessionLocal


def ensure_target_schema() -> None:
    """Create the Sprint 1 target/discovery schema idempotently."""
    with SessionLocal() as db:
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS targets (
            id SERIAL PRIMARY KEY,
            target_uuid VARCHAR(40) UNIQUE NOT NULL,
            hostname VARCHAR(255),
            hostname_normalized VARCHAR(255),
            ip_address INET NOT NULL,
            mac_address VARCHAR(17),
            mac_normalized VARCHAR(12),
            discovery_source VARCHAR(50) NOT NULL DEFAULT 'nmap',
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS target_addresses (
            id SERIAL PRIMARY KEY,
            target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            ip_address INET NOT NULL,
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_current BOOLEAN NOT NULL DEFAULT TRUE,
            UNIQUE(target_id, ip_address)
        );
        """))
        db.execute(text("""
        CREATE TABLE IF NOT EXISTS discovery_runs (
            id SERIAL PRIMARY KEY,
            run_uuid VARCHAR(40) UNIQUE NOT NULL,
            target_spec VARCHAR(255) NOT NULL,
            execution_mode VARCHAR(30) NOT NULL DEFAULT 'local',
            status VARCHAR(30) NOT NULL DEFAULT 'running',
            discovered_count INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_targets_hostname_normalized ON targets(hostname_normalized);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_targets_mac_normalized ON targets(mac_normalized) WHERE mac_normalized IS NOT NULL;"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_targets_ip_address ON targets(ip_address);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_targets_last_seen_at ON targets(last_seen_at DESC);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_target_addresses_ip ON target_addresses(ip_address);"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_discovery_runs_started_at ON discovery_runs(started_at DESC);"))
        db.commit()


def create_discovery_run(target_spec: str) -> dict[str, Any]:
    run_uuid = f"DSC-{uuid.uuid4().hex[:12].upper()}"
    with SessionLocal() as db:
        row = db.execute(text("""
            INSERT INTO discovery_runs (run_uuid, target_spec, status, started_at)
            VALUES (:run_uuid, :target_spec, 'running', :now)
            RETURNING id, run_uuid, target_spec, status, started_at
        """), {"run_uuid": run_uuid, "target_spec": target_spec, "now": datetime.utcnow()}).mappings().first()
        db.commit()
        return dict(row)


def finish_discovery_run(run_uuid: str, status: str, discovered_count: int, error: str | None = None) -> None:
    with SessionLocal() as db:
        db.execute(text("""
            UPDATE discovery_runs
            SET status = :status,
                discovered_count = :count,
                error = :error,
                finished_at = :now
            WHERE run_uuid = :run_uuid
        """), {"run_uuid": run_uuid, "status": status, "count": discovered_count, "error": error, "now": datetime.utcnow()})
        db.commit()


def _find_existing(db, hostname_normalized: str | None, ip_address: str, mac_normalized: str | None):
    if mac_normalized:
        row = db.execute(text("SELECT * FROM targets WHERE mac_normalized = :mac LIMIT 1"), {"mac": mac_normalized}).mappings().first()
        if row:
            return row
    if hostname_normalized:
        row = db.execute(text("""
            SELECT * FROM targets
            WHERE hostname_normalized = :hostname
              AND (mac_normalized IS NULL OR :mac IS NULL OR mac_normalized = :mac)
            ORDER BY last_seen_at DESC LIMIT 1
        """), {"hostname": hostname_normalized, "mac": mac_normalized}).mappings().first()
        if row:
            return row
    return db.execute(text("SELECT * FROM targets WHERE ip_address = CAST(:ip AS INET) ORDER BY last_seen_at DESC LIMIT 1"), {"ip": ip_address}).mappings().first()


def upsert_discovered_target(*, hostname: str | None, hostname_normalized: str | None, ip_address: str,
                             mac_address: str | None, mac_normalized: str | None, source: str = "nmap") -> dict[str, Any]:
    now = datetime.utcnow()
    with SessionLocal() as db:
        existing = _find_existing(db, hostname_normalized, ip_address, mac_normalized)
        if existing:
            target_id = int(existing["id"])
            previous_ip = str(existing["ip_address"])
            if previous_ip != ip_address:
                db.execute(text("UPDATE target_addresses SET is_current = FALSE WHERE target_id = :target_id"), {"target_id": target_id})
            row = db.execute(text("""
                UPDATE targets
                SET hostname = COALESCE(:hostname, hostname),
                    hostname_normalized = COALESCE(:hostname_normalized, hostname_normalized),
                    ip_address = CAST(:ip AS INET),
                    mac_address = COALESCE(:mac_address, mac_address),
                    mac_normalized = COALESCE(:mac_normalized, mac_normalized),
                    discovery_source = :source,
                    last_seen_at = :now,
                    updated_at = :now
                WHERE id = :target_id
                RETURNING *
            """), {
                "target_id": target_id, "hostname": hostname, "hostname_normalized": hostname_normalized,
                "ip": ip_address, "mac_address": mac_address, "mac_normalized": mac_normalized,
                "source": source, "now": now,
            }).mappings().first()
        else:
            target_uuid = f"TGT-{uuid.uuid4().hex[:12].upper()}"
            row = db.execute(text("""
                INSERT INTO targets (
                    target_uuid, hostname, hostname_normalized, ip_address,
                    mac_address, mac_normalized, discovery_source,
                    first_seen_at, last_seen_at, created_at, updated_at
                ) VALUES (
                    :target_uuid, :hostname, :hostname_normalized, CAST(:ip AS INET),
                    :mac_address, :mac_normalized, :source,
                    :now, :now, :now, :now
                ) RETURNING *
            """), {
                "target_uuid": target_uuid, "hostname": hostname, "hostname_normalized": hostname_normalized,
                "ip": ip_address, "mac_address": mac_address, "mac_normalized": mac_normalized,
                "source": source, "now": now,
            }).mappings().first()
            target_id = int(row["id"])

        db.execute(text("""
            INSERT INTO target_addresses (target_id, ip_address, first_seen_at, last_seen_at, is_current)
            VALUES (:target_id, CAST(:ip AS INET), :now, :now, TRUE)
            ON CONFLICT (target_id, ip_address)
            DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, is_current = TRUE
        """), {"target_id": target_id, "ip": ip_address, "now": now})
        db.commit()
        return _serialize_target(dict(row))


def _serialize_target(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("ip_address",):
        if row.get(key) is not None:
            row[key] = str(row[key])
    for key in ("first_seen_at", "last_seen_at", "created_at", "updated_at"):
        if row.get(key) is not None and hasattr(row[key], "isoformat"):
            row[key] = row[key].isoformat()
    return row


def list_targets(search: str | None = None, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    search_value = f"%{(search or '').strip().lower()}%"
    with SessionLocal() as db:
        params = {"search": search_value, "limit": limit, "offset": offset}
        where = """WHERE (:search = '%%' OR lower(COALESCE(hostname, '')) LIKE :search OR host(ip_address) LIKE :search OR lower(COALESCE(mac_address, '')) LIKE :search)"""
        rows = db.execute(text(f"""
            SELECT id, target_uuid, hostname, ip_address, mac_address, discovery_source,
                   first_seen_at, last_seen_at, created_at, updated_at
            FROM targets {where}
            ORDER BY last_seen_at DESC, hostname NULLS LAST
            LIMIT :limit OFFSET :offset
        """), params).mappings().all()
        total = db.execute(text(f"SELECT COUNT(*) FROM targets {where}"), {"search": search_value}).scalar_one()
        return {"items": [_serialize_target(dict(row)) for row in rows], "total": int(total), "limit": limit, "offset": offset}


def get_target(target_uuid: str) -> dict[str, Any] | None:
    with SessionLocal() as db:
        row = db.execute(text("SELECT * FROM targets WHERE target_uuid = :uuid LIMIT 1"), {"uuid": target_uuid}).mappings().first()
        if not row:
            return None
        result = _serialize_target(dict(row))
        addresses = db.execute(text("""
            SELECT host(ip_address) AS ip_address, first_seen_at, last_seen_at, is_current
            FROM target_addresses WHERE target_id = :id ORDER BY last_seen_at DESC
        """), {"id": row["id"]}).mappings().all()
        result["addresses"] = [
            {**dict(address), "first_seen_at": address["first_seen_at"].isoformat(), "last_seen_at": address["last_seen_at"].isoformat()}
            for address in addresses
        ]
        return result


def list_discovery_runs(limit: int = 20) -> list[dict[str, Any]]:
    with SessionLocal() as db:
        rows = db.execute(text("""
            SELECT run_uuid, target_spec, execution_mode, status, discovered_count, error, started_at, finished_at
            FROM discovery_runs ORDER BY started_at DESC LIMIT :limit
        """), {"limit": limit}).mappings().all()
        output = []
        for row in rows:
            item = dict(row)
            for key in ("started_at", "finished_at"):
                if item.get(key) is not None:
                    item[key] = item[key].isoformat()
            output.append(item)
        return output
