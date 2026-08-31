from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import text

from app.database.connection import get_db_session
from app.services.common import normalize_hostname


def ensure_reports_schema() -> None:
    with get_db_session() as db:
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_snapshots (
                id SERIAL PRIMARY KEY,
                source VARCHAR(50) NOT NULL,
                records JSONB NOT NULL DEFAULT '[]'::jsonb,
                record_count INTEGER NOT NULL DEFAULT 0,
                source_detail VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_scan_snapshots_source_created ON scan_snapshots(source, created_at DESC)"))
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS report_files (
                id SERIAL PRIMARY KEY,
                file_name VARCHAR(255) NOT NULL,
                label VARCHAR(255),
                size_bytes INTEGER DEFAULT 0,
                hostnames JSONB NOT NULL DEFAULT '[]'::jsonb,
                content BYTEA,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_report_files_created_at ON report_files(created_at DESC)"))
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_compare_runs (
                id SERIAL PRIMARY KEY,
                report_name VARCHAR(100) NOT NULL DEFAULT 'Scans',
                sources JSONB NOT NULL DEFAULT '{}'::jsonb,
                rows JSONB NOT NULL DEFAULT '[]'::jsonb,
                total INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_scan_compare_runs_created_at ON scan_compare_runs(created_at DESC)"))


def save_scan_snapshot(source: str, records: List[Dict[str, Any]], source_detail: str = "") -> int:
    ensure_reports_schema()
    payload = records or []
    with get_db_session() as db:
        row = db.execute(
            text("""
                INSERT INTO scan_snapshots(source, records, record_count, source_detail)
                VALUES(:source, CAST(:records AS jsonb), :record_count, :source_detail)
                RETURNING id
            """),
            {
                "source": source,
                "records": json.dumps(payload, ensure_ascii=False),
                "record_count": len(payload),
                "source_detail": source_detail or "",
            },
        ).mappings().first()
        return int(row["id"])


def get_latest_scan_snapshot(source: str) -> Dict[str, Any]:
    ensure_reports_schema()
    with get_db_session() as db:
        row = db.execute(
            text("""
                SELECT id, source, records, record_count, source_detail, created_at
                FROM scan_snapshots
                WHERE source = :source
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            """),
            {"source": source},
        ).mappings().first()
    if not row:
        return {"records": [], "record_count": 0, "source_detail": "", "created_at": None}
    records = row.get("records") or []
    if isinstance(records, str):
        try:
            records = json.loads(records)
        except Exception:
            records = []
    return {
        "id": row.get("id"),
        "source": row.get("source"),
        "records": records if isinstance(records, list) else [],
        "record_count": row.get("record_count") or 0,
        "source_detail": row.get("source_detail") or "",
        "created_at": row.get("created_at"),
    }


def get_latest_scan_records(source: str) -> List[Dict[str, Any]]:
    snapshot = get_latest_scan_snapshot(source)
    records = snapshot.get("records") or []
    return records if isinstance(records, list) else []


def save_report_file(file_name: str, label: str, content: bytes, hostnames: Set[str]) -> int:
    ensure_reports_schema()
    hostname_list = sorted({normalize_hostname(x) for x in hostnames if normalize_hostname(x)})
    with get_db_session() as db:
        row = db.execute(
            text("""
                INSERT INTO report_files(file_name, label, size_bytes, hostnames, content)
                VALUES(:file_name, :label, :size_bytes, CAST(:hostnames AS jsonb), :content)
                RETURNING id
            """),
            {
                "file_name": file_name,
                "label": label or file_name,
                "size_bytes": len(content or b""),
                "hostnames": json.dumps(hostname_list, ensure_ascii=False),
                "content": content or b"",
            },
        ).mappings().first()
        return int(row["id"])


def list_report_files() -> List[Dict[str, Any]]:
    ensure_reports_schema()
    with get_db_session() as db:
        rows = db.execute(
            text("""
                SELECT id, file_name, label, size_bytes, created_at
                FROM report_files
                ORDER BY created_at DESC, id DESC
            """)
        ).mappings().all()
    return [
        {
            "id": int(row["id"]),
            "file_name": row["file_name"],
            "label": row.get("label") or row["file_name"],
            "size": int(row.get("size_bytes") or 0),
            "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
        }
        for row in rows
    ]


def get_report_file_hostnames(file_id_or_name: str) -> Set[str]:
    ensure_reports_schema()
    query = """
        SELECT hostnames
        FROM report_files
        WHERE id = :id
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    """ if str(file_id_or_name).isdigit() else """
        SELECT hostnames
        FROM report_files
        WHERE file_name = :name
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    """
    params = {"id": int(file_id_or_name)} if str(file_id_or_name).isdigit() else {"name": file_id_or_name}
    with get_db_session() as db:
        row = db.execute(text(query), params).mappings().first()
    if not row:
        raise FileNotFoundError(f"Arquivo não encontrado no banco: {file_id_or_name}")
    hostnames = row.get("hostnames") or []
    if isinstance(hostnames, str):
        try:
            hostnames = json.loads(hostnames)
        except Exception:
            hostnames = []
    return {normalize_hostname(x) for x in hostnames if normalize_hostname(x)}


def save_scan_compare_run(sources: Dict[str, List[str]], rows: List[Dict[str, Any]]) -> int:
    ensure_reports_schema()
    with get_db_session() as db:
        row = db.execute(
            text("""
                INSERT INTO scan_compare_runs(report_name, sources, rows, total)
                VALUES('Scans', CAST(:sources AS jsonb), CAST(:rows AS jsonb), :total)
                RETURNING id
            """),
            {
                "sources": json.dumps(sources or {}, ensure_ascii=False),
                "rows": json.dumps(rows or [], ensure_ascii=False),
                "total": len(rows or []),
            },
        ).mappings().first()
        return int(row["id"])


def get_latest_scan_compare_run() -> Optional[Dict[str, Any]]:
    ensure_reports_schema()
    with get_db_session() as db:
        row = db.execute(
            text("""
                SELECT id, report_name, sources, rows, total, created_at
                FROM scan_compare_runs
                ORDER BY created_at DESC, id DESC
                LIMIT 1
            """)
        ).mappings().first()
    if not row:
        return None
    return {
        "id": int(row["id"]),
        "report_name": row.get("report_name") or "Scans",
        "sources": row.get("sources") or {},
        "rows": row.get("rows") or [],
        "total": int(row.get("total") or 0),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
    }
