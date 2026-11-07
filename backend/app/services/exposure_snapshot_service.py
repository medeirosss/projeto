"""MAGI 6.4.2: one UTC daily snapshot of actual exposure_findings.
Snapshots are immutable once taken for a day; no fabricated historical points.
"""
import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy import text
from app.database.connection import SessionLocal

log = logging.getLogger(__name__)

DDL = """
CREATE TABLE IF NOT EXISTS exposure_daily_snapshots (
  snapshot_day DATE PRIMARY KEY,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  total INTEGER NOT NULL,
  open_count INTEGER NOT NULL,
  resolved_count INTEGER NOT NULL,
  ignored_count INTEGER NOT NULL,
  critical_count INTEGER NOT NULL,
  high_count INTEGER NOT NULL,
  medium_count INTEGER NOT NULL,
  low_count INTEGER NOT NULL,
  info_count INTEGER NOT NULL
)
"""

def ensure_exposure_snapshot_schema():
    with SessionLocal() as db:
        db.execute(text(DDL))
        db.commit()

def take_daily_snapshot():
    """Idempotent across workers; first capture of each UTC day wins."""
    with SessionLocal() as db:
        db.execute(text("""
            INSERT INTO exposure_daily_snapshots (
                snapshot_day,total,open_count,resolved_count,ignored_count,
                critical_count,high_count,medium_count,low_count,info_count
            )
            SELECT (NOW() AT TIME ZONE 'UTC')::date, COUNT(*)::integer,
                COUNT(*) FILTER (WHERE status='open')::integer,
                COUNT(*) FILTER (WHERE status='resolved')::integer,
                COUNT(*) FILTER (WHERE status='ignored')::integer,
                COUNT(*) FILTER (WHERE severity='critical')::integer,
                COUNT(*) FILTER (WHERE severity='high')::integer,
                COUNT(*) FILTER (WHERE severity='medium')::integer,
                COUNT(*) FILTER (WHERE severity='low')::integer,
                COUNT(*) FILTER (WHERE severity NOT IN ('critical','high','medium','low') OR severity IS NULL)::integer
            FROM exposure_findings
            ON CONFLICT (snapshot_day) DO NOTHING
        """))
        db.commit()

def list_snapshots(days=30):
    with SessionLocal() as db:
        rows=db.execute(text("""
          SELECT snapshot_day AS day,captured_at,total,open_count AS open,
            resolved_count AS resolved,ignored_count AS ignored,
            critical_count AS critical,high_count AS high,medium_count AS medium,
            low_count AS low,info_count AS info
          FROM exposure_daily_snapshots
          WHERE snapshot_day >= (NOW() AT TIME ZONE 'UTC')::date - (:days - 1)
          ORDER BY snapshot_day
        """),{'days':days}).mappings().all()
    return [{k:(v.isoformat() if hasattr(v,'isoformat') else v) for k,v in dict(r).items()} for r in rows]

async def run_exposure_snapshot_scheduler():
    while True:
        try:
            await asyncio.to_thread(take_daily_snapshot)
        except Exception:
            log.exception('MAGI exposure snapshot failed; will retry')
        await asyncio.sleep(3600)
