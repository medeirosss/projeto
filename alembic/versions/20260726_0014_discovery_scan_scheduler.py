"""Sprint 1 v2: scan definitions, scheduling, soft delete and scan-target links.

Revision ID: 20260726_0014
Revises: 20260724_0013
"""
from alembic import op
revision="20260726_0014"
down_revision="20260724_0013"
branch_labels=None
depends_on=None

def upgrade():
    op.execute("""
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
    CREATE TABLE IF NOT EXISTS discovery_scans (
      id SERIAL PRIMARY KEY, scan_uuid VARCHAR(40) UNIQUE NOT NULL, name VARCHAR(150) NOT NULL,
      target_spec VARCHAR(255) NOT NULL, target_type VARCHAR(20) NOT NULL,
      schedule_type VARCHAR(20) NOT NULL DEFAULT 'manual', interval_minutes INTEGER,
      is_enabled BOOLEAN NOT NULL DEFAULT FALSE, is_running BOOLEAN NOT NULL DEFAULT FALSE,
      last_run_at TIMESTAMP, next_run_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual';
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS addresses_checked INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS discovery_scan_targets (
      scan_id INTEGER NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
      target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(scan_id,target_id)
    );
    CREATE INDEX IF NOT EXISTS idx_discovery_scans_next_run ON discovery_scans(next_run_at) WHERE is_enabled=TRUE;
    """)

def downgrade():
    op.execute("DROP TABLE IF EXISTS discovery_scan_targets;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS addresses_checked;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS trigger_type;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS scan_id;")
    op.execute("DROP TABLE IF EXISTS discovery_scans;")
    op.execute("ALTER TABLE targets DROP COLUMN IF EXISTS deleted_at;")
