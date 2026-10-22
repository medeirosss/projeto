"""Sprint 2.1: enrich discovered assets with vendor, status and provenance.

Revision ID: 20260727_0016
Revises: 20260726_0015
"""
from alembic import op

revision = "20260727_0016"
down_revision = "20260726_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS dns_name VARCHAR(255);
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'online';
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL;
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
    UPDATE targets SET status='online' WHERE status IS NULL OR status='';
    UPDATE targets SET dns_name=hostname WHERE dns_name IS NULL AND hostname IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
    CREATE INDEX IF NOT EXISTS idx_targets_vendor ON targets(vendor);
    CREATE INDEX IF NOT EXISTS idx_targets_runner_id ON targets(runner_id);
    CREATE INDEX IF NOT EXISTS idx_targets_last_scan_id ON targets(last_scan_id);
    """)


def downgrade() -> None:
    op.execute("""
    DROP INDEX IF EXISTS idx_targets_last_scan_id;
    DROP INDEX IF EXISTS idx_targets_runner_id;
    DROP INDEX IF EXISTS idx_targets_vendor;
    DROP INDEX IF EXISTS idx_targets_status;
    ALTER TABLE targets DROP COLUMN IF EXISTS runner_id;
    ALTER TABLE targets DROP COLUMN IF EXISTS last_scan_id;
    ALTER TABLE targets DROP COLUMN IF EXISTS status;
    ALTER TABLE targets DROP COLUMN IF EXISTS dns_name;
    ALTER TABLE targets DROP COLUMN IF EXISTS vendor;
    """)
