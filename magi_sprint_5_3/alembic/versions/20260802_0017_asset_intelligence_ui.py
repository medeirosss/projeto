"""Sprint 2.2: asset inventory fields and detected lifecycle label.

Revision ID: 20260802_0017
Revises: 20260727_0016
"""
from alembic import op

revision = "20260802_0017"
down_revision = "20260727_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) NOT NULL DEFAULT 'unknown';
    ALTER TABLE targets ADD COLUMN IF NOT EXISTS notes TEXT;
    UPDATE targets
       SET display_name = COALESCE(NULLIF(hostname, ''), NULLIF(dns_name, ''), host(ip_address))
     WHERE display_name IS NULL OR display_name = '';
    CREATE INDEX IF NOT EXISTS idx_targets_display_name ON targets(display_name);
    CREATE INDEX IF NOT EXISTS idx_targets_asset_type ON targets(asset_type);
    """)


def downgrade() -> None:
    op.execute("""
    DROP INDEX IF EXISTS idx_targets_asset_type;
    DROP INDEX IF EXISTS idx_targets_display_name;
    ALTER TABLE targets DROP COLUMN IF EXISTS notes;
    ALTER TABLE targets DROP COLUMN IF EXISTS asset_type;
    ALTER TABLE targets DROP COLUMN IF EXISTS display_name;
    """)
