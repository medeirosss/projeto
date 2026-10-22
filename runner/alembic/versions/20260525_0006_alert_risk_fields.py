from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260525_0006"
down_revision = "20260525_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_level VARCHAR(50) NOT NULL DEFAULT 'low'")


def downgrade() -> None:
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS risk_level")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS risk_score")
