from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260525_0004"
down_revision = "20260525_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("automation_status", sa.String(length=50), nullable=False, server_default="none"),
    )
    op.add_column(
        "alerts",
        sa.Column("automation_message", sa.Text(), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("automation_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("alerts", "automation_at")
    op.drop_column("alerts", "automation_message")
    op.drop_column("alerts", "automation_status")
