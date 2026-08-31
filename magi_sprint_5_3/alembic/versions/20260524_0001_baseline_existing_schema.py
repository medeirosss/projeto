"""baseline existing schema

Revision ID: 20260524_0001
Revises: 
Create Date: 2026-05-24
"""
from alembic import op

revision = "20260524_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Baseline marker for databases already initialized through db/init.sql.
    # New installations still use db/init.sql as the bootstrap schema in this stage.
    pass


def downgrade() -> None:
    pass
