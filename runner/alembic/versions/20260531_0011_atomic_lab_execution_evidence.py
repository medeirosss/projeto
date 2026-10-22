"""atomic lab execution evidence

Revision ID: 20260531_0011
Revises: 20260528_0010
Create Date: 2026-05-31
"""

from alembic import op

revision = "20260531_0011"
down_revision = "20260528_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE atomic_tests
        ADD COLUMN IF NOT EXISTS approved_by VARCHAR(255)
    """)
    op.execute("""
        ALTER TABLE atomic_tests
        ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP WITHOUT TIME ZONE
    """)
    op.execute("""
        ALTER TABLE atomic_execution_jobs
        ADD COLUMN IF NOT EXISTS executed_real_test BOOLEAN NOT NULL DEFAULT FALSE
    """)
    op.execute("""
        ALTER TABLE atomic_execution_jobs
        ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '{}'::jsonb
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE atomic_execution_jobs DROP COLUMN IF EXISTS evidence")
    op.execute("ALTER TABLE atomic_execution_jobs DROP COLUMN IF EXISTS executed_real_test")
    op.execute("ALTER TABLE atomic_tests DROP COLUMN IF EXISTS approved_at")
    op.execute("ALTER TABLE atomic_tests DROP COLUMN IF EXISTS approved_by")
