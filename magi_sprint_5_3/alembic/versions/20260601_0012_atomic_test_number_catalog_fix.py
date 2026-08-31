"""atomic test number catalog fix

Revision ID: 20260601_0012
Revises: 20260531_0011
Create Date: 2026-06-01
"""
from alembic import op

revision = "20260601_0012"
down_revision = "20260531_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE atomic_tests ADD COLUMN IF NOT EXISTS atomic_test_number INTEGER;")
    op.execute("""
        WITH numbered AS (
            SELECT id, ROW_NUMBER() OVER (PARTITION BY technique_id ORDER BY id) AS rn
            FROM atomic_tests
            WHERE atomic_test_number IS NULL
        )
        UPDATE atomic_tests t
        SET atomic_test_number = numbered.rn
        FROM numbered
        WHERE t.id = numbered.id;
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_atomic_tests_technique_number ON atomic_tests(technique_id, atomic_test_number);")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_atomic_tests_technique_number;")
