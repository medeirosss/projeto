"""atomic governance and execution preview

Revision ID: 20260528_0010
Revises: 20260527_0009, 20260524_0002
Create Date: 2026-05-28
"""
from alembic import op

revision = "20260528_0010"
down_revision = ("20260527_0009", "20260524_0002")
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE atomic_tests
      ADD COLUMN IF NOT EXISTS atomic_test_number INTEGER;
    """)
    op.execute("""
    ALTER TABLE atomic_tests
      ADD COLUMN IF NOT EXISTS approved_for_execution BOOLEAN NOT NULL DEFAULT FALSE;
    """)
    op.execute("""
    ALTER TABLE atomic_tests
      ADD COLUMN IF NOT EXISTS safe_for_production BOOLEAN NOT NULL DEFAULT FALSE;
    """)
    op.execute("""
    ALTER TABLE atomic_tests
      ADD COLUMN IF NOT EXISTS requires_reboot BOOLEAN NOT NULL DEFAULT FALSE;
    """)
    op.execute("""
    ALTER TABLE atomic_tests
      ADD COLUMN IF NOT EXISTS allowed_runner_groups JSONB NOT NULL DEFAULT '[]'::jsonb;
    """)
    op.execute("""
    UPDATE atomic_tests
    SET approved_for_execution = approved_for_lab
    WHERE approved_for_execution = FALSE AND approved_for_lab = TRUE;
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS atomic_execution_jobs (
        id SERIAL PRIMARY KEY,
        execution_uuid VARCHAR(100) UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
        atomic_test_id INTEGER REFERENCES atomic_tests(id) ON DELETE SET NULL,
        technique_id VARCHAR(40),
        atomic_test_number INTEGER,
        runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
        runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL,
        target_host VARCHAR(255),
        status VARCHAR(50) NOT NULL DEFAULT 'pending_review',
        requested_by VARCHAR(255),
        approved_by VARCHAR(255),
        command_preview TEXT,
        block_reason TEXT,
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        finished_at TIMESTAMP,
        exit_code INTEGER,
        stdout TEXT,
        stderr TEXT,
        error_message TEXT
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_atomic_execution_jobs_status ON atomic_execution_jobs(status);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_atomic_execution_jobs_test_id ON atomic_execution_jobs(atomic_test_id);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_atomic_execution_jobs_created_at ON atomic_execution_jobs(created_at DESC);")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS atomic_execution_jobs;")
    # Mantemos as colunas de governança para evitar perda de configuração operacional.
