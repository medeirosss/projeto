"""Sprint 1 v3: Runner-based discovery provider and async ingestion.

Revision ID: 20260726_0015
Revises: 20260726_0014
"""
from alembic import op
revision="20260726_0015"
down_revision="20260726_0014"
branch_labels=None
depends_on=None

def upgrade():
    op.execute("""
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL;
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS runner_id VARCHAR(80);
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS provider VARCHAR(20) NOT NULL DEFAULT 'runner';
    ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS raw_output TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_runs_runner_job_id ON discovery_runs(runner_job_id) WHERE runner_job_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status);
    """)

def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_discovery_runs_status;")
    op.execute("DROP INDEX IF EXISTS uq_discovery_runs_runner_job_id;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS raw_output;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS provider;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS runner_id;")
    op.execute("ALTER TABLE discovery_runs DROP COLUMN IF EXISTS runner_job_id;")
