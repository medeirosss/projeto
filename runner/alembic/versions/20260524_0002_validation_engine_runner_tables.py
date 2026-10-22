"""add validation engine runner tables

Revision ID: 20260524_0002
Revises: 20260524_0001
Create Date: 2026-05-24
"""
from alembic import op

revision = "20260524_0002"
down_revision = "20260524_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS runners (
        id SERIAL PRIMARY KEY,
        runner_id VARCHAR(100) UNIQUE NOT NULL,
        name VARCHAR(150) NOT NULL,
        hostname VARCHAR(255),
        status VARCHAR(50) NOT NULL DEFAULT 'offline',
        last_heartbeat TIMESTAMP,
        token_hash TEXT,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS runner_jobs (
        id SERIAL PRIMARY KEY,
        job_uuid VARCHAR(100) UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
        runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
        job_type VARCHAR(100) NOT NULL,
        target VARCHAR(255),
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        result JSONB,
        error TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        finished_at TIMESTAMP
    );
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS validation_jobs (
        id SERIAL PRIMARY KEY,
        validation_uuid VARCHAR(100) UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
        alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
        action_execution_id INTEGER REFERENCES playbook_executions(id) ON DELETE SET NULL,
        runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
        validation_type VARCHAR(100) NOT NULL,
        target VARCHAR(255),
        expected_state JSONB NOT NULL DEFAULT '{}'::jsonb,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        result JSONB,
        details TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        finished_at TIMESTAMP
    );
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_runner_jobs_runner_status ON runner_jobs(runner_id, status);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_runner_jobs_created_at ON runner_jobs(created_at DESC);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_status ON validation_jobs(status);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_alert_id ON validation_jobs(alert_id);")
    op.execute("CREATE INDEX IF NOT EXISTS idx_validation_jobs_created_at ON validation_jobs(created_at DESC);")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS validation_jobs;")
    op.execute("DROP TABLE IF EXISTS runner_jobs;")
    op.execute("DROP TABLE IF EXISTS runners;")
