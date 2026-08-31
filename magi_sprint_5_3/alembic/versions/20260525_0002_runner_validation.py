"""runner and validation engine tables

Revision ID: 20260525_0002
Revises: 20260525_0001
Create Date: 2026-05-25
"""

from alembic import op

revision = "20260525_0002"
down_revision = "20260525_0001"
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
        enabled BOOLEAN DEFAULT TRUE,
        metadata JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS runner_jobs (
        id SERIAL PRIMARY KEY,
        runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
        job_type VARCHAR(100) NOT NULL,
        target VARCHAR(255),
        payload JSONB DEFAULT '{}'::jsonb,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        result JSONB,
        error TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        finished_at TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS validation_jobs (
        id SERIAL PRIMARY KEY,
        alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
        action_execution_id INTEGER REFERENCES playbook_executions(id) ON DELETE SET NULL,
        runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
        validation_type VARCHAR(100) NOT NULL,
        target VARCHAR(255),
        expected_state JSONB DEFAULT '{}'::jsonb,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        result JSONB,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        started_at TIMESTAMP,
        finished_at TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);
    CREATE INDEX IF NOT EXISTS idx_runner_jobs_status ON runner_jobs(status);
    CREATE INDEX IF NOT EXISTS idx_runner_jobs_runner_status ON runner_jobs(runner_id, status);
    CREATE INDEX IF NOT EXISTS idx_validation_jobs_status ON validation_jobs(status);
    CREATE INDEX IF NOT EXISTS idx_validation_jobs_alert ON validation_jobs(alert_id);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS validation_jobs")
    op.execute("DROP TABLE IF EXISTS runner_jobs")
    op.execute("DROP TABLE IF EXISTS runners")
