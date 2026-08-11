"""Sprint 4.0 - Repository, Planner, Evidence and Remediation engines.

Revision ID: 0025_sprint4_repository_planner
Revises: 0024_exposure_engine
"""
from alembic import op
import sqlalchemy as sa

revision = '0025_sprint4_repository_planner'
down_revision = '20260810_0024'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
    CREATE TABLE IF NOT EXISTS validation_repositories (
      id SERIAL PRIMARY KEY,
      repository_key VARCHAR(80) UNIQUE NOT NULL,
      name VARCHAR(160) NOT NULL,
      provider VARCHAR(80) NOT NULL,
      description TEXT,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      available BOOLEAN NOT NULL DEFAULT TRUE,
      source_path TEXT,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      last_sync_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS validation_tasks (
      id SERIAL PRIMARY KEY,
      repository_key VARCHAR(80) NOT NULL,
      task_key VARCHAR(160) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      category VARCHAR(100),
      platform VARCHAR(80),
      executor VARCHAR(80) NOT NULL,
      impact VARCHAR(30) NOT NULL DEFAULT 'low',
      requires_admin BOOLEAN NOT NULL DEFAULT FALSE,
      approved BOOLEAN NOT NULL DEFAULT TRUE,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      detection JSONB NOT NULL DEFAULT '{}'::jsonb,
      remediation TEXT,
      references JSONB NOT NULL DEFAULT '[]'::jsonb,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS validation_task_executions (
      id SERIAL PRIMARY KEY,
      execution_uuid UUID NOT NULL DEFAULT gen_random_uuid(),
      validation_task_id INTEGER REFERENCES validation_tasks(id) ON DELETE SET NULL,
      repository_key VARCHAR(80) NOT NULL,
      task_key VARCHAR(160) NOT NULL,
      runner_id VARCHAR(100),
      runner_job_id INTEGER REFERENCES runner_jobs(id) ON DELETE SET NULL,
      target VARCHAR(255) NOT NULL,
      requested_by VARCHAR(160),
      status VARCHAR(50) NOT NULL DEFAULT 'queued',
      impact VARCHAR(30),
      plan JSONB NOT NULL DEFAULT '{}'::jsonb,
      evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
      finding_status VARCHAR(30),
      finding_message TEXT,
      remediation TEXT,
      error TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      started_at TIMESTAMP,
      finished_at TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_validation_tasks_repo ON validation_tasks(repository_key, enabled);
    CREATE INDEX IF NOT EXISTS idx_validation_task_exec_status ON validation_task_executions(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_validation_task_exec_target ON validation_task_executions(target, created_at DESC);
    """)


def downgrade():
    op.execute('DROP TABLE IF EXISTS validation_task_executions; DROP TABLE IF EXISTS validation_tasks; DROP TABLE IF EXISTS validation_repositories;')
