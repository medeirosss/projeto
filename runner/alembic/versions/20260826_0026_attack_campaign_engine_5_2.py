"""MAGI 5.2 attack campaign engine

Revision ID: 20260826_0026
Revises: 0025_sprint4_repository_planner
"""
from alembic import op
revision='20260826_0026'; down_revision='0025_sprint4_repository_planner'; branch_labels=None; depends_on=None

def upgrade():
    op.execute("""
    CREATE TABLE IF NOT EXISTS attack_campaigns (
      id SERIAL PRIMARY KEY,campaign_uuid VARCHAR(48) UNIQUE NOT NULL,name VARCHAR(180) NOT NULL,description TEXT,
      scope_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb,initial_seeds JSONB NOT NULL DEFAULT '[]'::jsonb,credential_id INTEGER,runner_id VARCHAR(100),
      start_at TIMESTAMP NOT NULL,end_at TIMESTAMP NOT NULL,daily_start TIME NOT NULL DEFAULT '08:00',daily_end TIME NOT NULL DEFAULT '18:00',
      cycle_interval_minutes INTEGER NOT NULL DEFAULT 15,cycle_timeout_minutes INTEGER NOT NULL DEFAULT 15,recurrence_days INTEGER,
      max_seeds_per_cycle INTEGER NOT NULL DEFAULT 3,branch_policy JSONB NOT NULL DEFAULT '[10,5,1,0]'::jsonb,max_paths_per_cycle INTEGER NOT NULL DEFAULT 60,
      max_outstanding_jobs INTEGER NOT NULL DEFAULT 5,snapshot_retention INTEGER NOT NULL DEFAULT 10,status VARCHAR(30) NOT NULL DEFAULT 'scheduled',enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_by VARCHAR(160),created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS attack_campaign_executions (
      id SERIAL PRIMARY KEY,campaign_id INTEGER NOT NULL REFERENCES attack_campaigns(id) ON DELETE CASCADE,execution_number INTEGER NOT NULL,status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
      scheduled_start TIMESTAMP NOT NULL,scheduled_end TIMESTAMP NOT NULL,started_at TIMESTAMP,finished_at TIMESTAMP,next_cycle_at TIMESTAMP,stop_reason VARCHAR(80),
      stats JSONB NOT NULL DEFAULT '{}'::jsonb,final_snapshot JSONB,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(campaign_id,execution_number));
    CREATE TABLE IF NOT EXISTS attack_campaign_cycles (
      id SERIAL PRIMARY KEY,execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,cycle_number INTEGER NOT NULL,status VARCHAR(30) NOT NULL DEFAULT 'scheduled',
      scheduled_at TIMESTAMP NOT NULL,started_at TIMESTAMP,deadline_at TIMESTAMP,finished_at TIMESTAMP,seeds JSONB NOT NULL DEFAULT '[]'::jsonb,frontier JSONB NOT NULL DEFAULT '[]'::jsonb,
      stats JSONB NOT NULL DEFAULT '{}'::jsonb,stop_reason VARCHAR(80),UNIQUE(execution_id,cycle_number));
    CREATE TABLE IF NOT EXISTS attack_campaign_assets (
      id SERIAL PRIMARY KEY,execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,address VARCHAR(255) NOT NULL,hostname VARCHAR(255),fqdn VARCHAR(255),
      state VARCHAR(40) NOT NULL DEFAULT 'discovered',access_confirmed BOOLEAN NOT NULL DEFAULT FALSE,seed_count INTEGER NOT NULL DEFAULT 0,inventory JSONB NOT NULL DEFAULT '{}'::jsonb,
      first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(execution_id,address));
    CREATE TABLE IF NOT EXISTS attack_campaign_paths (
      id SERIAL PRIMARY KEY,execution_id INTEGER NOT NULL REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,cycle_id INTEGER NOT NULL REFERENCES attack_campaign_cycles(id) ON DELETE CASCADE,
      origin VARCHAR(255) NOT NULL,target VARCHAR(255) NOT NULL,depth INTEGER NOT NULL DEFAULT 0,status VARCHAR(50) NOT NULL DEFAULT 'queued',runner_job_id INTEGER,validation_execution_id INTEGER,
      result VARCHAR(80),evidence JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,finished_at TIMESTAMP,UNIQUE(execution_id,origin,target));
    CREATE INDEX IF NOT EXISTS idx_attack_campaign_status ON attack_campaigns(status,enabled);
    CREATE INDEX IF NOT EXISTS idx_attack_campaign_exec_status ON attack_campaign_executions(status,scheduled_start,scheduled_end);
    CREATE INDEX IF NOT EXISTS idx_attack_campaign_cycle_status ON attack_campaign_cycles(status,scheduled_at);
    CREATE INDEX IF NOT EXISTS idx_attack_campaign_path_job ON attack_campaign_paths(runner_job_id);
    """)

def downgrade():
    for t in ['attack_campaign_paths','attack_campaign_assets','attack_campaign_cycles','attack_campaign_executions','attack_campaigns']:
        op.execute(f'DROP TABLE IF EXISTS {t} CASCADE')
