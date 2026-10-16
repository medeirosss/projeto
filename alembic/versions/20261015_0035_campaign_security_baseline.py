"""Campaign security baseline and change detection.
Revision ID: 0035_campaign_baseline
Revises: 20260921_0034
"""
from alembic import op
revision = '0035_campaign_baseline'
down_revision = '20260921_0034'
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS attack_campaign_baselines (
      id BIGSERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES attack_campaigns(id) ON DELETE CASCADE,
      execution_id INTEGER NOT NULL UNIQUE REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,
      schema_version INTEGER NOT NULL DEFAULT 1, snapshot JSONB NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    op.execute("""CREATE TABLE IF NOT EXISTS attack_campaign_baseline_diffs (
      id BIGSERIAL PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES attack_campaigns(id) ON DELETE CASCADE,
      execution_id INTEGER NOT NULL UNIQUE REFERENCES attack_campaign_executions(id) ON DELETE CASCADE,
      previous_baseline_id BIGINT REFERENCES attack_campaign_baselines(id) ON DELETE SET NULL,
      changes JSONB NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)""")

def downgrade():
    op.execute('DROP TABLE IF EXISTS attack_campaign_baseline_diffs')
    op.execute('DROP TABLE IF EXISTS attack_campaign_baselines')
