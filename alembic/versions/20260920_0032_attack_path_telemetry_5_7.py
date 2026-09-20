"""MAGI 5.7.0 Intelligent Attack Path + Path Telemetry foundation."""
from alembic import op
revision='20260920_0032'; down_revision='20260918_0031'; branch_labels=None; depends_on=None

def upgrade():
    op.execute("""
    CREATE TABLE IF NOT EXISTS attack_path_runs(
      id BIGSERIAL PRIMARY KEY,path_uuid VARCHAR(48) UNIQUE NOT NULL,
      campaign_execution_id INTEGER REFERENCES attack_campaign_executions(id) ON DELETE SET NULL,
      origin_target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
      status VARCHAR(32) NOT NULL DEFAULT 'planned', requested_by VARCHAR(160),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      started_at TIMESTAMP,finished_at TIMESTAMP);
    CREATE TABLE IF NOT EXISTS attack_path_edges(
      id BIGSERIAL PRIMARY KEY,path_run_id BIGINT NOT NULL REFERENCES attack_path_runs(id) ON DELETE CASCADE,
      parent_edge_id BIGINT REFERENCES attack_path_edges(id) ON DELETE SET NULL,
      origin_target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
      origin_address VARCHAR(255),target_address VARCHAR(255),hop INTEGER NOT NULL DEFAULT 0,
      protocol VARCHAR(32),technique_key VARCHAR(120),state VARCHAR(32) NOT NULL DEFAULT 'POSSIBLE' CHECK (state IN ('POSSIBLE','VALIDATABLE','EXECUTING','REACHED','CONFIRMED','RETURN_CONFIRMED','BLOCKED','STALE')),
      evidence JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS attack_path_telemetry(
      id BIGSERIAL PRIMARY KEY,path_run_id BIGINT NOT NULL REFERENCES attack_path_runs(id) ON DELETE CASCADE,
      edge_id BIGINT REFERENCES attack_path_edges(id) ON DELETE SET NULL,event_uuid VARCHAR(64) UNIQUE NOT NULL,
      sequence_no INTEGER NOT NULL,node_target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
      node_address VARCHAR(255),parent_address VARCHAR(255),hop INTEGER NOT NULL DEFAULT 0,
      event_type VARCHAR(32) NOT NULL CHECK (event_type IN ('ENTERED','ACTION_STARTED','ACTION_COMPLETED','EVIDENCE_CREATED','RELAY_STARTED','RELAY_RETURNED','EXITED','FAILED','RETURN_CONFIRMED')),technique_key VARCHAR(120),result VARCHAR(40),
      transport VARCHAR(20) NOT NULL DEFAULT 'relay',relay_depth INTEGER NOT NULL DEFAULT 0,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,event_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS ix_attack_path_telemetry_run_seq ON attack_path_telemetry(path_run_id,sequence_no);
    CREATE INDEX IF NOT EXISTS ix_attack_path_edges_run_hop ON attack_path_edges(path_run_id,hop);
    """)
def downgrade(): pass
