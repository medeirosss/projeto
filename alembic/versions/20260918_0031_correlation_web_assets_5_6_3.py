"""MAGI 5.6.3 Correlation + Web Assets."""
from alembic import op
revision='20260918_0031'; down_revision='20260918_0030'; branch_labels=None; depends_on=None

def upgrade():
    op.execute("""
    CREATE TABLE IF NOT EXISTS web_assets(
      id BIGSERIAL PRIMARY KEY, web_uuid VARCHAR(40) UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL, original_url TEXT NOT NULL, normalized_url TEXT NOT NULL,
      scheme VARCHAR(10) NOT NULL, hostname VARCHAR(255) NOT NULL, port INTEGER NOT NULL,
      base_path TEXT NOT NULL DEFAULT '/', status VARCHAR(30) NOT NULL DEFAULT 'unknown',
      http_status INTEGER, resolved_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
      response_headers JSONB NOT NULL DEFAULT '{}'::jsonb, fingerprint JSONB NOT NULL DEFAULT '{}'::jsonb,
      first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen_at TIMESTAMP,
      last_scan_at TIMESTAMP,last_scan_status VARCHAR(30),last_scan_details JSONB NOT NULL DEFAULT '{}'::jsonb,
      active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS web_asset_scan_history(
      id BIGSERIAL PRIMARY KEY,web_asset_id BIGINT NOT NULL REFERENCES web_assets(id) ON DELETE CASCADE,
      status VARCHAR(30) NOT NULL,http_status INTEGER,resolved_addresses JSONB NOT NULL DEFAULT '[]'::jsonb,
      response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS correlation_runs(
      id BIGSERIAL PRIMARY KEY,correlation_uuid VARCHAR(40) UNIQUE NOT NULL,target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
      web_asset_id BIGINT REFERENCES web_assets(id) ON DELETE SET NULL,status VARCHAR(30) NOT NULL DEFAULT 'created',
      requested_by VARCHAR(255),created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,finished_at TIMESTAMP);
    CREATE TABLE IF NOT EXISTS correlation_run_items(
      id BIGSERIAL PRIMARY KEY,correlation_run_id BIGINT NOT NULL REFERENCES correlation_runs(id) ON DELETE CASCADE,
      technique_key VARCHAR(120) NOT NULL,reason TEXT,status VARCHAR(30) NOT NULL DEFAULT 'pending',execution_id BIGINT,
      result JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,finished_at TIMESTAMP);
    """)
def downgrade(): pass
