"""MAGI 5.6.2 Scan Engine V2 + Attack Exposure foundation."""
from alembic import op
revision='20260918_0030'; down_revision='20260918_0029'; branch_labels=None; depends_on=None

def upgrade():
    op.execute("""
    CREATE TABLE IF NOT EXISTS discovery_scan_credentials(
      scan_id INTEGER NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
      credential_id INTEGER NOT NULL REFERENCES stored_credentials(id) ON DELETE RESTRICT,
      priority INTEGER NOT NULL DEFAULT 100, enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(scan_id,credential_id));
    CREATE INDEX IF NOT EXISTS ix_scan_credentials_priority ON discovery_scan_credentials(scan_id,priority);
    CREATE TABLE IF NOT EXISTS discovery_scan_exclusions(
      id SERIAL PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES discovery_scans(id) ON DELETE CASCADE,
      exclusion_spec VARCHAR(255) NOT NULL, exclusion_type VARCHAR(20) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(scan_id,exclusion_spec));
    ALTER TABLE discovery_scan_targets ADD COLUMN IF NOT EXISTS last_successful_credential_id INTEGER REFERENCES stored_credentials(id) ON DELETE SET NULL;
    ALTER TABLE discovery_scan_targets ADD COLUMN IF NOT EXISTS last_successful_method VARCHAR(40);
    ALTER TABLE discovery_scan_targets ADD COLUMN IF NOT EXISTS last_rescan_at TIMESTAMP;
    CREATE TABLE IF NOT EXISTS asset_rescan_history(
      id BIGSERIAL PRIMARY KEY,target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      scan_id INTEGER REFERENCES discovery_scans(id) ON DELETE SET NULL,status VARCHAR(30) NOT NULL,
      identity_status VARCHAR(30),located_by VARCHAR(30),old_ip INET,new_ip INET,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS asset_attack_exposure(
      id BIGSERIAL PRIMARY KEY,target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
      attack_id INTEGER NOT NULL REFERENCES attack_knowledge(id) ON DELETE CASCADE,state VARCHAR(30) NOT NULL DEFAULT 'POSSIBLE',
      match_confidence INTEGER NOT NULL DEFAULT 0,match_reason JSONB NOT NULL DEFAULT '{}'::jsonb,
      first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(target_id,attack_id));
    CREATE TABLE IF NOT EXISTS network_inventory_snapshot(
      target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,sys_name VARCHAR(255),sys_descr TEXT,
      sys_object_id VARCHAR(255),sys_location VARCHAR(255),vendor VARCHAR(255),model VARCHAR(255),os_name VARCHAR(255),firmware_version VARCHAR(255),
      credential_id INTEGER REFERENCES stored_credentials(id) ON DELETE SET NULL,runner_id VARCHAR(80),collected_at TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO discovery_scan_credentials(scan_id,credential_id,priority)
      SELECT id,credential_id,10 FROM discovery_scans WHERE credential_id IS NOT NULL ON CONFLICT DO NOTHING;
    """)
def downgrade(): pass
