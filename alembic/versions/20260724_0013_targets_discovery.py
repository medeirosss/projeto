"""Sprint 1: targets and local Nmap discovery.

Revision ID: 20260724_0013
Revises: 20260601_0012
"""
from alembic import op

revision = "20260724_0013"
down_revision = "20260601_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id SERIAL PRIMARY KEY,
        target_uuid VARCHAR(40) UNIQUE NOT NULL,
        hostname VARCHAR(255),
        hostname_normalized VARCHAR(255),
        ip_address INET NOT NULL,
        mac_address VARCHAR(17),
        mac_normalized VARCHAR(12),
        discovery_source VARCHAR(50) NOT NULL DEFAULT 'nmap',
        first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS target_addresses (
        id SERIAL PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        ip_address INET NOT NULL,
        first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_current BOOLEAN NOT NULL DEFAULT TRUE,
        UNIQUE(target_id, ip_address)
    );
    CREATE TABLE IF NOT EXISTS discovery_runs (
        id SERIAL PRIMARY KEY,
        run_uuid VARCHAR(40) UNIQUE NOT NULL,
        target_spec VARCHAR(255) NOT NULL,
        execution_mode VARCHAR(30) NOT NULL DEFAULT 'local',
        status VARCHAR(30) NOT NULL DEFAULT 'running',
        discovered_count INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_targets_hostname_normalized ON targets(hostname_normalized);
    CREATE INDEX IF NOT EXISTS idx_targets_mac_normalized ON targets(mac_normalized) WHERE mac_normalized IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_targets_ip_address ON targets(ip_address);
    CREATE INDEX IF NOT EXISTS idx_targets_last_seen_at ON targets(last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS idx_target_addresses_ip ON target_addresses(ip_address);
    CREATE INDEX IF NOT EXISTS idx_discovery_runs_started_at ON discovery_runs(started_at DESC);
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS discovery_runs;")
    op.execute("DROP TABLE IF EXISTS target_addresses;")
    op.execute("DROP TABLE IF EXISTS targets;")
