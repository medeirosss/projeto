-- Centric Portal v2 - clean baseline
-- This file is executed automatically by the official PostgreSQL image only when the data volume is created for the first time.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS license_status (
    id SERIAL PRIMARY KEY,
    license_id VARCHAR(100),
    customer_id VARCHAR(150),
    customer_name VARCHAR(255),
    domain_name VARCHAR(255),
    license_type VARCHAR(50),
    license_mode VARCHAR(50),
    expires_at DATE,
    status VARCHAR(50) NOT NULL DEFAULT 'unknown',
    status_message TEXT,
    modules JSONB DEFAULT '{}'::jsonb,
    max_users INTEGER,
    max_endpoints INTEGER,
    last_validation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_license JSONB
);

CREATE TABLE IF NOT EXISTS auth_settings (
    id SERIAL PRIMARY KEY,
    ldap_server VARCHAR(255) NOT NULL,
    ldap_port INTEGER DEFAULT 389,
    use_ssl BOOLEAN DEFAULT FALSE,
    domain_name VARCHAR(255) NOT NULL,
    base_dn VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_allowed_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_allowed_groups (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_local_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin',
    enabled BOOLEAN DEFAULT TRUE,
    must_change_password BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_settings (
    id SERIAL PRIMARY KEY,
    module VARCHAR(100) NOT NULL,
    setting_key VARCHAR(150) NOT NULL,
    setting_value TEXT,
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(module, setting_key)
);

CREATE TABLE IF NOT EXISTS stored_credentials (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    domain VARCHAR(255),
    secret_encrypted TEXT NOT NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) UNIQUE NOT NULL,
    description TEXT,
    script_type VARCHAR(50) NOT NULL,
    script_content TEXT NOT NULL,
    required_variables JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_uuid VARCHAR(100) UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    source_system VARCHAR(100),
    event_number VARCHAR(50),
    event_type VARCHAR(100),
    event_type_text VARCHAR(100),
    display_name TEXT,
    username VARCHAR(255),
    hostname VARCHAR(255),
    ip_address VARCHAR(100),
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),
    nist_control VARCHAR(100),
    severity VARCHAR(50),
    status INTEGER DEFAULT 1 CHECK (status IN (1,2,3)),
    raw_payload JSONB,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(255),
    resolution_method VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS alert_history (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    old_status INTEGER,
    new_status INTEGER,
    action TEXT,
    changed_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    playbook_id INTEGER REFERENCES playbooks(id) ON DELETE SET NULL,
    credential_id INTEGER REFERENCES stored_credentials(id) ON DELETE SET NULL,
    target VARCHAR(255),
    variables JSONB,
    status VARCHAR(50) DEFAULT 'pending',
    output TEXT,
    error TEXT,
    executed_by VARCHAR(255),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_audit_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    source_ip VARCHAR(100),
    login_result VARCHAR(50),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_audit_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255),
    action VARCHAR(255),
    module VARCHAR(100),
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_settings_module_key ON app_settings(module, setting_key);
CREATE INDEX IF NOT EXISTS idx_login_audit_created_at ON login_audit_log(created_at DESC);


CREATE INDEX IF NOT EXISTS idx_playbook_executions_started_at ON playbook_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_status ON playbook_executions(status);

-- Reports and scans persistence. Logs remain file-based by design.
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id SERIAL PRIMARY KEY,
    source VARCHAR(50) NOT NULL,
    records JSONB NOT NULL DEFAULT '[]'::jsonb,
    record_count INTEGER NOT NULL DEFAULT 0,
    source_detail VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS report_files (
    id SERIAL PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    label VARCHAR(255),
    size_bytes INTEGER DEFAULT 0,
    hostnames JSONB NOT NULL DEFAULT '[]'::jsonb,
    content BYTEA,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_compare_runs (
    id SERIAL PRIMARY KEY,
    report_name VARCHAR(100) NOT NULL DEFAULT 'Scans',
    sources JSONB NOT NULL DEFAULT '{}'::jsonb,
    rows JSONB NOT NULL DEFAULT '[]'::jsonb,
    total INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_snapshots_source_created ON scan_snapshots(source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_files_created_at ON report_files(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_compare_runs_created_at ON scan_compare_runs(created_at DESC);

