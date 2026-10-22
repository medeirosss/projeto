-- Magi Runner v2 - Sprint 2
-- PostgreSQL migration fallback when Alembic is not used.

CREATE TABLE IF NOT EXISTS runners (
    id SERIAL PRIMARY KEY,
    runner_uuid VARCHAR(64) NOT NULL UNIQUE,
    runner_name VARCHAR(255) NOT NULL,
    runner_group VARCHAR(120) NOT NULL DEFAULT 'default',
    runner_secret_hash VARCHAR(255) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'registered',
    version VARCHAR(80),
    hostname VARCHAR(255),
    os_name VARCHAR(120),
    ip_address VARCHAR(80),
    host_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_runners_status ON runners(status);
CREATE INDEX IF NOT EXISTS ix_runners_group ON runners(runner_group);
CREATE INDEX IF NOT EXISTS ix_runners_last_heartbeat ON runners(last_heartbeat_at);

CREATE TABLE IF NOT EXISTS runner_jobs (
    id SERIAL PRIMARY KEY,
    job_uuid VARCHAR(64) NOT NULL UNIQUE,
    runner_uuid VARCHAR(64) NULL REFERENCES runners(runner_uuid) ON DELETE SET NULL,
    runner_group VARCHAR(120) NOT NULL DEFAULT 'default',
    job_type VARCHAR(60) NOT NULL,
    command TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(40) NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 100,
    timeout_seconds INTEGER NOT NULL DEFAULT 300,
    claimed_at TIMESTAMP NULL,
    started_at TIMESTAMP NULL,
    finished_at TIMESTAMP NULL,
    result JSONB NULL,
    stdout TEXT NULL,
    stderr TEXT NULL,
    exit_code INTEGER NULL,
    error TEXT NULL,
    created_by VARCHAR(120),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_runner_jobs_queue ON runner_jobs(status, runner_uuid, runner_group, priority, created_at);
CREATE INDEX IF NOT EXISTS ix_runner_jobs_runner ON runner_jobs(runner_uuid);
CREATE INDEX IF NOT EXISTS ix_runner_jobs_status ON runner_jobs(status);
