-- Magi Runner v2 API schema normalization
-- Safe to run multiple times.

CREATE TABLE IF NOT EXISTS runners (
    id SERIAL PRIMARY KEY,
    runner_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(150),
    hostname VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'offline',
    last_heartbeat TIMESTAMP,
    token_hash TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS runner_jobs (
    id SERIAL PRIMARY KEY,
    runner_id VARCHAR(100) REFERENCES runners(runner_id) ON DELETE SET NULL,
    job_type VARCHAR(100) NOT NULL,
    target VARCHAR(255),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    result JSONB,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    finished_at TIMESTAMP
);

ALTER TABLE runners ALTER COLUMN name DROP NOT NULL;
ALTER TABLE runners ADD COLUMN IF NOT EXISTS token_hash TEXT;
ALTER TABLE runners ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE runners ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE runners ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE runner_jobs ADD COLUMN IF NOT EXISTS result JSONB;
ALTER TABLE runner_jobs ADD COLUMN IF NOT EXISTS error TEXT;

CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);
CREATE INDEX IF NOT EXISTS idx_runner_jobs_status ON runner_jobs(status);
CREATE INDEX IF NOT EXISTS idx_runner_jobs_runner_status ON runner_jobs(runner_id, status);
CREATE INDEX IF NOT EXISTS idx_runner_jobs_created_at ON runner_jobs(created_at DESC);
