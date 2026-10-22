-- Etapa 3D - CheckPrereqs / Readiness
-- Execute apenas se estas colunas ainda não existirem.

ALTER TABLE atomic_execution_jobs
ADD COLUMN IF NOT EXISTS prereq_status VARCHAR(30);

ALTER TABLE atomic_execution_jobs
ADD COLUMN IF NOT EXISTS prereq_result JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE atomic_execution_jobs
ADD COLUMN IF NOT EXISTS prereq_checked_at TIMESTAMP WITHOUT TIME ZONE;