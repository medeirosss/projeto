-- Magi Sprint 2.1.1 - DNS enrichment
ALTER TABLE targets ADD COLUMN IF NOT EXISTS hostname_source VARCHAR(30);
