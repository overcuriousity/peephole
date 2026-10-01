-- Distributed scan queue: who arbitrates a job (its origin, or the node
-- that adopted it from an unreachable origin) and which node scans it.
ALTER TABLE scan_jobs ADD COLUMN arbiter BLOB;
ALTER TABLE scan_jobs ADD COLUMN adopted_from BLOB;
ALTER TABLE scan_jobs ADD COLUMN scanner BLOB;
UPDATE scan_jobs SET arbiter = origin;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_arbiter ON scan_jobs(arbiter, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_scanner ON scan_jobs(scanner, started_at)
