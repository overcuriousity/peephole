-- Blocking a peer takes its rows out of the tables by origin; these make
-- that an index lookup on every table (requests and scan_jobs have one).
CREATE INDEX IF NOT EXISTS idx_fingerprints_origin ON fingerprints(origin);
CREATE INDEX IF NOT EXISTS idx_fp_claims_origin ON fp_claims(origin);
CREATE INDEX IF NOT EXISTS idx_scans_origin ON scans(origin)
