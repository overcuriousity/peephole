-- How this node judged each payable scan, once: the level its own rules
-- and requests back, and whether the scan ran with built-in arguments.
CREATE TABLE credit_scans (
  scan_uid TEXT PRIMARY KEY, job_uid TEXT NOT NULL, ip TEXT NOT NULL,
  scanner BLOB NOT NULL, trap BLOB NOT NULL, hlc INTEGER NOT NULL,
  level INTEGER NOT NULL, job_level INTEGER NOT NULL,
  args_ok INTEGER NOT NULL, judged_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE UNIQUE INDEX idx_credit_scans_job ON credit_scans(job_uid);

CREATE INDEX idx_credit_scans_hlc ON credit_scans(hlc)
