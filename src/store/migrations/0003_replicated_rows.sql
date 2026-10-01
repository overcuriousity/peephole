-- Distributed mode: every replicated row gets a cluster-wide uid, the
-- origin node that created it (NULL: created standalone, not yet in the
-- log) and the HLC of its record.
ALTER TABLE requests ADD COLUMN uid TEXT;
ALTER TABLE requests ADD COLUMN origin BLOB;
ALTER TABLE requests ADD COLUMN hlc INTEGER;
ALTER TABLE fingerprints ADD COLUMN uid TEXT;
ALTER TABLE fingerprints ADD COLUMN origin BLOB;
ALTER TABLE fingerprints ADD COLUMN hlc INTEGER;
ALTER TABLE fingerprints ADD COLUMN request_uid TEXT;
ALTER TABLE fp_claims ADD COLUMN uid TEXT;
ALTER TABLE fp_claims ADD COLUMN origin BLOB;
ALTER TABLE fp_claims ADD COLUMN hlc INTEGER;
ALTER TABLE fp_claims ADD COLUMN request_uid TEXT;
ALTER TABLE scan_jobs ADD COLUMN uid TEXT;
-- The job's arbiter (the node that enqueued it, or adopted it).
ALTER TABLE scan_jobs ADD COLUMN origin BLOB;
ALTER TABLE scan_jobs ADD COLUMN hlc INTEGER;
ALTER TABLE scan_jobs ADD COLUMN status_hlc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN uid TEXT;
ALTER TABLE scans ADD COLUMN origin BLOB;
ALTER TABLE scans ADD COLUMN hlc INTEGER;
ALTER TABLE scans ADD COLUMN job_uid TEXT;
ALTER TABLE ips ADD COLUMN geo_hlc INTEGER NOT NULL DEFAULT 0;
-- Existing rows: random uids (any unique string will do).
UPDATE requests SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
UPDATE fingerprints SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
UPDATE fp_claims SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
UPDATE scan_jobs SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
UPDATE scans SET uid = lower(hex(randomblob(16))) WHERE uid IS NULL;
UPDATE fingerprints SET request_uid = (SELECT uid FROM requests r WHERE r.id = fingerprints.request_id)
  WHERE request_id IS NOT NULL;
UPDATE fp_claims SET request_uid = (SELECT uid FROM requests r WHERE r.id = fp_claims.request_id);
UPDATE scans SET job_uid = (SELECT uid FROM scan_jobs j WHERE j.id = scans.job_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_uid ON requests(uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprints_uid ON fingerprints(uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_claims_uid ON fp_claims(uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_uid ON scan_jobs(uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_uid ON scans(uid);
CREATE INDEX IF NOT EXISTS idx_fingerprints_request_uid ON fingerprints(request_uid);
CREATE INDEX IF NOT EXISTS idx_fp_claims_request_uid ON fp_claims(request_uid);
CREATE INDEX IF NOT EXISTS idx_requests_origin ON requests(origin);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_origin ON scan_jobs(origin, status);
-- Deleted record uids, so a record arriving after its tombstone stays gone.
CREATE TABLE IF NOT EXISTS tombstoned (uid TEXT PRIMARY KEY, tombstone_uid TEXT NOT NULL);
-- IP deletes: everything about the IP up to hlc is gone.
CREATE TABLE IF NOT EXISTS ip_tombstones (
  ip TEXT PRIMARY KEY, hlc INTEGER NOT NULL, tombstone_uid TEXT NOT NULL
);
-- Enrichment for an IP whose first record has not arrived yet.
CREATE TABLE IF NOT EXISTS ip_enrich_pending (
  ip TEXT PRIMARY KEY, hlc INTEGER NOT NULL,
  country TEXT, asn INTEGER, asn_org TEXT, tor INTEGER NOT NULL
)
