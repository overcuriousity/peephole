-- Indexes for foreign-key child columns and hot lookups.
--
-- With foreign_keys ON, deleting a parent row scans each child table for
-- referencing rows; without these indexes a bulk delete full-scans
-- fingerprints / fp_claims / scans while holding the write lock for minutes,
-- during which every trap request times out. page_token is looked up by the
-- unauthenticated /panel and /collect endpoints on every call.
CREATE INDEX IF NOT EXISTS idx_fingerprints_request ON fingerprints(request_id);
CREATE INDEX IF NOT EXISTS idx_fp_claims_request ON fp_claims(request_id);
CREATE INDEX IF NOT EXISTS idx_scans_job ON scans(job_id);
CREATE INDEX IF NOT EXISTS idx_scans_job_uid ON scans(job_uid);
CREATE INDEX IF NOT EXISTS idx_requests_page_token ON requests(page_token) WHERE page_token IS NOT NULL;
-- Per-IP history is read on every trap request and time-bounded; (ip_id, ts)
-- lets it seek instead of walking every row the IP ever sent.
CREATE INDEX IF NOT EXISTS idx_requests_ip_ts ON requests(ip_id, ts);
-- idx_requests_ip_id_id (ip_id, id) duplicates idx_requests_ip (SQLite indexes
-- already carry the rowid = id), adding only write cost.
DROP INDEX IF EXISTS idx_requests_ip_id_id;
