-- Automatic retries of failed scans: a retry is a new job that names the
-- first failed job of its chain (retry_of, a uid). retry_at: no scanner
-- gets it before then; failed_by: the scanner that failed last, which
-- waits a while longer (see scan::retry). Replicated with the job.
ALTER TABLE scan_jobs ADD COLUMN retry_of TEXT;
ALTER TABLE scan_jobs ADD COLUMN retry_at TEXT;
ALTER TABLE scan_jobs ADD COLUMN failed_by BLOB;
CREATE INDEX idx_scan_jobs_retry_of ON scan_jobs(retry_of) WHERE retry_of IS NOT NULL;
