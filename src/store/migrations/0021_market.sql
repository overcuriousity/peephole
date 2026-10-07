-- Dynamic market: a scan offer names the job it funds (it lapses later
-- than a lookup offer), and the allowance asks whether a member recorded
-- a request on a day. The surge pricing it replaces leaves nothing behind.
ALTER TABLE credit_entries ADD COLUMN job_uid TEXT;
CREATE INDEX idx_requests_origin_hlc ON requests(origin, hlc) WHERE origin IS NOT NULL;
DELETE FROM intel_meta WHERE key LIKE 'surge:%';
