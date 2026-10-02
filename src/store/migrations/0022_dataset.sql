-- How each request was answered and what its connection showed (spec
-- 2026-10-02 dataset completeness). NULL on rows recorded before, so their
-- signed records still rebuild byte for byte.
ALTER TABLE requests ADD COLUMN answer TEXT;
ALTER TABLE requests ADD COLUMN status INTEGER;
ALTER TABLE requests ADD COLUMN unrecorded INTEGER;
ALTER TABLE requests ADD COLUMN transport TEXT;
ALTER TABLE requests ADD COLUMN via_proxy INTEGER;
ALTER TABLE requests ADD COLUMN raw_head BLOB;
ALTER TABLE requests ADD COLUMN tls_client_hello BLOB;
ALTER TABLE requests ADD COLUMN ja4 TEXT;
-- Requests the flood gate answered without recording them in full: one
-- light row each, replicated in batches per IP.
CREATE TABLE skipped_batches (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, origin BLOB, hlc INTEGER,
  ip_id INTEGER NOT NULL REFERENCES ips(id),
  first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, dropped INTEGER NOT NULL
);
CREATE INDEX idx_skipped_batches_ip ON skipped_batches(ip_id);
CREATE INDEX idx_skipped_batches_origin ON skipped_batches(origin);
CREATE TABLE skipped_requests (
  batch_id INTEGER NOT NULL REFERENCES skipped_batches(id) ON DELETE CASCADE,
  ts_ms INTEGER NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL
);
CREATE INDEX idx_skipped_requests_ts ON skipped_requests(ts_ms);
CREATE INDEX idx_skipped_requests_batch ON skipped_requests(batch_id);
