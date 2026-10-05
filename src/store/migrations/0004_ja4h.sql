-- JA4H (roadmap item 1): the HTTP client fingerprint of a request's
-- raw_head. Derived on each node from replicated rows, never replicated
-- itself; ja4h_v holds the derivation version a row was read with (0: not
-- yet).
ALTER TABLE requests ADD COLUMN ja4h TEXT;
ALTER TABLE requests ADD COLUMN ja4h_v INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_requests_ja4h ON requests(ja4h, ip_id) WHERE ja4h IS NOT NULL;
CREATE INDEX idx_requests_ja4h_v ON requests(ja4h_v, id) WHERE raw_head IS NOT NULL;
