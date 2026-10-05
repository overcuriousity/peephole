-- The User-Agent of a request in a column of its own (UI rework piece D:
-- the admin requests search filters by it, Analytics links to it). Derived
-- on each node from headers_json, never replicated itself; ua_v holds the
-- derivation version a row was read with (0: not yet, the rows the
-- background backfill reads).
ALTER TABLE requests ADD COLUMN user_agent TEXT;
ALTER TABLE requests ADD COLUMN ua_v INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_requests_ua ON requests(user_agent, ip_id) WHERE user_agent IS NOT NULL;
-- Only the rows still to derive: empty once the backfill is done.
CREATE INDEX idx_requests_ua_pending ON requests(id) WHERE ua_v = 0;
