-- Personas (MIK-560 D5): what the node presented as when it answered a
-- request, one of `crate::trap::persona::ALL`. Replicated with the row.
-- NULL: written before this migration or by an older member.
ALTER TABLE requests ADD COLUMN persona TEXT;
ALTER TABLE skipped_requests ADD COLUMN persona TEXT;
CREATE INDEX idx_requests_persona ON requests(persona, ts) WHERE persona IS NOT NULL;
CREATE INDEX idx_skipped_requests_persona ON skipped_requests(persona, ts_ms) WHERE persona IS NOT NULL;
