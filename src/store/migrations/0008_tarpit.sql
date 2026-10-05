-- The tarpit (roadmap item 1): how long a tarpitted request held its
-- client, in milliseconds, on full and light rows; NULL for every other
-- answer. Replicated with the row (the trap writes the row once the hold
-- has ended).
ALTER TABLE requests ADD COLUMN held_ms INTEGER;
ALTER TABLE skipped_requests ADD COLUMN held_ms INTEGER;
-- The wall's "scanner time wasted" sums them over a range.
CREATE INDEX idx_requests_held ON requests(ts) WHERE held_ms IS NOT NULL;
CREATE INDEX idx_skipped_held ON skipped_requests(ts_ms) WHERE held_ms IS NOT NULL;
