-- Exploit waves (roadmap item "New paths and exploit waves"): node-local,
-- never replicated, derived on each node from replicated rows (as
-- 0040_campaigns.sql). shapes.rule_hits counts a shape's requests that hit
-- a rule (classify::UNMATCHED_LABELS); 0 means no rule knows the shape.
-- NULL only on shapes from before this migration, until the start-up
-- backfill (store::shapes::backfill) counts them.
ALTER TABLE shapes ADD COLUMN rule_hits INTEGER;           -- NULL: not backfilled yet
CREATE TABLE waves (
  shape INTEGER PRIMARY KEY REFERENCES shapes(hash),      -- one wave per shape, ever
  detected_at TEXT NOT NULL, window_start TEXT NOT NULL, ips INTEGER NOT NULL,
  notified_at TEXT, notify_attempts INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
