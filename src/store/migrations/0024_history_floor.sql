-- Provenance: the build (source commit) of the binary that created each
-- data row. The node is the row's `origin`.
ALTER TABLE requests ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE skipped_batches ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_intel ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_intel_log ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE fp_claims ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE fingerprints ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN build TEXT NOT NULL DEFAULT '';
-- History floors (spec 2026-10-02 local history pruning): a node that keeps
-- only a window holds every entry of an origin from `seq` on, and below it
-- only membership entries. No row: the whole history (floor 1).
CREATE TABLE repl_floors (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL);
-- What each entry was counted with in `origin_usage`, so dropping it frees
-- its share of the origin's quota.
ALTER TABLE repl_log ADD COLUMN accounted INTEGER NOT NULL DEFAULT 128;
UPDATE repl_log SET accounted = COALESCE(length(payload), 0) + 128;
