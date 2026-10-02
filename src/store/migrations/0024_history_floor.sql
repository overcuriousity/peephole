-- Provenance: the build (source commit) of the binary that created each
-- data row. The node is the row's `origin`.
ALTER TABLE requests ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE skipped_batches ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_intel ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE ip_intel_log ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE fp_claims ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE fingerprints ADD COLUMN build TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN build TEXT NOT NULL DEFAULT '';
