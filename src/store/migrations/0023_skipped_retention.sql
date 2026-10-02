-- Retention looks up light-row batches by age, standalone and per origin.
CREATE INDEX idx_skipped_batches_last ON skipped_batches(last_ms);
CREATE INDEX idx_skipped_batches_origin_last ON skipped_batches(origin, last_ms);
