-- AI decoys (roadmap item 1): what an MCP or LLM decoy answer was rendered
-- from, parsed from the request once (compact JSON, at most 512 bytes; see
-- trap::decoy::ai::DecoyIn). NULL for every other answer. Replicated with
-- the row, on full and light rows.
ALTER TABLE requests ADD COLUMN decoy_in TEXT;
ALTER TABLE skipped_requests ADD COLUMN decoy_in TEXT;
-- The Decoys page and the wall card aggregate over it per range.
CREATE INDEX idx_requests_decoy_in ON requests(ts) WHERE decoy_in IS NOT NULL;
