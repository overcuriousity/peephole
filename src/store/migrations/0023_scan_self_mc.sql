-- Scanner prices: what a node's own job, granted to its own scanner,
-- counts against its scan budget. Local: paying oneself moves nothing,
-- so it is not in the ledger and not replicated.
ALTER TABLE scan_jobs ADD COLUMN self_mc INTEGER;
