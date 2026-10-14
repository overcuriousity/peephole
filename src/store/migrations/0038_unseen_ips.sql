-- Unseen IPs (MIK-329): a row that exists only because something other
-- than a visit named the address, such as a counter-scan an operator
-- bought for an address no listener recorded. Not a wire field: every
-- node sets it when such a record creates the row (`data::ensure_ip`
-- without a time) and clears it at the first request, so a peer that
-- receives the scan job shows the row unseen too. Existing rows are seen.
ALTER TABLE ips ADD COLUMN unseen INTEGER NOT NULL DEFAULT 0;
