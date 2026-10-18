-- The RDAP network an IP belongs to as columns of its own (MIK-502 S10):
-- the admin network page, the /ips filter and the search find it through
-- an index. Derived on each node from every origin's RDAP row with the
-- intel card's agreement rule (data::pick_rdap_by, keyed by the handle),
-- never replicated itself; rdap_v holds the derivation version a row was
-- read with (0: not yet, the rows the background backfill reads).
ALTER TABLE ips ADD COLUMN rdap_handle TEXT;
ALTER TABLE ips ADD COLUMN rdap_name TEXT;
ALTER TABLE ips ADD COLUMN rdap_v INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_ips_rdap_handle ON ips(rdap_handle) WHERE rdap_handle IS NOT NULL;
-- Only the IPs still to derive: empty once the backfill is done.
CREATE INDEX idx_ips_rdap_pending ON ips(id) WHERE rdap_v = 0;
