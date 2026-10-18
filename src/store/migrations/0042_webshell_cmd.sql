-- The command a request sent a webshell in a column of its own (MIK-482
-- S1): the admin requests search filters by it, pivots and campaign views
-- read it. Derived on each node from query/body of `answer = 'webshell'`
-- rows, never replicated itself; cmd_v holds the derivation version a row
-- was read with (0: not yet, the rows the background backfill reads).
ALTER TABLE requests ADD COLUMN cmd TEXT;
ALTER TABLE requests ADD COLUMN cmd_v INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_requests_cmd ON requests(cmd, ip_id) WHERE cmd IS NOT NULL;
-- Only the webshell rows still to derive: empty once the backfill is done.
CREATE INDEX idx_requests_cmd_pending ON requests(id) WHERE cmd_v = 0 AND answer = 'webshell';
