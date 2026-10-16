-- Path shapes (campaign clustering, roadmap item 2): the normalized form of
-- a request path (`model::shape`), derived on each node from replicated
-- rows, never replicated (as 0003_canaries.sql). shape holds the shape's
-- hash (NULL: not derived yet); shape_v the rules version it was derived
-- with (0: not yet). Light rows carry a path too; their batch holds the
-- version.
ALTER TABLE requests ADD COLUMN shape INTEGER;
ALTER TABLE requests ADD COLUMN shape_v INTEGER NOT NULL DEFAULT 0;
ALTER TABLE skipped_requests ADD COLUMN shape INTEGER;
ALTER TABLE skipped_batches ADD COLUMN shape_v INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_requests_shape_ip ON requests(shape, ip_id) WHERE shape IS NOT NULL;
CREATE INDEX idx_requests_shape_v ON requests(shape_v, id);
CREATE INDEX idx_skipped_batches_shape_v ON skipped_batches(shape_v, id);
CREATE INDEX idx_skipped_requests_shape ON skipped_requests(shape, batch_id) WHERE shape IS NOT NULL;

-- One row per distinct shape: its text, when it was first and last asked
-- for (as requests.ts) and by how many IPs.
CREATE TABLE shapes (
  hash INTEGER PRIMARY KEY, text TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, ips INTEGER NOT NULL
) WITHOUT ROWID;
