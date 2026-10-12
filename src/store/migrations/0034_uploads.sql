-- Files dropped on the trap (MIK-121). Content is hostile: it is stored
-- once per SHA-256 in upload_blobs and never served, executed, rendered
-- or unpacked. `sha256` is of the kept bytes; `size` is the full size as
-- received. `content_state`: held, dropped_rate, dropped_budget,
-- dropped_ceiling, dropped_disk, dropped_mismatch or too_big.
CREATE TABLE uploads (
  id INTEGER PRIMARY KEY,
  uid TEXT UNIQUE NOT NULL,
  request_uid TEXT NOT NULL,
  origin BLOB,
  hlc INTEGER,
  ts TEXT NOT NULL,
  ip_id INTEGER NOT NULL REFERENCES ips(id),
  kind TEXT NOT NULL,
  filename TEXT,
  sniffed_type TEXT NOT NULL,
  size INTEGER NOT NULL,
  truncated INTEGER NOT NULL,
  sha256 BLOB NOT NULL,
  answered_path TEXT NOT NULL,
  path_is_prefix INTEGER NOT NULL,
  content_state TEXT NOT NULL
);

CREATE INDEX idx_uploads_sha256 ON uploads(sha256);
CREATE INDEX idx_uploads_ts ON uploads(ts);
CREATE INDEX idx_uploads_origin_path ON uploads(origin, answered_path);
CREATE INDEX idx_uploads_ip ON uploads(ip_id);
CREATE INDEX idx_uploads_request ON uploads(request_uid);

CREATE TABLE upload_blobs (
  sha256 BLOB PRIMARY KEY,
  size INTEGER NOT NULL,
  content BLOB NOT NULL
) WITHOUT ROWID;

-- New content bytes stored per origin and UTC day of apply on this node
-- (the record's own `ts` is the origin's word and is not trusted for it).
-- The local node's own uploads count under its own origin; a standalone
-- node's under the empty origin.
CREATE TABLE upload_budget (
  origin BLOB NOT NULL,
  day TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY (origin, day)
) WITHOUT ROWID;

CREATE INDEX idx_requests_origin_path ON requests(origin, path);
