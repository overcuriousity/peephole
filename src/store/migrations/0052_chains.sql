-- Attack chains (docs/cluster.md, "Attack chains"): the pieces the X-ray
-- finds in stored requests and uploads, and the chains they join into.
-- Derived on each node from rows it holds (`store::pieces`), never
-- replicated, never exported. Decoded text is never stored.
ALTER TABLE requests ADD COLUMN xray_v INTEGER NOT NULL DEFAULT 0;
ALTER TABLE uploads  ADD COLUMN xray_v INTEGER NOT NULL DEFAULT 0;
-- The rows extraction has left (xray_v = 0), in id order.
CREATE INDEX idx_requests_xray_pending ON requests(id) WHERE xray_v = 0;
CREATE INDEX idx_uploads_xray_pending ON uploads(id) WHERE xray_v = 0;

CREATE TABLE pieces (
  hash INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  ips INTEGER NOT NULL, sources INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX idx_pieces_kind_value ON pieces(kind, value);

CREATE TABLE piece_sightings (
  piece INTEGER NOT NULL, source_kind TEXT NOT NULL,   -- 'request' | 'upload'
  source_id INTEGER NOT NULL, ip_id INTEGER NOT NULL,
  role TEXT NOT NULL, grade TEXT NOT NULL, ts TEXT NOT NULL,
  PRIMARY KEY (piece, source_kind, source_id, role)
) WITHOUT ROWID;
CREATE INDEX idx_sightings_source ON piece_sightings(source_kind, source_id);
CREATE INDEX idx_sightings_ip ON piece_sightings(ip_id);

CREATE TABLE piece_urls (                    -- raw attacker text, shown defanged
  piece INTEGER NOT NULL, url TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, sources INTEGER NOT NULL,
  PRIMARY KEY (piece, url)
) WITHOUT ROWID;
-- Which source named a URL, so a URL only a deleted source named goes with
-- it (`store::pieces::refresh_counts`).
CREATE TABLE piece_url_sources (
  piece INTEGER NOT NULL, url TEXT NOT NULL,
  source_kind TEXT NOT NULL, source_id INTEGER NOT NULL, ts TEXT NOT NULL,
  PRIMARY KEY (piece, url, source_kind, source_id)
) WITHOUT ROWID;
CREATE INDEX idx_url_sources_source ON piece_url_sources(source_kind, source_id);

CREATE TABLE chains (
  key TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  ips INTEGER NOT NULL, sources INTEGER NOT NULL, v INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE chain_pieces (
  chain TEXT NOT NULL REFERENCES chains(key) ON DELETE CASCADE,
  piece INTEGER NOT NULL, PRIMARY KEY (chain, piece)
) WITHOUT ROWID;

CREATE TABLE piece_results (                 -- written by an admin, node-local
  piece INTEGER NOT NULL, id INTEGER NOT NULL, sha256 TEXT, family TEXT,
  source_url TEXT, note TEXT, added_by TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (piece, id)
) WITHOUT ROWID;

-- Every deletion path (admin delete, address delete, retention, a
-- tombstone from the cluster) removes the row, so what only that row
-- sighted goes with it at once: its sightings, the pieces nothing else
-- sights (unless an operator entered results for them), and the URLs
-- nothing else named. Counts of what stays follow in
-- `store::pieces::refresh_counts`.
CREATE TRIGGER requests_del_sightings AFTER DELETE ON requests BEGIN
  DELETE FROM piece_urls WHERE (piece, url) IN
    (SELECT piece, url FROM piece_url_sources
     WHERE source_kind = 'request' AND source_id = OLD.id)
    AND NOT EXISTS (SELECT 1 FROM piece_url_sources o
      WHERE o.piece = piece_urls.piece AND o.url = piece_urls.url
        AND NOT (o.source_kind = 'request' AND o.source_id = OLD.id));
  DELETE FROM piece_url_sources WHERE source_kind = 'request' AND source_id = OLD.id;
  DELETE FROM pieces WHERE hash IN
    (SELECT piece FROM piece_sightings WHERE source_kind = 'request' AND source_id = OLD.id)
    AND NOT EXISTS (SELECT 1 FROM piece_sightings o WHERE o.piece = pieces.hash
      AND NOT (o.source_kind = 'request' AND o.source_id = OLD.id))
    AND NOT EXISTS (SELECT 1 FROM piece_results r WHERE r.piece = pieces.hash);
  DELETE FROM piece_sightings WHERE source_kind = 'request' AND source_id = OLD.id;
END;
CREATE TRIGGER uploads_del_sightings AFTER DELETE ON uploads BEGIN
  DELETE FROM piece_urls WHERE (piece, url) IN
    (SELECT piece, url FROM piece_url_sources
     WHERE source_kind = 'upload' AND source_id = OLD.id)
    AND NOT EXISTS (SELECT 1 FROM piece_url_sources o
      WHERE o.piece = piece_urls.piece AND o.url = piece_urls.url
        AND NOT (o.source_kind = 'upload' AND o.source_id = OLD.id));
  DELETE FROM piece_url_sources WHERE source_kind = 'upload' AND source_id = OLD.id;
  DELETE FROM pieces WHERE hash IN
    (SELECT piece FROM piece_sightings WHERE source_kind = 'upload' AND source_id = OLD.id)
    AND NOT EXISTS (SELECT 1 FROM piece_sightings o WHERE o.piece = pieces.hash
      AND NOT (o.source_kind = 'upload' AND o.source_id = OLD.id))
    AND NOT EXISTS (SELECT 1 FROM piece_results r WHERE r.piece = pieces.hash);
  DELETE FROM piece_sightings WHERE source_kind = 'upload' AND source_id = OLD.id;
END;
CREATE TRIGGER ips_del_sightings AFTER DELETE ON ips BEGIN
  DELETE FROM piece_sightings WHERE ip_id = OLD.id;
END;
