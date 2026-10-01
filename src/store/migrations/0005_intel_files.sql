-- Distributed mode: the newest version of each shared intel file (GeoLite2
-- databases, Tor exit list), as announced by the node that fetched it.
CREATE TABLE IF NOT EXISTS intel_files (
  kind TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, fetched_at TEXT NOT NULL,
  origin BLOB, hlc INTEGER NOT NULL
)
