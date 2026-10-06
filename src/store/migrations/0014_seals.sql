-- Seals: a digest per log entry (SHA-256 of what its origin signed; kept
-- when the entry is erased later), and where each origin's last sealing
-- entry sits.
ALTER TABLE repl_log ADD COLUMN digest BLOB;

CREATE TABLE seal_heads (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL) WITHOUT ROWID
