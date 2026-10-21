-- An API key that was never used has no last_seen_at (the Devices page
-- shows "never"); paired devices are seen at pairing, so theirs stays set.
-- SQLite cannot drop NOT NULL in place: rebuild the table. A key whose
-- last_seen_at still equals its created_at was never touched by a bearer
-- request a minute or more after minting, and reads as unused from now on.
CREATE TABLE devices_new (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  paired_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT,
  kind TEXT NOT NULL DEFAULT 'device'
);
INSERT INTO devices_new (id, name, token_hash, scopes, paired_by, created_at, last_seen_at, revoked_at, kind)
  SELECT id, name, token_hash, scopes, paired_by, created_at,
         CASE WHEN kind = 'api_key' AND last_seen_at = created_at THEN NULL ELSE last_seen_at END,
         revoked_at, kind
  FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
