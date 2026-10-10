-- Devices paired with this node's machine API (/api/v1) and the codes that
-- pair them. Only hashes at rest: a pairing code lives 5 minutes and dies
-- with its redemption (one transaction in store::devices); a device token
-- is shown once at pairing. token_hash is the lookup key, so comparing is
-- an indexed exact match, not a row scan.
CREATE TABLE pairing_codes (
  code_hash TEXT PRIMARY KEY,
  scopes TEXT NOT NULL,
  paired_by TEXT NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  paired_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked_at TEXT
);
