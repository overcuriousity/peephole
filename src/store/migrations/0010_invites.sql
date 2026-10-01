-- Invites are reusable: one token can admit a whole peer group over time.
-- Only the secret's hash is stored. Existing one-time invites are dropped.
DROP TABLE IF EXISTS invites;
CREATE TABLE invites (
  id INTEGER PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT
);
CREATE TABLE invite_uses (
  invite_id INTEGER NOT NULL REFERENCES invites(id),
  node BLOB NOT NULL,
  used_at TEXT NOT NULL
);
CREATE INDEX idx_invite_uses_invite ON invite_uses(invite_id)
