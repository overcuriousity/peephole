-- Admin sessions: only a SHA-256 of the cookie value is stored, with the
-- key that signed in (its sessions end when the key is deleted) and the
-- last use (idle timeout). Sessions from before are dropped: their ids were
-- stored in the clear. Local, never replicated.
DROP TABLE IF EXISTS sessions;
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  cred_id BLOB,
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX idx_sessions_cred ON sessions(cred_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at)
