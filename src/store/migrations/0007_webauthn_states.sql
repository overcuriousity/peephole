-- WebAuthn ceremony state, held server-side instead of in a client cookie.
-- The browser only carries the random id; the challenge and credential list
-- never leave the server, so a client cannot forge a ceremony. Rows are
-- single-use (deleted when taken) and expire.
CREATE TABLE IF NOT EXISTS webauthn_states (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state_json TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_states_expires ON webauthn_states(expires_at);
