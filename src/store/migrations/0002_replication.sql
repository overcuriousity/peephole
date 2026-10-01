-- Distributed mode: the replication log. One row per record, identified by
-- (origin node key, per-origin sequence). payload is the signed CBOR body;
-- NULL once a tombstone erased it (erased_by names that tombstone).
CREATE TABLE IF NOT EXISTS repl_log (
  origin BLOB NOT NULL, seq INTEGER NOT NULL,
  hlc INTEGER NOT NULL, kind TEXT NOT NULL, uid TEXT,
  payload BLOB, sig BLOB,
  erased_by TEXT,
  -- 0: kind unknown to this build; kept and relayed, applied after upgrade.
  applied INTEGER NOT NULL DEFAULT 1,
  received_at TEXT NOT NULL,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_repl_log_uid ON repl_log(uid);
-- Entries whose origin is not (yet) a trusted member, or that wait for an
-- earlier entry; retried whenever membership changes.
CREATE TABLE IF NOT EXISTS repl_pending (
  origin BLOB NOT NULL, seq INTEGER NOT NULL,
  entry BLOB NOT NULL, received_at TEXT NOT NULL,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;
-- Cluster membership, materialized from member records (last write wins by
-- HLC between add/update and revoke).
CREATE TABLE IF NOT EXISTS members (
  id BLOB PRIMARY KEY,
  name TEXT NOT NULL, address TEXT,
  roles_json TEXT NOT NULL DEFAULT '[]', never_scan_json TEXT NOT NULL DEFAULT '[]',
  proto_min INTEGER NOT NULL DEFAULT 1, proto_max INTEGER NOT NULL DEFAULT 1,
  sponsor BLOB NOT NULL,
  -- name/address/roles/... come from the node's own updates (LWW by HLC);
  -- admission only from another member's add, revocation from anyone's revoke.
  info_hlc INTEGER NOT NULL,
  admitted_hlc INTEGER NOT NULL,
  revoked_hlc INTEGER, revoked_by BLOB
);
-- One-time join invites created on this node (only the secret's hash).
CREATE TABLE IF NOT EXISTS invites (
  secret_hash TEXT PRIMARY KEY,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  used_at TEXT, used_by BLOB
);
-- Last contact with each peer, written by the daemon (CLI status, admin UI).
CREATE TABLE IF NOT EXISTS peer_contact (
  id BLOB PRIMARY KEY,
  last_ok TEXT, last_error TEXT, error_at TEXT, version TEXT
)
