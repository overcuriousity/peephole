-- Config keys other operators gave to this node (local, never replicated).
CREATE TABLE config_keys (
  node BLOB PRIMARY KEY, key BLOB NOT NULL, added_at TEXT NOT NULL
) WITHOUT ROWID;
-- Whether a member lets config key holders change its runtime settings.
ALTER TABLE members ADD COLUMN remote_config INTEGER NOT NULL DEFAULT 0
