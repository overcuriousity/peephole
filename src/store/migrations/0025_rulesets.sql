-- Rulesets: the fingerprint of the rules that classified each request
-- (NULL on rows recorded before, and on claims, so their signed records
-- still rebuild byte for byte), and each ruleset's files, published once
-- per node and change in a replicated `ruleset` record.
ALTER TABLE requests ADD COLUMN rules TEXT;
CREATE TABLE rulesets (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, origin BLOB, hlc INTEGER NOT NULL,
  hash TEXT NOT NULL, files_json TEXT NOT NULL, build TEXT NOT NULL DEFAULT '',
  published_at TEXT NOT NULL
);
CREATE INDEX idx_rulesets_origin ON rulesets(origin, hlc);
CREATE INDEX idx_rulesets_hash ON rulesets(hash);
