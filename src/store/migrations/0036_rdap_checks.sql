-- RDAP spot-checks (MIK-259): this node's re-query of another origin's
-- RDAP row. Local, not replicated. `agreed` is NULL while a first
-- mismatch waits for its second query, then 1 (same tags) or 0 (a dispute).
CREATE TABLE rdap_checks (
  ip TEXT NOT NULL, origin BLOB NOT NULL,
  checked_at TEXT NOT NULL, agreed INTEGER,
  PRIMARY KEY (ip, origin)
) WITHOUT ROWID;
