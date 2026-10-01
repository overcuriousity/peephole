-- Tombstones received as proof for an erased entry before the tombstone
-- itself arrived in its origin's stream; kept so the erasure can be relayed.
CREATE TABLE tomb_proofs (
  origin BLOB NOT NULL, tomb_uid TEXT NOT NULL, entry BLOB NOT NULL,
  PRIMARY KEY (origin, tomb_uid)
) WITHOUT ROWID
