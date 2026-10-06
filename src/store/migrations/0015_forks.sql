-- Origins that showed two histories (permanent for that node key), with
-- the fork proof once one is known, and the ranges still to be compared
-- with the peers' copies.
CREATE TABLE forked (
  origin BLOB PRIMARY KEY, seq INTEGER NOT NULL, found_at TEXT NOT NULL,
  proof_origin BLOB, proof_seq INTEGER
) WITHOUT ROWID;

CREATE TABLE fork_suspects (
  origin BLOB NOT NULL, from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL,
  found_at TEXT NOT NULL,
  PRIMARY KEY (origin, from_seq, to_seq)
) WITHOUT ROWID
