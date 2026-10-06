-- Lookup credits: the offers, receipts and transfers of the log as rows.
-- `peer` is the receiver of an offer or transfer and the payer of a
-- receipt; `parts` is a JSON array of [day, mc]; `seal` says how the
-- entry's seal checked out here (0 none, 1 consistent, 2 unchecked,
-- 3 inconsistent).
CREATE TABLE credit_entries (
  origin BLOB NOT NULL, seq INTEGER NOT NULL, hlc INTEGER NOT NULL,
  kind TEXT NOT NULL, peer BLOB NOT NULL, parts TEXT NOT NULL DEFAULT '[]',
  offer_seq INTEGER, charged_mc INTEGER, answered TEXT,
  seal INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;

CREATE INDEX idx_credit_entries_hlc ON credit_entries(hlc)
