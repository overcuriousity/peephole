-- Protocol 7, scarce credits. Hourly reach reports (`credits::reach`):
-- the advertised members each member completed a sync round with in one
-- UTC hour. `reached` is the members' 32-byte keys, concatenated.
CREATE TABLE reach_reports (
  origin BLOB NOT NULL,
  hour INTEGER NOT NULL,
  reached BLOB NOT NULL,
  PRIMARY KEY (origin, hour)
) WITHOUT ROWID;

CREATE INDEX idx_reach_reports_hour ON reach_reports(hour);

-- Payments of protocol 7's credits carry `economy` 2; the ledger reads
-- only those. Older rows stay, unread, until they age out.
ALTER TABLE credit_entries ADD COLUMN economy INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_credit_entries_economy_hlc ON credit_entries(economy, hlc);
-- The judge and its counted scans are gone.
DROP TABLE credit_scans;
