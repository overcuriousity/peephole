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
