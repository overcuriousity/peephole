-- Why the arbiter gave each scan job to the scanner it did, for the scan
-- page and the Scans history. Local only (only the arbiter decides); one
-- row per grant, kept for 8 days.
CREATE TABLE job_handouts (
  id INTEGER PRIMARY KEY,
  job_uid TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (datetime('now')),
  scanner BLOB NOT NULL,
  level INTEGER NOT NULL,
  paid INTEGER NOT NULL,
  price_mc INTEGER,             -- NULL: the scanner has no price here
  rate REAL NOT NULL,           -- its weight at the level
  effective_mc INTEGER NOT NULL,
  next_scanner BLOB,            -- the next best claimant, if any
  next_effective_mc INTEGER,
  waited_secs INTEGER NOT NULL, -- held for the reserve, or queued (override)
  reason TEXT NOT NULL,         -- cheapest, override; unpaid: unpaid (budget),
                                -- no_price, below_min, offer_failed
  sat_out INTEGER NOT NULL DEFAULT 0  -- unpaid: claimants that sat the level out
);
CREATE INDEX job_handouts_job ON job_handouts(job_uid, id);
CREATE INDEX job_handouts_at ON job_handouts(at);
