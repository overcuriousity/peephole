-- Hourly price snapshots for the Credits page's charts: this node's price
-- per good, the spread live members announce, and the demand and supply
-- the price was computed from. Local only (each node has its own view);
-- kept for 8 days.
CREATE TABLE price_history (
  hour INTEGER NOT NULL,   -- Unix time / 3600
  good TEXT NOT NULL,      -- scan, probe, resolve, or a provider
  own_mc INTEGER,          -- NULL: this node does not offer it
  lo_mc INTEGER, median_mc INTEGER, hi_mc INTEGER,  -- NULL: nobody announces it
  demand REAL NOT NULL,    -- per hour
  supply REAL NOT NULL,    -- per hour
  PRIMARY KEY (hour, good)
) WITHOUT ROWID;
