-- What the whole cluster sold and offered of a good in the hour, from the
-- replicated ledger and heartbeats (MIK-528). NULL: not known.
ALTER TABLE price_history ADD COLUMN cluster_demand REAL;
ALTER TABLE price_history ADD COLUMN cluster_supply REAL;
