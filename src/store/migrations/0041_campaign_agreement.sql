-- Campaign v2 (store::campaigns): a paths edge's order agreement, the share
-- of shared shapes the two IPs first asked for in the same order, -1..1;
-- NULL for hard edges and for pairs with too few ordered pairs.
ALTER TABLE campaign_edges ADD COLUMN agreement REAL;
