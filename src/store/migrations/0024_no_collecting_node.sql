-- Fleets: nothing is forwarded to a collecting node any more; every node
-- keeps what it earns and a lookup draws from its siblings.
DELETE FROM settings WHERE key = 'credits.collect_to';
