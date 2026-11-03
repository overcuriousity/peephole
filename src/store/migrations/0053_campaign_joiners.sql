-- Joiner edges (`store::campaigns`): kinds 'stager', 'key' and 'file', two
-- addresses naming one value. merged = 0: the two groups stayed apart, so the
-- edge is listed as not merged. joiner_edges: the campaign's joiner edges,
-- counted apart from hard_edges, since a body can claim anything.
ALTER TABLE campaign_edges ADD COLUMN merged INTEGER NOT NULL DEFAULT 1;
ALTER TABLE campaigns ADD COLUMN joiner_edges INTEGER NOT NULL DEFAULT 0;
