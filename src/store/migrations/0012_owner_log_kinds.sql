-- Owner commands that did not verify are listed apart from the ones that
-- did, and a sibling still on the previous key carries the reason.
ALTER TABLE owner_log ADD COLUMN verified INTEGER NOT NULL DEFAULT 1;

ALTER TABLE reown_pending ADD COLUMN why TEXT NOT NULL DEFAULT ''
