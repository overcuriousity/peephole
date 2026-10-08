-- When this node last looked up the source's reverse DNS (intel::rdns);
-- NULL: never. Local, like the names it finds.
ALTER TABLE ips ADD COLUMN rdns_at TEXT;
