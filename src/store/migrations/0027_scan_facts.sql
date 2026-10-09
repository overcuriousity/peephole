-- What a scan says a source serves and calls itself (scan::facts): the
-- service details nmap writes per port, and facts from scripts with
-- structured output. Derived from scans.raw_xml on each node like
-- host_keys, never replicated; facts_parsed marks the scans already read.
ALTER TABLE ports ADD COLUMN extrainfo TEXT;
ALTER TABLE ports ADD COLUMN ostype TEXT;
ALTER TABLE ports ADD COLUMN devicetype TEXT;
ALTER TABLE ports ADD COLUMN hostname TEXT;
ALTER TABLE ports ADD COLUMN cpe TEXT;  -- a JSON array of strings; NULL: none
CREATE TABLE scan_facts (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  port INTEGER,     -- NULL: a fact about the host (smb-os-discovery)
  proto TEXT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE INDEX idx_scan_facts_scan ON scan_facts(scan_id);
ALTER TABLE scans ADD COLUMN facts_parsed INTEGER NOT NULL DEFAULT 0;
-- How many times the scanner replaced its own address or name in the XML
-- before signing it (scan::scrub).
ALTER TABLE scans ADD COLUMN scrubbed INTEGER NOT NULL DEFAULT 0;
