-- SSH host keys, TLS certificates, JA4X and HASSH of scanned sources, as
-- nmap's scripts report them. Derived from scans.raw_xml on each node, so
-- not replicated themselves; keys_parsed marks the scans already read.
CREATE TABLE host_keys (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip_id INTEGER NOT NULL REFERENCES ips(id),
  port INTEGER NOT NULL,
  kind TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_host_keys_scan ON host_keys(scan_id, port, kind, fingerprint);
CREATE INDEX idx_host_keys_fp ON host_keys(kind, fingerprint, ip_id);
CREATE INDEX idx_host_keys_ip ON host_keys(ip_id);
ALTER TABLE scans ADD COLUMN keys_parsed INTEGER NOT NULL DEFAULT 0;
