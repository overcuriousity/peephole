-- Observational probes (scan::probe), replicated as probe_result records.
CREATE TABLE probes (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, group_uid TEXT NOT NULL,
  ip_id INTEGER NOT NULL REFERENCES ips(id), origin BLOB, hlc INTEGER, asker BLOB NOT NULL,
  vantage_ip TEXT, vantage_ip_source TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL, finished_at TEXT NOT NULL, rtt_min_ms INTEGER,
  build TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_probes_ip ON probes(ip_id, id);
CREATE INDEX idx_probes_group ON probes(group_uid);
CREATE INDEX idx_probes_origin_ip ON probes(origin, ip_id, finished_at);
CREATE TABLE probe_ports (
  id INTEGER PRIMARY KEY, probe_id INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
  port INTEGER NOT NULL, protocol TEXT NOT NULL, outcome TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_probe_ports_probe ON probe_ports(probe_id, port);
-- host_keys may come from a probe: rebuild with a nullable scan_id.
CREATE TABLE host_keys_new (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  probe_id INTEGER REFERENCES probes(id) ON DELETE CASCADE,
  ip_id INTEGER NOT NULL REFERENCES ips(id), port INTEGER NOT NULL,
  kind TEXT NOT NULL, fingerprint TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  CHECK ((scan_id IS NULL) != (probe_id IS NULL))
);
INSERT INTO host_keys_new (id, scan_id, ip_id, port, kind, fingerprint, detail)
  SELECT id, scan_id, ip_id, port, kind, fingerprint, detail FROM host_keys;
DROP TABLE host_keys;
ALTER TABLE host_keys_new RENAME TO host_keys;
CREATE UNIQUE INDEX idx_host_keys_scan ON host_keys(scan_id, port, kind, fingerprint) WHERE scan_id IS NOT NULL;
CREATE UNIQUE INDEX idx_host_keys_probe ON host_keys(probe_id, port, kind, fingerprint) WHERE probe_id IS NOT NULL;
CREATE INDEX idx_host_keys_fp ON host_keys(kind, fingerprint, ip_id);
CREATE INDEX idx_host_keys_ip ON host_keys(ip_id);
-- Names an admin looked up that resolved to the address (intel::dns).
CREATE TABLE ip_names (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  name TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'dns',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  agreed INTEGER NOT NULL DEFAULT 0, asked INTEGER NOT NULL DEFAULT 0,
  answered INTEGER NOT NULL DEFAULT 0, votes INTEGER NOT NULL DEFAULT 0,
  record_uid TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_ip_names_unique ON ip_names(ip_id, name, source);
CREATE INDEX idx_ip_names_name ON ip_names(name)
