-- One provider's result for one IP, per node that looked it up. The ips
-- columns (country, asn, asn_org, is_tor_exit) show the newest result.
-- origin is empty on a standalone node.
CREATE TABLE ip_intel (
  ip TEXT NOT NULL, provider TEXT NOT NULL, origin BLOB NOT NULL,
  hlc INTEGER NOT NULL, fetched_at TEXT NOT NULL, source_version TEXT,
  data_json TEXT NOT NULL,
  PRIMARY KEY (ip, provider, origin)
) WITHOUT ROWID;
CREATE INDEX idx_ip_intel_provider ON ip_intel(provider, ip);
CREATE INDEX idx_ip_intel_origin ON ip_intel(origin);
-- Facts recorded before this table existed stay, as this node's results.
INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
  SELECT ip, 'maxmind-geolite2', x'', 0, last_seen, NULL,
         json_object('country', country, 'asn', asn, 'asn_org', asn_org)
  FROM ips WHERE country IS NOT NULL OR asn IS NOT NULL;
INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
  SELECT ip, 'tor-exits', x'', 0, last_seen, NULL, '{"exit":true}'
  FROM ips WHERE is_tor_exit = 1;
DROP TABLE IF EXISTS ip_enrich_pending;
ALTER TABLE ips DROP COLUMN geo_hlc
