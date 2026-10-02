-- Every applied ip_intel record, also the ones a newer result replaced:
-- the lookup history of the research dataset. ip_intel keeps the newest
-- result per (ip, provider, origin); this keeps them all.
CREATE TABLE ip_intel_log (
  ip TEXT NOT NULL, provider TEXT NOT NULL, origin BLOB NOT NULL,
  hlc INTEGER NOT NULL, fetched_at TEXT NOT NULL, source_version TEXT,
  data_json TEXT NOT NULL,
  PRIMARY KEY (ip, provider, origin, hlc)
) WITHOUT ROWID;
CREATE INDEX idx_ip_intel_log_provider ON ip_intel_log(provider, ip, fetched_at);
CREATE INDEX idx_ip_intel_log_origin ON ip_intel_log(origin);
CREATE INDEX idx_ip_intel_log_time ON ip_intel_log(fetched_at, ip, provider, hlc);
INSERT INTO ip_intel_log (ip, provider, origin, hlc, fetched_at, source_version, data_json)
  SELECT ip, provider, origin, hlc, fetched_at, source_version, data_json FROM ip_intel;
-- Local read models (never replicated), kept by refresh_ip_view from the
-- newest result of each provider: the AbuseIPDB score and every
-- provider's tags as 'provider:tag', for the admin IP list.
ALTER TABLE ips ADD COLUMN abuse_score INTEGER;
CREATE INDEX idx_ips_abuse_score ON ips(abuse_score);
CREATE TABLE ip_intel_tags (
  ip TEXT NOT NULL, tag TEXT NOT NULL,
  PRIMARY KEY (ip, tag)
) WITHOUT ROWID;
CREATE INDEX idx_ip_intel_tags_tag ON ip_intel_tags(tag, ip);
