CREATE TABLE IF NOT EXISTS ips (
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  country TEXT, asn INTEGER, asn_org TEXT,
  is_tor_exit INTEGER NOT NULL DEFAULT 0,
  fp_claimed INTEGER NOT NULL DEFAULT 0,
  notes TEXT
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, ip_id INTEGER NOT NULL REFERENCES ips(id),
  method TEXT NOT NULL, path TEXT NOT NULL, query TEXT,
  headers_json TEXT NOT NULL, body BLOB,
  labels_json TEXT NOT NULL DEFAULT '[]', severity INTEGER NOT NULL DEFAULT 0,
  scan_level INTEGER NOT NULL DEFAULT 0, is_fp_claim INTEGER NOT NULL DEFAULT 0,
  page_token TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip_id);
CREATE TABLE IF NOT EXISTS fp_claims (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  request_id INTEGER NOT NULL REFERENCES requests(id),
  ts TEXT NOT NULL, contact_email TEXT, user_agent TEXT
);
CREATE TABLE IF NOT EXISTS scan_jobs (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  level INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
  queued_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status, level);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
  ip_id INTEGER NOT NULL REFERENCES ips(id), level INTEGER NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT,
  os_guess TEXT, raw_xml BLOB
);
CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL, state TEXT NOT NULL,
  service TEXT, product TEXT, version TEXT
);
CREATE TABLE IF NOT EXISTS fingerprints (
  id INTEGER PRIMARY KEY, request_id INTEGER REFERENCES requests(id),
  ip_id INTEGER NOT NULL REFERENCES ips(id), ts TEXT NOT NULL,
  fp_hash TEXT, visitor_id TEXT,
  attributes_json TEXT, behavior_summary_json TEXT, event_blob BLOB
);
CREATE INDEX IF NOT EXISTS idx_fingerprints_hash ON fingerprints(fp_hash);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY, cred_id BLOB NOT NULL UNIQUE,
  passkey_json TEXT NOT NULL, created_at TEXT NOT NULL, label TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
