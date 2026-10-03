-- peephole schema, version 1 (0.1.0). Later changes are new numbered files.

CREATE TABLE ips (
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  country TEXT, asn INTEGER, asn_org TEXT,
  is_tor_exit INTEGER NOT NULL DEFAULT 0,
  fp_claimed INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  request_count INTEGER NOT NULL DEFAULT 0,
  max_severity INTEGER NOT NULL DEFAULT 0,
  ip_key TEXT,
  abuse_score INTEGER
);

CREATE TABLE requests (
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, ip_id INTEGER NOT NULL REFERENCES ips(id),
  method TEXT NOT NULL, path TEXT NOT NULL, query TEXT,
  headers_json TEXT NOT NULL, body BLOB,
  labels_json TEXT NOT NULL DEFAULT '[]',
  owasp_json TEXT NOT NULL DEFAULT '[]', severity INTEGER NOT NULL DEFAULT 0,
  scan_level INTEGER NOT NULL DEFAULT 0, is_fp_claim INTEGER NOT NULL DEFAULT 0,
  page_token TEXT,
  uid TEXT,
  origin BLOB,
  hlc INTEGER,
  answer TEXT,
  status INTEGER,
  unrecorded INTEGER,
  transport TEXT,
  via_proxy INTEGER,
  raw_head BLOB,
  tls_client_hello BLOB,
  ja4 TEXT,
  build TEXT NOT NULL DEFAULT '',
  rules TEXT
);

CREATE TABLE fp_claims (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  request_id INTEGER NOT NULL REFERENCES requests(id),
  ts TEXT NOT NULL, contact_email TEXT, user_agent TEXT,
  uid TEXT,
  origin BLOB,
  hlc INTEGER,
  request_uid TEXT,
  build TEXT NOT NULL DEFAULT ''
);

CREATE TABLE scan_jobs (
  id INTEGER PRIMARY KEY, ip_id INTEGER NOT NULL REFERENCES ips(id),
  level INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
  queued_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0, error TEXT,
  uid TEXT,
  origin BLOB,
  hlc INTEGER,
  status_hlc INTEGER NOT NULL DEFAULT 0,
  arbiter BLOB,
  adopted_from BLOB,
  scanner BLOB
);

CREATE TABLE scans (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES scan_jobs(id),
  ip_id INTEGER NOT NULL REFERENCES ips(id), level INTEGER NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT,
  os_guess TEXT, raw_xml BLOB,
  uid TEXT,
  origin BLOB,
  hlc INTEGER,
  job_uid TEXT,
  build TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ports (
  id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL REFERENCES scans(id),
  port INTEGER NOT NULL, proto TEXT NOT NULL, state TEXT NOT NULL,
  service TEXT, product TEXT, version TEXT
);

CREATE TABLE fingerprints (
  id INTEGER PRIMARY KEY, request_id INTEGER REFERENCES requests(id),
  ip_id INTEGER NOT NULL REFERENCES ips(id), ts TEXT NOT NULL,
  fp_hash TEXT, visitor_id TEXT,
  attributes_json TEXT, behavior_summary_json TEXT, event_blob BLOB,
  uid TEXT,
  origin BLOB,
  hlc INTEGER,
  request_uid TEXT,
  build TEXT NOT NULL DEFAULT ''
);

CREATE TABLE credentials (
  id INTEGER PRIMARY KEY, cred_id BLOB NOT NULL UNIQUE,
  passkey_json TEXT NOT NULL, created_at TEXT NOT NULL, label TEXT
);

CREATE TABLE intel_meta (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE repl_log (
  origin BLOB NOT NULL, seq INTEGER NOT NULL,
  hlc INTEGER NOT NULL, kind TEXT NOT NULL, uid TEXT,
  payload BLOB, sig BLOB,
  erased_by TEXT,
  applied INTEGER NOT NULL DEFAULT 1,
  received_at TEXT NOT NULL, retry_attempts INTEGER NOT NULL DEFAULT 0, retry_after INTEGER NOT NULL DEFAULT 0, wait_uid TEXT, accounted INTEGER NOT NULL DEFAULT 128,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;

CREATE TABLE repl_pending (
  origin BLOB NOT NULL, seq INTEGER NOT NULL,
  entry BLOB NOT NULL, received_at TEXT NOT NULL,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;

CREATE TABLE members (
  id BLOB PRIMARY KEY,
  name TEXT NOT NULL, address TEXT,
  roles_json TEXT NOT NULL DEFAULT '[]', proto_min INTEGER NOT NULL DEFAULT 1, proto_max INTEGER NOT NULL DEFAULT 1,
  sponsor BLOB NOT NULL,
  info_hlc INTEGER NOT NULL,
  admitted_hlc INTEGER NOT NULL,
  revoked_hlc INTEGER, revoked_by BLOB,
  remote_config INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE peer_contact (
  id BLOB PRIMARY KEY,
  last_ok TEXT, last_error TEXT, error_at TEXT, version TEXT
);

CREATE TABLE tombstoned (uid TEXT PRIMARY KEY, tombstone_uid TEXT NOT NULL);

CREATE TABLE repl_heads (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL) WITHOUT ROWID;

CREATE TABLE webauthn_states (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state_json TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE invites (
  id INTEGER PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT
);

CREATE TABLE invite_uses (
  invite_id INTEGER NOT NULL REFERENCES invites(id),
  node BLOB NOT NULL,
  used_at TEXT NOT NULL
);

CREATE TABLE tomb_proofs (
  origin BLOB NOT NULL, tomb_uid TEXT NOT NULL, entry BLOB NOT NULL,
  PRIMARY KEY (origin, tomb_uid)
) WITHOUT ROWID;

CREATE TABLE hidden (uid TEXT PRIMARY KEY, hidden_at TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE blocked_peers (id BLOB PRIMARY KEY, blocked_at TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE config_audit (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, by BLOB, changes TEXT NOT NULL
);

CREATE TABLE config_keys (
  node BLOB PRIMARY KEY, key BLOB NOT NULL, added_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE ip_intel (
  ip TEXT NOT NULL, provider TEXT NOT NULL, origin BLOB NOT NULL,
  hlc INTEGER NOT NULL, fetched_at TEXT NOT NULL, source_version TEXT,
  data_json TEXT NOT NULL, build TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ip, provider, origin)
) WITHOUT ROWID;

CREATE TABLE sponsorships (
  sponsor BLOB NOT NULL, member BLOB NOT NULL, hlc INTEGER NOT NULL,
  PRIMARY KEY (sponsor, member)
) WITHOUT ROWID;

CREATE TABLE origin_usage (
  origin BLOB PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0, entries INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE TABLE purged_origins (id BLOB PRIMARY KEY, purged_at TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE "intel_files" (
  kind TEXT NOT NULL, origin BLOB NOT NULL,
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, fetched_at TEXT NOT NULL, hlc INTEGER NOT NULL,
  PRIMARY KEY (kind, origin)
) WITHOUT ROWID;

CREATE TABLE ip_labels (
  ip_id INTEGER NOT NULL, label TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (ip_id, label)
) WITHOUT ROWID;

CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  cred_id BLOB,
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE ip_intel_log (
  ip TEXT NOT NULL, provider TEXT NOT NULL, origin BLOB NOT NULL,
  hlc INTEGER NOT NULL, fetched_at TEXT NOT NULL, source_version TEXT,
  data_json TEXT NOT NULL, build TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (ip, provider, origin, hlc)
) WITHOUT ROWID;

CREATE TABLE ip_intel_tags (
  ip TEXT NOT NULL, tag TEXT NOT NULL,
  PRIMARY KEY (ip, tag)
) WITHOUT ROWID;

CREATE TABLE skipped_batches (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, origin BLOB, hlc INTEGER,
  ip_id INTEGER NOT NULL REFERENCES ips(id),
  first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, dropped INTEGER NOT NULL,
  build TEXT NOT NULL DEFAULT ''
);

CREATE TABLE skipped_requests (
  batch_id INTEGER NOT NULL REFERENCES skipped_batches(id) ON DELETE CASCADE,
  ts_ms INTEGER NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL
);

CREATE TABLE repl_floors (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL);

CREATE INDEX idx_requests_ts ON requests(ts);

CREATE INDEX idx_scan_jobs_status ON scan_jobs(status, level);

CREATE INDEX idx_fingerprints_hash ON fingerprints(fp_hash);

CREATE INDEX idx_requests_severity ON requests(severity);

CREATE INDEX idx_ips_country ON ips(country);

CREATE INDEX idx_ips_asn ON ips(asn);

CREATE INDEX idx_scans_ip ON scans(ip_id);

CREATE INDEX idx_ports_scan ON ports(scan_id);

CREATE INDEX idx_fingerprints_ip ON fingerprints(ip_id);

CREATE INDEX idx_fp_claims_ip ON fp_claims(ip_id);

CREATE INDEX idx_scan_jobs_ip ON scan_jobs(ip_id);

CREATE INDEX idx_scan_jobs_queued_at ON scan_jobs(queued_at);

CREATE INDEX idx_repl_log_uid ON repl_log(uid);

CREATE UNIQUE INDEX idx_requests_uid ON requests(uid);

CREATE UNIQUE INDEX idx_fingerprints_uid ON fingerprints(uid);

CREATE UNIQUE INDEX idx_fp_claims_uid ON fp_claims(uid);

CREATE UNIQUE INDEX idx_scan_jobs_uid ON scan_jobs(uid);

CREATE UNIQUE INDEX idx_scans_uid ON scans(uid);

CREATE INDEX idx_fingerprints_request_uid ON fingerprints(request_uid);

CREATE INDEX idx_fp_claims_request_uid ON fp_claims(request_uid);

CREATE INDEX idx_requests_origin ON requests(origin);

CREATE INDEX idx_scan_jobs_origin ON scan_jobs(origin, status);

CREATE INDEX idx_scan_jobs_arbiter ON scan_jobs(arbiter, status);

CREATE INDEX idx_scan_jobs_scanner ON scan_jobs(scanner, started_at);

CREATE INDEX idx_webauthn_states_expires ON webauthn_states(expires_at);

CREATE INDEX idx_fingerprints_request ON fingerprints(request_id);

CREATE INDEX idx_fp_claims_request ON fp_claims(request_id);

CREATE INDEX idx_scans_job ON scans(job_id);

CREATE INDEX idx_scans_job_uid ON scans(job_uid);

CREATE INDEX idx_requests_page_token ON requests(page_token) WHERE page_token IS NOT NULL;

CREATE INDEX idx_requests_ip_ts ON requests(ip_id, ts);

CREATE INDEX idx_invite_uses_invite ON invite_uses(invite_id);

CREATE INDEX idx_fingerprints_origin ON fingerprints(origin);

CREATE INDEX idx_fp_claims_origin ON fp_claims(origin);

CREATE INDEX idx_scans_origin ON scans(origin);

CREATE INDEX idx_ip_intel_provider ON ip_intel(provider, ip);

CREATE INDEX idx_ip_intel_origin ON ip_intel(origin);

CREATE INDEX idx_repl_log_unapplied ON repl_log(applied, retry_after) WHERE applied != 1;

CREATE INDEX idx_repl_log_wait ON repl_log(wait_uid) WHERE wait_uid IS NOT NULL;

CREATE INDEX idx_repl_pending_received ON repl_pending(received_at);

CREATE INDEX idx_scan_jobs_origin_hlc ON scan_jobs(origin, hlc);

CREATE INDEX idx_ips_ip_key ON ips(ip_key);

CREATE INDEX idx_ips_request_count ON ips(request_count, last_seen);

CREATE INDEX idx_ips_last_seen ON ips(last_seen);

CREATE INDEX idx_ip_labels_label ON ip_labels(label, ip_id);

CREATE INDEX idx_requests_ip_severity ON requests(ip_id, severity);

CREATE INDEX idx_scan_jobs_status_finished ON scan_jobs(status, finished_at);

CREATE INDEX idx_sessions_cred ON sessions(cred_id);

CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE INDEX idx_ip_intel_log_provider ON ip_intel_log(provider, ip, fetched_at);

CREATE INDEX idx_ip_intel_log_origin ON ip_intel_log(origin);

CREATE INDEX idx_ip_intel_log_time ON ip_intel_log(fetched_at, ip, provider, hlc);

CREATE INDEX idx_ips_abuse_score ON ips(abuse_score);

CREATE INDEX idx_ip_intel_tags_tag ON ip_intel_tags(tag, ip);

CREATE INDEX idx_skipped_batches_ip ON skipped_batches(ip_id);

CREATE INDEX idx_skipped_batches_origin ON skipped_batches(origin);

CREATE INDEX idx_skipped_requests_ts ON skipped_requests(ts_ms);

CREATE INDEX idx_skipped_requests_batch ON skipped_requests(batch_id);

CREATE INDEX idx_skipped_batches_last ON skipped_batches(last_ms);

CREATE INDEX idx_skipped_batches_origin_last ON skipped_batches(origin, last_ms);

CREATE TRIGGER requests_agg_ai AFTER INSERT ON requests BEGIN
  UPDATE ips SET request_count = request_count + 1,
                 max_severity = MAX(max_severity, NEW.severity)
   WHERE id = NEW.ip_id;
  INSERT INTO ip_labels (ip_id, label, count)
    SELECT NEW.ip_id, value, 1 FROM (
      SELECT DISTINCT value FROM json_each(
        CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
      WHERE type = 'text')
    WHERE true
    ON CONFLICT (ip_id, label) DO UPDATE SET count = count + 1;
END;

CREATE TRIGGER requests_agg_ad AFTER DELETE ON requests BEGIN
  UPDATE ips SET request_count = MAX(request_count - 1, 0) WHERE id = OLD.ip_id;
  UPDATE ips SET max_severity =
      COALESCE((SELECT MAX(severity) FROM requests WHERE ip_id = OLD.ip_id), 0)
   WHERE id = OLD.ip_id AND max_severity <= OLD.severity;
  UPDATE ip_labels SET count = count - 1
   WHERE ip_id = OLD.ip_id AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  DELETE FROM ip_labels WHERE ip_id = OLD.ip_id AND count <= 0;
END;

CREATE TRIGGER requests_agg_au AFTER UPDATE OF ip_id, severity, labels_json ON requests BEGIN
  UPDATE ips SET request_count = MAX(request_count - 1, 0) WHERE id = OLD.ip_id;
  UPDATE ips SET max_severity =
      COALESCE((SELECT MAX(severity) FROM requests WHERE ip_id = OLD.ip_id), 0)
   WHERE id = OLD.ip_id;
  UPDATE ip_labels SET count = count - 1
   WHERE ip_id = OLD.ip_id AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  DELETE FROM ip_labels WHERE ip_id = OLD.ip_id AND count <= 0;
  UPDATE ips SET request_count = request_count + 1,
                 max_severity = MAX(max_severity, NEW.severity)
   WHERE id = NEW.ip_id;
  INSERT INTO ip_labels (ip_id, label, count)
    SELECT NEW.ip_id, value, 1 FROM (
      SELECT DISTINCT value FROM json_each(
        CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
      WHERE type = 'text')
    WHERE true
    ON CONFLICT (ip_id, label) DO UPDATE SET count = count + 1;
END;

CREATE TRIGGER ips_labels_ad AFTER DELETE ON ips BEGIN
  DELETE FROM ip_labels WHERE ip_id = OLD.id;
END;
