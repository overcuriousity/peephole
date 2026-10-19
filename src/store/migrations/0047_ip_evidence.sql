-- Evidence rows (docs/detection.md, "Device evidence"): typed observations
-- about one address, derived on each node from rows it already holds
-- (`store::evidence`), recomputed with the hourly campaign pass, never
-- replicated, never exported, never written by a person. Node-local
-- because a dynamic address can be personal data. A recompute replaces
-- the table in one transaction.
--
-- kind: 'device.cpe' | 'device.proxy' | 'name.consumer' | 'name.scanner' |
-- 'fleet.key' | 'fleet.canary' | 'fleet.dense' | 'net.hosting' |
-- 'net.eyeball'. value: the catalogue id, fingerprint, canary hash, prefix
-- or AS type. ref_kind / ref_id: the row that produced it ('scan' →
-- scans.id, 'name' → ip_names.id, 'host_key' → host_keys.id, 'request' →
-- requests.id of the reuse, 'ip' → ips.id). v: store::evidence::EVIDENCE_V.
CREATE TABLE ip_evidence (
  ip_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  ref_id INTEGER NOT NULL,
  first_ts TEXT NOT NULL, last_ts TEXT NOT NULL,
  v INTEGER NOT NULL,
  PRIMARY KEY (ip_id, kind, value, ref_kind, ref_id)
) WITHOUT ROWID;
CREATE INDEX idx_ip_evidence_kind ON ip_evidence(kind, ip_id);
