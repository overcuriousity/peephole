-- Local read models (never replicated): per-IP aggregates kept up to date by
-- triggers, so public pages read the ips table instead of aggregating every
-- request, and a sortable key for CIDR searches in SQL.
--
-- request_count / max_severity: over the IP's rows in requests.
ALTER TABLE ips ADD COLUMN request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN max_severity INTEGER NOT NULL DEFAULT 0;
-- ip_key: the address as 16 bytes (IPv4 as ::ffff:a.b.c.d), big-endian,
-- lowercase hex. Fixed width, so text order is address order and a CIDR is
-- a BETWEEN range. Filled in by the code that inserts IPs (SQL cannot parse
-- an IPv6 address); rows without it are backfilled on startup.
ALTER TABLE ips ADD COLUMN ip_key TEXT;
CREATE INDEX idx_ips_ip_key ON ips(ip_key);
CREATE INDEX idx_ips_request_count ON ips(request_count, last_seen);
CREATE INDEX idx_ips_last_seen ON ips(last_seen);
-- Requests per (IP, label): a request counts once per distinct label.
CREATE TABLE ip_labels (
  ip_id INTEGER NOT NULL, label TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (ip_id, label)
) WITHOUT ROWID;
CREATE INDEX idx_ip_labels_label ON ip_labels(label, ip_id);
-- MAX(severity) per IP is recomputed when its worst request goes; this
-- index makes that a seek. (ip_id) alone is covered by (ip_id, ts) and
-- (ip_id, severity), so the single-column index only cost writes.
CREATE INDEX idx_requests_ip_severity ON requests(ip_id, severity);
DROP INDEX IF EXISTS idx_requests_ip;
-- Queue summary counts by status and finish time without a table scan.
CREATE INDEX idx_scan_jobs_status_finished ON scan_jobs(status, finished_at);
-- Backfill.
UPDATE ips SET
  request_count = (SELECT COUNT(*) FROM requests r WHERE r.ip_id = ips.id),
  max_severity = COALESCE((SELECT MAX(r.severity) FROM requests r WHERE r.ip_id = ips.id), 0);
INSERT INTO ip_labels (ip_id, label, count)
  SELECT r.ip_id, je.value, COUNT(DISTINCT r.id)
  FROM requests r,
       json_each(CASE WHEN json_valid(r.labels_json) THEN r.labels_json ELSE '[]' END) je
  WHERE je.type = 'text'
  GROUP BY r.ip_id, je.value;
-- Upkeep. Every write path (local, replicated, hide, block, tombstone)
-- inserts or deletes request rows, so the triggers cover all of them.
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
END
