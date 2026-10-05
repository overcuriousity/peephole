-- Delayed publication (spec 2026-10-05-public-delay). A request reaches
-- public pages only once released (public_at NULL). publish_cfg holds this
-- node's delay, the pub_* columns the public read models. All of it is
-- local to the node and never replicated.
CREATE TABLE publish_cfg (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  delay_s INTEGER NOT NULL,
  jitter_s INTEGER NOT NULL
);
INSERT INTO publish_cfg (id, delay_s, jitter_s) VALUES (1, 0, 0);

ALTER TABLE requests ADD COLUMN public_at TEXT;
CREATE INDEX idx_requests_pending ON requests(public_at) WHERE public_at IS NOT NULL;

ALTER TABLE ips ADD COLUMN pub_request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_max_severity INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_first_seen TEXT;
ALTER TABLE ips ADD COLUMN pub_last_seen TEXT;
UPDATE ips SET pub_request_count = request_count, pub_max_severity = max_severity,
               pub_first_seen = first_seen, pub_last_seen = last_seen
 WHERE request_count > 0;
CREATE INDEX idx_ips_pub_request_count ON ips(pub_request_count, pub_last_seen);
CREATE INDEX idx_ips_pub_last_seen ON ips(pub_last_seen);

ALTER TABLE ip_labels ADD COLUMN pub_count INTEGER NOT NULL DEFAULT 0;
UPDATE ip_labels SET pub_count = count;

DROP TRIGGER requests_agg_ai;
DROP TRIGGER requests_agg_ad;
DROP TRIGGER requests_agg_au;

-- Insert: admin read models as before, then the publication time, then
-- the public read models when the row is public at once.
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
  UPDATE requests SET public_at = (
      SELECT datetime('now', '+' || (delay_s + abs(random() % (jitter_s + 1))) || ' seconds')
        FROM publish_cfg WHERE id = 1 AND delay_s + jitter_s > 0)
   WHERE id = NEW.id AND NEW.public_at IS NULL;
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id
     AND (SELECT public_at FROM requests WHERE id = NEW.id) IS NULL;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id
     AND label IN (SELECT value FROM json_each(
           CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
         WHERE type = 'text')
     AND (SELECT public_at FROM requests WHERE id = NEW.id) IS NULL;
END;

-- Release: a pending row becomes public.
CREATE TRIGGER requests_pub_release AFTER UPDATE OF public_at ON requests
WHEN OLD.public_at IS NOT NULL AND NEW.public_at IS NULL BEGIN
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id
     AND label IN (SELECT value FROM json_each(
           CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
         WHERE type = 'text');
END;

-- Delete: the public side moves only for a released row. Seen-times are
-- not recomputed, as on the admin side.
CREATE TRIGGER requests_agg_ad AFTER DELETE ON requests BEGIN
  UPDATE ips SET pub_request_count = MAX(pub_request_count - 1, 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ips SET pub_max_severity =
      COALESCE((SELECT MAX(severity) FROM requests
                 WHERE ip_id = OLD.ip_id AND public_at IS NULL), 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL AND pub_max_severity <= OLD.severity;
  UPDATE ip_labels SET pub_count = pub_count - 1
   WHERE ip_id = OLD.ip_id AND OLD.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
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

-- Reclassification or a moved row: both sides as before, the public side
-- for a released row only.
CREATE TRIGGER requests_agg_au AFTER UPDATE OF ip_id, severity, labels_json ON requests BEGIN
  UPDATE ips SET pub_request_count = MAX(pub_request_count - 1, 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ips SET pub_max_severity =
      COALESCE((SELECT MAX(severity) FROM requests
                 WHERE ip_id = OLD.ip_id AND public_at IS NULL AND id != OLD.id), 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ip_labels SET pub_count = pub_count - 1
   WHERE ip_id = OLD.ip_id AND OLD.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
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
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id AND NEW.public_at IS NULL;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id AND NEW.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
     WHERE type = 'text');
END;
