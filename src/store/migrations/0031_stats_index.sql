-- The dashboard's timeline (per hour and severity) and its families and
-- OWASP tags group every request of a range, all of them for "all time".
-- Covered here, they read this index instead of the rows, whose headers,
-- bodies and raw heads make a full scan slow.
CREATE INDEX idx_requests_stats ON requests(ts, severity, labels_json, owasp_json);
