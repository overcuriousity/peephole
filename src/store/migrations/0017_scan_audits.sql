-- Audits: a scan run again by another scanner. `audit_of` is the uid of
-- the scan it checks, `audit_result` how the two compare here.
ALTER TABLE scans ADD COLUMN audit_of TEXT;

ALTER TABLE scans ADD COLUMN audit_result TEXT;

CREATE INDEX idx_scans_audit_of ON scans(audit_of) WHERE audit_of IS NOT NULL
