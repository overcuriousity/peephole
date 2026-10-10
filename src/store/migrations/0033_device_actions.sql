-- What paired devices did through the act scope of /api/v1 (MIK-22).
-- scan_quotes: a quoted counter-scan price, bound to the device, the
-- address, the level and the price; it lives 2 minutes and is deleted by
-- the purchase that spends it. device_actions: the audit log of every act
-- call that queued something, and the jobs a device may read back. The
-- device's name and pairing admin are copied in, so an entry outlives a
-- rename or a revocation as it was.
CREATE TABLE scan_quotes (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  addr TEXT NOT NULL,
  level INTEGER NOT NULL,
  credits_mc INTEGER NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE device_actions (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  device_id TEXT NOT NULL,
  device_name TEXT NOT NULL,
  paired_by TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  credits_mc INTEGER NOT NULL,
  job_id TEXT NOT NULL UNIQUE
);

CREATE INDEX idx_device_actions_at ON device_actions(at);
