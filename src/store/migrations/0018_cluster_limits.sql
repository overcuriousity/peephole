-- Hardening of the replicated log against hostile or careless members.
--
-- repl_log.applied: 1 applied, 0 deferred (its parent has not arrived, or
-- an adoption waits for the arbiter to look silent here; retried with
-- backoff), 2 kind unknown to this build (retried after an upgrade only),
-- 3 deferred for too long (kept and relayed, no longer retried).
ALTER TABLE repl_log ADD COLUMN retry_attempts INTEGER NOT NULL DEFAULT 0;
-- Unix ms before which a deferred entry is not retried.
ALTER TABLE repl_log ADD COLUMN retry_after INTEGER NOT NULL DEFAULT 0;
-- The uid a deferred entry waits for (a scan job): its arrival makes the
-- entry due at once.
ALTER TABLE repl_log ADD COLUMN wait_uid TEXT;
UPDATE repl_log SET applied = 2 WHERE applied = 0 AND kind NOT IN (
  'member_add','member_update','member_revoke','request','ip_intel','fp_claim',
  'fingerprint','scan_job','job_status','job_adopt','scan_result','tombstone',
  'intel_manifest');
CREATE INDEX idx_repl_log_unapplied ON repl_log(applied, retry_after) WHERE applied != 1;
CREATE INDEX idx_repl_log_wait ON repl_log(wait_uid) WHERE wait_uid IS NOT NULL;
CREATE INDEX idx_repl_pending_received ON repl_pending(received_at);
-- Every admission a member made, for the per-sponsor rate limit.
CREATE TABLE sponsorships (
  sponsor BLOB NOT NULL, member BLOB NOT NULL, hlc INTEGER NOT NULL,
  PRIMARY KEY (sponsor, member)
) WITHOUT ROWID;
INSERT OR IGNORE INTO sponsorships (sponsor, member, hlc)
  SELECT sponsor, id, admitted_hlc FROM members WHERE admitted_hlc > 0 AND sponsor != id;
-- Bytes of log entries stored per origin (per-origin quota).
CREATE TABLE origin_usage (
  origin BLOB PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0, entries INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
INSERT INTO origin_usage (origin, bytes, entries)
  SELECT origin, SUM(COALESCE(length(payload), 0) + 128), COUNT(*) FROM repl_log GROUP BY origin;
-- Blocked nodes whose content this node deleted (`cluster purge`); their
-- entries are refused and no longer relayed.
CREATE TABLE purged_origins (id BLOB PRIMARY KEY, purged_at TEXT NOT NULL) WITHOUT ROWID;
-- Intel file announcements per origin, so a block falls back to the newest
-- announcement of a node that is not blocked.
CREATE TABLE intel_files_by_origin (
  kind TEXT NOT NULL, origin BLOB NOT NULL,
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, fetched_at TEXT NOT NULL, hlc INTEGER NOT NULL,
  PRIMARY KEY (kind, origin)
) WITHOUT ROWID;
INSERT INTO intel_files_by_origin (kind, origin, sha256, size, fetched_at, hlc)
  SELECT kind, COALESCE(origin, x''), sha256, size, fetched_at, hlc FROM intel_files;
DROP TABLE intel_files;
ALTER TABLE intel_files_by_origin RENAME TO intel_files;
-- Per-origin scan job rate limit.
CREATE INDEX idx_scan_jobs_origin_hlc ON scan_jobs(origin, hlc)
