-- A scan an admin bought from the Actions card: the scanners skip their
-- evidence re-check for it (the safety preflight still applies) and the
-- arbiter funds it at the level-scaled price.
ALTER TABLE scan_jobs ADD COLUMN manual INTEGER NOT NULL DEFAULT 0;
