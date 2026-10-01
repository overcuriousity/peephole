-- Highest held sequence per origin (log or parked), kept up to date with
-- every insert, so version vectors need no scan of the whole log.
CREATE TABLE IF NOT EXISTS repl_heads (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL) WITHOUT ROWID;
INSERT OR REPLACE INTO repl_heads (origin, seq)
  SELECT origin, MAX(seq) FROM (
    SELECT origin, seq FROM repl_log UNION ALL SELECT origin, seq FROM repl_pending
  ) GROUP BY origin
