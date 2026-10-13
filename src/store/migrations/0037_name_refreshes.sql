-- Resolve refresh (MIK-258): when this node last re-resolved a name on one
-- of its own sources, whatever the answer. Local, not replicated; a name
-- that no longer resolves waits its 7 days like one that does.
CREATE TABLE name_refreshes (
  name TEXT PRIMARY KEY, at TEXT NOT NULL
) WITHOUT ROWID;
