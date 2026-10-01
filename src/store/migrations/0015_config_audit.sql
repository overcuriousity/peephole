-- Local list of settings changes made by other nodes (config key holders).
CREATE TABLE config_audit (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, by BLOB, changes TEXT NOT NULL
)
