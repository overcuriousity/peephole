-- Node ownership: the nodes that share this node's owner, the owner
-- commands this node received, and siblings still on the previous key
-- after a rotation.
CREATE TABLE siblings (
  node BLOB PRIMARY KEY, cert BLOB NOT NULL, seen_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE owner_log (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, from_node BLOB NOT NULL,
  command TEXT NOT NULL, result TEXT NOT NULL
);

CREATE TABLE reown_pending (node BLOB PRIMARY KEY) WITHOUT ROWID
