-- Local decisions of this node; never replicated.
-- hidden: records of other nodes an admin deleted here.
CREATE TABLE hidden (uid TEXT PRIMARY KEY, hidden_at TEXT NOT NULL) WITHOUT ROWID;
-- blocked_peers: nodes this node does not talk to or show records of.
CREATE TABLE blocked_peers (id BLOB PRIMARY KEY, blocked_at TEXT NOT NULL) WITHOUT ROWID
