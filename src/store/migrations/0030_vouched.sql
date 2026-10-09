-- Members this node admitted as members already (its inviter, its
-- configured peers): its own admission of them does not date them (see
-- members::may_sponsor). Local, never replicated.
CREATE TABLE vouched (id BLOB PRIMARY KEY) WITHOUT ROWID;
