-- Campaigns (roadmap item 2): source IPs tied together by typed evidence
-- edges, recomputed on each node from replicated rows (`store::campaigns`),
-- never replicated, never written by a person. A recompute replaces all
-- three tables in one transaction.

-- key: the anchor's IP text (the member active first); num: display rank.
CREATE TABLE campaigns (
  key TEXT PRIMARY KEY,
  num INTEGER NOT NULL UNIQUE,
  anchor_ip_id INTEGER NOT NULL,
  size INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  hard_edges INTEGER NOT NULL, soft_edges INTEGER NOT NULL,
  v INTEGER NOT NULL, computed_at TEXT NOT NULL
) WITHOUT ROWID;

-- An IP is in at most one campaign.
CREATE TABLE campaign_members (
  ip_id INTEGER PRIMARY KEY,
  campaign_key TEXT NOT NULL REFERENCES campaigns(key) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX idx_campaign_members_key ON campaign_members(campaign_key);

-- a, b: ip ids, a's IP text sorting before b's. kind: 'ssh' | 'tls' | 'fp' |
-- 'canary' | 'paths'. value: the shared value for the hard kinds, '' for
-- paths (a key column of a WITHOUT ROWID table cannot be NULL). score,
-- shared: paths only (weighted Jaccard, shared shapes); fp_support: paths,
-- 1 when the two share a JA4 and JA4H pair.
CREATE TABLE campaign_edges (
  a INTEGER NOT NULL, b INTEGER NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  score REAL,
  shared INTEGER,
  fp_support INTEGER NOT NULL DEFAULT 0,
  first_ts TEXT NOT NULL, last_ts TEXT NOT NULL,
  PRIMARY KEY (a, b, kind, value)
) WITHOUT ROWID;
CREATE INDEX idx_campaign_edges_b ON campaign_edges(b);
