-- Canaries (roadmap item 1). decoy_v: the decoy template version of a
-- decoy row (NULL: version 0, or not a decoy). Light rows answered with a
-- decoy keep what is needed to trace it. canaries and request_tokens are
-- derived on each node from replicated rows, never replicated themselves;
-- canary_parsed holds the tokenizer version a row was parsed with (0: not
-- yet).
ALTER TABLE requests ADD COLUMN decoy_v INTEGER;
ALTER TABLE requests ADD COLUMN canary_parsed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE skipped_batches ADD COLUMN canary_parsed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE skipped_requests ADD COLUMN page_token TEXT;
ALTER TABLE skipped_requests ADD COLUMN host TEXT;
ALTER TABLE skipped_requests ADD COLUMN answer TEXT;
ALTER TABLE skipped_requests ADD COLUMN decoy_v INTEGER;

CREATE TABLE canaries (
  value_hash INTEGER NOT NULL,
  kind TEXT NOT NULL,
  request_id INTEGER REFERENCES requests(id) ON DELETE CASCADE,
  batch_id INTEGER REFERENCES skipped_batches(id) ON DELETE CASCADE,
  skip_rowid INTEGER,
  ts TEXT NOT NULL,
  ip_id INTEGER NOT NULL
);
CREATE INDEX idx_canaries_hash ON canaries(value_hash);
CREATE INDEX idx_canaries_request ON canaries(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_canaries_batch ON canaries(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX idx_canaries_ip ON canaries(ip_id);

CREATE TABLE request_tokens (
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  value_hash INTEGER NOT NULL,
  place TEXT NOT NULL,
  PRIMARY KEY (request_id, value_hash, place)
) WITHOUT ROWID;
CREATE INDEX idx_request_tokens_hash ON request_tokens(value_hash);
CREATE INDEX idx_requests_canary_parsed ON requests(canary_parsed);
