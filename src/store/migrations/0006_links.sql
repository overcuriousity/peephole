-- Links (UI rework piece C): JA4 values are looked up by value (the item
-- page, the link graph, the requests filter), as JA4H already is.
CREATE INDEX idx_requests_ja4 ON requests(ja4, ip_id) WHERE ja4 IS NOT NULL;
