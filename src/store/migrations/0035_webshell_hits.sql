-- The public wall's webshell verbs (MIK-121) read only the requests
-- answered as a webshell, by time: a few rows, never a scan of all.
CREATE INDEX idx_requests_webshell ON requests(ts) WHERE answer = 'webshell';
