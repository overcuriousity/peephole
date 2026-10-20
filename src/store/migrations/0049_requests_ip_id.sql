-- An IP's first request and its origin by index alone (MIK-775): the
-- sources filter of the intel, rDNS and probe candidate queries looks it
-- up once per IP, and without (ip_id, id) read all of the IP's requests
-- and sorted them. With origin the lookup does not touch the table.
CREATE INDEX idx_requests_ip_id ON requests(ip_id, id, origin);
