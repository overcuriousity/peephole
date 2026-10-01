-- never_scan is local to each scanner now; members no longer publish it.
ALTER TABLE members DROP COLUMN never_scan_json
