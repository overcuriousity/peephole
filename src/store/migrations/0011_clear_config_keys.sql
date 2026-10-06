-- Config keys were replaced by the ownership key. The keys go; the table
-- stays, so a database restored to the previous version still opens there.
DELETE FROM config_keys;

DELETE FROM settings WHERE key = 'cluster.config_key'
