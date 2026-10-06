-- Config keys were replaced by the ownership key.
DROP TABLE config_keys;

DELETE FROM settings WHERE key = 'cluster.config_key'
