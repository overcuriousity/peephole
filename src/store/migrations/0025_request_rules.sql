-- The fingerprint of the rules that classified each request (those built
-- into the recording binary); NULL on rows recorded before, and on claims,
-- so their signed records still rebuild byte for byte.
ALTER TABLE requests ADD COLUMN rules TEXT;
