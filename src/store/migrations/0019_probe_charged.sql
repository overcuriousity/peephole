-- What the asker was charged for a probe (probe_result.charged_mc).
ALTER TABLE probes ADD COLUMN charged_mc INTEGER NOT NULL DEFAULT 0;
