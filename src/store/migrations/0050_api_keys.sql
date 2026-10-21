-- Admin-minted API keys are devices that were never paired: same token,
-- scopes, revocation and audit; kind tells the Devices page them apart.
-- Values: 'device' | 'api_key' (checked in Rust, store::devices).
ALTER TABLE devices ADD COLUMN kind TEXT NOT NULL DEFAULT 'device';
