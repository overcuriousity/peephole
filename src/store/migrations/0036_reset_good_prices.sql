-- MIK-249: every good but a scan job rose on any sale, however small its
-- share of the supply (rDNS went from 142 mc to 37,569 mc in two days).
-- The new rule raises a price only at 90 % of the supply. Start every
-- such good again from 0 and let the rule relearn it; a scanner's price
-- (`price:scan:*`) and the legacy scan price are kept. The ledger is not
-- touched.
UPDATE intel_meta SET value = '0'
WHERE key LIKE 'price:%' AND key NOT LIKE 'price:scan%';
