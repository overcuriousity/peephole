# Rules evaluation against the real-world dataset — design

Date: 2026-10-06
Dataset: `/home/user01/Downloads/peephole-export.csv` (58,045 rows; 50,628 recorded
requests + 7,417 light rows; 2026-10-03 22:29 → 2026-10-06 18:44 UTC; 4 nodes;
1,635 distinct source IPs)

## Evaluation findings

### Severity and scan-level distribution

Per request: severity 0 ×1 (fp-claim), 1 ×4,388, 2 ×41,055, 3 ×3,466, 4 ×1,718.
`scan_level` equals `severity` on every row (both are `weight.min(4)`).

Per distinct source IP (the unit that drives counter-scans, via cooldowns and
evidence caps): 819 IPs earn level 1, 444 level 2, 299 level 3, 73 level 4.

- The severity-2 mass (81% of requests) is `path-scanner`/`sensitive-path` volume;
  capping weak-label-only requests at scan level 1 changes the per-IP outcome for
  exactly 1 of 444 level-2 IPs. It only lightens *first-touch* scans of drive-by
  probers (a lone probe currently earns a level-2 scan, the thin-evidence cap).
- Level 3 is driven by `form-interaction` (148 of 299 IPs), `mcp-probe` (62),
  `webshell-probe` (49). 98% of POSTs carry real bodies and target attack
  endpoints (`/wp-login.php`, GraphQL, `/cgi-bin/.%2e/...`, `/read-document`),
  so POST → level 3 stays: these are the engaged actors worth traceroute + NSE
  scripts. Decision: **keep `form-interaction` at weight 3.**
- Level 4 is driven by `path-traversal` (54 IPs) and `rce` (54 IPs) — the
  libredtail-http and RootEvidence waves. Proportionate. The 17 "Google LLC"
  level-4 IPs are spoofed-`Claude-SearchBot` UA attack probes from GCP VMs
  (`googleusercontent.com` is deliberately not a crawler domain); correct.
- `webshell` (weight 4, shell interaction) never fired — correct: nobody
  actually talked to a shell in the window.

### Rules-version artifact

The dataset's dominant rules fingerprint `51911a36…` (48,579 rows) is a
*superseded* ruleset; the current tree fingerprints as `6799c277…` (1,644 rows).
Apparent `sensitive-path` gaps (`/config.json`, `/appsettings.json`,
`/.git-credentials`, `/docker-compose.yml`, …) are already covered by the
current `rules/paths.toml`; those rows predate the fix. Rule evaluation must
therefore check the *current* ruleset, not the stored labels.

### Genuine rule gap: webshell-probe name list

Sprayed shell names hitting only `php-probe` (weight 1) or nothing under the
current rules: `chosen.php` (27 IPs), `simple.php` (25), `adminfuns.php` (30),
`dex.php` (35), `go.php` (29), `ebkid.php` (25), `sm.php` (26), `ccc.php` (36),
`this_is_a_new_hello_world.php` (42). These are documented WordPress upload
shells / malware droppers and belong in `webshell-probe` (weight 3), consistent
with the rule's existing generic short names.

### Research scanners

`research-scanner` + `scanner-ua` rows: Censys (48 IPs), LeakIX l9scan/l9explore
(6 IPs), zgrab (126 IPs — arbitrary cloud tenants; UA proves nothing).
Live DNS verification from the dataset IPs:

- Censys: PTR `*.censys-scanner.com`, forward-confirmed (8/8 sampled).
- LeakIX: PTR `*.scan.leakix.org`, forward-confirmed (4/6; 2 have no PTR and
  stay scannable — the safe direction).
- Shodan: not present in the dataset; documents FCrDNS under `shodan.io`.
- zgrab: no verification possible; stays scannable.

## Decisions (from operator)

1. Deliverable: evaluation report + concrete rule changes (Approach 1: direct
   changes, fixture-validated with real dataset samples).
2. Verified research scanners are **excluded from counter-scans**, displayed
   transparently in the admin interface (who is not scanned and why), and
   documented in a `docs/` page that invites PRs to join the list.
3. Weak-label-only requests (`probe`, `path-scanner`, `php-probe`) are capped at
   scan level 1.
4. `form-interaction` keeps weight 3.

## Changes

### A. Weak-label scan-level cap — `src/classify/mod.rs`

In `Classifier::classify` (verdict assembly, currently `mod.rs:352-358`):
after computing `labels` and `weight`, if every label is in
{`probe`, `path-scanner`, `php-probe`}, then `scan_level = min(1, weight)`;
else `scan_level = weight.min(4)` as today. `severity` is unchanged — it records
what was seen; only the counter-scan response softens.

Docs: update the taxonomy table in `docs/operations.md` and the `scan_level`
column semantics in `docs/dataset.md`.

### B. Verified research scanners — `src/scan/crawler.rs`

- Add `censys-scanner.com`, `leakix.org`, `shodan.io` to `Crawlers::DOMAINS`
  (`crawler.rs:34`). FCrDNS covers all three; no CIDR list is shipped.
  UA alone never suffices (zgrab stays scannable).
- The existing confirmed-hostname result feeds the refusal reason, so the
  reason names the operator (e.g. "verified crawler: …censys-scanner.com").
- Admin transparency: surface scan refusals with their reason in the admin
  scans view, so an operator sees who was not scanned and why.
- New docs page (e.g. `docs/scanners.md`): the excluded operators, the FCrDNS
  verification method, and an invitation to submit a PR to be added to the list.
  Linked from `docs/operations.md`.

### C. `webshell-probe` additions — `rules/webshells.toml`

Extend the shell-name alternation with the names from the findings section
(`chosen`, `simple`, `adminfuns`, `dex`, `go`, `ebkid`, `sm`, `ccc`,
`this_is_a_new_hello_world`). Weight and OWASP tag unchanged (3, A08:2021).

### Tests

- `src/classify/mod.rs` (existing `check()` style): weak-only requests cap at
  scan level 1 (`GET /x.php` alone; 25-path scan burst; burst + `/wp-login.php`
  → level 2 via `sensitive-path`); new webshell names label `webshell-probe`.
- `src/scan/crawler.rs` (fake-resolver tests): `censys-scanner.com`,
  `scan.leakix.org`, `shodan.io` confirmed hosts are recognised; lookalikes
  (`evil-censys-scanner.com`, `censys-scanner.com.attacker.net`) are not.
- Admin scans view: refusal reason rendering covered by existing view tests
  where applicable.
- Full `cargo test` must pass; rule meta-tests (`rules.rs`) validate the edited
  TOML.

## Out of scope

- Replay tooling for arbitrary exports (declined as a deliverable).
- Severity-scale redefinition; `severity` semantics are unchanged.
- Retroactive re-classification of stored rows (`stored.rs` already brackets
  this for agreement checks; no migration).
