# Unrestricted probes and a paid scan action

**Goal:** Two changes to the Lookup/IP page's Actions card. (1) Remove three probe
restrictions: the 24 h per-node cooldown, the 16-port cap, and the level-2 evidence
requirement — plus the "finished counter-scan with an open port" requirement, with a
well-known-port fallback. (2) Add a buyable counter-scan action: a paid scan of level
1–4, priced exponentially from the cluster's cheapest scanner offer, submitted as a
normal scan job, with a spinner and asynchronous result, and a 24 h exact-level cache.

Credit payment for probes and scans stays. All safety checks stay: non-global
addresses, `never_scan`, the safety lists, Tor exits, verified crawlers (probe gate and
scan preflight alike). Timeouts stay: 10 s per connection, 120 s per probe, the scan
pace timeouts.

## Part 1: Unrestricted probes

### Port cap

- `src/scan/probe/mod.rs`: delete `MAX_PORTS` (line 30) and
  `ports.truncate(MAX_PORTS)` (line 267). A probe reads every open port the target
  list carries, lowest-numbered first; the 120 s `PROBE_TIMEOUT` remains the real
  budget — ports reached after it are recorded `timeout` without connecting, as
  today.
- `src/scan/probe/serve.rs`: drop `.take(super::MAX_PORTS)` in the panic path
  (line 195) so a failed probe still reports one `error` port per wanted port.
- `src/store/probes.rs`: the `MAX_PORTS` at line 19 is peer-record input validation,
  not the operator cap. Raise it 16 → 1024 so uncapped probe results from peers still
  apply, while a garbage record is refused.

### 24 h cooldown

- `src/scan/probe/mod.rs`: delete `PROBE_COOLDOWN_HOURS` (line 42).
- `src/scan/probe/gate.rs`: delete the cooldown SQL block (lines 135–148).
- `src/store/probes.rs`: delete the now-dead `Store::probed_recently` (lines 320–333)
  and its test assertions; fix the stale comment at line 139.
- `src/scan/probe/serve.rs`: the `running` set in `Prober` stays — it prevents two
  simultaneous probes of one address; reword the `admit` doc comment (it cites the
  cooldown).
- `src/admin/probes.rs`: `this_node_only` loses the obsolete `"this node probed"`
  arm.

### Evidence-level requirement

- `src/scan/probe/gate.rs`: delete `PROBE_LEVEL` (line 18) and the evidence fetch +
  level check (lines 104–112). `Gate::allowed_level` (lines 53–59) and the
  `classifier` field become unused and are removed (with the `Classifier` import).
- `src/scan/probe/serve.rs`: remove `Prober::allowed_level` (lines 157–160).
- `src/admin/probes.rs`: the guard line becomes "Counter-scan found N open ports
  (date)" or, on the fallback path (below), "No open port known here; probing the
  well-known ports". The `allowed_level` call (line 570) goes.

### Scan requirement and the well-known fallback

- `src/scan/probe/gate.rs`: `check()` no longer requires the address in the dataset
  or a finished counter-scan. Its port list is:
  1. the open TCP ports of the latest finished (non-audit) counter-scan, when one
     exists — as today, minus the truncation; otherwise
  2. `WELL_KNOWN_PORTS`: `22 (ssh), 80 (http), 443 (https), 8080 (http),
     8443 (https)`, carried with service names so `protocol_for` picks the right
     readers.
- `src/scan/probe/mod.rs`: new `pub const WELL_KNOWN_PORTS` holding the five
  `(port, service)` pairs.
- The remaining gate checks, in order: probes enabled → global address →
  `never_scan` → safety lists → Tor exit → verified crawler. The admin UI flow still
  starts from an IP page, so the address is in the dataset by construction; cluster
  askers may now name any address that passes the checks.

### Tests (part 1)

- Delete `a_gate_enforces_the_24_hour_cooldown`.
- Invert `a_gate_needs_an_open_port_in_a_finished_scan`: no scan / no open port now
  yields `WELL_KNOWN_PORTS` instead of an error.
- Rework `a_gate_refuses_thin_evidence_and_protected_addresses`: thin evidence is
  admitted; `never_scan` still refuses.
- Remove the `requests()` evidence seeding in gate/serve/admin tests where it only
  served the level check; delete the helper if it becomes unused.
- `serve.rs` test `run_local_declines_when_the_gate_says_no` needs a different
  refusal (`never_scan`), since a missing scan no longer refuses.
- `admin/probes.rs` tests: rework `the_actions_card_explains_why_a_probe_is_unavailable`
  and the guard-line assertions.

## Part 2: Paid scan action

### What the admin sees

The Actions card gains a Scan section: four buttons, levels 1–4, each with its
price. Price of level L shown = `cheapest × 4^(L-1)`, where `cheapest` is the lowest
`price_mc` over `Node::price_table().scanners` (the table includes this node,
`src/credits/price.rs:273-286`). Displayed "from {price}" — the actual charge is the
chosen scanner's level-scaled price. When a finished scan of exactly that level less
than 24 h old exists, the button is replaced by "fresh level-N result (date)" — no
purchase, the existing result stands. On a standalone node the buttons queue a local
job for free.

After submitting, the page shows the job as queued/running (the IP page's jobs table
already renders these, `templates/_queue_row.html`) with a spinner affordance like
the probes'; a per-IP SSE stream reloads the page when the job ends and its result
has landed.

### Submission

- New route `POST /admin/lookup/scan` beside `probes::routes`
  (`src/admin/probes.rs:37-40`), taking `ip` and `level`; the level is validated with
  `scan::valid_level` (`src/scan/mod.rs:36-38`).
- The handler re-checks the 24 h exact-level cache (a finished scan of that level
  under 24 h old) and redirects with a notice instead of buying again.
- It enqueues through the existing path: `Recorder::enqueue_scan_with`
  (`src/store/recorder.rs:419-536`) with an `EnqueuePolicy` that skips the
  thin-evidence cap, the queue budgets and the per-IP cooldown (the 24 h exact-level
  cache above is this action's only throttle — buying L2 right after L1 must work),
  and publishes `store.queue_job(id)` to the notifier like the trap does
  (`src/trap/mod.rs:760-763`).
- Standalone, that is all: the job runs locally, unpaid
  (`Source::acquire_local` has no evidence check, `src/scan/mod.rs:499-562`).

### The manual marker and the evidence bypass

- `ScanJobRec` (`src/cluster/record.rs:263`) gains
  `#[serde(default, skip_serializing_if)] pub manual: bool`; `scan_jobs` gains a
  `manual INTEGER NOT NULL DEFAULT 0` column in a new migration (next number after
  `0023_scan_self_mc.sql`; append to `MIGRATIONS`, never edit a shipped one).
- The new route enqueues with `manual: true`.
- `check_grant_here` (`src/scan/mod.rs:804-820`) skips its evidence-level check for
  jobs whose replicated row carries the marker. Nothing else changes: `preflight`
  (`src/scan/mod.rs:387-445`) still refuses non-global addresses, `never_scan`,
  safety-list hits, Tor exits and verified crawlers for every job, manual or not. A
  manual job at a level the evidence would not support is no longer "declined by
  every scanner"; it runs wherever it is granted.
- Threat note: a malicious member could already fabricate requests to raise an
  address's evidence level; the marker lets it buy the same scans without the
  forgery. No new capability, so the marker is honored as replicated.

### Pricing and funding

- Display price (asker side): `cheapest × 4^(L-1)` as above; no scanners announced →
  the section says so (mirroring "no live scanner announces a probe price").
- Actual funding: `credits::jobs::fund` (`src/credits/jobs.rs:109-181`) pays the
  granting scanner's price; for jobs marked manual the price is scaled by
  `4^(level-1)` (level is on the job row). The scanner's `min_mc` floor is its flat
  price, so scaled offers always clear it.
- The POST handler pre-checks fundability with `credits::jobs::budget` +
  `jobs::price_for` (`src/credits/jobs.rs:17-33, 66-80`) and refuses with "the scan
  budget does not cover this" when the level-scaled price exceeds the budget —
  otherwise the job would silently run unfunded (`fund` degrades to unfunded grants
  by design).
- Settlement is unchanged: the scanner writes the `CreditReceipt` on delivery
  (`jobs::settle`, `src/credits/jobs.rs:185-195`).

### Spinner and result arrival

- New SSE endpoint `GET /admin/api/scans?ip=…`, shaped on the probes stream
  (`src/admin/probes.rs:959-1038`): in a cluster it watches
  `node.subscribe_changes()`; standalone it polls every 3 s. It re-reads
  `jobs_for_ip` + `scans_for_ip` and emits the job states when they change; it closes
  once no job for the address is queued/running **and** the finished job's `scans`
  row is present (the `ScanResult` can land after the `JobStatus`,
  `src/store/data.rs:851-859`). The page reloads into the normal `_target.html`
  rendering, like the probes flow.
- `assets/js/app.js`: extend the probes stream handler to the new endpoint (same
  event shape: `[job uid, status]` entries).

### Tests (part 2)

- Actions card: prices render as cheapest × 1/4/16/64; a fresh exact-level scan
  replaces the button; no scanners → the section explains itself.
- POST: queues a `manual` job at the given level (cluster and standalone); a fresh
  exact-level scan redirects without a new job; an unfundable request is refused
  with the budget message; an invalid level is rejected.
- Cluster: a scanner whose evidence allows less than the job's level still runs a
  `manual` job (test at `check_grant_here`); an unmarked job is still declined.
- Funding: a manual L3 job is funded at 16 × the scanner's price; the receipt
  charges the scaled price on delivery.
- The SSE stream emits on job state change and closes when the result row exists.
- 24 h cache boundary: a finished scan 23 h old blocks, 25 h old allows.

## Docs

- `docs/operations.md:289-292`: the probe section currently says "Probes only touch
  ports a scan already found open" — rewrite for the well-known fallback and the
  removed cooldown/caps; add the paid scan action (pricing, cache, manual jobs).
- `docs/cluster.md:210-214`: the Probes paragraph gains the scan action's payment
  flow (level-scaled price, arbiter funding as normal).
- `README.md`: the Actions-card description (~line 38) mentions probes; add the
  buyable scan.
- `CHANGELOG.md`: unreleased entries for both parts.
- `docs/superpowers/plans/*` and older specs are historical; untouched.
