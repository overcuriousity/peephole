# API Enrichment Providers — Implementation Plan

**Goal:** AbuseIPDB, Shodan (host API), Shodan InternetDB and GreyNoise Community as enrichment providers, looked up once per cluster with refresh on return, with a replicated lookup history and admin-only display and filters.

**Spec:** `docs/superpowers/specs/2026-10-02-api-enrichment-design.md`

## Global Constraints

- No new record kind; `ip_intel` carries every lookup.
- API keys never leave the node's TOML: never logged, never replicated, never in an error message.
- Admin-only: no public page, filter or query reads the new providers.
- Every task ends green on: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Review Focus

1. Quota exhausted on rank 0. Expected: it stops announcing, the next node takes over, and nothing is queried past the budget.
2. An IP with a malformed or rejected address at the head of the queue. Expected: skipped, the queue moves on.
3. A returning IP after 30, 45 and 67.5 days. Expected: a refresh each time, nothing in between.
4. Erase IP, block and unblock a peer, adopt a standalone DB. Expected: `ip_intel_log` follows `ip_intel` in each case.
5. A Shodan error. Expected: the log line holds no key.

## Tasks

### Task 1: Schema and history
- Migration `0021_intel_history.sql`: `ip_intel_log`, backfill from `ip_intel`; `ips.abuse_score`; `ip_intel_tags`.
- `store/data.rs::ip_intel`: insert a log row on every applied record; reject `data_json` > 32 KiB; known-provider check covers the new names.
- `refresh_ip_view`: fill `abuse_score` and `ip_intel_tags`.
- Erase (`data.rs`), block/unblock (`cluster/block.rs`), adopt (`cluster/adopt.rs`): handle `ip_intel_log`.
- `record_intel`: dedupe only for MaxMind/Tor.
- Tests: log grows per lookup; tags and score follow the newest result; erase/block clear the log.

### Task 2: Scheduling query
- `Store::intel_candidates(provider, step_secs, refresh: RefreshPolicy, skip: &[String], extra: CandidateExtra, limit)` → IPs due per spec §3.2, newest `last_seen` first. The intervals are passed as a JSON array (`N × 1.5^k`) so SQLite needs no math functions.
- Tests: new IP due; looked-up IP not due until it returns after N, then 1.5 N; step-in delay; InternetDB skips Shodan-covered IPs.

### Task 3: Provider runtime
- `intel/api.rs`: shared HTTP client (timeout 20 s, body cap 1 MiB), `Quota` (per-period counters in `intel_meta`), `Pacer` (1 req/s), back-off, skip list, error classification (`Found`, `NotFound`, `Rejected`, `RateLimited{until}`, `KeyRejected`, `Transient`).
- `Provider` gains `ipv6()`, `batch()`, `extra()` defaults; `lookup` keeps returning findings only for answered IPs.
- `enrich_loop` runs one task per provider.

### Task 4: The four providers
- `intel/abuseipdb.rs`, `intel/shodan.rs` (host + InternetDB), `intel/greynoise.rs`: request, parse into the compact shapes, unit tests on recorded sample bodies.
- Register them in `KNOWN_PROVIDERS` (public: false) and in `lib.rs` from config.

### Task 5: Config, example, installer, README
- `config.rs`: `[enrichment]`, `[abuseipdb]`, `[shodan]`, `[internetdb]`, `[greynoise]` with validation and tests.
- `deploy/config.example.toml`, `install.sh` (optional prompts + env vars), `README.md` section.

### Task 6: Web interface
- `intel_facts` renderers for the four providers.
- Admin IP list: `min_abuse`, `sort=abuse`, `tag`, `intel`/`nointel` (ignored without a session); filter form controls; abuse score column for admins.
- Cluster page: this node's quota use per provider.
- Export: full lookup history (`/admin/export/intel?history=1`).
