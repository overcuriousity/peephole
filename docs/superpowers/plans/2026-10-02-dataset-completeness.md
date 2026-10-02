# Dataset completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every answered request ends up in the dataset with how it was answered, its connection-level signals (raw head, TLS ClientHello, JA4), its sampling weight, and every enrichment, scan and fingerprint, in one export; plus cluster-wide pace capacity.

**Architecture:** New nullable `requests` columns travel in `RequestRec` as optional, skip-if-none fields (so old records rebuild byte-identically). Skipped requests are buffered per IP and replicated as `SkipBatch` records. A second trap listener terminates TLS itself after reading the ClientHello (and an optional PROXY header from trusted peers). The export is rewritten around a wide row assembled page by page.

**Tech Stack:** Rust (axum 0.8, hyper 1, tokio-rustls 0.26, rcgen 0.14, sqlx/SQLite, arrow/parquet 60), bash installer, nginx `stream` + `ssl_preread`.

**Spec:** `docs/superpowers/specs/2026-10-02-dataset-completeness-design.md`

## Global Constraints

- Old records must rebuild byte-identically: every new `RequestRec` field is `Option<_>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`, and old rows keep NULL in the new columns (no backfill of `unrecorded`; the export reads old rows' `:unrecorded` pseudo-header instead — this refines spec §3's "migration backfills").
- Timestamps stored as UTC `YYYY-MM-DD HH:MM:SS`; skipped rows store `ts_ms` (i64 Unix ms).
- Raw head cap 64 KiB; ClientHello cap 16 KiB / 10 s; light-row path cut at 1 KiB; batch flush at 10 s or 1000 rows; `trap.skip_log_rate` default 100.
- Default `trap_tls_listen` in installer/examples: `127.0.0.1:8081`; nginx admin TLS server moves to `127.0.0.1:8444`.
- No proxy product other than nginx is named (docs, comments, config examples).
- Claim e-mails and claim text are never exported.
- Next migration number: `0022`.
- Before every commit: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` for the touched tests.

## Review Focus

- A TLS client that sends the ClientHello across several TCP segments or TLS records → still parsed, JA4 recorded (test in Task 5).
- A trusted proxy peer that sends no or a malformed PROXY header → connection dropped, nothing recorded, no panic (test in Task 6).
- A flood of 10 000 requests from one IP → full rows + light rows + `dropped` sum to exactly 10 000 (test in Task 4).
- An old-style request record (no new fields) replicated to/rebuilt on a new node → rebuild reproduces the payload byte-for-byte (test in Task 2).
- Export with a label filter → no light rows; redistributable mode → no GeoLite2/API data anywhere in the file (tests in Task 7).

---

### Task 1: Cluster-wide pace capacity

**Files:**
- Modify: `src/scan/pace.rs` (`recommend`, `Recommendation`, tests)
- Modify: `src/admin/pages.rs` (`pace_view`, `PaceView`)
- Modify: `src/cluster/confkey.rs:205-207` (ConfigGet recommendation)
- Modify: `templates/admin_queue.html` (capacity card subtitle)

**Interfaces:**
- Produces: `pub struct Others { pub capacity_per_hour: f64, pub scanners: usize }` and `pub fn recommend(m: &QueueMetrics, current: Pace, others: Others) -> Recommendation`; `Recommendation` gains `own_capacity_per_hour: f64` and `scanners: usize` (this node included when it scans). `pub fn others(node: &crate::cluster::Node, scan_secs: f64) -> Others` in `src/scan/pace.rs` (sums `capacity(pace, scan_secs)` over live members ≠ self whose heartbeat has the `scanner` role and a pace; window `crate::scan::arbiter::LIVE_WINDOW`, made `pub(crate)` if it is not).

Semantics: `capacity_per_hour = own + others.capacity_per_hour`; `net = arrival − capacity_per_hour`; drain uses the cluster capacity; the recommended pace for *this* node sizes `target_own = max(1, target − others.capacity_per_hour)`.

- [ ] **Step 1: Failing tests** in `pace.rs` tests:

```rust
#[test]
fn other_scanners_count_toward_capacity_and_shrink_our_share() {
    let o = Others { capacity_per_hour: 20.0, scanners: 1 };
    // 240/day = 10/h arrivals, no backlog, 300 s scans.
    let r = recommend(&m(0, 240, Some(300.0)), P, o);
    assert_eq!(r.own_capacity_per_hour, 24.0);
    assert_eq!(r.capacity_per_hour, 44.0);
    assert!(r.net_growth_per_hour < 0.0);
    assert_eq!(r.scanners, 2);
    // target 10 × 1.25 = 12.5 → 13, minus 20 elsewhere → the minimum.
    assert_eq!(r.pace.max_scans_per_hour, 1);
    assert_eq!(r.pace.max_workers, 1);
}

#[test]
fn alone_is_unchanged() {
    let a = recommend(&m(480, 240, Some(300.0)), P, Others::default());
    assert_eq!(a.capacity_per_hour, 24.0);
    assert_eq!(a.scanners, 1);
}
```

Update every existing `recommend(…, P)` call in tests to pass `Others::default()`.

- [ ] **Step 2:** `cargo test --lib scan::pace` → fails to compile (no `Others`).
- [ ] **Step 3: Implement.**

```rust
/// Capacity of the cluster's other live scanners.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Others {
    pub capacity_per_hour: f64,
    pub scanners: usize,
}

/// What the other live scanners of this node's cluster can finish per
/// hour, from the paces they announce in heartbeats.
pub fn others(node: &crate::cluster::Node, scan_secs: f64) -> Others {
    let me = node.id();
    let mut o = Others::default();
    for id in node.live_members(crate::scan::arbiter::LIVE_WINDOW) {
        if id == me || node.is_blocked(&id) {
            continue;
        }
        let Some(k) = node.status.known(&id) else { continue };
        if !k.hb.roles.iter().any(|r| r == "scanner") {
            continue;
        }
        if let Some(p) = k.hb.pace {
            let p = Pace {
                max_workers: p.max_workers as usize,
                max_scans_per_hour: p.max_scans_per_hour,
                timeout_secs: p.timeout_secs,
            };
            o.capacity_per_hour += capacity(p, scan_secs);
            o.scanners += 1;
        }
    }
    o
}
```

In `recommend`: `let own = capacity(current, measured); let cap = own + others.capacity_per_hour; let net = arrival - cap;` drain from `net`; `let target_own = (target - others.capacity_per_hour).ceil().max(1.0);` and size `workers`/`per_hour` from `target_own`. Set `capacity_per_hour: cap, own_capacity_per_hour: own, scanners: others.scanners + usize::from(!current.paused() || others.scanners == 0)`. (Check the exact `node.status.known` / `node.is_blocked` paths with `grep` and adapt.)

`pace_view`: `let others = st.recorder.node().map(|n| pace::others(&n, m.avg_scan_secs.unwrap_or(pace::DEFAULT_SCAN_SECS))).unwrap_or_default();` pass it; add `PaceView.cluster_note: Option<String>` = `Some(format!("{} own + {} from {} other scanner(s)", fmt_rate(r.own_capacity_per_hour), fmt_rate(others.capacity_per_hour), others.scanners))` when `others.scanners > 0`. Template: show `cluster_note` under the capacity card instead of the "finished last hour" line when set; the recommendation sentence gets "(this node's share)" when set.

`confkey.rs`: pass `crate::scan::pace::others(&node, …)` likewise.

- [ ] **Step 4:** `cargo test --lib scan::pace` and `cargo test --test cluster` pass.
- [ ] **Step 5: Commit** `fix(pace): capacity and recommendation count the whole cluster`.

---

### Task 2: Schema and replicated fields

**Files:**
- Create: `src/store/migrations/0022_dataset.sql`
- Modify: `src/cluster/record.rs` (`RequestRec`, new `SkipBatchRec`, `Record::SkipBatch`, `kind`, `uid`)
- Modify: `src/store/requests.rs` (`NewRequest`)
- Modify: `src/store/recorder.rs:136-160` (`insert_request_from`)
- Modify: `src/store/data.rs` (`request` apply, `rebuild` "request", new `skip_batch` apply, erase/tombstone handling for `skip_batch` uids)
- Test: `src/store/data.rs` tests

**Interfaces:**
- Produces (all `Option`, skip-if-none, on both `RequestRec` and `NewRequest`):
  `answer: Option<String>, status: Option<i64>, unrecorded: Option<i64>, transport: Option<String>, via_proxy: Option<bool>, raw_head: Option<Vec<u8>> (serde_bytes), tls_client_hello: Option<Vec<u8>> (serde_bytes), ja4: Option<String>`.
- Produces: `pub struct SkipBatchRec { pub uid: String, pub ip: String, pub dropped: i64, pub rows: Vec<SkipRow> }`, `pub struct SkipRow { pub ts_ms: i64, pub method: String, pub path: String }`; `Record::SkipBatch(SkipBatchRec)` with kind `"skip_batch"`; `Recorder::insert_skip_batch(&self, ip: &str, dropped: i64, rows: Vec<SkipRow>) -> Result<()>`.

Migration:

```sql
-- How each request was answered and what the connection showed (spec
-- 2026-10-02 dataset completeness). NULL on rows recorded before.
ALTER TABLE requests ADD COLUMN answer TEXT;
ALTER TABLE requests ADD COLUMN status INTEGER;
ALTER TABLE requests ADD COLUMN unrecorded INTEGER;
ALTER TABLE requests ADD COLUMN transport TEXT;
ALTER TABLE requests ADD COLUMN via_proxy INTEGER;
ALTER TABLE requests ADD COLUMN raw_head BLOB;
ALTER TABLE requests ADD COLUMN tls_client_hello BLOB;
ALTER TABLE requests ADD COLUMN ja4 TEXT;
-- Requests answered but not recorded in full (flood sampling): one light
-- row each, replicated in batches.
CREATE TABLE skipped_batches (
  id INTEGER PRIMARY KEY, uid TEXT NOT NULL UNIQUE, origin BLOB, hlc INTEGER,
  ip_id INTEGER NOT NULL REFERENCES ips(id),
  first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL, dropped INTEGER NOT NULL
);
CREATE INDEX idx_skipped_batches_ip ON skipped_batches(ip_id);
CREATE INDEX idx_skipped_batches_origin ON skipped_batches(origin);
CREATE TABLE skipped_requests (
  batch_id INTEGER NOT NULL REFERENCES skipped_batches(id) ON DELETE CASCADE,
  ts_ms INTEGER NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL
);
CREATE INDEX idx_skipped_requests_ts ON skipped_requests(ts_ms);
CREATE INDEX idx_skipped_requests_batch ON skipped_requests(batch_id);
```

(Check `PRAGMA foreign_keys` is on in `Store::connect`; if not, delete `skipped_requests` explicitly wherever a batch is deleted.)

- [ ] **Step 1: Failing tests** in `data.rs` tests (next to the existing request apply test at ~1590):

```rust
#[tokio::test]
async fn request_rebuild_reproduces_old_and_new_records() {
    // old-style: no new fields
    // new-style: all new fields set (raw_head, ja4, answer "decoy:dotenv", status 200, unrecorded 3 …)
    // for each: apply, rebuild(conn, "request", uid), assert cbor::encode(rebuilt) == cbor::encode(original)
}

#[tokio::test]
async fn skip_batch_applies_and_erases() {
    // apply SkipBatch with 3 rows and dropped 5 → 1 skipped_batches row, 3 skipped_requests rows
    // apply a tombstone of the batch uid from the same origin → both tables empty
}
```

Write them with the helpers the existing tests in that module use (`request(…)`, `ctx`, `apply`).

- [ ] **Step 2:** `cargo test --lib store::data` → fails.
- [ ] **Step 3: Implement** fields, migration, `request` INSERT with the 8 new columns, `rebuild` SELECT of the 8 columns (`via_proxy` as `Option<bool>`), `skip_batch` apply (ensure_ip; insert batch with `first_ms`/`last_ms` from rows min/max (0 when empty); insert rows; path cut to 1024 bytes on a char boundary; ignore batches with > 1000 rows or a non-IP `ip`), tombstone erase of `skip_batch` uids (find where tombstones delete by uid per table — `src/store/delete.rs` / `data.rs` — and add `skipped_batches`), `Recorder::insert_skip_batch`. Retention (`src/cluster/retention.rs`): add `"SELECT uid FROM skipped_batches WHERE origin = ? AND last_ms < (strftime('%s','now', ?) * 1000) AND uid IS NOT NULL ORDER BY id LIMIT ?"`. Admin delete-by-IP/range (`src/store/delete.rs`): include `skipped_batches` of the IP.
- [ ] **Step 4:** `cargo test --lib` passes; `cargo test --test cluster` passes.
- [ ] **Step 5: Commit** `feat(store): dataset columns and replicated skip batches`.

---

### Task 3: Per-request answer and unrecorded count

**Files:**
- Modify: `src/trap/decoy.rs` (`Decoy.name`)
- Modify: `src/trap/mod.rs` (`trap_handler`, `record`, `Capture`, `claim_handler`)
- Modify: `templates/request.html`, `src/admin/views.rs` or wherever the request page model is built (show answer, status, unrecorded)
- Test: `tests/capture.rs`

**Interfaces:**
- Consumes: `NewRequest` fields from Task 2.
- Produces: `Capture` gains `answer: &'static str`-ish `String`, `status: u16`, `unrecorded: u64`; decoy names `dotenv`, `git-config`, `git-head`, `wp-login`, `wp-login-failed`, `phpinfo`.

- [ ] **Step 1: Failing tests** in `tests/capture.rs`:

```rust
#[tokio::test]
async fn answer_and_status_are_recorded() {
    let (base, store, _d) = spawn("[trap]\ndecoys = true\n").await;
    let c = reqwest::Client::new();
    c.get(format!("{base}/.env")).send().await.unwrap();
    c.get(format!("{base}/nothing")).send().await.unwrap();
    let rows: Vec<(Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT answer, status FROM requests ORDER BY id")
            .fetch_all(&store.pool).await.unwrap();
    assert_eq!(rows, vec![
        (Some("decoy:dotenv".into()), Some(200)),
        (Some("not-found".into()), Some(404)),
    ]);
}
```

Change the existing flood-sampling test that asserts an `:unrecorded` pseudo-header to assert `SELECT unrecorded` instead, and assert no `:unrecorded` header is written any more.

- [ ] **Step 2:** `cargo test --test capture` → fails.
- [ ] **Step 3: Implement.** In `trap_handler`, compute `let d = state.cfg.trap.decoys.then(|| decoy::decoy(method, path, &canary)).flatten();` *before* recording; `answer = d.map(|d| format!("decoy:{}", d.name)).unwrap_or("not-found")`, `status = if d.is_some() {200} else {404}`; drop the `:unrecorded` push; pass `unrecorded: (unrecorded > 0).then_some(unrecorded as i64)`. Use the same `d` for the response. Claim posts: `answer = "claim"`, status as returned there.
- [ ] **Step 4:** `cargo test --test capture` passes.
- [ ] **Step 5: Commit** `feat(trap): record how each request was answered`.

---

### Task 4: Light rows for skipped requests

**Files:**
- Create: `src/trap/skiplog.rs`
- Modify: `src/trap/mod.rs` (state field, `Admission::Skip` arm, flush on record, background flusher started with the trap)
- Modify: `src/trap/config.rs` (`skip_log_rate: u32`, default 100)
- Modify: `src/lib.rs` (spawn flusher next to `serve_trap`, stop with it)
- Modify: `templates/ip.html` + IP page model (light-row count)
- Modify: `deploy/config.example.toml` (`# skip_log_rate = 100`)
- Test: unit tests in `skiplog.rs`; `tests/capture.rs`

**Interfaces:**
- Produces:

```rust
pub struct SkipLog { inner: Mutex<HashMap<IpAddr, Pending>> }
struct Pending { rows: Vec<SkipRow>, dropped: u64, opened: Instant, sec: i64, in_sec: u32 }
impl SkipLog {
    /// Note a skipped request; returns a full batch to flush, if any.
    pub fn note(&self, ip: IpAddr, ts_ms: i64, method: &str, path: &str, rate: u32, now: Instant) -> Option<(IpAddr, i64, Vec<SkipRow>)>;
    /// Take the IP's pending batch (on its next recorded request).
    pub fn take(&self, ip: IpAddr) -> Option<(IpAddr, i64, Vec<SkipRow>)>;
    /// Take every batch older than `age`.
    pub fn take_older(&self, age: Duration, now: Instant) -> Vec<(IpAddr, i64, Vec<SkipRow>)>;
}
```

Rules: per IP, rows within one wall second (`ts_ms / 1000`) beyond `rate` (0 = unlimited) increment `dropped` instead; a batch is returned by `note` when it reaches 1000 rows; path cut to 1024 bytes on a char boundary; map bounded at 100 000 IPs (on overflow, `take_older(Duration::ZERO)` everything and flush).

- [ ] **Step 1: Failing unit tests:**

```rust
#[test]
fn rate_bound_counts_drops() {
    let s = SkipLog::default();
    let ip = "192.0.2.1".parse().unwrap();
    let now = Instant::now();
    for i in 0..150 { assert!(s.note(ip, 1_000_000 + i, "GET", "/x", 100, now).is_none()); }
    let (_, dropped, rows) = s.take(ip).unwrap();
    assert_eq!((rows.len(), dropped), (100, 50));
}

#[test]
fn full_batch_is_returned_at_1000() {
    let s = SkipLog::default();
    let ip = "192.0.2.1".parse().unwrap();
    let now = Instant::now();
    let mut got = None;
    for i in 0..1000 { got = s.note(ip, i * 1000, "GET", "/x", 0, now); }
    assert_eq!(got.unwrap().2.len(), 1000);
    assert!(s.take(ip).is_none());
}

#[test]
fn long_paths_are_cut_on_a_char_boundary() { /* "é".repeat(600) → ≤ 1024 bytes, valid UTF-8 */ }
```

Integration (`tests/capture.rs`): with `[trap]\nrecord_rate = 1\nrecord_burst = 1\nsample_every = 0\nskip_log_rate = 5`, send 50 requests on one connection-less loop as fast as possible, then one more after 1.1 s; then assert `COUNT(requests) + COUNT(skipped_requests) + SUM(dropped) == 51` (allow the flusher by calling the recorded request path, which takes the pending batch). `TrapState::for_test` must create the `SkipLog`.

- [ ] **Step 2:** tests fail.
- [ ] **Step 3: Implement** `skiplog.rs`; in `trap_handler` `Skip` arm call `note` and, on a full batch, `recorder.insert_skip_batch` in a spawned task; in the `Record` arm, `take(ip)` and insert before recording the request (same task, errors logged with `warn!`); flusher task every 2 s calls `take_older(10 s)`. Export `SkipRow` from `cluster::record`.
- [ ] **Step 4:** tests pass.
- [ ] **Step 5: Commit** `feat(trap): light rows for requests the flood gate skips`.

---

### Task 5: Connection parsers (ClientHello/JA4, PROXY, raw head)

Pure code, no I/O wiring yet.

**Files:**
- Create: `src/trap/tls_hello.rs`, `src/trap/proxy_proto.rs`, `src/trap/raw_head.rs`
- Modify: `src/trap/mod.rs` (`mod` lines)

**Interfaces:**
- Produces:
  - `pub struct ClientHello { pub raw: Vec<u8>, pub legacy_version: u16, pub ciphers: Vec<u16>, pub extensions: Vec<u16>, pub sni: Option<String>, pub alpn: Vec<Vec<u8>>, pub sig_algs: Vec<u16>, pub supported_versions: Vec<u16> }`
  - `pub fn parse_client_hello(buf: &[u8]) -> Hello` where `pub enum Hello { Incomplete, Invalid, Done { hello: ClientHello, consumed: usize } }` — `buf` is the raw TCP byte stream starting at the first TLS record; reassembles the handshake across records; `raw` = the full TLS records consumed (what the client sent).
  - `pub fn ja4(h: &ClientHello) -> String`
  - `pub enum Proxy { Incomplete, Invalid, Done { src: Option<SocketAddr>, consumed: usize } }` and `pub fn parse_proxy(buf: &[u8]) -> Proxy` (v1 `PROXY TCP4|TCP6|UNKNOWN …\r\n` ≤ 107 bytes; v2 signature `\r\n\r\n\0\r\nQUIT\n`, ver 2, cmd LOCAL → `src: None`, PROXY with AF_INET/AF_INET6 STREAM → src; length ≤ 16 + 216 else Invalid).
  - `pub struct Tee<S> { inner: S, buf: Arc<Mutex<Vec<u8>>>, cap: usize }` implementing `AsyncRead + AsyncWrite` (copies bytes read into `buf` until `cap`), `pub type HeadBuf = Arc<Mutex<Vec<u8>>>`, and `pub fn head_of(buf: &[u8]) -> Option<&[u8]>` (bytes through the first `\r\n\r\n`).

JA4 (FoxIO): `t` + version + `d|i` (SNI ext present) + 2-digit cipher count + 2-digit extension count (both without GREASE, capped 99) + ALPN code; `_` + first 12 hex of sha256 of sorted 4-hex ciphers joined by `,` (or `000000000000` when none); `_` + first 12 hex of sha256 of (sorted extensions without GREASE, 0x0000 and 0x0010, joined by `,`) + (`_` + sig algs in order joined by `,`, only when there are any) (or `000000000000` when no extensions). Version: highest non-GREASE of `supported_versions`, else `legacy_version`; map 0x0304 `13`, 0x0303 `12`, 0x0302 `11`, 0x0301 `10`, 0x0300 `s3`, 0x0002 `s2`, else `00`. ALPN code: `00` if none; else first and last char of the first value if both are ASCII alphanumeric; otherwise first char of the hex of its first byte + last char of the hex of its last byte. GREASE: `v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff`.

- [ ] **Step 1: Failing tests.** Build a ClientHello in the test with a small builder (record header `16 03 01 len`, handshake `01 len24`, legacy version 0x0303, 32-byte random, session id len 0, ciphers `[0x1a1a GREASE, 0x1301, 0x1302, 0xc02b]`, compression `01 00`, extensions: GREASE `0x0a0a`, SNI `0x0000` (`example.com`), ALPN `0x0010` (`h2`, `http/1.1`), sig algs `0x000d` (`0403, 0804, 0401`), supported versions `0x002b` (`1a1a, 0304, 0303`), supported groups `0x000a`).

```rust
#[test]
fn ja4_of_a_built_hello() {
    let raw = build_hello();
    let Hello::Done { hello, consumed } = parse_client_hello(&raw) else { panic!() };
    assert_eq!(consumed, raw.len());
    let b = sha12("1301,1302,c02b");
    let c = sha12("000a,000d,002b_0403,0804,0401");
    assert_eq!(ja4(&hello), format!("t13d0305h2_{b}_{c}"));
}
#[test] fn split_across_records_and_segments() { /* same hello split into two TLS records; parse every prefix → Incomplete until full */ }
#[test] fn garbage_is_invalid() { assert!(matches!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Hello::Invalid)); }
#[test] fn alpn_non_alnum_uses_hex() { /* first ALPN value [0xab, 0x01] → "a1" */ }
#[test] fn proxy_v1_v2_local_and_garbage() { /* v1 TCP4 → src; v1 truncated → Incomplete; v2 LOCAL → None; v2 TCP6 → src; "PROXY BOGUS\r\n" → Invalid */ }
#[test] fn head_of_cuts_after_blank_line() { assert_eq!(head_of(b"GET / HTTP/1.1\r\nA: b\r\n\r\nbody"), Some(&b"GET / HTTP/1.1\r\nA: b\r\n\r\n"[..])); }
#[tokio::test] async fn tee_copies_up_to_cap() { /* tokio::io::duplex; read 10 bytes through Tee with cap 4 → buf has 4 */ }
```

(`sha12(s)` = first 12 hex chars of sha256 via `sha2`.) Extension count in `t13d0305`: GREASE removed → SNI, ALPN, sig algs, versions, groups = 5. Cipher count 3.

- [ ] **Step 2:** `cargo test --lib trap::` → fails.
- [ ] **Step 3: Implement** the three modules (bounds-checked cursor parsing, never panicking on any input; ClientHello reassembly stops with `Invalid` past 16 KiB).
- [ ] **Step 4:** pass. Add a fuzz-ish test: every prefix and every single-byte mutation of the built hello parses without panic.
- [ ] **Step 5: Commit** `feat(trap): ClientHello/JA4, PROXY protocol and raw head parsers`.

---

### Task 6: TLS trap listener, PROXY, raw head capture

**Files:**
- Modify: `src/config.rs` (`trap_tls_listen: Option<SocketAddr>`, `trap_tls_cert: Option<PathBuf>`, `trap_tls_key: Option<PathBuf>`; validation: TLS listen needs listener role; cert and key both or neither; add to the settings key table near `("", "trusted_proxies", "[]")` if that table lists top-level keys)
- Modify: `src/lib.rs` (`start_listener`: bind the TLS listener too; `serve_trap` generalised)
- Create: `src/trap/listen.rs` (connection preparation: PROXY, ClientHello, TLS accept, `Tee`, `ConnMeta`)
- Modify: `src/trap/mod.rs` (`trap_handler` and `collect_handler`/`claim_handler` read `ConnMeta`)
- Test: `tests/capture.rs` (TLS + PROXY), using `tokio-rustls` client with a no-verify verifier

**Interfaces:**
- Consumes: Task 5 parsers.
- Produces:

```rust
/// What the connection showed, attached to every request on it.
#[derive(Clone, Debug, Default)]
pub struct ConnMeta {
    pub transport: &'static str,          // "http" | "https"
    pub proxied_src: Option<SocketAddr>,  // from a PROXY header
    pub via_proxy: bool,                  // peer is a trusted proxy
    pub client_hello: Option<Arc<Vec<u8>>>,
    pub ja4: Option<String>,
    pub head: raw_head::HeadBuf,
}
pub async fn serve_trap(listener: TcpListener, app: Router, tls: Option<Arc<rustls::ServerConfig>>, trusted: Arc<Vec<IpNet>>, shutdown: watch::Receiver<bool>)
pub fn trap_tls_config(cert: Option<&Path>, key: Option<&Path>) -> anyhow::Result<Arc<rustls::ServerConfig>> // self-signed for "localhost" via rcgen when None; ALPN h2, http/1.1
```

Per connection: if `tls` is Some and the peer is trusted → read until `parse_proxy` is Done (10 s, 232 bytes max), drop on Incomplete-at-limit/Invalid/`Proxy` missing; then read until `parse_client_hello` is Done (10 s, 16 KiB), drop on Invalid; compute JA4; wrap the stream in a reader that first yields the buffered ClientHello bytes (and anything read past it) then the socket (`tokio::io::AsyncReadExt::chain` over `std::io::Cursor` works for reads; for writes use a small `Prefixed<S>` struct implementing both); `tokio_rustls::TlsAcceptor::accept`; then `Tee` (cap 64 KiB) over the TLS stream. Plain listener: `Tee` over the TCP stream directly, `via_proxy` = peer in trusted. HTTP/1 `keep_alive(false)`. Insert `ConnMeta` into request extensions next to `ConnectInfo`. In `trap_handler`: client IP = `proxied_src` if set, else existing `client_ip(...)`; `raw_head = head_of(&meta.head.lock())` only when `parts.version < HTTP_2`; pass `transport`, `via_proxy`, `tls_client_hello`, `ja4` into the capture. Requests served by the router in tests without `ConnMeta` (axum::serve) get `None` for all.

- [ ] **Step 1: Failing integration tests** (`tests/capture.rs`), a `spawn_tls(extra)` helper that builds `TrapState::for_test`, binds two listeners and runs `peephole::serve_trap` (make it `pub`) with `trap_tls_config(None, None)`:

```rust
#[tokio::test]
async fn https_request_records_ja4_hello_and_raw_head() { /* rustls client, SNI "probe.test", GET /x over HTTP/1.1 with header "X-Mixed-Case: 1" → row: transport "https", ja4 starts with "t13d", tls_client_hello non-empty, raw_head contains "X-Mixed-Case: 1\r\n" */ }
#[tokio::test]
async fn proxy_header_from_trusted_peer_sets_the_source() { /* trusted 127.0.0.1: send "PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\n" then TLS → ips row 203.0.113.9 */ }
#[tokio::test]
async fn trusted_peer_without_proxy_header_is_dropped() { /* plain TLS from 127.0.0.1 when trusted → handshake fails, 0 requests */ }
#[tokio::test]
async fn plain_listener_records_raw_head() { /* raw TCP write "GET /a HTTP/1.1\r\nHost: x\r\nUser-AGENT: Q\r\n\r\n" → raw_head equals that, transport "http" */ }
```

- [ ] **Step 2:** fail.
- [ ] **Step 3: Implement.** Keep the existing slowloris bounds (header timeout, 120 s deadline, 2048 conns) for both listeners; the TLS listener shares the semaphore.
- [ ] **Step 4:** `cargo test --test capture --test roles_e2e --test integration` pass.
- [ ] **Step 5: Commit** `feat(trap): TLS listener with JA4, PROXY protocol and raw request heads`.

---

### Task 7: Export everything; remove the enrichment export

**Files:**
- Rewrite: `src/export/mod.rs` (wide `ExportRow`, CSV/JSONL writers, stream with two phases, mode)
- Rewrite: `src/export/parquet.rs` (typed schema, footer metadata)
- Modify: `src/store/mod.rs:407-500` (`export_page` wide; new `export_skipped_page`; `export_context(page)` bulk loads)
- Modify: `src/store/inspect.rs` (remove `intel_export`, `intel_log_page` if unused elsewhere)
- Modify: `src/intel/mod.rs` (`ProviderInfo.redistributable`)
- Modify: `src/admin/pages.rs` (remove `export_intel` route/handler, `INTEL_EXPORT_CAP`; `mode` param)
- Modify: `templates/admin_export.html`
- Test: `src/export/mod.rs` tests, `tests/integration.rs` export tests (adapt existing ones)

**Interfaces:**
- Consumes: Tasks 2–6 columns.
- Produces: `pub enum Mode { Full, Redistributable }`; `ExportFilter` unchanged plus `mode`; `pub struct ExportRow` with fields matching spec §5.1:

```rust
pub struct ExportRow {
    pub kind: &'static str, pub uid: String, pub node: String, pub ts_ms: i64,
    pub ip: String, pub method: String, pub path: String, pub query: Option<String>,
    pub http_version: Option<String>, pub host: Option<String>, pub user_agent: Option<String>,
    pub headers: Vec<(String, String)>, pub body: Option<Vec<u8>>, pub body_size: Option<i64>,
    pub body_truncated_at: Option<i64>, pub transport: Option<String>, pub via_proxy: Option<bool>,
    pub raw_head: Option<Vec<u8>>, pub tls_client_hello: Option<Vec<u8>>, pub ja4: Option<String>,
    pub answer: Option<String>, pub status: Option<i64>, pub unrecorded: i64, pub weight: i64,
    pub labels: Vec<String>, pub severity: Option<i64>, pub scan_level: Option<i64>, pub fp_claim: bool,
    pub country: Option<String>, pub asn: Option<i64>, pub asn_org: Option<String>, pub is_tor: Option<bool>,
    pub intel: serde_json::Value, pub scans: serde_json::Value, pub fingerprints: serde_json::Value,
}
```

Assembly per page (≤ 5000 rows): one query for the requests; then, for the page's distinct `ip_id`s and request uids, bulk queries (`WHERE ip IN (SELECT value FROM json_each(?))`): `ip_intel_log` (all lookups), scans + ports + job status (`scan_jobs.scanner`), raw XML decompressed with `zstd`, fingerprints by `request_uid` (event_blob decompressed, parsed as JSON when it parses, else base64), `fp_claims` existence per IP. Node names from `cluster::members::all` (as `export_intel` did). `unrecorded` = column, else old rows' `:unrecorded` pseudo-header. `http_version`/`host`/`body_truncated_at` from the `:version`/`:authority` pseudo-headers or `host`; `user_agent` from `user-agent`. Point-in-time geo: from the IP's `maxmind-geolite2` / `tor-exits` lookups, newest `fetched_at <= ts`, else the earliest. Redistributable: filter `intel` to providers with `redistributable`, set `country/asn/asn_org` to None.

Phase 2 (skipped): `kind = "skipped"`, `weight = 1`, only when no label/min_severity filter; keyset by `(ts_ms, rowid)`; `unrecorded = 0`; each batch's `dropped` goes on its last row as `unrecorded` with `weight = dropped + 1`, so weights sum to every answered request.

CSV: header row of every column; lists/JSON as JSON text, blobs base64 (`data_encoding::BASE64`), `csv_safe` on text fields, plus `message,datetime,timestamp_desc`. JSONL: same keys, Timesketch fields. Parquet: `ts` `Timestamp(Millisecond, Some("UTC"))`, `labels` `List<Utf8>`, `headers` `List<Struct<name: Utf8, value: Utf8>>`, blobs `Binary`, JSON columns `Utf8`, booleans/ints typed, dictionary encoding on (writer default), ZSTD compression (`parquet` feature `zstd` — add to Cargo.toml), footer key-values per spec §5.1.

- [ ] **Step 1: Failing tests:**

```rust
#[tokio::test]
async fn export_carries_every_field_and_both_kinds() {
    // store: one request with all new columns, an intel lookup per provider (maxmind, tor, abuseipdb),
    // a scan with ports and xml, a fingerprint, an fp claim; one skip batch with 2 rows + dropped 3.
    // CSV: header has every column name in spec order; 3 data rows; the request row's intel JSON has 3 entries;
    // weights sum = 1 + 1 + (3 + 1) = 6.
    // JSONL: same, with datetime/timestamp_desc.
    // Parquet: read back with parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder; 3 rows; ts type;
    // footer metadata peephole.format_version == "1".
}
#[tokio::test]
async fn label_filter_leaves_out_skipped_rows() { /* … */ }
#[tokio::test]
async fn redistributable_drops_restricted_providers() { /* intel only tor-exits; country/asn empty; no "abuseipdb" substring in any format */ }
```

Delete the tests of the removed intel export; `GET /admin/export/intel` now 404s (assert it in the admin integration test that covered it).

- [ ] **Step 2:** fail.
- [ ] **Step 3: Implement.** Export page: format select, mode select (`full` / `redistributable` with one sentence each), no row cap text; remove the enrichment section.
- [ ] **Step 4:** `cargo test` (whole suite) passes.
- [ ] **Step 5: Commit** `feat(export): one export with every field; redistributable mode`.

---

### Task 8: nginx stream layout, installer, docs

**Files:**
- Modify: `install.sh` (`nginx_example` → two outputs: http sites and the stream config; nginx setup installs `libnginx-mod-stream` when `apt-cache show` has it, writes `/etc/nginx/peephole-stream.conf`, appends `include /etc/nginx/peephole-stream.conf;` to `/etc/nginx/nginx.conf` once (grep -q first), sets `trap_tls_listen = "127.0.0.1:8081"` for local-proxy nodes and `0.0.0.0:443`-style direct listening only when the operator says there is no proxy)
- Modify: `deploy/nginx.example.conf` (regenerated), new `deploy/nginx-stream.example.conf`
- Modify: `deploy/config.example.toml` (TLS listener keys; drop the other proxy product's name)
- Modify: `README.md` ("How it fits" diagram: `internet ──► reverse proxy (nginx)`; feature bullet for JA4/raw heads/light rows/export), `docs/operations.md` (stream setup, manual steps, replace the other-proxy paragraph → "Behind any other reverse proxy: forward unknown TLS names untouched to `trap_tls_listen` with the PROXY protocol, and list it in `trusted_proxies`"), `src/trap/mod.rs:165,779` comments (say "a proxy that appends")
- Test: `tests/deploy-check.sh` (example equality), `tests/install-smoke.sh` (nginx -t with stream)

Stream config (listener+web node):

```nginx
# Port 443 by server name, without decrypting (ssl_preread): the admin
# domain to nginx's admin site, every other name to the peephole trap, which
# reads the TLS handshake itself (JA4) and gets the client address through
# the PROXY protocol.
stream {
    map $ssl_preread_server_name $peephole_upstream {
        ${PEEPHOLE_DOMAIN} 127.0.0.1:8444;
        default            127.0.0.1:${trap_tls_port};
    }
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass $peephole_upstream;
        proxy_protocol on;
    }
}
```

Admin server block: `listen 127.0.0.1:8444 ssl proxy_protocol; http2 on;` (with the existing comment adapted), `set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`, and `X-Forwarded-For $proxy_protocol_addr`. The `ssl_reject_handshake` block and both commented self-signed alternatives are removed. Listener-only node: the map has only `default`.

- [ ] **Step 1:** Update `tests/deploy-check.sh` expectations first (stream example equals `install.sh --nginx-stream-example` output) → fails.
- [ ] **Step 2:** Implement installer and examples; `shellcheck install.sh` (via the container per memory `installer-smoke-local`).
- [ ] **Step 3:** Run `tests/deploy-check.sh` and the podman smoke test (`tests/install-smoke.sh`, ubuntu:26.04) → `nginx -t` passes with the stream module.
- [ ] **Step 4:** the product-name grep over the repo (outside target/ and older design docs) → no hits.
- [ ] **Step 5: Commit** `feat(install): pass TLS through to the trap; docs`.

---

### Task 9: Whole-branch verification

- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
- [ ] Local e2e per memory `local-e2e-setup` (fixture GeoIP + fake nmap; avoid ports 18080/18443): run the binary with both trap listeners, send an HTTPS probe with `openssl s_client`/curl `-k`, a flood, then download each export format and inspect.
- [ ] Spec coverage re-read; then PR per memory `release-ritual`.
