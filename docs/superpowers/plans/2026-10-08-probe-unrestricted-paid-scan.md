# Unrestricted Probes and a Paid Scan Action — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the probe's port cap, 24 h cooldown, evidence and counter-scan requirements (with a well-known-port fallback), and add a buyable level 1–4 counter-scan to the Actions card, priced `cheapest × 4^(level-1)`, with a 24 h exact-level cache and live job states on the IP page.

**Architecture:** Probes keep their gate minus the removed checks; the port list comes from the latest finished scan or a built-in well-known set. Bought scans reuse the existing scan market: a `manual` marker on the replicated `ScanJobRec` lets every scanner skip its evidence re-check (the safety preflight is untouched), the arbiter funds manual jobs at the level-scaled price, and the admin posts through a new route that enqueues via `Recorder::enqueue_manual`. A per-IP SSE stream (cloned from the probes stream) reloads the IP page when job states change.

**Tech Stack:** Rust, axum, sqlx/SQLite, askama templates, tokio; tests with `cargo test --lib`.

**Spec:** `docs/superpowers/specs/2026-10-08-probe-unrestricted-paid-scan-design.md`

## Global Constraints

- Schema changes are a new migration file only, appended to `MIGRATIONS`; never edit a shipped one.
- Every record field added to an existing struct is `#[serde(default)]` (and `skip_serializing_if` when optional) so older peers decode and older signed entries rebuild byte for byte.
- Credit payment for probes and scans stays. All safety checks stay: non-global addresses, `never_scan`, safety lists, Tor exits, verified crawlers (probe gate and scan preflight alike). Never touch `Source::preflight` (`src/scan/mod.rs:387-445`).
- Timeouts stay: 10 s per connection, 120 s per probe, scan pace timeouts.
- `docs/superpowers/plans/*` and older specs are historical; never edit them.
- Commit after every task. Commit message style follows the log, e.g. "Probes: read every open port, uncapped".

---

### Task 1: A probe reads every open port

**Files:**
- Modify: `src/scan/probe/mod.rs` (delete `MAX_PORTS` at line 29-30 and `ports.truncate(MAX_PORTS)` at line 267)
- Modify: `src/scan/probe/serve.rs:195` (drop `.take(super::MAX_PORTS)`)
- Modify: `src/store/probes.rs:19` (peer-record validation bound 16 → 1024)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: no new names. Later tasks rely on `run_probe` recording one `ProbePortRec` per port in `Target.ports`, however many.

- [ ] **Step 1: Write the failing tests**

In `src/scan/probe/mod.rs`'s `mod tests`, add:

```rust
    #[tokio::test]
    async fn a_probe_reads_every_open_port_not_just_the_first_sixteen() {
        // 17 closed ports: each is recorded, none is truncated away.
        let ports: Vec<u16> = (0..17)
            .map(|_| {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let p = l.local_addr().unwrap().port();
                drop(l);
                p
            })
            .collect();
        let t = Target {
            ip: "127.0.0.1".parse().unwrap(),
            ports: ports.iter().map(|p| (*p, None)).collect(),
        };
        let out = run_probe(&t, &|_| None).await;
        assert_eq!(out.ports.len(), 17);
    }
```

In `src/store/probes.rs`'s `mod tests`, add:

```rust
    #[tokio::test]
    async fn a_peer_may_send_more_than_sixteen_ports() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut r = rec("203.0.113.10", 7);
        r.ports = (0u16..17)
            .map(|i| ProbePortRec {
                port: 1000 + i,
                protocol: "banner".into(),
                outcome: "ok".into(),
                detail_json: "{}".into(),
            })
            .collect();
        let ctx = Ctx {
            origin: Some(&NodeId([7; 32])),
            hlc: 5,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(
            apply(&mut conn, ctx, &Record::ProbeResult(r))
                .await
                .unwrap(),
            Effect::Applied
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib scan::probe::tests::a_probe_reads_every store::probes::tests::a_peer_may_send`
Expected: the first test fails with `assert_eq!(out.ports.len(), 17)` getting 16; the second fails getting `Effect::Ignored`.

- [ ] **Step 3: Implement**

In `src/scan/probe/mod.rs`:

- Delete the `MAX_PORTS` constant and its doc comment (lines 29-30).
- In `run_probe`, delete `ports.truncate(MAX_PORTS);` and change the doc comment's first line to `/// Read the open ports of `t`, lowest-numbered first, one after another,`.

In `src/scan/probe/serve.rs`, in `run`'s panic path, delete the line `.take(super::MAX_PORTS)` so the `wanted.ports.iter()` chain goes straight to `.map(...)`.

In `src/store/probes.rs:19`, change:

```rust
const MAX_PORTS: usize = 16;
```

to:

```rust
const MAX_PORTS: usize = 1024;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib scan::probe store::probes`
Expected: PASS, all of them (the new two and every pre-existing probe test).

- [ ] **Step 5: Commit**

```bash
git add src/scan/probe/mod.rs src/scan/probe/serve.rs src/store/probes.rs
git commit -m "Probes: read every open port, no 16-port cap"
```

---

### Task 2: Probes without the 24 h cooldown

**Files:**
- Modify: `src/scan/probe/gate.rs` (delete the cooldown SQL block, lines 135-148; delete the import of `PROBE_COOLDOWN_HOURS` at line 7; replace the cooldown test at lines 296-320)
- Modify: `src/scan/probe/mod.rs:41-42` (delete `PROBE_COOLDOWN_HOURS`)
- Modify: `src/store/probes.rs` (delete `Store::probed_recently`, lines 320-333; reword the comment at lines 138-140; delete its assertions in the test at lines 394-405)
- Modify: `src/admin/probes.rs:539-541` (`this_node_only`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: no new names. `Store::probed_recently` no longer exists after this task.

- [ ] **Step 1: Write the failing test**

In `src/scan/probe/gate.rs`'s `mod tests`, replace `a_gate_enforces_the_24_hour_cooldown` with:

```rust
    #[tokio::test]
    async fn a_gate_allows_probing_the_same_address_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.22".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        // A probe of this address by this node finished a minute ago.
        sqlx::query(
            "INSERT INTO probes (uid, group_uid, ip_id, origin, hlc, asker, vantage_ip_source,
               started_at, finished_at, build)
             VALUES ('p1', 'g1', ?, ?, 0, ?, 'local', datetime('now'),
               datetime('now'), '')",
        )
        .bind(ip.id)
        .bind(&LOCAL.0[..])
        .bind(&LOCAL.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(gate.check(&store, None, &addr).await.is_ok());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib scan::probe::gate`
Expected: FAIL — `check` returns `Err("this node probed the address 0 h ago")`.

- [ ] **Step 3: Implement**

In `src/scan/probe/gate.rs`:

- Change line 7 to `use super::Target;`.
- Delete the whole cooldown block in `check` (from `let ago: Option<i64> = sqlx::query_scalar(` through the `if let Some(h) = ago { ... }`).
- Update the doc comment of `check`: its check list ends "...Tor exit; verified crawler. The ports are the latest finished scan's open ones." (drop "not probed by this node in 24 h").

In `src/scan/probe/mod.rs`, delete `PROBE_COOLDOWN_HOURS` and its doc comment (lines 41-42).

In `src/store/probes.rs`:

- Delete `Store::probed_recently` (the whole method, lines 320-333).
- Change the comment above `let origin = ...` in `apply_probe_result` to:

```rust
    // Standalone nodes have no origin: the asker stands in as the
    // probe's origin.
```

- In the test `a_probe_result_lands_in_probes_ports_and_host_keys`, delete both `probed_recently` assertion blocks (the `assert!(store.probed_recently(...))` and `assert!(!store.probed_recently(...))`).

In `src/admin/probes.rs`, change `this_node_only` to:

```rust
/// Reasons that concern this node only: in a cluster the other scanners
/// judge for themselves.
fn this_node_only(why: &str) -> bool {
    why == "probes are off on this node"
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib scan::probe store::probes admin::probes`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scan/probe/gate.rs src/scan/probe/mod.rs src/store/probes.rs src/admin/probes.rs
git commit -m "Probes: no 24-hour cooldown per address"
```

---

### Task 3: Probes without evidence or a finished counter-scan

**Files:**
- Modify: `src/scan/probe/mod.rs` (add `WELL_KNOWN_PORTS`)
- Modify: `src/scan/probe/gate.rs` (remove `PROBE_LEVEL`, the evidence check, `Gate::allowed_level`, the `classifier` field; port list with fallback; rewrite two tests; delete the `requests` helper)
- Modify: `src/scan/probe/serve.rs` (remove `Prober::allowed_level`; update tests that seed requests or expect "no finished counter-scan")
- Modify: `src/admin/probes.rs` (guard line without the evidence clause, with the fallback form; `state()` test helper gains a config parameter; rework two tests)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `pub const WELL_KNOWN_PORTS: [(u16, &str); 5]` in `crate::scan::probe`, used by the gate and by the admin guard line. `Gate::allowed_level` and `Prober::allowed_level` no longer exist. The gate tests' `requests` helper no longer exists — its remaining callers (serve.rs tests, admin/probes.rs tests) are updated in this task.

- [ ] **Step 1: Write the failing tests**

In `src/scan/probe/gate.rs`'s `mod tests`, replace `a_gate_needs_an_open_port_in_a_finished_scan` and `a_gate_refuses_thin_evidence_and_protected_addresses` with:

```rust
    #[tokio::test]
    async fn a_gate_reads_the_scans_open_ports_or_the_well_known_ones() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        let addr: IpAddr = "203.0.113.20".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        // Never scanned: the well-known fallback.
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports.len(), super::WELL_KNOWN_PORTS.len());
        assert_eq!(t.ports[0], (22, Some("ssh".to_string())));
        // A scan with only closed ports: still the fallback.
        scanned(&store, &ip.ip, &[(22, "closed", Some("ssh"))]).await;
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports.len(), super::WELL_KNOWN_PORTS.len());
        // An open port: the scan's.
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        let t = gate.check(&store, None, &addr).await.unwrap();
        assert_eq!(t.ports, [(22, Some("ssh".to_string()))]);
    }

    #[tokio::test]
    async fn a_gate_refuses_protected_addresses_but_not_thin_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let addr: IpAddr = "203.0.113.21".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        scanned(&store, &ip.ip, &[(22, "open", Some("ssh"))]).await;
        // No requests held at all: probed anyway.
        let gate = Gate::new(&config_with(dir.path(), ""), None);
        assert!(gate.check(&store, None, &addr).await.is_ok());
        let covered = Gate::new(
            &config_with(dir.path(), "never_scan = [\"203.0.113.0/24\"]"),
            None,
        );
        let err = covered.check(&store, None, &addr).await.unwrap_err();
        assert!(err.contains("never_scan"), "{err}");
    }
```

Delete the `requests` helper from gate's `mod tests` (it is `pub(crate)`; its other callers are updated below), and delete the `requests(&store, ip.id, 3, 2).await;` line from `a_gate_allows_probing_the_same_address_again` (added in Task 2 — thin evidence no longer holds a probe back).

In `src/scan/probe/serve.rs`'s tests, delete every `requests(&store, ip.id, 3, 2).await;` line (in `run_local_writes_a_probe_result_the_store_reads_back`, `this_nodes_own_request_needs_no_offer_and_charges_nothing`, `an_address_being_probed_is_not_probed_again_meanwhile`, `run_local_declines_when_the_gate_says_no`) and drop `requests` from the `use crate::scan::probe::gate::tests::{...}` import. Replace `run_local_declines_when_the_gate_says_no` with:

```rust
    #[tokio::test]
    async fn run_local_declines_when_the_gate_says_no() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let addr: IpAddr = "203.0.113.31".parse().unwrap();
        let ip = store.upsert_ip(addr).await.unwrap();
        let prober = Arc::new(Prober::new(
            &config_with(dir.path(), "never_scan = [\"203.0.113.31/32\"]"),
            None,
        ));
        let err = prober.run_local(&store, addr, "g1").await.unwrap_err();
        assert!(err.contains("never_scan"), "{err}");
        assert!(store.probes_for_ip(ip.id).await.unwrap().is_empty());
    }
```

In `src/admin/probes.rs`'s tests:

- Change `state`'s signature to `async fn state(scan: Option<u16>, extra: &str)` and add `{extra}` at the end of the `[scan]` TOML section (after `verify_crawlers = false`), with `extra = extra` next to the existing `db =`/`d =` format arguments. Update all existing callers: `state(None)` → `state(None, "")`, `state(Some(x))` → `state(Some(x), "")`. Delete the `requests(&store, ip.id, 3, 2).await;` line and drop `requests` from the `use crate::scan::probe::gate::tests::{...}` import.
- Replace `the_actions_card_explains_why_a_probe_is_unavailable` and add the fallback test:

```rust
    #[tokio::test]
    async fn the_actions_card_explains_why_a_probe_is_unavailable() {
        let (state, _c, _id, _d) = state(None, "never_scan = [\"203.0.113.40/32\"]").await;
        let a = actions_for(&state, &IP.parse().unwrap()).await;
        assert!(!a.allowed);
        let why = a.why_not.unwrap();
        assert!(why.contains("never_scan"), "{why}");
        assert!(a.guard_line.contains(&why));
    }

    #[tokio::test]
    async fn the_actions_card_announces_the_well_known_fallback() {
        let (state, _c, _id, _d) = state(None, "").await;
        let a = actions_for(&state, &IP.parse().unwrap()).await;
        assert!(a.allowed, "{:?}", a.why_not);
        assert_eq!(
            a.guard_line,
            "No open port known here; probing the 5 well-known ports"
        );
    }
```

- In `the_actions_card_offers_the_local_probe_standalone`, replace the `guard_line` assertion with:

```rust
        assert!(
            a.guard_line.starts_with("Counter-scan found 1 open port (")
                && !a.guard_line.contains("evidence"),
            "{}",
            a.guard_line
        );
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib scan::probe admin::probes`
Expected: compile errors first — `requests` is gone for serve/admin tests, `Gate` still has `classifier`/evidence — then the new gate test fails with "no finished counter-scan of this address here".

- [ ] **Step 3: Implement**

In `src/scan/probe/mod.rs`, add after the `MAX_REDIRECTS` constant:

```rust
/// The ports a probe reads when no counter-scan found any open: the
/// well-known ones, each with the service name `protocol_for` expects.
pub const WELL_KNOWN_PORTS: [(u16, &str); 5] = [
    (22, "ssh"),
    (80, "http"),
    (443, "https"),
    (8080, "http"),
    (8443, "https"),
];
```

In `src/scan/probe/gate.rs`:

- Replace the module doc (lines 1-6) with:

```rust
//! What must hold before this node probes an address: the same checks a
//! counter-scan obeys (non-global addresses, `never_scan`, the members'
//! and the operator's lists, Tor exits, verified crawlers). The ports read
//! are the open ones of the latest finished counter-scan, or the
//! well-known ones when there is none.
```

- Delete `use crate::classify::Classifier;`, the `PROBE_LEVEL` constant and its doc comment, the `classifier` field of `Gate`, the `classifier: Classifier::builtin(),` line in `Gate::new`, and the whole `allowed_level` method.
- In `check`, delete the evidence block (from `let ev = guard::evidence(...)` through the `if allowed < PROBE_LEVEL { ... }`) and replace everything from `let no_scan = ...` down to the end of the function with:

```rust
        let known: Vec<(u16, Option<String>)> = match store.ip_by_addr(&ip_text).await.map_err(internal)? {
            Some(row) => {
                let scans = store.scans_for_ip(row.id).await.map_err(internal)?;
                match scans
                    .iter()
                    .find(|s| s.finished_at.is_some() && s.audit_of.is_none())
                {
                    Some(scan) => store
                        .ports_for_scan(scan.id)
                        .await
                        .map_err(internal)?
                        .into_iter()
                        .filter(|p| p.state == "open" && p.proto == "tcp")
                        .filter_map(|p| Some((u16::try_from(p.port).ok()?, p.service)))
                        .collect(),
                    None => vec![],
                }
            }
            None => vec![],
        };
        let ports = match known.is_empty() {
            true => super::WELL_KNOWN_PORTS
                .iter()
                .map(|(p, s)| (*p, Some((*s).to_string())))
                .collect(),
            false => known,
        };
        Ok(Target { ip, ports })
```

- Update `check`'s doc comment: "The address and ports to probe, or the reason shown to the asker. Checks, in order: enabled; global address; `never_scan`; safety lists (members, own, peer-observed public); Tor exit; verified crawler. The ports are the latest finished scan's open ones, or the well-known ones."

In `src/scan/probe/serve.rs`, delete the `allowed_level` method (lines 157-160).

In `src/admin/probes.rs`, replace the body of `guard_line` from `let target = ...` to the end with:

```rust
    prober.check(&state.store, node, ip).await?;
    let found = async {
        let row = state.store.ip_by_addr(&ip.to_string()).await.ok()??;
        let scans = state.store.scans_for_ip(row.id).await.ok()?;
        let scan = scans
            .into_iter()
            .find(|s| s.finished_at.is_some() && s.audit_of.is_none())?;
        let ports = state.store.ports_for_scan(scan.id).await.ok()?;
        let n = ports
            .iter()
            .filter(|p| p.state == "open" && p.proto == "tcp")
            .count();
        Some((n, scan.finished_at.unwrap_or_default()))
    }
    .await;
    Ok(match found {
        Some((n, when)) if n > 0 => format!(
            "Counter-scan found {n} open port{} ({when})",
            if n == 1 { "" } else { "s" }
        ),
        _ => format!(
            "No open port known here; probing the {} well-known ports",
            crate::scan::probe::WELL_KNOWN_PORTS.len()
        ),
    })
```

(The `prober: &Prober = match ...` preamble above it stays unchanged.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib scan::probe admin::probes`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/scan/probe/mod.rs src/scan/probe/gate.rs src/scan/probe/serve.rs src/admin/probes.rs
git commit -m "Probes: no evidence or scan requirement; well-known-port fallback"
```

---

### Task 4: A `manual` marker on scan jobs

**Files:**
- Create: `src/store/migrations/0026_manual_scan_jobs.sql`
- Modify: `src/store/mod.rs:63` (append to `MIGRATIONS`)
- Modify: `src/cluster/record.rs:263-278` (`ScanJobRec` gains `manual`)
- Modify: `src/store/data.rs:678-694` (`scan_job` INSERT binds `manual`)
- Modify: `src/store/recorder.rs` (constructor at line 523, retry query + constructor at lines 797-846, new `enqueue_manual` after `enqueue_scan_with`)
- Modify: `src/cluster/adopt.rs:49-76` (the `scan_job` re-read carries `manual`)
- Modify: `src/store/data.rs:2130,2188,2424`, `tests/cluster.rs:2146`, `tests/cluster_limits.rs:130` (test constructors add `manual: false`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `ScanJobRec { ..., pub manual: bool }` (serde default, skipped when false).
  - `scan_jobs.manual INTEGER NOT NULL DEFAULT 0`.
  - `Recorder::enqueue_manual(&self, ip_id: i64, level: u8) -> anyhow::Result<crate::store::scans::EnqueueOutcome>` — queues a marked job with no cooldown, evidence or budget checks. Used by Tasks 5, 6, 7 and 8.

- [ ] **Step 1: Write the failing test**

In `src/store/recorder.rs`'s `mod tests`, add:

```rust
    #[tokio::test]
    async fn a_manual_job_ignores_the_cooldown_and_is_marked() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let ip = store
            .upsert_ip("203.0.113.60".parse().unwrap())
            .await
            .unwrap();
        // Two jobs at the same level right away: the automatic queue's
        // cooldown would suppress the second.
        let first = rec.enqueue_manual(ip.id, 2).await.unwrap();
        assert!(matches!(first, EnqueueOutcome::Queued(_)));
        let second = rec.enqueue_manual(ip.id, 2).await.unwrap();
        assert!(matches!(second, EnqueueOutcome::Queued(_)));
        let manual: i64 = sqlx::query_scalar("SELECT manual FROM scan_jobs WHERE ip_id = ?")
            .bind(ip.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(manual, 1);
    }
```

(If `EnqueueOutcome` is not already in scope in the tests module, add `use crate::store::scans::EnqueueOutcome;`.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib store::recorder`
Expected: FAIL to compile — `enqueue_manual` and the `manual` column do not exist.

- [ ] **Step 3: Implement**

Create `src/store/migrations/0026_manual_scan_jobs.sql`:

```sql
-- A scan an admin bought from the Actions card: the scanners skip their
-- evidence re-check for it (the safety preflight still applies) and the
-- arbiter funds it at the level-scaled price.
ALTER TABLE scan_jobs ADD COLUMN manual INTEGER NOT NULL DEFAULT 0;
```

In `src/store/mod.rs`, append after the `0025_rdns.sql` line in `MIGRATIONS`:

```rust
    include_str!("migrations/0026_manual_scan_jobs.sql"),
```

In `src/cluster/record.rs`, add to `ScanJobRec`, after `failed_by`:

```rust
    /// Bought by an admin from the Actions card: the evidence rule does
    /// not apply (the safety preflight does); funded at the level-scaled
    /// price (`credits::jobs::level_factor`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manual: bool,
```

In `src/store/data.rs`'s `scan_job`, change the INSERT to:

```rust
    sqlx::query(
        "INSERT OR IGNORE INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at,
                                          retry_of, retry_at, failed_by, manual)
         VALUES (?,?,?,?,?,?,'queued',?,?,?,?,?)",
    )
```

with `.bind(r.manual)` appended after the `failed_by` bind.

In `src/store/recorder.rs`:

- In `enqueue_scan_with`'s `ScanJobRec` literal, add `manual: false,`.
- In `retry_failed`, extend the job query type to
  `type Job = (i64, String, i64, String, Option<String>, Option<String>, i64);`
  and the SQL to `SELECT j.ip_id, i.ip, j.level, j.status, j.error, j.retry_of, j.manual`,
  destructure `let Some((ip_id, ip, level, status, error, retry_of, manual)) = job else { ... }`,
  and add `manual: manual != 0,` to the retry's `ScanJobRec` literal.
- Add after `enqueue_scan_with`:

```rust
    /// A scan an admin bought on the Actions card: queued without the
    /// cooldown, evidence or budget checks (those are the automatic
    /// queue's); the marker lets every scanner skip its evidence
    /// re-check and the arbiter fund it at the level-scaled price.
    pub async fn enqueue_manual(&self, ip_id: i64, level: u8) -> Result<EnqueueOutcome> {
        if !(1..=4).contains(&level) {
            return Ok(EnqueueOutcome::Suppressed);
        }
        let ip_text = self.ip_of(ip_id).await?;
        let uid = self.uid();
        self.write(vec![Record::ScanJob(ScanJobRec {
            uid: uid.clone(),
            ip: ip_text,
            level: level as i64,
            queued_at: now_ts(),
            retry_of: None,
            retry_at: None,
            failed_by: None,
            manual: true,
        })])
        .await?;
        Ok(EnqueueOutcome::Queued(
            self.id_by_uid("scan_jobs", &uid).await?,
        ))
    }
```

In `src/cluster/adopt.rs`'s `"scan_job"` arm, extend `Row` with a seventh element `i64`, add `j.manual` to the SELECT, destructure it, and set `manual: manual != 0,` in the `ScanJobRec` literal.

In the test constructors (`src/store/data.rs:2130,2188,2424`, `tests/cluster.rs:2146`, `tests/cluster_limits.rs:130`), add `manual: false,` to each `ScanJobRec` literal.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib store:: cluster::`
Expected: PASS (including the schema-version tests, which read `MIGRATIONS.len()`).

- [ ] **Step 5: Commit**

```bash
git add src/store/migrations/0026_manual_scan_jobs.sql src/store/mod.rs src/cluster/record.rs src/store/data.rs src/store/recorder.rs src/cluster/adopt.rs tests/cluster.rs tests/cluster_limits.rs
git commit -m "Scans: a manual marker for bought scan jobs"
```

---

### Task 5: Scanners run manual jobs without evidence

**Files:**
- Modify: `src/scan/mod.rs:765-774` (the grant check's job-row read gains `j.manual`) and `src/scan/mod.rs:804-820` (the evidence check is skipped for manual jobs)

**Interfaces:**
- Consumes: Task 4's `scan_jobs.manual` column and `Recorder::enqueue_manual`.
- Produces: no new names. `check_grant_here` runs a grant whose replicated job row has `manual != 0` without consulting the evidence.

- [ ] **Step 1: Write the failing test**

In `src/scan/mod.rs`'s `mod tests`, add after `grants_need_requests_our_rules_put_at_the_level`:

```rust
    /// A bought (manual) job needs no evidence: the scanner's own rules
    /// never enter into it; the safety preflight still applies.
    #[tokio::test]
    async fn a_manual_grant_runs_without_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (node, source, store) = cluster_source(dir.path(), "").await;
        let rec = Recorder::Cluster(node.clone());
        let ip = store
            .upsert_ip("203.0.113.75".parse().unwrap())
            .await
            .unwrap();
        rec.enqueue_manual(ip.id, 4).await.unwrap();
        let uid = job_uid(&store, ip.id).await;
        let r = source
            .check_grant(node.id(), &grant(&uid, &ip.ip, 4))
            .await
            .unwrap();
        assert!(r.is_ok(), "a bought scan runs with no requests held");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib scan::tests::a_manual_grant`
Expected: FAIL — the grant is turned down `declined` ("no request here asks for level 4").

- [ ] **Step 3: Implement**

In `src/scan/mod.rs`'s `check_grant_here`, change the row read to:

```rust
        let row: Option<(String, i64, Option<Vec<u8>>, String, i64)> = sqlx::query_as(
            "SELECT i.ip, j.level, j.arbiter, j.queued_at, j.manual FROM scan_jobs j
             JOIN ips i ON i.id = j.ip_id WHERE j.uid = ?",
        )
        .bind(&g.job_uid)
        .fetch_optional(pool)
        .await?;
        let Some((ip_text, job_level, job_arbiter, queued_at, manual)) = row else {
            return Ok(Err(("later", Some(NOT_REPLICATED.into()))));
        };
```

and wrap the evidence block:

```rust
        // A bought (manual) job skips the evidence rule; the preflight's
        // safety checks below apply to it all the same.
        if manual == 0 {
            let ev = guard::evidence(pool, &ip_text, &self.origins, Some(self.classifier)).await?;
            let allowed = ev.allowed_level(&self.cfg.scan.safety);
            if allowed < level {
                if ev.max_level < level {
                    let why = format!(
                        "no request here asks for level {level} (highest: {})",
                        ev.max_level
                    );
                    return Ok(Err(("declined", Some(why))));
                }
                // More requests may still arrive or replicate here.
                let why = format!(
                    "level {level} needs more evidence ({} request(s); thin evidence allows {allowed})",
                    ev.requests
                );
                return Ok(Err(("later", Some(why))));
            }
        }
```

(The block's body is unchanged; only the `if manual == 0 {` wrapper is new.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib scan::`
Expected: PASS — the new test and every pre-existing grant test (unmarked jobs are still declined on thin evidence).

- [ ] **Step 5: Commit**

```bash
git add src/scan/mod.rs
git commit -m "Scans: bought jobs skip the evidence re-check, never the preflight"
```

---

### Task 6: Level-scaled funding for manual jobs

**Files:**
- Modify: `src/credits/jobs.rs` (new `level_factor`, after `price_for` at line 80)
- Modify: `src/scan/arbiter.rs:326-337` (`next_job_for` scales the price of manual jobs)

**Interfaces:**
- Consumes: Task 4's `scan_jobs.manual`.
- Produces: `pub fn crate::credits::jobs::level_factor(level: i64) -> u32` — `4^(level-1)`, i.e. 1, 4, 16, 64 for levels 1–4. Also used by the admin's price display and budget check (Task 7).

- [ ] **Step 1: Write the failing tests**

In `src/credits/jobs.rs`'s `mod tests`, add:

```rust
    #[test]
    fn the_level_factor_is_four_to_the_level_minus_one() {
        assert_eq!(level_factor(1), 1);
        assert_eq!(level_factor(2), 4);
        assert_eq!(level_factor(3), 16);
        assert_eq!(level_factor(4), 64);
    }
```

In `src/scan/arbiter.rs`'s `mod tests`, add after `an_own_job_is_funded_by_a_reservation_not_an_offer`:

```rust
    /// A bought (manual) job is funded at the scanner's price times
    /// 4^(level-1) — level 3 at 16 times.
    #[tokio::test]
    async fn a_manual_job_is_funded_at_the_level_scaled_price() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        give_credits(&store, node.id()).await;
        node.set_scan_share(1.0);
        selling(&node, 300);
        let ip = store
            .upsert_ip("203.0.113.98".parse().unwrap())
            .await
            .unwrap();
        Recorder::Cluster(node.clone())
            .enqueue_manual(ip.id, 3)
            .await
            .unwrap();
        let g = arbiter
            .next_job_for(&mut Default::default(), node.id(), &[], 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 300 * 16));
        assert_eq!(self_mc(&store, &g.job_uid).await, Some(300 * 16));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib credits::jobs::tests::the_level_factor scan::arbiter::tests::a_manual_job`
Expected: FAIL to compile (`level_factor` missing), then the arbiter test fails getting `price_mc` 300.

- [ ] **Step 3: Implement**

In `src/credits/jobs.rs`, add after `price_for`:

```rust
/// The factor a bought (manual) job's level scales its funding price by:
/// 4^(level-1) — level 1 at the scanner's price, level 4 at 64 times it.
pub fn level_factor(level: i64) -> u32 {
    1u32
        .checked_shl(2 * level.clamp(1, 4) as u32 - 2)
        .unwrap_or(u32::MAX)
}
```

In `src/scan/arbiter.rs`'s `next_job_for`, replace:

```rust
        let price = crate::credits::jobs::price_for(&self.node, &scanner);
```

with:

```rust
        let manual: i64 = sqlx::query_scalar("SELECT manual FROM scan_jobs WHERE uid = ?")
            .bind(&g.job_uid)
            .fetch_one(&self.node.store.pool)
            .await?;
        let price = crate::credits::jobs::price_for(&self.node, &scanner).map(|p| match manual {
            0 => p,
            _ => p.saturating_mul(crate::credits::jobs::level_factor(g.level)),
        });
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib credits::jobs scan::arbiter`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/credits/jobs.rs src/scan/arbiter.rs
git commit -m "Scans: bought jobs are funded at the level-scaled price"
```

---

### Task 7: The Actions card sells scans

**Files:**
- Create: `src/admin/scan_buy.rs`
- Modify: `src/admin/mod.rs` (`pub mod scan_buy;` with the other modules, line 21 area; `.merge(scan_buy::routes())` after `.merge(probes::routes())` at line 172)
- Modify: `src/admin/probes.rs` (`ActionsView` gains `scans`; `actions_for` populates it)
- Modify: `templates/_actions.html` (the Scan section)

**Interfaces:**
- Consumes: Task 4's `Recorder::enqueue_manual`, Task 6's `crate::credits::jobs::level_factor`.
- Produces:
  - `crate::admin::scan_buy::ScanOffer { pub level: u8, pub price: String, pub fresh: Option<String> }` — `price` is `"from {amount} credits"`, `"free"` standalone, `""` when no scanner announces a price; `fresh` is the finish date of an exact-level scan under 24 h old.
  - `pub async fn crate::admin::scan_buy::offers_for(state: &AdminState, ip_id: i64) -> Vec<ScanOffer>` (levels 1–4, in order).
  - `pub fn crate::admin::scan_buy::routes() -> Router<Arc<AdminState>>` serving `POST /admin/lookup/scan` (Task 8 adds `GET /admin/api/scan-jobs` to it).
  - `ActionsView.scans: Vec<ScanOffer>`.

- [ ] **Step 1: Write the failing tests**

Create `src/admin/scan_buy.rs` with only this for now (the implementation lands in Step 3; the tests need the harness first):

```rust
//! Buying a counter-scan from the Actions card: `POST /admin/lookup/scan`.
//! The job goes through the normal queue (`Recorder::enqueue_manual`,
//! marked so the scanners skip their evidence re-check); its price grows
//! with its level (`credits::jobs::level_factor`). A finished scan of the
//! same level less than a day old is shown instead and costs nothing.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::AdminState;
    use crate::scan::probe::gate::tests::scanned;
    use std::sync::Arc;
    use tower::ServiceExt;

    pub(crate) const IP: &str = "203.0.113.40";

    /// A standalone admin; `IP` is in the dataset.
    pub(crate) async fn state() -> (Arc<AdminState>, String, i64, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[scan]
tor_unknown = "scan"
verify_crawlers = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        let ip = store.upsert_ip(IP.parse().unwrap()).await.unwrap();
        let token = store.create_session().await.unwrap();
        let cookie = format!("{}={token}", crate::admin::auth::session_cookie_name(&cfg));
        (Arc::new(AdminState::public_only(store, cfg)), cookie, ip.id, dir)
    }

    pub(crate) fn post(cookie: &str, body: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::post("/admin/lookup/scan")
            .header("cookie", cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[test]
    fn the_fresh_window_is_24_hours() {
        let at = |h: i64| {
            (chrono::Utc::now() - chrono::Duration::hours(h))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };
        assert!(fresh_enough(&at(23)));
        assert!(!fresh_enough(&at(25)));
    }

    #[tokio::test]
    async fn standalone_offers_are_free_and_a_fresh_result_stands() {
        let (state, _c, ip_id, _d) = state().await;
        let offers = offers_for(&state, ip_id).await;
        assert_eq!(offers.len(), 4);
        assert!(offers.iter().all(|o| o.price == "free" && o.fresh.is_none()));
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let offers = offers_for(&state, ip_id).await;
        let l2 = offers.iter().find(|o| o.level == 2).unwrap();
        assert!(l2.fresh.is_some(), "the level-2 scan just finished");
        assert!(offers.iter().filter(|o| o.level != 2).all(|o| o.fresh.is_none()));
    }

    #[tokio::test]
    async fn buying_a_scan_queues_a_marked_job_once() {
        let (state, cookie, ip_id, _d) = state().await;
        let app = crate::admin::full_router(state.clone());
        let r = app.clone().oneshot(post(&cookie, &format!("ip={IP}&level=2"))).await.unwrap();
        assert_eq!(r.status(), 303);
        let jobs: Vec<(i64, i64)> =
            sqlx::query_as("SELECT level, manual FROM scan_jobs WHERE ip_id = ?")
                .bind(ip_id)
                .fetch_all(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(jobs, vec![(2, 1)]);
        // Again at the same level while queued: no second job.
        let r = app.clone().oneshot(post(&cookie, &format!("ip={IP}&level=2"))).await.unwrap();
        assert_eq!(r.status(), 303);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ?")
            .bind(ip_id)
            .fetch_one(&state.store.pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Not a level.
        let r = app.oneshot(post(&cookie, &format!("ip={IP}&level=9"))).await.unwrap();
        assert_eq!(r.status(), 303);
        assert_eq!(r.headers()["location"], format!("/ip/{IP}#scans").as_str());
    }

    #[tokio::test]
    async fn a_fresh_exact_level_scan_is_not_bought_again() {
        let (state, cookie, ip_id, _d) = state().await;
        scanned(&state.store, IP, &[(80, "open", Some("http"))]).await;
        let app = crate::admin::full_router(state.clone());
        let r = app.oneshot(post(&cookie, &format!("ip={IP}&level=2"))).await.unwrap();
        assert_eq!(r.status(), 303);
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE ip_id = ? AND manual = 1")
                .bind(ip_id)
                .fetch_one(&state.store.pool)
                .await
                .unwrap();
        assert_eq!(n, 0, "the fresh level-2 result stands");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib admin::scan_buy`
Expected: FAIL to compile — `offers_for` and the route do not exist.

- [ ] **Step 3: Implement**

Replace the file header of `src/admin/scan_buy.rs` (keeping the tests module below it) with the full implementation:

```rust
//! Buying a counter-scan from the Actions card: `POST /admin/lookup/scan`.
//! The job goes through the normal queue (`Recorder::enqueue_manual`,
//! marked so the scanners skip their evidence re-check); its price grows
//! with its level (`credits::jobs::level_factor`). A finished scan of the
//! same level less than a day old is shown instead and costs nothing.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::AppResult;
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::scan::valid_level;
use crate::store::scans::EnqueueOutcome;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    response::Response,
    routing::post,
};
use std::net::IpAddr;
use std::sync::Arc;

/// A scan of an address this fresh needs no buying: the result stands.
pub const FRESH_HOURS: i64 = 24;

/// One level's offer on the Actions card.
pub struct ScanOffer {
    pub level: u8,
    /// "from 1.23 credits" in a cluster, "free" standalone; empty when no
    /// live scanner announces a price.
    pub price: String,
    /// A finished scan of exactly this level under [`FRESH_HOURS`] old
    /// (its finish date): no new scan is sold.
    pub fresh: Option<String>,
}

/// Whether `ts` (a store timestamp) is less than [`FRESH_HOURS`] old.
fn fresh_enough(ts: &str) -> bool {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(FRESH_HOURS))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    ts > cutoff.as_str()
}

/// The four levels' offers for `ip_id`.
pub async fn offers_for(state: &AdminState, ip_id: i64) -> Vec<ScanOffer> {
    let scans = state.store.scans_for_ip(ip_id).await.unwrap_or_default();
    let node = state.recorder.node();
    let cheapest = node.and_then(|n| n.price_table().scanners.iter().map(|s| s.price_mc).min());
    (1u8..=4)
        .map(|level| {
            let fresh = scans
                .iter()
                .filter(|s| {
                    s.level == level as i64 && s.audit_of.is_none()
                })
                .filter_map(|s| s.finished_at.clone())
                .find(|f| fresh_enough(f));
            let price = match (node.is_some(), cheapest) {
                (false, _) => "free".into(),
                (true, Some(c)) => format!(
                    "from {} credits",
                    crate::credits::show(
                        c as u64 * crate::credits::jobs::level_factor(level as i64) as u64
                    )
                ),
                (true, None) => String::new(),
            };
            ScanOffer { level, price, fresh }
        })
        .collect()
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/lookup/scan", post(buy))
}

/// The form: the address and the level.
#[derive(Debug, Default)]
struct BuyForm {
    ip: String,
    level: String,
}

impl BuyForm {
    fn parse(body: &[u8]) -> Self {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).unwrap_or_default();
        let mut f = Self::default();
        for (k, v) in pairs {
            match k.as_str() {
                "ip" => f.ip = v,
                "level" => f.level = v,
                _ => {}
            }
        }
        f
    }
}

/// POST /admin/lookup/scan: queue a marked job, then back to the IP
/// page's Counter-scans section. A job of this level already on its way,
/// or a fresh result of it, sells nothing.
async fn buy(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    body: Bytes,
) -> AppResult<Response> {
    let form = BuyForm::parse(&body);
    let Ok(ip) = form.ip.trim().parse::<IpAddr>() else {
        return Ok(redirect_with_error("/admin/lookup", "Not an IP address."));
    };
    let ip = crate::net::canonical(ip);
    let back = format!("/ip/{ip}#scans");
    let Some(level) = form.level.parse::<i64>().ok().and_then(valid_level) else {
        return Ok(redirect_with_error(&back, "No scan: not a scan level."));
    };
    let Some(row) = state.store.ip_by_addr(&ip.to_string()).await? else {
        return Ok(redirect_with_error(
            &format!("/admin/lookup?ip={ip}"),
            "No scan: the address is not in the dataset.",
        ));
    };
    let jobs = state.store.jobs_for_ip(row.id, 20).await?;
    if jobs
        .iter()
        .any(|j| j.level == level as i64 && matches!(j.status.as_str(), "queued" | "running"))
    {
        return Ok(redirect_with_notice(
            &back,
            &format!("A level {level} scan of this address is already on its way."),
        ));
    }
    let fresh = offers_for(&state, row.id)
        .await
        .into_iter()
        .find(|o| o.level == level)
        .and_then(|o| o.fresh);
    if let Some(fresh) = fresh {
        return Ok(redirect_with_notice(
            &back,
            &format!("No new scan: the level {level} scan of {fresh} is less than a day old."),
        ));
    }
    // In a cluster the scan budget must cover the level-scaled cheapest
    // price; otherwise the job would silently run unfunded.
    if let Some(node) = state.recorder.node() {
        let Some(cheapest) = node.price_table().scanners.iter().map(|s| s.price_mc).min() else {
            return Ok(redirect_with_error(
                &back,
                "No scan: no live scanner announces a price.",
            ));
        };
        let price = cheapest as u64 * crate::credits::jobs::level_factor(level as i64) as u64;
        let book = crate::credits::book(node).await?;
        let self_mc = crate::credits::jobs::self_committed(&state.store.pool, &node.id()).await?;
        let left =
            crate::credits::jobs::budget(&book.ledger, &node.id(), node.scan_share(), self_mc);
        if (left as u64) < price {
            return Ok(redirect_with_error(
                &back,
                "No scan: the scan budget does not cover this.",
            ));
        }
    }
    match state.recorder.enqueue_manual(row.id, level).await? {
        EnqueueOutcome::Queued(id) => {
            if let Ok(Some(job)) = state.store.queue_job(id).await {
                state.notifier.publish(job);
            }
            Ok(redirect_with_notice(
                &back,
                &format!("Level {level} scan queued; the result appears below when it is in."),
            ))
        }
        _ => Ok(redirect_with_error(&back, "No scan: the job was not queued.")),
    }
}
```

In `src/admin/mod.rs`, add `pub mod scan_buy;` to the module list (alphabetical, after `pub mod scans;`) and add `.merge(scan_buy::routes())` after `.merge(probes::routes())` in `full_router`.

In `src/admin/probes.rs`:

- Add to `ActionsView`, after `pub standalone: bool,`:

```rust
    /// The four scan levels' offers (`admin::scan_buy`).
    pub scans: Vec<crate::admin::scan_buy::ScanOffer>,
```

- In `actions_for`, add before the `ActionsView { ... }` literal:

```rust
    let scans = match state.store.ip_by_addr(&ip.to_string()).await {
        Ok(Some(row)) => crate::admin::scan_buy::offers_for(state, row.id).await,
        _ => vec![],
    };
```

  and add `scans,` to the literal.

In `templates/_actions.html`, add inside the `<section>`, after the probe `</form>`:

```html
  <form method="post" action="/admin/lookup/scan">
    <input type="hidden" name="ip" value="{{ t.ov.ip.ip }}">
    <p class="muted small">Counter-scan this address now{% if a.standalone %}, from this node{% endif %}. A result of the same level less than a day old costs nothing.</p>
    <p>
      {% for o in a.scans %}
      {% if let Some(f) = o.fresh %}
      <button class="btn" type="button" disabled title="Level {{ o.level }} finished {{ f }}: fresh results cost nothing">L{{ o.level }}</button>
      {% else if o.price.is_empty() %}
      <button class="btn" type="button" disabled title="No live scanner announces a price">L{{ o.level }}</button>
      {% else %}
      <button class="btn" type="submit" name="level" value="{{ o.level }}">L{{ o.level }} · {{ o.price }}</button>
      {% endif %}
      {% endfor %}
    </p>
  </form>
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib admin::`
Expected: PASS (the three new tests and every pre-existing admin test).

- [ ] **Step 5: Commit**

```bash
git add src/admin/scan_buy.rs src/admin/mod.rs src/admin/probes.rs templates/_actions.html
git commit -m "Admin: the Actions card sells counter-scans of level 1-4"
```

---

### Task 8: Live job states on the IP page

**Files:**
- Modify: `src/admin/scan_buy.rs` (SSE endpoint `GET /admin/api/scan-jobs`, `states_json`, `any_waiting`; route added to `routes()`)
- Modify: `src/admin/target.rs` (`Target::scan_states`, `Target::scans_waiting`)
- Modify: `templates/_target.html:19` (stream wiring on the Counter-scans card)
- Modify: `assets/js/app.js` (reload on `scan-jobs` events, after the probes block at lines 324-333)

**Interfaces:**
- Consumes: `crate::events::QueueJob` (fields `id`, `status`, `level` — `src/events.rs:5-21`), `Store::jobs_for_ip` (`src/store/inspect.rs:202-217`).
- Produces:
  - `pub fn crate::admin::scan_buy::states_json(jobs: &[crate::events::QueueJob]) -> String` — `[[id, status], ...]`.
  - `pub async fn crate::admin::scan_buy::any_waiting(store: &crate::store::Store, ip_id: i64) -> bool`.
  - `Target::scan_states(&self) -> String` and `Target::scans_waiting(&self) -> bool`, used by `templates/_target.html`.

- [ ] **Step 1: Write the failing tests**

In `src/admin/scan_buy.rs`'s `mod tests`, add:

```rust
    #[test]
    fn job_states_are_id_status_pairs() {
        let j = |id, status: &str| crate::events::QueueJob {
            id,
            ip: IP.into(),
            level: 2,
            status: status.into(),
            queued_at: String::new(),
            started_at: None,
            finished_at: None,
            error: None,
            scanner: None,
            arbiter: None,
            retry_at: None,
        };
        assert_eq!(
            states_json(&[j(3, "queued"), j(2, "done")]),
            "[[3,\"queued\"],[2,\"done\"]]"
        );
    }

    #[tokio::test]
    async fn waiting_until_the_result_lands() {
        let (state, _c, ip_id, _d) = state().await;
        let store = &state.store;
        assert!(!any_waiting(store, ip_id).await);
        state.recorder.enqueue_manual(ip_id, 2).await.unwrap();
        assert!(any_waiting(store, ip_id).await, "queued");
        sqlx::query(
            "UPDATE scan_jobs SET status = 'done', finished_at = datetime('now') WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(any_waiting(store, ip_id).await, "done, result not here yet");
        sqlx::query(
            "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
             SELECT id, ip_id, level, datetime('now'), datetime('now'), 's1', NULL, uid
             FROM scan_jobs WHERE ip_id = ?",
        )
        .bind(ip_id)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(!any_waiting(store, ip_id).await, "the result landed");
    }

    #[tokio::test]
    async fn the_stream_reports_the_job_states() {
        use futures::StreamExt;
        let (state, cookie, ip_id, _d) = state().await;
        state.recorder.enqueue_manual(ip_id, 2).await.unwrap();
        let app = crate::admin::full_router(state.clone());
        let r = app
            .oneshot(
                axum::http::Request::get(format!("/admin/api/scan-jobs?ip={IP}"))
                    .header("cookie", &cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let mut body = r.into_body().into_data_stream();
        let mut seen = String::new();
        let read = async {
            while let Some(Ok(chunk)) = body.next().await {
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if seen.contains("event: scan-jobs") {
                    return;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), read)
            .await
            .unwrap_or_else(|_| panic!("no scan-jobs event in {seen:?}"));
        assert!(seen.contains("queued"), "{seen}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib admin::scan_buy`
Expected: FAIL to compile — `states_json`, `any_waiting` and the route do not exist.

- [ ] **Step 3: Implement**

In `src/admin/scan_buy.rs`:

- Extend the `use axum::{...}` block and add imports:

```rust
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    response::{
        Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::time::Duration;
```

- Change `routes()` to:

```rust
pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/lookup/scan", post(buy))
        .route("/admin/api/scan-jobs", get(stream))
}
```

- Add at the end of the file (before the tests module):

```rust
/// How often the stream looks again without a log change.
const POLL: Duration = Duration::from_secs(3);
/// How often the stream re-checks the session.
const SESSION_EVERY: Duration = Duration::from_secs(30);

/// `[id, status]` per job: what the stream compares.
pub fn states_json(jobs: &[crate::events::QueueJob]) -> String {
    let v: Vec<(i64, &str)> = jobs.iter().map(|j| (j.id, j.status.as_str())).collect();
    serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())
}

/// A job is still on its way, or a recently done one's result has not
/// landed here yet (the scanner and the arbiter write separately).
pub async fn any_waiting(store: &crate::store::Store, ip_id: i64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs j WHERE j.ip_id = ?
           AND (j.status IN ('queued','running')
                OR (j.status = 'done' AND j.finished_at > datetime('now', '-2 days')
                    AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.job_uid = j.uid)))",
    )
    .bind(ip_id)
    .fetch_one(&store.pool)
    .await
    .unwrap_or(0);
    n > 0
}

#[derive(serde::Deserialize)]
pub struct JobsQuery {
    ip: String,
}

/// GET /admin/api/scan-jobs?ip=…: a `scan-jobs` event with the states
/// whenever they change, while a job waits for its result.
async fn stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<JobsQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session = crate::admin::auth::session_token(&state, &jar);
    let ip_id = match q.ip.trim().parse::<IpAddr>() {
        Ok(ip) => state
            .store
            .ip_by_addr(&crate::net::canonical(ip).to_string())
            .await
            .ok()
            .flatten()
            .map(|r| r.id),
        Err(_) => None,
    };
    Sse::new(events(state, ip_id, session)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn events(
    state: Arc<AdminState>,
    ip_id: Option<i64>,
    session: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        ip_id: Option<i64>,
        session: Option<String>,
        changes: Option<tokio::sync::watch::Receiver<u64>>,
        last: Option<String>,
        done: bool,
        next_check: tokio::time::Instant,
    }
    let changes = state.recorder.node().map(|n| n.subscribe_changes());
    futures::stream::unfold(
        St {
            state,
            ip_id,
            session,
            changes,
            last: None,
            done: false,
            next_check: tokio::time::Instant::now() + SESSION_EVERY,
        },
        |mut st| async move {
            if st.done {
                return None;
            }
            loop {
                if st.last.is_some() {
                    let closing = async {
                        match st.state.closing.clone() {
                            Some(mut rx) => {
                                let _ = rx.wait_for(|v| *v).await;
                            }
                            None => std::future::pending().await,
                        }
                    };
                    let changed = async {
                        match st.changes.as_mut() {
                            Some(rx) => {
                                if rx.changed().await.is_err() {
                                    std::future::pending::<()>().await;
                                }
                            }
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = closing => return None,
                        _ = changed => {}
                        _ = tokio::time::sleep(POLL) => {}
                    }
                }
                if tokio::time::Instant::now() >= st.next_check {
                    st.next_check = tokio::time::Instant::now() + SESSION_EVERY;
                    if let Some(id) = &st.session
                        && !st.state.store.validate_session(id).await.unwrap_or(false)
                    {
                        return None;
                    }
                }
                let jobs = match st.ip_id {
                    Some(id) => st
                        .state
                        .store
                        .jobs_for_ip(id, 20)
                        .await
                        .unwrap_or_default(),
                    None => vec![],
                };
                let states = states_json(&jobs);
                // The last event once nothing waits: the page reloads and
                // opens no new stream.
                st.done = match st.ip_id {
                    Some(id) => !any_waiting(&st.state.store, id).await,
                    None => true,
                };
                if st.last.as_deref() != Some(&states) || st.done {
                    st.last = Some(states.clone());
                    let ev = Event::default().event("scan-jobs").data(states);
                    return Some((Ok(ev), st));
                }
            }
        },
    )
}
```

In `src/admin/target.rs`, add to `impl Target` (after `probes_waiting`):

```rust
    /// `[id, status]` of every scan job, for the live stream.
    pub fn scan_states(&self) -> String {
        let jobs = self
            .admin
            .as_ref()
            .map(|a| a.jobs.clone())
            .unwrap_or_default();
        crate::admin::scan_buy::states_json(&jobs)
    }

    /// A scan job is still on its way.
    pub fn scans_waiting(&self) -> bool {
        self.admin.as_ref().is_some_and(|a| {
            a.jobs
                .iter()
                .any(|j| matches!(j.status.as_str(), "queued" | "running"))
        })
    }
```

In `templates/_target.html`, change the Counter-scans section's opening tag (line 19) to:

```html
<section class="card ip-scans" id="scans" data-section="scans"{% if t.scans_waiting() %} data-scans-src="/admin/api/scan-jobs?ip={{ t.ov.ip.ip|urlencode }}" data-scans-states="{{ t.scan_states() }}"{% endif %}>
```

In `assets/js/app.js`, add after the probes block (after line 333):

```js
  // Counter-scans card: while a job waits for its result, reload the page
  // when the states the server reports differ from the rendered ones.
  var sj = document.querySelector("[data-scans-src]");
  if (sj && window.EventSource) {
    var shownJobs = sj.getAttribute("data-scans-states");
    var sjes = new EventSource(sj.getAttribute("data-scans-src"));
    sjes.addEventListener("scan-jobs", function (ev) {
      if (ev.data !== shownJobs) { sjes.close(); location.reload(); }
    });
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib admin::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/admin/scan_buy.rs src/admin/target.rs templates/_target.html assets/js/app.js
git commit -m "Admin: the Counter-scans card follows its jobs live"
```

---

### Task 9: Docs and changelog

**Files:**
- Modify: `docs/operations.md:289-292`
- Modify: `docs/cluster.md:210-214`
- Modify: `README.md:38-40`
- Modify: `CHANGELOG.md` (Unreleased)

**Interfaces:**
- Consumes: all previous tasks.
- Produces: nothing code-facing.

- [ ] **Step 1: Rewrite the probe section of `docs/operations.md`**

Replace the paragraph at lines 289-292 ("**Probes.** ... protected-address rules as scans.") with:

```markdown
**Probes.** `[probe] enabled` (default `true`) lets this node's scanner run
observational probes that admins request; `max_parallel` (default `2`)
bounds how many run at once. A probe reads the open ports of the address's
latest counter-scan — or the well-known ones (22, 80, 443, 8080, 8443)
when there is none — takes at most two minutes, and obeys the same
protected-address rules as scans.

**Bought scans.** The Actions card also sells a counter-scan of level
1–4: level 1 costs the cluster's cheapest scanner offer, each level above
four times the previous. The job goes through the normal queue, paid like
any other; a finished scan of the same level less than 24 hours old is
shown instead of selling a new one.
```

- [ ] **Step 2: Extend the Probes paragraph of `docs/cluster.md`**

Append to the Probes paragraph (after "an accepted probe with no result lapses after 15 minutes.", line 214):

```markdown
  The Actions card sells counter-scans the same way: the arbiter funds a
  bought (manual) job at the scanner's price times 4^(level−1), and the
  scanners skip their evidence re-check for it — the safety preflight
  (protected addresses, Tor exits, verified crawlers) still applies.
```

- [ ] **Step 3: Extend the README**

After the probe sentence at lines 38-40 ("...from one or several vantages at once, with a diff and a light-speed RTT check." — match the actual sentence end), add:

```markdown
  The same card sells a full counter-scan of level 1–4 from the cluster's
  cheapest scanner, four times the price per level.
```

- [ ] **Step 4: CHANGELOG**

Under `## [Unreleased]`, add a `### Changed` section (before `### Added` if none exists) with:

```markdown
### Changed

- Probes are no longer capped at 16 ports, need neither level-2 evidence
  nor a finished counter-scan (without one they read the well-known ports
  22, 80, 443, 8080 and 8443), and the same address can be probed again
  right away. The safety rules are unchanged.
```

and to `### Added`:

```markdown
- The Actions card sells a counter-scan of level 1–4: level 1 at the
  cluster's cheapest scanner offer, four times that per level above. The
  job runs through the normal queue and appears live on the IP page; a
  result of the same level less than 24 hours old stands instead of a new
  purchase.
```

- [ ] **Step 5: Full verification**

Run: `cargo test`
Expected: PASS, the whole suite (unit, doc and integration tests).

- [ ] **Step 6: Commit**

```bash
git add docs/operations.md docs/cluster.md README.md CHANGELOG.md
git commit -m "Docs: unrestricted probes and the bought scan action"
```
