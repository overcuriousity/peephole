# Federated Cluster, Part 3: Enrichment as Results — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GeoLite2 databases stay on the node that downloaded them; what the cluster shares is the lookup result per IP, with its provenance, in a form that later providers (Shodan, AbuseIPDB) reuse unchanged.

**Architecture:** A new replicated record, `ip_intel`, carries one provider's result for one IP. Rows are kept per (ip, provider, origin); the familiar `ips` columns become a view of the newest result. A provider is something a node may or may not be able to query; nodes announce the providers they can serve in their heartbeat, and for every IP that lacks a result the able nodes rank themselves so that one of them looks it up and the others step in only after a delay. MaxMind is the first provider behind that interface.

**Tech Stack:** Rust, tokio, sqlx/SQLite (JSON1 functions), maxminddb, askama.

**Spec:** `docs/superpowers/specs/2026-10-01-federated-cluster-design.md`, section 6; §3.3 ("ignores its enrichment results"); §8 (no legacy for clusters; standalone databases migrate forward).

## Global Constraints

- No GeoLite2 file is announced, served or copied between nodes. The Tor exit list stays shared as a file.
- API keys and MaxMind credentials stay in the local TOML; a node only announces provider names.
- `ip_intel` replaces the `ip_enrich` record kind (no compatibility for clusters). Standalone databases keep their GeoIP facts through the migration.
- Provider names: `maxmind-geolite2`, `tor-exits`.
- A result is written for every IP a provider was asked about, also when the provider knows nothing (empty data), so the IP is not asked again and the absence is recorded.
- Step-in delay: the node at rank *r* among the able nodes handles IPs first seen more than *r* × 10 minutes ago.
- Every task ends green on: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Review Focus

1. Results from two nodes for the same IP arrive in either order. Expected: every node shows the newest one; the older is kept as a row.
2. A result arrives before the IP's first request. Expected: it is stored and shows up when the IP row is created.
3. No node in the cluster can serve a provider. Expected: no results, no errors, no busy loop.
4. A blocked peer's results. Expected: gone from the view on block, back on unblock.
5. A standalone database from before this change. Expected: its countries, ASNs and Tor flags are still shown after the upgrade, and are shared when the node later joins a cluster.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `src/cluster/record.rs` | modify | `IpIntelRec` replaces `IpEnrichRec` |
| `src/store/migrations/0017_ip_intel.sql` | create | `ip_intel` table, backfill, drop `ip_enrich_pending` and `ips.geo_hlc` |
| `src/store/data.rs` | modify | apply `ip_intel`; `refresh_ip_view` |
| `src/store/recorder.rs`, `src/store/requests.rs` | modify | `record_intel`; `enrich_ip` on top of it |
| `src/cluster/adopt.rs`, `src/cluster/block.rs`, `src/cluster/repl.rs` | modify | adoption of standalone results; block drops a peer's results |
| `src/intel/provider.rs` | create | `Provider` trait, `MaxMind` |
| `src/intel/mod.rs`, `src/intel/share.rs`, `src/intel/geo.rs` | modify | per-node GeoLite2 download; enrichment loop; Tor-only file sharing |
| `src/cluster/status.rs`, `src/cluster/mod.rs` | modify | `providers` in heartbeats |
| `src/trap/mod.rs` | modify | record results at request time |
| `src/store/inspect.rs` or `src/export/mod.rs`, `src/admin/pages.rs`, templates | modify | enrichment export; provider display |
| `README.md`, `deploy/config.example.toml`, `install.sh` | modify | wording |

---

### Task 1: The `ip_intel` record

**Files:**
- Create: `src/store/migrations/0017_ip_intel.sql`
- Modify: `src/store/mod.rs`, `src/cluster/record.rs`, `src/store/data.rs`, `src/store/recorder.rs`, `src/cluster/adopt.rs`, `src/cluster/block.rs`, `src/cluster/repl.rs`, `src/trap/mod.rs`
- Test: `src/store/data.rs` (unit), `tests/cluster.rs`

**Interfaces (produced):**

```rust
// src/cluster/record.rs
pub struct IpIntelRec {
    pub ip: String,
    /// `maxmind-geolite2`, `tor-exits`; later `shodan`, `abuseipdb`.
    pub provider: String,
    pub fetched_at: String,
    /// Version of the provider's data, if it has one (database build date).
    pub source_version: Option<String>,
    /// Provider-specific fields as a JSON object. `{}`: the provider was
    /// asked and knows nothing.
    pub data_json: String,
}
Record::IpIntel(IpIntelRec)            // kind "ip_intel"; Record::IpEnrich and IpEnrichRec are removed

// src/intel/mod.rs
pub const MAXMIND: &str = "maxmind-geolite2";
pub const TOR: &str = "tor-exits";

// src/store/data.rs
pub(crate) async fn refresh_ip_view(conn: &mut SqliteConnection, ip: &str) -> Result<()>;

// src/store/recorder.rs
/// Record one provider's result for an IP; nothing is written when this
/// node's last result for it says the same.
pub async fn record_intel(&self, ip: &str, provider: &str, source_version: Option<&str>, data: serde_json::Value) -> Result<()>;
/// Unchanged signature, now on top of `record_intel`.
pub async fn enrich_ip(&self, ip_id: i64, country: Option<&str>, asn: Option<u32>, asn_org: Option<&str>, tor: bool) -> Result<()>;
```

- [ ] **Step 1: Write the failing unit tests** in the `tests` module of `src/store/data.rs`:

```rust
    use crate::cluster::record::IpIntelRec;

    fn intel(ip: &str, provider: &str, data: &str) -> Record {
        Record::IpIntel(IpIntelRec {
            ip: ip.into(),
            provider: provider.into(),
            fetched_at: now_ts(),
            source_version: Some("2026-09-30".into()),
            data_json: data.into(),
        })
    }

    type View = (Option<String>, Option<i64>, Option<String>, bool);

    async fn view(conn: &mut SqliteConnection, ip: &str) -> View {
        sqlx::query_as("SELECT country, asn, asn_org, is_tor_exit FROM ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&mut *conn)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_newest_result_wins_whatever_the_arrival_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let ip = "203.0.113.7";
        apply(&mut conn, Ctx { origin: Some(&a), hlc: 5 }, &request(&format!("{}r", a.uid_prefix()), "/x"))
            .await
            .unwrap();
        let de = r#"{"country":"DE","asn":3320,"asn_org":"DTAG"}"#;
        let us = r#"{"country":"US","asn":15169,"asn_org":"Google"}"#;
        // B's newer result arrives first, A's older one afterwards.
        apply(&mut conn, Ctx { origin: Some(&b), hlc: 20 }, &intel(ip, "maxmind-geolite2", us))
            .await
            .unwrap();
        apply(&mut conn, Ctx { origin: Some(&a), hlc: 10 }, &intel(ip, "maxmind-geolite2", de))
            .await
            .unwrap();
        assert_eq!(
            view(&mut conn, ip).await,
            (Some("US".into()), Some(15169), Some("Google".into()), false)
        );
        // Both results are kept, with their origin.
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ip_intel").await, 2);
        // A node's own newer result replaces its older one.
        apply(&mut conn, Ctx { origin: Some(&a), hlc: 30 }, &intel(ip, "maxmind-geolite2", "{}"))
            .await
            .unwrap();
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ip_intel").await, 2);
        assert_eq!(view(&mut conn, ip).await, (None, None, None, false), "newest says unknown");
        // Tor is its own provider.
        apply(&mut conn, Ctx { origin: Some(&b), hlc: 40 }, &intel(ip, "tor-exits", r#"{"exit":true}"#))
            .await
            .unwrap();
        assert!(view(&mut conn, ip).await.3);
    }

    #[tokio::test]
    async fn a_result_that_arrives_before_the_ip_shows_once_the_ip_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let ctx = |hlc| Ctx { origin: None, hlc };
        apply(&mut conn, ctx(1), &intel("203.0.113.7", "maxmind-geolite2", r#"{"country":"NL"}"#))
            .await
            .unwrap();
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ips").await, 0);
        apply(&mut conn, ctx(2), &request("req", "/x")).await.unwrap();
        assert_eq!(view(&mut conn, "203.0.113.7").await.0.as_deref(), Some("NL"));
        // Garbage in the data field is stored but changes nothing shown.
        apply(&mut conn, ctx(3), &intel("203.0.113.7", "maxmind-geolite2", "not json"))
            .await
            .unwrap();
        assert_eq!(view(&mut conn, "203.0.113.7").await.0, None);
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib the_newest_result_wins a_result_that_arrives`
Expected: compile error, `IpIntelRec` not found.

- [ ] **Step 3: Schema.** Create `src/store/migrations/0017_ip_intel.sql` and append it to `MIGRATIONS`:

```sql
-- One provider's result for one IP, per node that looked it up. The ips
-- columns (country, asn, asn_org, is_tor_exit) show the newest result.
-- origin is empty on a standalone node.
CREATE TABLE ip_intel (
  ip TEXT NOT NULL, provider TEXT NOT NULL, origin BLOB NOT NULL,
  hlc INTEGER NOT NULL, fetched_at TEXT NOT NULL, source_version TEXT,
  data_json TEXT NOT NULL,
  PRIMARY KEY (ip, provider, origin)
) WITHOUT ROWID;
CREATE INDEX idx_ip_intel_provider ON ip_intel(provider, ip);
CREATE INDEX idx_ip_intel_origin ON ip_intel(origin);
-- Facts recorded before this table existed stay, as this node's results.
INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
  SELECT ip, 'maxmind-geolite2', x'', 0, last_seen, NULL,
         json_object('country', country, 'asn', asn, 'asn_org', asn_org)
  FROM ips WHERE country IS NOT NULL OR asn IS NOT NULL;
INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
  SELECT ip, 'tor-exits', x'', 0, last_seen, NULL, '{"exit":true}'
  FROM ips WHERE is_tor_exit = 1;
DROP TABLE IF EXISTS ip_enrich_pending;
ALTER TABLE ips DROP COLUMN geo_hlc
```

- [ ] **Step 4: Record and apply.**

`src/intel/mod.rs`: add `pub const MAXMIND: &str = "maxmind-geolite2";` and `pub const TOR: &str = "tor-exits";`.

`src/cluster/record.rs`: replace `IpEnrichRec` by `IpIntelRec` (fields as in Interfaces, all `Serialize, Deserialize`), `Record::IpEnrich` by `Record::IpIntel`, kind `"ip_intel"`.

`src/store/data.rs`:

- `apply`: `Record::IpIntel(r) => ip_intel(conn, ctx, r).await`; `CONTENT_KINDS` lists `"ip_intel"` in place of `"ip_enrich"`; delete `ip_enrich` and the `IpFacts` type if nothing else uses it (`recorder.rs` does: move what it needs there or drop it with the rewrite below).
- In `ensure_ip`, replace the whole "Enrichment that arrived before the IP's first record" block by `refresh_ip_view(conn, ip).await?;` before `Ok(id)`.
- Add:

```rust
/// Store one provider's result for an IP (per origin, newest wins) and
/// bring the IP's shown facts up to date.
async fn ip_intel(conn: &mut SqliteConnection, ctx: Ctx<'_>, r: &IpIntelRec) -> Result<Effect> {
    sqlx::query(
        "INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(ip, provider, origin) DO UPDATE SET hlc = excluded.hlc,
           fetched_at = excluded.fetched_at, source_version = excluded.source_version,
           data_json = excluded.data_json
         WHERE excluded.hlc > ip_intel.hlc",
    )
    .bind(&r.ip)
    .bind(&r.provider)
    .bind(ctx.origin_bytes().unwrap_or_default())
    .bind(ctx.hlc as i64)
    .bind(&r.fetched_at)
    .bind(&r.source_version)
    .bind(&r.data_json)
    .execute(&mut *conn)
    .await?;
    refresh_ip_view(conn, &r.ip).await?;
    Ok(Effect::Applied)
}

/// The newest result of `provider` for `ip`, as JSON (None: no result, or
/// one that is not a JSON object).
async fn newest_intel(
    conn: &mut SqliteConnection,
    ip: &str,
    provider: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT data_json FROM ip_intel WHERE ip = ? AND provider = ? ORDER BY hlc DESC LIMIT 1",
    )
    .bind(ip)
    .bind(provider)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(raw
        .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
        .and_then(|v| v.as_object().cloned()))
}

/// Set the facts shown for an IP (country, ASN, Tor flag) from the newest
/// result of each provider. Does nothing while the IP has no row yet.
pub(crate) async fn refresh_ip_view(conn: &mut SqliteConnection, ip: &str) -> Result<()> {
    let geo = newest_intel(conn, ip, crate::intel::MAXMIND).await?.unwrap_or_default();
    let tor = newest_intel(conn, ip, crate::intel::TOR).await?.unwrap_or_default();
    sqlx::query("UPDATE ips SET country = ?, asn = ?, asn_org = ?, is_tor_exit = ? WHERE ip = ?")
        .bind(geo.get("country").and_then(|v| v.as_str()))
        .bind(geo.get("asn").and_then(|v| v.as_i64()))
        .bind(geo.get("asn_org").and_then(|v| v.as_str()))
        .bind(tor.get("exit").and_then(|v| v.as_bool()).unwrap_or(false))
        .bind(ip)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
```

`src/store/recorder.rs`: replace `enrich_ip` by:

```rust
    /// Record one provider's result for an IP. Nothing is written when this
    /// node's last result for it says the same, so a cluster does not
    /// replicate one record per request.
    pub async fn record_intel(
        &self,
        ip: &str,
        provider: &str,
        source_version: Option<&str>,
        data: serde_json::Value,
    ) -> Result<()> {
        let data_json = data.to_string();
        let mine = self.node_id().map(|id| id.0.to_vec()).unwrap_or_default();
        let last: Option<String> = sqlx::query_scalar(
            "SELECT data_json FROM ip_intel WHERE ip = ? AND provider = ? AND origin = ?",
        )
        .bind(ip)
        .bind(provider)
        .bind(mine)
        .fetch_optional(&self.store().pool)
        .await?;
        if last.as_deref() == Some(data_json.as_str()) {
            return Ok(());
        }
        self.write(vec![Record::IpIntel(IpIntelRec {
            ip: ip.to_string(),
            provider: provider.to_string(),
            fetched_at: now_ts(),
            source_version: source_version.map(str::to_string),
            data_json,
        })])
        .await
    }

    /// GeoIP facts as a MaxMind result (fields that are unknown are left out).
    pub fn geo_data(country: Option<&str>, asn: Option<u32>, asn_org: Option<&str>) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if let Some(c) = country {
            m.insert("country".into(), c.into());
        }
        if let Some(a) = asn {
            m.insert("asn".into(), a.into());
        }
        if let Some(o) = asn_org {
            m.insert("asn_org".into(), o.into());
        }
        serde_json::Value::Object(m)
    }

    /// Set GeoIP / Tor facts for an IP (tests and legacy callers).
    pub async fn enrich_ip(
        &self,
        ip_id: i64,
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
        tor: bool,
    ) -> Result<()> {
        let Ok(ip) = self.ip_of(ip_id).await else {
            return Ok(());
        };
        if country.is_some() || asn.is_some() || asn_org.is_some() {
            self.record_intel(&ip, crate::intel::MAXMIND, None, Self::geo_data(country, asn, asn_org))
                .await?;
        }
        self.record_intel(&ip, crate::intel::TOR, None, serde_json::json!({ "exit": tor }))
            .await
    }
```

(`enrich_ip` with `tor = false` on an IP that has no Tor result writes `{"exit":false}` once; that is a result like any other.)

`src/trap/mod.rs`, `record_and_respond`: replace the enrichment block by

```rust
    // Enrichment (every IP, every request — spec §4): what this node can
    // look up itself. Written only when it changes. IPs this node cannot
    // look up are filled in by a node that can (intel::enrich_once).
    let ip_text = crate::net::canonical(ip).to_string();
    let geo_hit = state
        .geo
        .read()
        .unwrap()
        .as_ref()
        .map(|g| (g.lookup(&ip), g.build_date()));
    if let Some((g, version)) = geo_hit {
        state
            .recorder
            .record_intel(
                &ip_row.ip,
                crate::intel::MAXMIND,
                version.as_deref(),
                crate::store::recorder::Recorder::geo_data(
                    g.country.as_deref(),
                    g.asn,
                    g.asn_org.as_deref(),
                ),
            )
            .await?;
    }
    let is_tor = state.tor.read().unwrap().contains(&ip);
    if is_tor {
        state
            .recorder
            .record_intel(&ip_row.ip, crate::intel::TOR, None, serde_json::json!({ "exit": true }))
            .await?;
    }
    let _ = ip_text;
```

(use `ip_row.ip` as the key so it equals the `ips.ip` text; drop the `ip_text` lines if `IpRow` has the `ip` field, which it does via `SELECT *`.) `GeoIp::build_date` is added in `src/intel/geo.rs`:

```rust
    /// Build date of the city database (`YYYY-MM-DD`), as the version of
    /// the data a lookup came from.
    pub fn build_date(&self) -> Option<String> {
        chrono::DateTime::from_timestamp(self.city.metadata.build_epoch as i64, 0)
            .map(|t| t.format("%Y-%m-%d").to_string())
    }
```

`src/cluster/adopt.rs`: replace the IP-facts adoption (the loop over `ips` writing `Record::IpEnrich`, the `IPS_ADOPTED` setting and `geo_hlc`) by adopting standalone results:

```rust
    // Enrichment results recorded while standalone (origin empty) become
    // this node's results in the log.
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        type Row = (String, String, String, Option<String>, String);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT ip, provider, fetched_at, source_version, data_json FROM ip_intel
             WHERE origin = x'' LIMIT ?",
        )
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            break;
        }
        for (ip, provider, fetched_at, source_version, data_json) in rows {
            let e = repl::append_existing(
                node,
                &mut tx,
                &Record::IpIntel(IpIntelRec {
                    ip: ip.clone(),
                    provider: provider.clone(),
                    fetched_at,
                    source_version,
                    data_json,
                }),
            )
            .await?;
            // Our own result under our key replaces the standalone row.
            sqlx::query("DELETE FROM ip_intel WHERE ip = ? AND provider = ? AND origin = ?")
                .bind(&ip)
                .bind(&provider)
                .bind(&me)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE ip_intel SET origin = ?, hlc = ? WHERE ip = ? AND provider = ? AND origin = x''",
            )
            .bind(&me)
            .bind(e.hlc as i64)
            .bind(&ip)
            .bind(&provider)
            .execute(&mut *tx)
            .await?;
            total += 1;
        }
        tx.commit().await?;
    }
```

`src/cluster/repl.rs`, `rematerialize`: `'ip_intel'` in place of `'ip_enrich'` in the kind list. `src/cluster/block.rs`, `block`: after the table loop, drop the peer's results and refresh the IPs they were about, in batches of `BATCH`:

```rust
    // Its enrichment results go too; the IPs fall back to other nodes' results.
    loop {
        let _g = node.apply_lock.lock().await;
        let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let ips: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT ip FROM ip_intel WHERE origin = ? LIMIT ?")
                .bind(&id.0[..])
                .bind(BATCH as i64)
                .fetch_all(&mut *tx)
                .await?;
        if ips.is_empty() {
            break;
        }
        for ip in &ips {
            sqlx::query("DELETE FROM ip_intel WHERE origin = ? AND ip = ?")
                .bind(&id.0[..])
                .bind(ip)
                .execute(&mut *tx)
                .await?;
            data::refresh_ip_view(&mut tx, ip).await?;
        }
        tx.commit().await?;
    }
```

- [ ] **Step 5: Run the unit tests**

Run: `cargo test --lib`
Expected: PASS (existing tests using `set_ip_geo` / `set_ip_tor` keep passing through `enrich_ip`).

- [ ] **Step 6: Cluster test.** Add to `tests/cluster.rs`:

```rust
/// Enrichment results replicate with their origin; a blocked peer's results
/// stop counting and come back on unblock.
#[tokio::test]
async fn enrichment_results_replicate_and_follow_blocks() {
    use peephole::cluster::block;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.90", "/x").await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    let country = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT country FROM ips WHERE ip = '203.0.113.90'",
            )
            .fetch_optional(&pool)
            .await
            .unwrap()
            .flatten()
        }
    };
    eventually("b shows a's result", || async {
        country(&nb).await.as_deref() == Some("NL")
    })
    .await;
    let origin: Vec<u8> = sqlx::query_scalar("SELECT origin FROM ip_intel")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(origin, a.id.0.to_vec(), "provenance is kept");
    // The same result again writes nothing.
    let head = head_of(&na, a.id).await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    assert_eq!(head_of(&na, a.id).await, head);

    block::block(&nb, a.id).await.unwrap();
    assert_eq!(country(&nb).await, None, "a blocked peer's results do not count");
    block::unblock(&nb, a.id).await.unwrap();
    assert_eq!(country(&nb).await.as_deref(), Some("NL"));
}
```

- [ ] **Step 7: Run everything, lint, commit**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: PASS (`standalone_history_is_adopted_and_backfilled` still finds country `NL` on the second node).

```bash
git add -A
git commit -m "feat(intel)!: enrichment results as per-origin ip_intel records"
```

---

### Task 2: GeoLite2 stays local; able nodes fill in the rest

**Files:**
- Create: `src/intel/provider.rs`
- Modify: `src/intel/mod.rs`, `src/intel/share.rs`, `src/store/data.rs`, `src/store/requests.rs`, `src/cluster/status.rs`, `src/cluster/mod.rs`, `src/lib.rs`, `tests/cluster.rs`, and every `NodeParams { … }` literal (`has_maxmind` goes)

**Interfaces:**
- Consumes: `Recorder::record_intel`, `MAXMIND`, `GeoIp::build_date` (Task 1).
- Produces:

```rust
// src/intel/provider.rs
pub struct Finding { pub ip: String, pub source_version: Option<String>, pub data: serde_json::Value }
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether this node can answer right now (database loaded, key set, quota left).
    fn ready(&self) -> bool;
    /// One finding per IP that was asked, also when nothing is known.
    fn lookup<'a>(&'a self, ips: &'a [String]) -> futures::future::BoxFuture<'a, Vec<Finding>>;
}
pub struct MaxMind(pub SharedGeo);
/// Seconds after an IP was first seen before the node at `rank` looks it up.
pub fn step_in_secs(rank: usize) -> i64;        // rank * 600

// src/intel/mod.rs
pub type Providers = Vec<std::sync::Arc<dyn provider::Provider>>;
/// One pass: look up IPs that lack a result, for every provider this node can serve. Returns results written.
pub async fn enrich_once(rec: &Recorder, providers: &Providers) -> anyhow::Result<usize>;
pub async fn enrich_loop(rec: Recorder, providers: Providers, shutdown: tokio::sync::watch::Receiver<bool>);

// src/cluster
Heartbeat::providers: Vec<String>          // replaces has_maxmind
Node::providers(&self) -> Vec<String>; Node::set_providers(&self, p: Vec<String>)
NodeParams: `has_maxmind` is removed

// src/store/requests.rs
pub async fn ips_missing_intel(&self, provider: &str, older_than_secs: i64, limit: i64) -> Result<Vec<String>>;
```

- [ ] **Step 1: Write the failing tests.**

`src/intel/provider.rs` (new file, tests first):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_ranks_step_in_ten_minutes_apart() {
        assert_eq!(step_in_secs(0), 0);
        assert_eq!(step_in_secs(1), 600);
        assert_eq!(step_in_secs(3), 1800);
    }

    #[tokio::test]
    async fn maxmind_answers_for_every_ip_asked_once_its_database_is_loaded() {
        let shared: SharedGeo = Default::default();
        let p = MaxMind(shared.clone());
        assert_eq!(p.name(), crate::intel::MAXMIND);
        assert!(!p.ready());
        assert!(p.lookup(&["2.125.160.216".into()]).await.is_empty());
        let dir = tempfile::tempdir().unwrap();
        for f in ["GeoLite2-City", "GeoLite2-ASN"] {
            std::fs::copy(
                format!("tests/fixtures/{f}-Test.mmdb"),
                dir.path().join(format!("{f}.mmdb")),
            )
            .unwrap();
        }
        *shared.write().unwrap() = Some(crate::intel::geo::GeoIp::load(dir.path()).unwrap());
        assert!(p.ready());
        let found = p
            .lookup(&["2.125.160.216".into(), "203.0.113.1".into(), "junk".into()])
            .await;
        assert_eq!(found.len(), 2, "one finding per valid IP, known or not");
        assert_eq!(found[0].data["country"], "GB");
        assert!(found[0].source_version.is_some());
        assert_eq!(found[1].data, serde_json::json!({}));
    }
}
```

`tests/cluster.rs`: replace `intel_files_are_shared_by_hash` with

```rust
/// The Tor exit list is shared as a file; GeoLite2 databases are not.
#[tokio::test]
async fn only_the_tor_list_is_shared_as_a_file() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    std::fs::write(na.dir.path().join("tor-exit.txt"), "192.0.2.1\n192.0.2.2\n").unwrap();
    std::fs::copy(
        "tests/fixtures/GeoLite2-City-Test.mmdb",
        na.dir.path().join("GeoLite2-City.mmdb"),
    )
    .unwrap();
    share::publish(&na, na.dir.path(), &[share::TOR])
        .await
        .unwrap();
    assert!(
        share::publish(&na, na.dir.path(), &["geolite2-city"])
            .await
            .is_err(),
        "a database is never announced"
    );
    eventually("b knows the manifest", || async {
        share::manifests(&nb.store).await.unwrap().len() == 1
    })
    .await;
    assert_eq!(
        share::sync_files(&nb, nb.dir.path()).await.unwrap(),
        [share::TOR]
    );
    assert!(nb.dir.path().join("tor-exit.txt").exists());
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // A manifest for a database, written by a peer on its own, is ignored.
    repl::append(
        &na,
        &[Record::IntelManifest(
            peephole::cluster::record::IntelManifestRec {
                kind: "geolite2-city".into(),
                sha256: "00".into(),
                size: 1,
                fetched_at: peephole::store::data::now_ts(),
            },
        )],
    )
    .await
    .unwrap();
    eventually("b holds a's newest entry", || async {
        head_of(&nb, a.id).await == head_of(&na, a.id).await
    })
    .await;
    assert_eq!(share::manifests(&nb.store).await.unwrap().len(), 1);
}

/// A node without the databases gets GeoIP facts from one that has them;
/// the database itself does not travel.
#[tokio::test]
async fn geo_results_come_from_a_node_that_has_the_database() {
    use peephole::intel::provider::MaxMind;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    let geo: peephole::intel::SharedGeo = Default::default();
    *geo.write().unwrap() = Some(peephole::intel::geo::GeoIp::load(na.dir.path()).unwrap());
    let providers: peephole::intel::Providers = vec![Arc::new(MaxMind(geo))];
    // B, which cannot look anything up, records a request.
    record(&nb, "2.125.160.216", "/x").await;
    let nothing: peephole::intel::Providers = vec![Arc::new(MaxMind(Default::default()))];
    assert_eq!(peephole::intel::enrich_once(&rec(&nb), &nothing).await.unwrap(), 0);
    eventually("a has b's request", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    assert_eq!(peephole::intel::enrich_once(&rec(&na), &providers).await.unwrap(), 1);
    assert_eq!(na.providers(), [peephole::intel::MAXMIND]);
    eventually("b shows the country", || async {
        sqlx::query_scalar::<_, Option<String>>("SELECT country FROM ips")
            .fetch_one(&nb.store.pool)
            .await
            .unwrap()
            .as_deref()
            == Some("GB")
    })
    .await;
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // Asked once: a second pass has nothing to do.
    assert_eq!(peephole::intel::enrich_once(&rec(&na), &providers).await.unwrap(), 0);
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib provider::` and `cargo test --test cluster only_the_tor_list geo_results_come`
Expected: compile errors.

- [ ] **Step 3: Providers.** `src/intel/provider.rs` above the tests (`pub mod provider;` in `src/intel/mod.rs`):

```rust
//! Enrichment providers. A provider is something a node may or may not be
//! able to query: it needs a local database or an API key, and those stay on
//! the node. What a provider finds out about an IP is shared with the
//! cluster as an `ip_intel` record.
use super::SharedGeo;
use futures::future::BoxFuture;

/// What a provider says about one IP.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub ip: String,
    /// Version of the data the answer came from, if the provider has one.
    pub source_version: Option<String>,
    /// Provider-specific fields; an empty object when it knows nothing.
    pub data: serde_json::Value,
}

pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether this node can answer right now (database loaded, key set,
    /// quota left).
    fn ready(&self) -> bool;
    /// One finding per IP that was asked, also when nothing is known, so
    /// the IP is not asked again.
    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>>;
}

/// Seconds after an IP was first seen before the node at `rank` among the
/// able nodes looks it up: rank 0 at once, the others only if it is still
/// missing ten minutes per rank later.
pub fn step_in_secs(rank: usize) -> i64 {
    rank as i64 * 600
}

/// MaxMind GeoLite2: country and ASN from the node's own databases.
pub struct MaxMind(pub SharedGeo);

impl Provider for MaxMind {
    fn name(&self) -> &'static str {
        super::MAXMIND
    }

    fn ready(&self) -> bool {
        self.0.read().unwrap().is_some()
    }

    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
        Box::pin(async move {
            let guard = self.0.read().unwrap();
            let Some(g) = guard.as_ref() else {
                return vec![];
            };
            let version = g.build_date();
            ips.iter()
                .filter_map(|ip| {
                    let addr = ip.parse().ok()?;
                    let hit = g.lookup(&addr);
                    Some(Finding {
                        ip: ip.clone(),
                        source_version: version.clone(),
                        data: crate::store::recorder::Recorder::geo_data(
                            hit.country.as_deref(),
                            hit.asn,
                            hit.asn_org.as_deref(),
                        ),
                    })
                })
                .collect()
        })
    }
}
```

`src/store/requests.rs`:

```rust
    /// IPs first seen at least `older_than_secs` ago that have no result
    /// from `provider`, oldest first.
    pub async fn ips_missing_intel(
        &self,
        provider: &str,
        older_than_secs: i64,
        limit: i64,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT i.ip FROM ips i
             WHERE i.first_seen <= datetime('now', ?)
               AND NOT EXISTS (SELECT 1 FROM ip_intel t WHERE t.ip = i.ip AND t.provider = ?)
             ORDER BY i.id LIMIT ?",
        )
        .bind(format!("-{older_than_secs} seconds"))
        .bind(provider)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
```

- [ ] **Step 4: Heartbeat providers.** `src/cluster/status.rs`: in `Heartbeat` replace `pub has_maxmind: bool,` by

```rust
    /// Enrichment providers this node can query right now.
    #[serde(default)]
    pub providers: Vec<String>,
```

and build it with `providers: self.providers(),` in `refresh_heartbeat` (test literal: `providers: vec![],`). `src/cluster/mod.rs`: remove `has_maxmind` from `NodeParams` and `Node`; add the field `providers: RwLock<Vec<String>>` (empty at start) and

```rust
    /// Enrichment providers this node can query right now.
    pub fn providers(&self) -> Vec<String> {
        self.providers.read().unwrap().clone()
    }

    pub fn set_providers(&self, p: Vec<String>) {
        if *self.providers.read().unwrap() != p {
            *self.providers.write().unwrap() = p;
            self.publish_status();
        }
    }
```

Delete `has_maxmind: …,` from every `NodeParams { … }` literal (`src/cluster/repl.rs`, `src/scan/arbiter.rs`, `tests/cluster.rs`).

- [ ] **Step 5: Tor-only file sharing.** `src/intel/share.rs`: delete `CITY`, `ASN`, `backfill_missing_geo` and its imports; `pub const KINDS: [&str; 1] = [TOR];`; `file_name` knows only `TOR`. Update the module doc: "one node fetches the Tor exit list … GeoLite2 databases are never shared: their licence does not allow redistribution; nodes share lookup results instead (see `intel::provider`)". The unit test `fetch_order_prefers_dialable_then_key_and_staggers_failover` stays.

`src/store/data.rs`, `intel_manifest`: first line

```rust
    // Only the public Tor exit list is shared as a file.
    if crate::intel::share::file_name(&m.kind).is_none() {
        return Ok(Effect::Ignored);
    }
```

- [ ] **Step 6: The loops.** In `src/intel/mod.rs`:

```rust
pub mod provider;

/// The providers a node was started with.
pub type Providers = Vec<Arc<dyn provider::Provider>>;

/// IPs looked up per provider and pass.
const ENRICH_BATCH: i64 = 500;
/// How often the enrichment loop runs.
const ENRICH_TICK: Duration = Duration::from_secs(60);

/// One pass: for every provider this node can serve, look up IPs that have
/// no result from it yet and record what it says. In a cluster the able
/// nodes take turns by rank (see [`provider::step_in_secs`]). Returns how
/// many results were written.
pub async fn enrich_once(rec: &Recorder, providers: &Providers) -> anyhow::Result<usize> {
    let ready: Vec<_> = providers.iter().filter(|p| p.ready()).collect();
    if let Some(node) = rec.node() {
        node.set_providers(ready.iter().map(|p| p.name().to_string()).collect());
    }
    let mut written = 0;
    for p in ready {
        let rank = match rec.node() {
            None => 0,
            Some(node) => {
                let me = node.id();
                let members = node.members();
                let able: Vec<_> = node
                    .live_members(LIVE_WINDOW)
                    .into_iter()
                    .filter(|id| {
                        *id == me
                            || node
                                .status
                                .known(id)
                                .is_some_and(|k| k.hb.providers.iter().any(|n| n == p.name()))
                    })
                    .map(|id| (id, members.get(&id).is_some_and(|m| m.address.is_some())))
                    .collect();
                share::rank(me, &able).unwrap_or(0)
            }
        };
        let ips = rec
            .store()
            .ips_missing_intel(p.name(), provider::step_in_secs(rank), ENRICH_BATCH)
            .await?;
        if ips.is_empty() {
            continue;
        }
        for f in p.lookup(&ips).await {
            rec.record_intel(&f.ip, p.name(), f.source_version.as_deref(), f.data)
                .await?;
            written += 1;
        }
    }
    Ok(written)
}

/// Keep filling in results for IPs that lack them, until shutdown.
pub async fn enrich_loop(
    rec: Recorder,
    providers: Providers,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut wait = Duration::from_secs(5);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
        wait = ENRICH_TICK;
        match enrich_once(&rec, &providers).await {
            Ok(0) => {}
            Ok(n) => info!(n, "enrichment: results recorded"),
            Err(e) => warn!(?e, "enrichment pass failed"),
        }
    }
}
```

Restructure the scheduler in the same file:

- Extract the standalone MaxMind branch into `async fn refresh_maxmind(store: &Store, rec: &Recorder, cfg: &Config, geo: &SharedGeo)` (the `if let Some(mm) = &cfg.maxmind && (geo_missing || is_stale(…)) { … }` block, unchanged), and call it from the standalone loop.
- In `run_cluster`: delete the MaxMind election block (`if let Some(mm) = &cfg.maxmind { let key_holders … }`) and the `backfill_missing_geo` block; `reload` handles only `share::TOR`; after the Tor block call `refresh_maxmind(&node.store, &rec, &cfg, &geo).await;` once per pass when the last attempt is more than an hour ago (keep an `Instant` next to `failed`), so every node with credentials keeps its own databases fresh.

`src/lib.rs`, after the `intel::run_scheduler` spawn:

```rust
    // Results for IPs this or other nodes recorded without them.
    tokio::spawn(intel::enrich_loop(
        recorder.clone(),
        vec![Arc::new(intel::provider::MaxMind(geo.clone()))],
        shutdown_rx.clone(),
    ));
```

- [ ] **Step 7: Run everything, lint, commit**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: PASS.

```bash
git add -A
git commit -m "feat(intel)!: GeoLite2 stays local; able nodes fill in results for the cluster"
```

---

### Task 3: Export, display and documentation

**Files:**
- Modify: `src/store/inspect.rs`, `src/admin/pages.rs`, `templates/admin_export.html`, `src/admin/cluster.rs`, `templates/admin_cluster.html`, `README.md`, `deploy/config.example.toml`, `install.sh`
- Test: `tests/cluster.rs`

**Interfaces:**
- Produces: `GET /admin/export/intel` (JSON Lines, one enrichment result per line: `ip`, `provider`, `fetched_at`, `source_version`, `node`, `data`); `MemberView::providers: String`.

- [ ] **Step 1: Write the failing test** in `tests/cluster.rs`:

```rust
/// Enrichment results can be exported with their provenance.
#[tokio::test]
async fn enrichment_results_are_exported_with_provenance() {
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.91", "/x").await;
    rec(&nb)
        .record_intel(
            "203.0.113.91",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL"}),
        )
        .await
        .unwrap();
    eventually("a has the result", || async {
        count(&na, "SELECT COUNT(*) FROM ip_intel").await == 1
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let body = text(&admin, format!("{base}/admin/export/intel")).await;
    let line: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(line["ip"], "203.0.113.91");
    assert_eq!(line["provider"], "maxmind-geolite2");
    assert_eq!(line["source_version"], "2026-09-30");
    assert_eq!(line["node"], "node-bravo");
    assert_eq!(line["data"]["country"], "NL");
    // Not public.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = anon
        .get(format!("{base}/admin/export/intel"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test cluster enrichment_results_are_exported`
Expected: FAIL (404).

- [ ] **Step 3: Implement.**

`src/store/inspect.rs`:

```rust
    /// Enrichment results with the node that looked them up, newest first.
    /// `(ip, provider, fetched_at, source_version, origin, data_json)`.
    pub async fn intel_export(&self, limit: i64) -> Result<Vec<IntelRow>> {
        Ok(sqlx::query_as(
            "SELECT ip, provider, fetched_at, source_version, origin, data_json
             FROM ip_intel ORDER BY fetched_at DESC, ip LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
```

with `pub type IntelRow = (String, String, String, Option<String>, Vec<u8>, String);` next to it.

`src/admin/pages.rs`: route `.route("/admin/export/intel", get(export_intel))` and

```rust
/// Enrichment results as JSON Lines: what each provider said about each
/// IP, when, from which data version, and which node looked it up.
async fn export_intel(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let names: HashMap<Vec<u8>, String> = match st.recorder.node() {
        Some(node) => crate::cluster::members::all(&node.store)
            .await?
            .into_iter()
            .map(|m| (m.id.0.to_vec(), m.name))
            .collect(),
        None => HashMap::new(),
    };
    let mut out = String::new();
    for (ip, provider, fetched_at, source_version, origin, data_json) in
        st.store.intel_export(1_000_000).await?
    {
        let node = match names.get(&origin) {
            Some(n) => n.clone(),
            None if origin.is_empty() => "this node".to_string(),
            None => data_encoding::HEXLOWER.encode(&origin[..origin.len().min(6)]),
        };
        let data: serde_json::Value =
            serde_json::from_str(&data_json).unwrap_or(serde_json::Value::Null);
        out.push_str(
            &serde_json::json!({
                "ip": ip, "provider": provider, "fetched_at": fetched_at,
                "source_version": source_version, "node": node, "data": data,
            })
            .to_string(),
        );
        out.push('\n');
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/x-ndjson"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"peephole-enrichment.jsonl\"",
            ),
        ],
        out,
    )
        .into_response())
}
```

`templates/admin_export.html`, before `{% endblock %}`:

```html
<section class="card"><h2>Enrichment results</h2>
  <p class="muted">What each provider (GeoIP, Tor exit list, later others) said about each IP, with the time, the data version and the node that looked it up. JSON Lines.</p>
  <a class="btn" href="/admin/export/intel">Download</a></section>
```

`src/admin/cluster.rs`: `MemberView` gains `pub providers: String` (`hb.map(|h| h.providers.join(", ")).unwrap_or_default()`; for this node `node.providers().join(", ")`). `templates/admin_cluster.html`: in the Roles cell append `{% if !m.providers.is_empty() %}<br><span class="muted small">looks up: {{ m.providers }}</span>{% endif %}`; change the Shared intel card's subtitle to `the Tor exit list: fetched by one node, copied by hash`, and add under its table: `<p class="muted">GeoIP databases are not shared. A node that has them looks up the IPs other nodes recorded and shares the results.</p>`.

- [ ] **Step 4: Documentation.**

`README.md`: in "Distributed mode", replace the sentence "…the scan queue, scan results and the Tor intel." by "…the scan queue, scan results and what is known about each IP." and add to "Things to know":

```markdown
- GeoIP: a node with MaxMind credentials downloads the GeoLite2 databases
  for itself. The databases are never passed on. That node looks up the IPs
  the other nodes recorded and shares the results, so one member with
  credentials is enough; without any, the dataset has no GeoIP data. The Tor
  exit list is public and is fetched by one node for all. Every result
  records which provider and which node it came from (Admin → Export).
```

In "Install", the bullet about MaxMind: append "(optional; in a cluster another member's lookups are used when you have none)".

`deploy/config.example.toml`: above `[maxmind]`, replace the comment by: `# Optional. Without credentials this node cannot look up GeoIP data itself; in a cluster it then shows what other members looked up. The databases stay on the node that downloaded them.`

`install.sh`: the MaxMind prompt text becomes `MaxMind GeoLite2 account ID (https://www.maxmind.com/en/accounts/current/license-key; optional: in a cluster the lookups of a member with credentials are shared, the databases are not)` and the warning becomes `no MaxMind credentials: this node cannot look up GeoIP data; it shows what other cluster members look up, if any can`.

- [ ] **Step 5: Run everything, lint, commit**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test && bash -n install.sh`
Expected: PASS.

```bash
git add -A
git commit -m "feat(intel): export enrichment results with provenance; show providers; docs"
```
