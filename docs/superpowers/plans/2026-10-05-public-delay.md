# Public Delay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every public page and endpoint shows a request only after a
configurable delay plus per-row random jitter. Nothing on the public pages
is live. The wall lists the last N requests of the last 24 h, and the
admin live feed moves to `/admin`.

**Architecture:** An insert trigger stamps each request with `public_at`
(local now + delay + random jitter, from a one-row `publish_cfg` table). A
background task clears `public_at` once it has passed ("release"). Triggers
keep public copies of the per-IP read models (`ips.pub_*`,
`ip_labels.pub_count`) that only move on release. Every anonymous read goes
through `Audience::Public` SQL fragments that read only released rows and
public read models; admin reads are unchanged.

**Tech Stack:** Rust 2024, axum, askama templates, sqlx + SQLite (WAL),
tokio, vanilla JS assets.

**Spec:** `docs/superpowers/specs/2026-10-05-public-delay-design.md`

## Global Constraints

- Work on branch `public-delay` (exists, holds the spec).
- `[public]` settings: `delay_minutes` default 5 (0–60), `jitter_minutes`
  default 5 (0–60), `recent_rows` default 50 (1–200).
- `public_at` and the `pub_*` columns are local to each node. Never add
  them to a cluster `Record`; publishing writes go through `store.pool`
  directly.
- With `delay_s + jitter_s = 0` (the table default) rows are released at
  insert. Tests that never call `set_publish_delay` keep their current
  behaviour.
- Public paths in "Recent requests": no query string, at most 80
  characters including the trailing "…", never linked.
- No public template carries `data-ago`, `data-refresh`, `data-recent`,
  `data-live` or the pulse; times there are static `YYYY-MM-DD HH:MM` UTC.
- Migration statements contain no `;` inside strings and no `--` except
  comments (the splitter in `src/store/mod.rs` strips `--` to end of line).
- Every commit passes `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  and `cargo test`. Commit messages end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **An IP whose only requests are pending** must be a 404 on `/ip/{addr}`
   for anonymous visitors and absent from `/ips` and the blocklist. It must
   also leave the wall's top lists, map and new-IP count untouched (Task 4,
   Task 5 tests).
2. **A known IP gets a new pending request:** public count, last seen,
   labels, max severity, week chart and calendar stay unchanged until
   release (Task 4 test `known_ip_overview_ignores_pending_rows`).
3. **Deleting a pending row** must not decrement public counters, and
   deleting a released row must (Task 1 test `deletes_adjust_the_right_side`).
4. **Reclassification** (`UPDATE requests SET severity/labels_json`) of a
   released row moves the public read models, and of a pending row
   doesn't (Task 1 test `reclassifying_moves_public_models_only_when_released`).
5. **Signed-in admins** still see pending rows everywhere: wall, `/ip`,
   `/ips` (Task 4 test `admin_sees_pending_rows`, Task 5 test
   `signed_in_wall_shows_pending_rows`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/store/migrations/0005_public_delay.sql` (new) | `publish_cfg`, `requests.public_at`, `ips.pub_*`, `ip_labels.pub_count`, backfill, recreated triggers |
| `src/store/publish.rs` (new) | `set_publish_delay`, `release_due`, the `run` loop |
| `src/store/mod.rs` | register migration and module |
| `src/config.rs` | `[public]` fields, defaults, validation |
| `src/lib.rs` | apply delay at startup, spawn publisher, warn at zero |
| `src/store/browse.rs` | `Audience` SQL helpers; `list_ips_as`, `ip_overview_as`, audience-aware IP filter |
| `src/store/stats.rs` | `stats_as`, `map_counts_as`, `recent_requests`, `RECENT_MAX`; cache uses public variants |
| `src/store/canaries.rs` | `canary_summary_as` |
| `src/store/blocklist.rs` | public read models and released rows only |
| `src/admin/views.rs` | `minute`, `public_path` |
| `src/admin/public.rs` | wall page fields, recent rows, delay line |
| `templates/wall.html`, `templates/ip.html`, `templates/ips.html` | static times, recent card, no live elements |
| `assets/js/charts.js` | soft refresh removed |
| `src/admin/pages.rs`, `templates/admin_home.html` | live "Recent activity" on `/admin` |
| `tests/integration.rs` | `full_stack_smoke` sets zero delay |
| `deploy/config.example.toml`, `docs/operations.md`, `CHANGELOG.md` | docs |

---

### Task 1: Migration, triggers, and release

**Files:**
- Create: `src/store/migrations/0005_public_delay.sql`
- Create: `src/store/publish.rs`
- Modify: `src/store/mod.rs` (the `MIGRATIONS` list near line 32, the `mod` declarations)

**Interfaces:**
- Produces: `Store::set_publish_delay(&self, delay: Duration, jitter: Duration) -> anyhow::Result<()>`,
  `Store::release_due(&self) -> anyhow::Result<u64>`,
  `store::publish::run(store: Store, shutdown: tokio::sync::watch::Receiver<bool>)`,
  `store::publish::TICK: Duration`. The schema columns listed in the spec §1.

- [ ] **Step 1: Write the failing tests** at the bottom of the new `src/store/publish.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    async fn hit(s: &Store, ip: &str, severity: i64, labels: &str) -> (i64, i64) {
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let id = s
            .insert_request(&NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/p".into(),
                headers_json: "[]".into(),
                labels_json: labels.into(),
                severity,
                ..Default::default()
            })
            .await
            .unwrap();
        (row.id, id)
    }

    /// (request_count, max_severity, pub_request_count, pub_max_severity,
    ///  pub_first_seen IS NOT NULL, pub_last_seen IS NOT NULL)
    async fn models(s: &Store, ip_id: i64) -> (i64, i64, i64, i64, bool, bool) {
        sqlx::query_as(
            "SELECT request_count, max_severity, pub_request_count, pub_max_severity,
                    pub_first_seen IS NOT NULL, pub_last_seen IS NOT NULL
             FROM ips WHERE id = ?",
        )
        .bind(ip_id)
        .fetch_one(&s.read)
        .await
        .unwrap()
    }

    async fn label(s: &Store, ip_id: i64, l: &str) -> (i64, i64) {
        sqlx::query_as("SELECT count, pub_count FROM ip_labels WHERE ip_id = ? AND label = ?")
            .bind(ip_id)
            .bind(l)
            .fetch_optional(&s.read)
            .await
            .unwrap()
            .unwrap_or((0, 0))
    }

    /// Make every pending row due now.
    async fn make_due(s: &Store) {
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn without_a_delay_rows_are_public_at_once() {
        let (s, _d) = store().await;
        let (ip, _) = hit(&s, "203.0.113.1", 3, r#"["wp"]"#).await;
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE public_at IS NOT NULL")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(pending, 0);
        assert_eq!(models(&s, ip).await, (1, 3, 1, 3, true, true));
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
    }

    #[tokio::test]
    async fn a_delayed_row_waits_within_delay_plus_jitter() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::from_secs(300))
            .await
            .unwrap();
        let (ip, id) = hit(&s, "203.0.113.1", 3, r#"["wp"]"#).await;
        let wait: i64 = sqlx::query_scalar(
            "SELECT CAST(strftime('%s', public_at) AS INTEGER) - CAST(strftime('%s', 'now') AS INTEGER)
             FROM requests WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert!((299..=601).contains(&wait), "waits {wait} s");
        assert_eq!(models(&s, ip).await, (1, 3, 0, 0, false, false));
        assert_eq!(label(&s, ip, "wp").await, (1, 0));
    }

    #[tokio::test]
    async fn release_moves_the_public_models() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 3, r#"["wp","sqli"]"#).await;
        assert_eq!(s.release_due().await.unwrap(), 0, "nothing due yet");
        make_due(&s).await;
        assert_eq!(s.release_due().await.unwrap(), 1);
        assert_eq!(models(&s, ip).await, (1, 3, 1, 3, true, true));
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
        assert_eq!(label(&s, ip, "sqli").await, (1, 1));
        assert_eq!(s.release_due().await.unwrap(), 0, "idempotent");
    }

    #[tokio::test]
    async fn release_covers_more_than_one_chunk() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 1, "[]").await;
        // CHUNK + 5 pending rows, inserted in one statement.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < {})
             INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
             SELECT 'bulk' || x, datetime('now'), {ip}, 'GET', '/b', '[]', '[]', 1 FROM n",
            CHUNK + 4
        )))
        .execute(&s.pool)
        .await
        .unwrap();
        make_due(&s).await;
        assert_eq!(s.release_due().await.unwrap(), CHUNK as u64 + 5);
        assert_eq!(models(&s, ip).await.2, CHUNK + 5);
    }

    #[tokio::test]
    async fn deletes_adjust_the_right_side() {
        let (s, _d) = store().await;
        let (ip, released) = hit(&s, "203.0.113.1", 4, r#"["wp"]"#).await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (_, pending) = hit(&s, "203.0.113.1", 2, r#"["wp"]"#).await;
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert!(s.delete_request(pending).await.unwrap());
        assert_eq!(models(&s, ip).await, (1, 4, 1, 4, true, true), "pending delete leaves public side");
        assert_eq!(label(&s, ip, "wp").await, (1, 1));
        assert!(s.delete_request(released).await.unwrap());
        assert_eq!(models(&s, ip).await.0, 0);
        assert_eq!((models(&s, ip).await.2, models(&s, ip).await.3), (0, 0));
        assert_eq!(label(&s, ip, "wp").await, (0, 0));
    }

    #[tokio::test]
    async fn reclassifying_moves_public_models_only_when_released() {
        let (s, _d) = store().await;
        let (ip, released) = hit(&s, "203.0.113.1", 1, r#"["a"]"#).await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (_, pending) = hit(&s, "203.0.113.1", 1, r#"["a"]"#).await;
        sqlx::query("UPDATE requests SET severity = 4, labels_json = '[\"b\"]' WHERE id = ?")
            .bind(released)
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert_eq!(label(&s, ip, "a").await, (1, 0));
        assert_eq!(label(&s, ip, "b").await, (1, 1));
        sqlx::query("UPDATE requests SET severity = 3, labels_json = '[\"c\"]' WHERE id = ?")
            .bind(pending)
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(models(&s, ip).await, (2, 4, 1, 4, true, true));
        assert_eq!(label(&s, ip, "c").await, (1, 0));
        assert_eq!(label(&s, ip, "b").await, (1, 1));
    }

    #[tokio::test]
    async fn run_releases_and_stops_on_shutdown() {
        let (s, _d) = store().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        let (ip, _) = hit(&s, "203.0.113.1", 2, "[]").await;
        make_due(&s).await;
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run(s.clone(), rx));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while models(&s, ip).await.2 == 0 {
            assert!(std::time::Instant::now() < deadline, "not released");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stops")
            .unwrap();
    }
}
```

Also add to `src/store/mod.rs`'s tests module (next to the existing
`schema_version` assertions near line 447):

```rust
    #[tokio::test]
    async fn migration_0005_keeps_existing_rows_public() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        // A 0.4.0 database: migrations 0001-0004 only, with one request.
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true);
            let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
            check_application_id(&pool).await.unwrap();
            migrate(&pool, &MIGRATIONS[..4]).await.unwrap();
            sqlx::query(
                "INSERT INTO ips (ip, ip_key, first_seen, last_seen)
                 VALUES ('203.0.113.7', '', '2026-01-01 00:00:00', '2026-01-02 00:00:00')",
            )
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
                 VALUES ('old', '2026-01-02 00:00:00', (SELECT id FROM ips WHERE ip = '203.0.113.7'),
                         'GET', '/', '[]', '[\"wp\"]', 2)",
            )
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
        let s = Store::connect(&path).await.unwrap();
        assert_eq!(s.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
        let row: (i64, i64, String, String) = sqlx::query_as(
            "SELECT pub_request_count, pub_max_severity, pub_first_seen, pub_last_seen
             FROM ips WHERE ip = '203.0.113.7'",
        )
        .fetch_one(&s.read)
        .await
        .unwrap();
        assert_eq!(
            row,
            (1, 2, "2026-01-01 00:00:00".into(), "2026-01-02 00:00:00".into())
        );
        let pc: i64 = sqlx::query_scalar("SELECT pub_count FROM ip_labels WHERE label = 'wp'")
            .fetch_one(&s.read)
            .await
            .unwrap();
        assert_eq!(pc, 1);
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE public_at IS NOT NULL")
                .fetch_one(&s.read)
                .await
                .unwrap();
        assert_eq!(pending, 0);
    }
```

(`SqliteConnectOptions`, `SqlitePoolOptions`, `check_application_id` and
`migrate` are already in scope in `src/store/mod.rs`; add a `use` in the
tests module if the compiler disagrees.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib store::publish store::tests::migration_0005`
Expected: compile errors (`publish` module, `set_publish_delay`, `release_due`, `run`, `CHUNK` missing).

- [ ] **Step 3: Write the migration** `src/store/migrations/0005_public_delay.sql`:

```sql
-- Delayed publication (spec 2026-10-05-public-delay). A request reaches
-- public pages only once released (public_at NULL). publish_cfg holds this
-- node's delay, the pub_* columns the public read models. All of it is
-- local to the node and never replicated.
CREATE TABLE publish_cfg (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  delay_s INTEGER NOT NULL,
  jitter_s INTEGER NOT NULL
);
INSERT INTO publish_cfg (id, delay_s, jitter_s) VALUES (1, 0, 0);

ALTER TABLE requests ADD COLUMN public_at TEXT;
CREATE INDEX idx_requests_pending ON requests(public_at) WHERE public_at IS NOT NULL;

ALTER TABLE ips ADD COLUMN pub_request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_max_severity INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_first_seen TEXT;
ALTER TABLE ips ADD COLUMN pub_last_seen TEXT;
UPDATE ips SET pub_request_count = request_count, pub_max_severity = max_severity,
               pub_first_seen = first_seen, pub_last_seen = last_seen
 WHERE request_count > 0;
CREATE INDEX idx_ips_pub_request_count ON ips(pub_request_count, pub_last_seen);
CREATE INDEX idx_ips_pub_last_seen ON ips(pub_last_seen);

ALTER TABLE ip_labels ADD COLUMN pub_count INTEGER NOT NULL DEFAULT 0;
UPDATE ip_labels SET pub_count = count;

DROP TRIGGER requests_agg_ai;
DROP TRIGGER requests_agg_ad;
DROP TRIGGER requests_agg_au;

-- Insert: admin read models as before, then the publication time, then
-- the public read models when the row is public at once.
CREATE TRIGGER requests_agg_ai AFTER INSERT ON requests BEGIN
  UPDATE ips SET request_count = request_count + 1,
                 max_severity = MAX(max_severity, NEW.severity)
   WHERE id = NEW.ip_id;
  INSERT INTO ip_labels (ip_id, label, count)
    SELECT NEW.ip_id, value, 1 FROM (
      SELECT DISTINCT value FROM json_each(
        CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
      WHERE type = 'text')
    WHERE true
    ON CONFLICT (ip_id, label) DO UPDATE SET count = count + 1;
  UPDATE requests SET public_at = (
      SELECT datetime('now', '+' || (delay_s + abs(random() % (jitter_s + 1))) || ' seconds')
        FROM publish_cfg WHERE id = 1 AND delay_s + jitter_s > 0)
   WHERE id = NEW.id AND NEW.public_at IS NULL;
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id
     AND (SELECT public_at FROM requests WHERE id = NEW.id) IS NULL;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id
     AND label IN (SELECT value FROM json_each(
           CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
         WHERE type = 'text')
     AND (SELECT public_at FROM requests WHERE id = NEW.id) IS NULL;
END;

-- Release: a pending row becomes public.
CREATE TRIGGER requests_pub_release AFTER UPDATE OF public_at ON requests
WHEN OLD.public_at IS NOT NULL AND NEW.public_at IS NULL BEGIN
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id
     AND label IN (SELECT value FROM json_each(
           CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
         WHERE type = 'text');
END;

-- Delete: the public side moves only for a released row. Seen-times are
-- not recomputed, as on the admin side.
CREATE TRIGGER requests_agg_ad AFTER DELETE ON requests BEGIN
  UPDATE ips SET pub_request_count = MAX(pub_request_count - 1, 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ips SET pub_max_severity =
      COALESCE((SELECT MAX(severity) FROM requests
                 WHERE ip_id = OLD.ip_id AND public_at IS NULL), 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL AND pub_max_severity <= OLD.severity;
  UPDATE ip_labels SET pub_count = pub_count - 1
   WHERE ip_id = OLD.ip_id AND OLD.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  UPDATE ips SET request_count = MAX(request_count - 1, 0) WHERE id = OLD.ip_id;
  UPDATE ips SET max_severity =
      COALESCE((SELECT MAX(severity) FROM requests WHERE ip_id = OLD.ip_id), 0)
   WHERE id = OLD.ip_id AND max_severity <= OLD.severity;
  UPDATE ip_labels SET count = count - 1
   WHERE ip_id = OLD.ip_id AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  DELETE FROM ip_labels WHERE ip_id = OLD.ip_id AND count <= 0;
END;

-- Reclassification or a moved row: both sides as before, the public side
-- for a released row only.
CREATE TRIGGER requests_agg_au AFTER UPDATE OF ip_id, severity, labels_json ON requests BEGIN
  UPDATE ips SET pub_request_count = MAX(pub_request_count - 1, 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ips SET pub_max_severity =
      COALESCE((SELECT MAX(severity) FROM requests
                 WHERE ip_id = OLD.ip_id AND public_at IS NULL AND id != OLD.id), 0)
   WHERE id = OLD.ip_id AND OLD.public_at IS NULL;
  UPDATE ip_labels SET pub_count = pub_count - 1
   WHERE ip_id = OLD.ip_id AND OLD.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  UPDATE ips SET request_count = MAX(request_count - 1, 0) WHERE id = OLD.ip_id;
  UPDATE ips SET max_severity =
      COALESCE((SELECT MAX(severity) FROM requests WHERE ip_id = OLD.ip_id), 0)
   WHERE id = OLD.ip_id;
  UPDATE ip_labels SET count = count - 1
   WHERE ip_id = OLD.ip_id AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(OLD.labels_json) THEN OLD.labels_json ELSE '[]' END)
     WHERE type = 'text');
  DELETE FROM ip_labels WHERE ip_id = OLD.ip_id AND count <= 0;
  UPDATE ips SET request_count = request_count + 1,
                 max_severity = MAX(max_severity, NEW.severity)
   WHERE id = NEW.ip_id;
  INSERT INTO ip_labels (ip_id, label, count)
    SELECT NEW.ip_id, value, 1 FROM (
      SELECT DISTINCT value FROM json_each(
        CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
      WHERE type = 'text')
    WHERE true
    ON CONFLICT (ip_id, label) DO UPDATE SET count = count + 1;
  UPDATE ips SET pub_request_count = pub_request_count + 1,
                 pub_max_severity = MAX(pub_max_severity, NEW.severity),
                 pub_first_seen = MIN(COALESCE(pub_first_seen, NEW.ts), NEW.ts),
                 pub_last_seen = MAX(COALESCE(pub_last_seen, NEW.ts), NEW.ts)
   WHERE id = NEW.ip_id AND NEW.public_at IS NULL;
  UPDATE ip_labels SET pub_count = pub_count + 1
   WHERE ip_id = NEW.ip_id AND NEW.public_at IS NULL AND label IN (
     SELECT value FROM json_each(
       CASE WHEN json_valid(NEW.labels_json) THEN NEW.labels_json ELSE '[]' END)
     WHERE type = 'text');
END;
```

Notes:
- In `requests_agg_au`, `pub_max_severity` for the old IP excludes the
  updated row (`id != OLD.id`); the row's new severity is added back
  through the `NEW` statements. This matches what the admin side gets by
  recomputing after the update.
- Keep the old trigger statements in their original order: the
  `DELETE FROM ip_labels … count <= 0` has to come after both
  decrements.

- [ ] **Step 4: Register the migration and module.** In `src/store/mod.rs`
  add `include_str!("migrations/0005_public_delay.sql"),` after the 0004
  entry, and `pub mod publish;` next to the other `pub mod` lines.

- [ ] **Step 5: Write `src/store/publish.rs`** (above the tests):

```rust
//! Delayed publication: a request reaches the public pages only once
//! released (`requests.public_at` NULL). The insert trigger sets
//! `public_at` from `publish_cfg`; [`run`] releases due rows. Local to each
//! node: neither the column nor the table is replicated.
use super::Store;
use anyhow::Result;
use std::time::Duration;

/// Rows released per write transaction.
pub(crate) const CHUNK: i64 = 2000;
/// Pause between two chunks, so the trap's inserts waiting for the lock
/// get in.
const CHUNK_PAUSE: Duration = Duration::from_millis(50);
/// How often due rows are released.
pub const TICK: Duration = Duration::from_secs(15);

impl Store {
    /// Delay and jitter for requests inserted from now on; zero releases
    /// them at insert.
    pub async fn set_publish_delay(&self, delay: Duration, jitter: Duration) -> Result<()> {
        sqlx::query("UPDATE publish_cfg SET delay_s = ?, jitter_s = ? WHERE id = 1")
            .bind(delay.as_secs() as i64)
            .bind(jitter.as_secs() as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Release every request whose `public_at` has passed. Returns how many.
    pub async fn release_due(&self) -> Result<u64> {
        let mut total = 0;
        loop {
            let n = sqlx::query(
                "UPDATE requests SET public_at = NULL
                 WHERE id IN (SELECT id FROM requests
                              WHERE public_at IS NOT NULL AND public_at <= datetime('now')
                              ORDER BY public_at LIMIT ?)",
            )
            .bind(CHUNK)
            .execute(&self.pool)
            .await?
            .rows_affected();
            total += n;
            if n < CHUNK as u64 {
                return Ok(total);
            }
            tokio::time::sleep(CHUNK_PAUSE).await;
        }
    }
}

/// Release due rows every [`TICK`] until `shutdown` turns `true`.
pub async fn run(store: Store, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if let Err(e) = store.release_due().await {
            tracing::warn!(?e, "releasing requests to the public pages failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => {}
        }
        if *shutdown.borrow() {
            return;
        }
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib store::publish store::tests::migration_0005`
Expected: all PASS. If `run_releases_and_stops_on_shutdown` fails on
timing because the first `release_due` happens before `make_due`, it's in
the wrong order: `make_due` runs before the spawn, as written.

- [ ] **Step 7: Run the whole suite** (the recreated triggers touch every insert)

Run: `cargo test`
Expected: PASS. A failure here means a trigger statement was mistyped:
compare it with migration 0001 lines 367–418.

- [ ] **Step 8: Commit**

```bash
git add src/store/migrations/0005_public_delay.sql src/store/publish.rs src/store/mod.rs
git commit -m "Store: publication delay, release task and public read models

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Settings and startup wiring

**Files:**
- Modify: `src/config.rs` (`PublicConfig` ~line 149, `Default` ~line 156, `validate` ~line 550, tests module)
- Modify: `src/lib.rs` (after `Store::connect` ~line 108; spawns ~line 183)
- Modify: `tests/integration.rs` (`full_stack_smoke` config ~line 1283)
- Modify: `deploy/config.example.toml` (`[public]` ~line 167)

**Interfaces:**
- Consumes: `Store::set_publish_delay`, `store::publish::run` (Task 1).
- Produces: `PublicConfig { show_labels: bool, delay_minutes: u32, jitter_minutes: u32, recent_rows: usize }`.

- [ ] **Step 1: Write the failing tests** in `src/config.rs`'s tests module:

```rust
    #[test]
    fn public_delay_defaults_and_bounds() {
        let base = format!("{BASE}[roles]\nlistener = false\nweb = false\n");
        let cfg = parse(&base).unwrap();
        assert_eq!(
            (cfg.public.delay_minutes, cfg.public.jitter_minutes, cfg.public.recent_rows),
            (5, 5, 50)
        );
        let with = |extra: &str| parse(&format!("{base}[public]\n{extra}\n"));
        assert!(with("delay_minutes = 0\njitter_minutes = 0").is_ok());
        assert!(with("delay_minutes = 60\njitter_minutes = 60").is_ok());
        assert!(with("delay_minutes = 61").is_err());
        assert!(with("jitter_minutes = 61").is_err());
        assert!(with("recent_rows = 0").is_err());
        assert!(with("recent_rows = 201").is_err());
        assert!(with("recent_rows = 200").is_ok());
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib config::tests::public_delay_defaults_and_bounds`
Expected: compile error, no field `delay_minutes`.

- [ ] **Step 3: Implement.** Replace `PublicConfig` and its `Default`:

```rust
/// `[public]`: what anonymous visitors see.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicConfig {
    /// Rule labels (coarse categories of what an IP requested) on public
    /// pages: per-IP label chips, the label filter and the label chart.
    #[serde(default = "default_true")]
    pub show_labels: bool,
    /// Minutes before a request shows on public pages ...
    #[serde(default = "default_public_delay")]
    pub delay_minutes: u32,
    /// ... plus a random 0 to this many minutes per request.
    #[serde(default = "default_public_delay")]
    pub jitter_minutes: u32,
    /// Rows of the wall's "Recent requests".
    #[serde(default = "default_recent_rows")]
    pub recent_rows: usize,
}

fn default_public_delay() -> u32 {
    5
}

fn default_recent_rows() -> usize {
    50
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            show_labels: true,
            delay_minutes: default_public_delay(),
            jitter_minutes: default_public_delay(),
            recent_rows: default_recent_rows(),
        }
    }
}
```

In `validate`, after the `retention_days` check:

```rust
        let p = &self.public;
        if p.delay_minutes > 60 || p.jitter_minutes > 60 {
            bail!("public.delay_minutes and public.jitter_minutes must be between 0 and 60");
        }
        if !(1..=200).contains(&p.recent_rows) {
            bail!("public.recent_rows must be between 1 and 200");
        }
```

- [ ] **Step 4: Wire startup** in `src/lib.rs`, right after
  `let store = store::Store::connect(&cfg.database_path).await?;`:

```rust
    // Public pages show a request only after this delay (spec 2026-10-05).
    let minutes = |m: u32| std::time::Duration::from_secs(u64::from(m) * 60);
    store
        .set_publish_delay(
            minutes(cfg.public.delay_minutes),
            minutes(cfg.public.jitter_minutes),
        )
        .await?;
    if cfg.public.delay_minutes + cfg.public.jitter_minutes == 0 {
        warn!("[public] delay_minutes and jitter_minutes are 0: public pages show requests at once");
    }
```

After the `store::maintenance::run` spawn:

```rust
    // Release delayed requests to the public pages.
    tokio::spawn(store::publish::run(store.clone(), shutdown_rx.clone()));
```

(`shutdown_rx` is created further down in `run`. If it isn't in scope yet
where `set_publish_delay` runs, that's fine: only the spawn needs it, and
the spawn sits next to the maintenance spawn, which already uses it.)

- [ ] **Step 5: Keep `full_stack_smoke` immediate.** In
  `tests/integration.rs`, in `full_stack_smoke`'s config text, add before
  `[webauthn]`:

```toml
[public]
delay_minutes = 0
jitter_minutes = 0
```

(Check that the config text has no other `[public]` table. If it does,
add the two keys there instead.)

- [ ] **Step 6: Document the settings** in `deploy/config.example.toml`,
  replacing the `[public]` block:

```toml
# [public]
# show_labels = true   # rule labels (coarse categories of what an IP requested):
#                      # per-IP chips, the label filter and the label chart
# delay_minutes = 5    # a request shows on public pages (wall, IPs, blocklist)
# jitter_minutes = 5   # only after the delay plus a random 0..jitter per request
# recent_rows = 50     # rows of the wall's "Recent requests" (last 24 h)
```

- [ ] **Step 7: Run tests**

Run: `cargo test --lib config && cargo test --test integration full_stack_smoke`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/config.rs src/lib.rs tests/integration.rs deploy/config.example.toml
git commit -m "Config: [public] delay, jitter and recent rows; start the publisher

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Audience helpers and public aggregates (wall, map, canary tile)

**Files:**
- Modify: `src/store/browse.rs` (`impl Audience`, ~line 238)
- Modify: `src/store/stats.rs` (`all_time_ip_aggregates`, `ranged_ip_aggregates`, `stats`, `timeline_and_heatmap`, `previous_window`, `families_and_owasp`, `map_counts`, `StatsCache::{stats,map}`)
- Modify: `src/store/canaries.rs` (`canary_summary` ~line 371)

**Interfaces:**
- Consumes: schema from Task 1.
- Produces (used by Tasks 4–6):
  - `Audience::released(self, alias: &str) -> String`
  - `Audience::rm(self) -> &'static str`
  - `Audience::label_count(self) -> &'static str`
  - `Audience::scans(self, alias: &str) -> String`
  - `Store::stats_as(&self, r: Range, a: Audience) -> Result<Stats>` (`stats(r)` = Admin)
  - `Store::map_counts_as(&self, r: Range, a: Audience) -> Result<MapCounts>` (`map_counts(r)` = Admin)
  - `Store::recent_requests(&self, limit: i64, a: Audience) -> Result<Vec<RecentRequest>>`
  - `pub const RECENT_MAX: i64 = 200;` in `stats.rs`
  - `Store::canary_summary_as(&self, r: Range, a: Audience) -> Result<CanarySummary>` (`canary_summary(r)` = Admin)

- [ ] **Step 1: Write the failing tests** in `src/store/stats.rs`'s tests module:

```rust
    async fn delayed() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // One released request from a known IP ...
        let known = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.set_ip_geo(known.id, Some("DE"), Some(3320), Some("DTAG")).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: known.id, method: "GET".into(), path: "/old".into(),
            headers_json: "[]".into(), labels_json: r#"["wp"]"#.into(), severity: 1,
            ..Default::default()
        }).await.unwrap();
        // ... then pending ones: the known IP again, and a new IP.
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: known.id, method: "POST".into(), path: "/new".into(),
            headers_json: "[]".into(), labels_json: r#"["sqli"]"#.into(), severity: 4,
            ..Default::default()
        }).await.unwrap();
        let fresh = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        s.set_ip_geo(fresh.id, Some("US"), Some(15169), Some("G")).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: fresh.id, method: "GET".into(), path: "/fresh".into(),
            headers_json: "[]".into(), labels_json: r#"["sqli"]"#.into(), severity: 4,
            ..Default::default()
        }).await.unwrap();
        (s, dir)
    }

    #[tokio::test]
    async fn public_stats_count_released_rows_only() {
        let (s, _d) = delayed().await;
        for r in Range::ALL {
            let p = s.stats_as(r, Audience::Public).await.unwrap();
            assert_eq!((p.total_requests, p.unique_ips), (1, 1), "{r:?}");
            assert_eq!(p.top_ips.len(), 1, "{r:?}");
            assert_eq!(p.top_ips[0].max_severity, 1, "{r:?}");
            assert!(p.top_labels.iter().all(|l| l.name != "sqli"), "{r:?}");
            assert!(p.recent.iter().all(|x| x.path == "/old"), "{r:?}");
            assert_eq!(p.top_countries.len(), 1, "{r:?}");
            let a = s.stats_as(r, Audience::Admin).await.unwrap();
            assert_eq!((a.total_requests, a.unique_ips), (3, 2), "{r:?}");
        }
        let h = s.stats_as(Range::H24, Audience::Public).await.unwrap();
        assert_eq!(h.new_ips, 1);
        assert_eq!(h.timeline.iter().map(|b| b.count).sum::<i64>(), 1);
        let m = s.map_counts_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!(m.countries.get("US"), None);
        assert_eq!(m.countries.get("DE"), Some(&1));
        let m = s.map_counts_as(Range::H24, Audience::Public).await.unwrap();
        assert_eq!(m.countries.get("US"), None);
    }

    #[tokio::test]
    async fn released_rows_appear_publicly() {
        let (s, _d) = delayed().await;
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool).await.unwrap();
        s.release_due().await.unwrap();
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!((p.total_requests, p.unique_ips), (3, 2));
        assert_eq!(s.recent_requests(RECENT_MAX, Audience::Public).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn recent_requests_cover_the_last_day_newest_first() {
        let (s, _d) = delayed().await;
        let admin = s.recent_requests(2, Audience::Admin).await.unwrap();
        assert_eq!(admin.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(), ["/fresh", "/new"]);
        sqlx::query("UPDATE requests SET ts = datetime('now', '-25 hours') WHERE path = '/old'")
            .execute(&s.pool).await.unwrap();
        assert!(s.recent_requests(RECENT_MAX, Audience::Public).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn public_scans_wait_for_the_delay_and_a_public_ip() {
        let (s, _d) = delayed().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO).await.unwrap();
        // A scan of the public IP finished long ago, one just now, and one
        // of the pending-only IP long ago.
        for (ip, ago) in [("203.0.113.1", "-1 hours"), ("203.0.113.1", "-0 seconds"), ("198.51.100.2", "-1 hours")] {
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at)
                 VALUES ((SELECT id FROM ips WHERE ip = ?), 1, datetime('now', ?), datetime('now', ?))",
            )
            .bind(ip).bind(ago).bind(ago)
            .execute(&s.pool).await.unwrap();
        }
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!((p.scans_done, p.scanned_ips), (1, 1));
        let a = s.stats_as(Range::All, Audience::Admin).await.unwrap();
        assert_eq!((a.scans_done, a.scanned_ips), (3, 2));
    }
```

> Note for the implementer: check the `scans` table's NOT NULL columns in
> `src/store/migrations/0001_initial.sql` (around line 67) and add any
> others the `INSERT` needs (`uid`, for example). Keep `finished_at` as
> written.

Add `use crate::store::browse::Audience;` to the tests module imports if
the `super::*` glob doesn't bring it in.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib store::stats`
Expected: compile errors (`stats_as`, `map_counts_as`, `recent_requests`, `RECENT_MAX` missing).

- [ ] **Step 3: Add the `Audience` helpers** to `impl Audience` in `src/store/browse.rs`:

```rust
    /// `AND`-fragment keeping only the requests this audience may count
    /// (`alias` names the requests table): the public sees released rows.
    pub(crate) fn released(self, alias: &str) -> String {
        match self {
            Self::Admin => String::new(),
            Self::Public => format!(" AND {alias}.public_at IS NULL"),
        }
    }
    /// Prefix of the per-IP read models (`request_count`, `max_severity`,
    /// `first_seen`, `last_seen`) this audience reads: `pub_` for the public.
    pub(crate) fn rm(self) -> &'static str {
        match self {
            Self::Admin => "",
            Self::Public => "pub_",
        }
    }
    /// The `ip_labels` column holding this audience's count.
    pub(crate) fn label_count(self) -> &'static str {
        match self {
            Self::Admin => "count",
            Self::Public => "pub_count",
        }
    }
    /// `AND`-fragment for the scans this audience may count (`alias` names
    /// the scans table): the public sees scans finished at least the
    /// publication delay ago, of IPs it can see.
    pub(crate) fn scans(self, alias: &str) -> String {
        match self {
            Self::Admin => String::new(),
            Self::Public => format!(
                " AND {alias}.finished_at <= datetime('now', '-' || \
                 (SELECT delay_s FROM publish_cfg WHERE id = 1) || ' seconds') \
                 AND EXISTS (SELECT 1 FROM ips pi WHERE pi.id = {alias}.ip_id \
                 AND pi.pub_request_count > 0)"
            ),
        }
    }
```

- [ ] **Step 4: Make the aggregates audience-aware** in `src/store/stats.rs`.
  Add `use super::browse::Audience;` at the top.

  4a. `all_time_ip_aggregates(&self)` → `all_time_ip_aggregates(&self, a: Audience)`.
  Build every SQL string with `let p = a.rm(); let lc = a.label_count();`:

```rust
        let (total_requests, unique_ips, countries, tor_ips): (i64, i64, i64, i64) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT COALESCE(SUM({p}request_count), 0), COUNT(*),
                        COUNT(DISTINCT country), COALESCE(SUM(is_tor_exit = 1), 0)
                 FROM ips WHERE {p}request_count > 0"
            )))
            .fetch_one(&self.read)
            .await?;
        let top_ips = sqlx::query_as::<_, TopIp>(sqlx::AssertSqlSafe(format!(
            "SELECT ip, {p}request_count AS count, country, {p}max_severity AS max_severity,
                    is_tor_exit AS is_tor
             FROM ips WHERE {p}request_count > 0
             ORDER BY {p}request_count DESC, {p}last_seen DESC LIMIT 20"
        )))
        .fetch_all(&self.read)
        .await?;
```

  `top_countries` and `top_asns`: replace `request_count > 0` with
  `{p}request_count > 0` (use `&format!(…)` as the `named` argument).
  `top_labels`:

```rust
                &format!(
                    "SELECT label AS name, SUM({lc}) AS count FROM ip_labels WHERE {lc} > 0
                     GROUP BY label ORDER BY count DESC LIMIT 20"
                ),
```

  4b. `ranged_ip_aggregates(&self, r: Range)` → `(&self, r: Range, a: Audience)`.
  Change its first line to:

```rust
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
```

  No other change: every query there uses alias `r` and `{w}`.

  4c. `timeline_and_heatmap(&self, r)` and `families_and_owasp(&self, r)`
  → add `a: Audience`, with the same two-line `w` change.

  4d. `previous_window(&self, since)` → `(&self, since: &'static str, a: Audience)`:

```rust
        let (total_requests, unique_ips): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*), COUNT(DISTINCT r.ip_id) FROM requests r
             WHERE r.ts >= datetime('now', ?) AND r.ts < datetime('now', ?){}",
            a.released("r")
        )))
        .bind(earlier)
        .bind(since)
        .fetch_one(&self.read)
        .await?;
```

  4e. Add the recent-rows query (above `impl Store`'s `stats`, next to the
  other constants):

```rust
/// Most rows "Recent requests" can show (`[public] recent_rows` is at most
/// this).
pub const RECENT_MAX: i64 = 200;
```

```rust
    /// The newest requests of the last 24 hours this audience may see,
    /// newest first.
    pub async fn recent_requests(&self, limit: i64, a: Audience) -> Result<Vec<RecentRequest>> {
        let sql = format!(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.ts >= datetime('now', '-24 hours'){}
             ORDER BY r.id DESC LIMIT ?",
            a.released("r")
        );
        Ok(
            sqlx::query_as::<_, RecentTuple>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(limit)
                .fetch_all(&self.read)
                .await?
                .into_iter()
                .map(recent_from)
                .collect(),
        )
    }
```

  4f. Rename `pub async fn stats(&self, r: Range)` to
  `pub async fn stats_as(&self, r: Range, a: Audience)` and add the
  wrapper:

```rust
    /// Everything, as an admin sees it.
    pub async fn stats(&self, r: Range) -> Result<Stats> {
        self.stats_as(r, Audience::Admin).await
    }
```

  Inside `stats_as`:
  - `let (w, since) = r.ts_clause("r.ts"); let w = w + &a.released("r");`
  - the aggregates: `Range::All => self.all_time_ip_aggregates(a).await?`, `_ => self.ranged_ip_aggregates(r, a).await?`
  - `let (ws, since_s) = r.ts_clause("s.finished_at"); let ws = ws + &a.scans("s");`
  - `timeline_and_heatmap(r, a)`, `previous_window(m, a)`, `families_and_owasp(r, a)`
  - `new_ips`:

```rust
            _ => {
                let p = a.rm();
                self.count_where(
                    &format!(
                        "SELECT COUNT(*) FROM ips i WHERE i.{p}request_count > 0{}",
                        r.ts_clause(&format!("i.{p}first_seen")).0
                    ),
                    since,
                )
                .await?
            }
```

  - `last_request`:

```rust
        let last_request: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT MAX(r.ts) FROM requests r WHERE 1=1{}",
            a.released("r")
        )))
        .fetch_one(&self.read)
        .await?;
```

  - replace the `recent` query block with `let recent = self.recent_requests(RECENT_MAX, a).await?;`
  - `let sum = self.canary_summary_as(r, a).await?;`
  - update the `recent` field doc on `Stats`: "The newest requests of the
    last 24 hours (up to [`RECENT_MAX`]) this audience may see, for the
    wall's 'Recent requests'. Not serialized to `/api/stats`."

  4g. `map_counts(&self, r)` → `map_counts_as(&self, r: Range, a: Audience)`
  plus a `map_counts(r)` wrapper calling it with `Audience::Admin`:

```rust
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let p = a.rm();
        let sql = match r {
            Range::All => format!(
                "SELECT country AS name, COUNT(*) AS count FROM ips
                 WHERE country IS NOT NULL AND {p}request_count > 0 GROUP BY country"
            ),
            _ => format!(
                "SELECT i.country AS name, COUNT(DISTINCT i.id) AS count
                 FROM requests r JOIN ips i ON r.ip_id = i.id
                 WHERE i.country IS NOT NULL{w} GROUP BY i.country"
            ),
        };
```

  4h. `StatsCache::stats` and `StatsCache::map` call
  `store.stats_as(r, Audience::Public)` and `store.map_counts_as(r, Audience::Public)`.
  `StatsCache::analytics` is unchanged.

- [ ] **Step 5: Canary tile.** In `src/store/canaries.rs`, rename
  `canary_summary` to `canary_summary_as(&self, range, a: crate::store::browse::Audience)`,
  and in the subquery change the `WHERE t.value_hash = c.value_hash` block
  to:

```rust
            "SELECT c.request_id, c.batch_id, c.skip_row, c.kind,
                    (SELECT MIN(CAST(strftime('%s', u.ts) AS INTEGER) - CAST(strftime('%s', c.ts) AS INTEGER))
                     FROM request_tokens t JOIN requests u ON u.id = t.request_id
                     WHERE t.value_hash = c.value_hash
                       AND (c.request_id IS NULL OR t.request_id != c.request_id){rel})
             FROM canaries c WHERE 1 = 1{window}"
```

  with `let rel = a.released("u");` before it. Add:

```rust
    /// Canary reuse as an admin sees it.
    pub async fn canary_summary(&self, range: crate::store::stats::Range) -> Result<CanarySummary> {
        self.canary_summary_as(range, crate::store::browse::Audience::Admin).await
    }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib store::stats store::canaries admin::public`
Expected: PASS. `admin_wall_reads_past_the_cache` still passes because
its rows are released at insert.

- [ ] **Step 7: Commit**

```bash
git add src/store/browse.rs src/store/stats.rs src/store/canaries.rs
git commit -m "Store: wall, map and canary tile read released rows for the public

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Public IP directory, IP page and blocklist

**Files:**
- Modify: `src/store/browse.rs` (`IP_SUMMARY_SELECT` ~line 223, `ip_filter_sql` ~line 290, `list_ips` ~line 500, `matching_ip_ids_after`, `count_ips`, `ip_overview` ~line 614)
- Modify: `src/store/stats.rs` (`StatsCache::{ips, ip}`)
- Modify: `src/store/blocklist.rs`

**Interfaces:**
- Consumes: `Audience::{released, rm, label_count}` (Task 3).
- Produces: `Store::list_ips_as(&self, f: &IpFilter, a: Audience) -> Result<Page<IpSummary>>`
  (`list_ips(f)` = Admin), and
  `Store::ip_overview_as(&self, ip_id: i64, a: Audience) -> Result<Option<IpOverview>>`
  (`ip_overview(id)` = Admin; Public returns `None` when `pub_request_count = 0`).

- [ ] **Step 1: Write the failing tests** in `src/store/browse.rs`'s tests module:

```rust
    /// A released hit from `known`, then (delay on) a pending hit from
    /// `known` and one from `fresh`.
    async fn delayed() -> (Store, tempfile::TempDir, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let req = |ip_id, path: &str, sev, labels: &str| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: labels.into(),
            severity: sev,
            ..Default::default()
        };
        let known = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.insert_request(&req(known.id, "/old", 1, r#"["wp"]"#)).await.unwrap();
        s.set_publish_delay(std::time::Duration::from_secs(300), std::time::Duration::ZERO)
            .await
            .unwrap();
        s.insert_request(&req(known.id, "/new", 4, r#"["sqli"]"#)).await.unwrap();
        let fresh = s.upsert_ip("203.0.113.2".parse().unwrap()).await.unwrap();
        s.insert_request(&req(fresh.id, "/fresh", 4, r#"["sqli"]"#)).await.unwrap();
        (s, dir, known.id, fresh.id)
    }

    #[tokio::test]
    async fn public_directory_lists_released_ips_with_public_counts() {
        let (s, _d, _, _) = delayed().await;
        let p = s.list_ips_as(&IpFilter::default(), Audience::Public).await.unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].ip, "203.0.113.1");
        assert_eq!((p.items[0].request_count, p.items[0].max_severity), (1, 1));
        let by_label = |l: &str| IpFilter { label: Some(l.into()), ..Default::default() };
        assert!(s.list_ips_as(&by_label("sqli"), Audience::Public).await.unwrap().items.is_empty());
        let sev4 = IpFilter { min_severity: Some(4), ..Default::default() };
        assert!(s.list_ips_as(&sev4, Audience::Public).await.unwrap().items.is_empty());
        let exact = IpFilter { q: Some("203.0.113.2".into()), ..Default::default() };
        assert!(s.list_ips_as(&exact, Audience::Public).await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn admin_sees_pending_rows() {
        let (s, _d, known, fresh) = delayed().await;
        assert_eq!(s.list_ips(&IpFilter::default()).await.unwrap().items.len(), 2);
        let ov = s.ip_overview(known).await.unwrap().unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (2, 4));
        assert!(s.ip_overview(fresh).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn known_ip_overview_ignores_pending_rows() {
        let (s, _d, known, fresh) = delayed().await;
        assert!(s.ip_overview_as(fresh, Audience::Public).await.unwrap().is_none());
        let ov = s.ip_overview_as(known, Audience::Public).await.unwrap().unwrap();
        assert_eq!((ov.request_count, ov.max_severity), (1, 1));
        assert_eq!(ov.labels.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["wp"]);
        assert_eq!(ov.week.iter().map(|b| b.count).sum::<i64>(), 1);
        assert_eq!(ov.calendar.iter().map(|d| d.count).sum::<i64>(), 1);
        assert_eq!(ov.net_count, 0, "the pending-only neighbour is not public");
        assert_eq!(ov.ranked, 1);
    }
```

In `src/store/blocklist.rs` add a tests module (or extend the existing one):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    #[tokio::test]
    async fn pending_rows_stay_off_the_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.set_publish_delay(std::time::Duration::from_secs(300), std::time::Duration::ZERO)
            .await
            .unwrap();
        let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 4,
            ..Default::default()
        })
        .await
        .unwrap();
        let q = BlocklistQuery { since: "2000-01-01 00:00:00".into(), min_severity: 3, limit: 100 };
        assert!(s.blocklist_ips(&q).await.unwrap().is_empty());
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds')")
            .execute(&s.pool)
            .await
            .unwrap();
        s.release_due().await.unwrap();
        assert_eq!(s.blocklist_ips(&q).await.unwrap(), ["203.0.113.5"]);
    }
}
```

Add `use crate::store::requests::NewRequest;` to the browse tests module
if it isn't imported there yet.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib store::browse store::blocklist`
Expected: compile errors (`list_ips_as`, `ip_overview_as` missing), and the blocklist test fails.

- [ ] **Step 3: Directory.** In `src/store/browse.rs` replace `IP_SUMMARY_SELECT` with:

```rust
/// `IpSummary` columns as `a` sees them.
fn ip_summary_select(a: Audience) -> String {
    let p = a.rm();
    format!(
        "SELECT i.ip, i.country, i.asn, i.asn_org, i.is_tor_exit AS is_tor,
                i.{p}first_seen AS first_seen, i.{p}last_seen AS last_seen,
                i.{p}request_count AS request_count, i.{p}max_severity AS max_severity,
                i.abuse_score
         FROM ips i"
    )
}
```

  `ip_filter_sql(f: &IpFilter)` → `ip_filter_sql(f: &IpFilter, a: Audience)`.
  At its start:

```rust
    if a == Audience::Public {
        wheres.push("i.pub_request_count > 0".into());
    }
```

  Label and severity clauses:

```rust
    if let Some(l) = nonempty(&f.label) {
        wheres.push(format!(
            "i.id IN (SELECT l.ip_id FROM ip_labels l WHERE l.label = ? AND l.{} > 0)",
            a.label_count()
        ));
        binds.push(l);
    }
    if let Some(m) = f.min_severity {
        wheres.push(format!("i.{}max_severity >= CAST(? AS INTEGER)", a.rm()));
        binds.push(m.to_string());
    }
```

  `matching_ip_ids_after` and `count_ips` pass `Audience::Admin` (bulk
  actions are admin-only). Rename `list_ips` to `list_ips_as(&self, f, a)`:

```rust
        let Some(fs) = ip_filter_sql(f, a) else { … unchanged … };
        let p = a.rm();
        let order = match f.sort.as_deref() {
            Some("recent") => format!("i.{p}last_seen DESC"),
            Some("abuse") => format!("i.abuse_score IS NULL, i.abuse_score DESC, i.{p}last_seen DESC"),
            _ => format!("i.{p}request_count DESC, i.{p}last_seen DESC"),
        };
        let sql = format!(
            "{}{} ORDER BY {order} LIMIT {} OFFSET {}",
            ip_summary_select(a),
            fs.where_sql,
            PAGE_SIZE + 1,
            offset(page)
        );
```

  and add:

```rust
    pub async fn list_ips(&self, f: &IpFilter) -> Result<Page<IpSummary>> {
        self.list_ips_as(f, Audience::Admin).await
    }
```

- [ ] **Step 4: IP overview.** Rename `ip_overview(&self, ip_id)` to
  `ip_overview_as(&self, ip_id: i64, a: Audience)` and add the Admin
  wrapper `ip_overview(&self, ip_id)`. Inside, with `let p = a.rm(); let lc = a.label_count(); let rel = a.released("requests");`:

```rust
        let row_sql = match a {
            Audience::Admin => "SELECT * FROM ips WHERE id = ?",
            Audience::Public => {
                "SELECT id, ip, pub_first_seen AS first_seen, pub_last_seen AS last_seen,
                        country, asn, asn_org, is_tor_exit, fp_claimed, notes,
                        pub_request_count AS request_count, pub_max_severity AS max_severity
                 FROM ips WHERE id = ? AND pub_request_count > 0"
            }
        };
        let Some(ip) = sqlx::query_as::<_, IpRow>(row_sql)
            .bind(ip_id)
            .fetch_optional(&self.read)
            .await?
        else {
            return Ok(None);
        };
```

  - labels: `format!("SELECT label AS name, {lc} AS count FROM ip_labels WHERE ip_id = ? AND {lc} > 0 ORDER BY count DESC, label LIMIT 20")`
  - families: `format!("SELECT label, {lc} FROM ip_labels WHERE ip_id = ? AND {lc} > 0")`
  - week: `format!("SELECT strftime('%Y-%m-%dT%H:00', ts) AS h, severity, COUNT(*) FROM requests WHERE ip_id = ? AND ts >= datetime('now','-7 days'){rel} GROUP BY h, severity ORDER BY h")`
  - calendar: `format!("SELECT date(ts) AS day, COUNT(*) AS count, MAX(severity) AS max_severity FROM requests WHERE ip_id = ? AND ts >= date('now', ?){rel} GROUP BY day ORDER BY day")`
  - rank: `format!("SELECT (SELECT COUNT(*) + 1 FROM ips WHERE {p}request_count > ?1), (SELECT COUNT(*) FROM ips WHERE {p}request_count > 0)")`
  - neighbour count: replace `request_count > 0` with `{p}request_count > 0`
  - neighbours: `SELECT ip, {p}request_count AS request_count, {p}max_severity AS max_severity FROM ips WHERE ip_key BETWEEN ? AND ? AND id != ? AND {p}request_count > 0{v6} ORDER BY {p}request_count DESC, ip LIMIT 8`
  - asn_count: `format!("SELECT COUNT(*) FROM ips WHERE asn = ? AND id != ? AND {p}request_count > 0")`

  Wrap every string that is now a `format!` result in
  `sqlx::AssertSqlSafe(…)`, as the existing neighbour queries do. The
  `request_count`/`max_severity` fields of `IpOverview` keep coming from
  `ip` (which already holds the audience's values).

- [ ] **Step 5: Caches.** In `src/store/stats.rs`, `StatsCache::ips` calls
  `store.list_ips_as(&f, Audience::Public)` and `StatsCache::ip` calls
  `store.ip_overview_as(ip_id, Audience::Public)`.

- [ ] **Step 6: Blocklist.** In `src/store/blocklist.rs`:

```rust
            "SELECT i.ip FROM ips i
             WHERE i.pub_last_seen >= ?1 AND i.pub_max_severity >= ?2 AND i.is_tor_exit = 0
               AND EXISTS (SELECT 1 FROM requests r
                           WHERE r.ip_id = i.id AND r.severity >= ?2 AND r.ts >= ?1
                             AND r.public_at IS NULL)
               AND NOT EXISTS (SELECT 1 FROM scan_jobs j
                               WHERE j.ip_id = i.id AND j.status = 'refused'
                                 AND j.error LIKE 'verified crawler%')
             ORDER BY i.pub_last_seen DESC LIMIT ?3",
```

  and in `blocklist_spared_ips` use `WHERE i.pub_last_seen >= ?1`. Update
  the module doc: "Public, like the IP directory it is drawn from: only
  released requests count (`[public] delay_minutes`)."

- [ ] **Step 7: Run tests**

Run: `cargo test --lib store admin`
Expected: PASS. If an existing `admin::blocklist` test fails because its
fixture sets `ips.last_seen` directly, set `pub_last_seen` in the same
`UPDATE`. Its fixture uses `insert_request`, which needs no change.

- [ ] **Step 8: Commit**

```bash
git add src/store/browse.rs src/store/stats.rs src/store/blocklist.rs
git commit -m "Store: public IP directory, IP page and blocklist read released rows

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Public pages: Recent requests, static times, no live elements

**Files:**
- Modify: `src/admin/views.rs` (add `minute`, `public_path`)
- Modify: `src/admin/public.rs` (`WallPage` ~line 56, `wall` ~line 128, tests)
- Modify: `templates/wall.html` (lines 5, 9, the "Recent activity" section ~162–181)
- Modify: `templates/ip.html` (lines 11–12)
- Modify: `templates/ips.html` (line 60)
- Modify: `assets/js/charts.js` (the "Soft refresh" block, ~lines 436–462)

**Interfaces:**
- Consumes: `Stats.recent` (up to `RECENT_MAX` rows, audience-filtered; Task 3), `cfg.public.{delay_minutes, jitter_minutes, recent_rows}` (Task 2).
- Produces: `views::minute<S: Stamp>(ts: S) -> String`, `views::public_path<S: AsRef<str>>(p: S) -> String`.

- [ ] **Step 1: Write the failing tests.** In `src/admin/views.rs` tests (create a `#[cfg(test)] mod tests` if none exists):

```rust
    #[test]
    fn minute_and_public_path() {
        assert_eq!(minute("2026-10-05 12:34:56"), "2026-10-05 12:34");
        assert_eq!(minute("garbage"), "");
        assert_eq!(public_path("/short"), "/short");
        let long = format!("/{}", "a".repeat(100));
        let cut = public_path(&long);
        assert_eq!(cut.chars().count(), 80);
        assert!(cut.ends_with('…'));
        let exact = format!("/{}", "é".repeat(79));
        assert_eq!(public_path(&exact), exact, "80 characters stay whole");
    }
```

In `src/admin/public.rs` tests:

```rust
    async fn admin_cookie(st: &AdminState) -> String {
        let token = st.store.create_session().await.unwrap();
        format!("{}={token}", crate::admin::auth::session_cookie_name(&st.cfg))
    }

    async fn get_with(app: &axum::Router, path: &str, cookie: Option<&str>) -> (u16, String) {
        let mut req = axum::http::Request::get(path);
        if let Some(c) = cookie {
            req = req.header(axum::http::header::COOKIE, c);
        }
        let r = app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
        let status = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&b).into_owned())
    }

    /// `state(true)` plus, with a 5 min delay, a pending request from a
    /// new IP with a long path and a query string.
    async fn delayed_state() -> (Arc<AdminState>, tempfile::TempDir) {
        let (st, dir) = state(true).await;
        st.store
            .set_publish_delay(std::time::Duration::from_secs(300), std::time::Duration::ZERO)
            .await
            .unwrap();
        let ip = st.store.upsert_ip("198.51.100.77".parse().unwrap()).await.unwrap();
        st.store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/pending-path".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                severity: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        (st, dir)
    }

    #[tokio::test]
    async fn anonymous_wall_is_static_and_lists_released_requests() {
        let (st, _d) = delayed_state().await;
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", None).await;
        for live in ["data-refresh", "data-ago", "pulse-dot", "data-recent", "data-live"] {
            assert!(!wall.contains(live), "anonymous wall carries {live}");
        }
        assert!(wall.contains("Recent requests"));
        assert!(wall.contains("Data delayed by about 5–10 min"));
        assert!(wall.contains(r#"<td class="path">/x</td>"#), "released request listed");
        assert!(!wall.contains("/pending-path"), "pending request hidden");
        assert!(!wall.contains("198.51.100.77"));
    }

    #[tokio::test]
    async fn signed_in_wall_shows_pending_rows() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", Some(&cookie)).await;
        assert!(wall.contains("/pending-path"));
        assert!(wall.contains("Live view (signed in)"));
        assert!(!wall.contains("data-recent"), "the live feed lives on /admin now");
    }

    #[tokio::test]
    async fn pending_only_ip_is_a_404_for_the_public() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        assert_eq!(get_with(&app, "/ip/198.51.100.77", None).await.0, 404);
        assert_eq!(get_with(&app, "/ip/198.51.100.77", Some(&cookie)).await.0, 200);
        let (_, ips) = get_with(&app, "/ips", None).await;
        assert!(!ips.contains("198.51.100.77"));
        assert!(!ips.contains("data-ago"));
        let (_, ip) = get_with(&app, "/ip/203.0.113.9", None).await;
        assert!(!ip.contains("data-ago"));
    }

    #[tokio::test]
    async fn recent_requests_hide_queries_cut_paths_and_respect_labels() {
        let (st, _d) = state(false).await;
        let ip = st.store.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        st.store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: format!("/{}", "z".repeat(120)),
                query: Some("token=hunter2".into()),
                headers_json: "[]".into(),
                labels_json: r#"["secret-category"]"#.into(),
                severity: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        let app = crate::admin::full_router(st.clone());
        let (_, wall) = get_with(&app, "/", None).await;
        assert!(!wall.contains("hunter2"));
        assert!(wall.contains(&format!("/{}…", "z".repeat(78))));
        assert!(!wall.contains(&"z".repeat(80)));
        assert!(!wall.contains("secret-category"), "labels hidden with show_labels = false");
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib admin::views admin::public`
Expected: compile errors (`minute`, `public_path`), then assertion failures on the wall.

- [ ] **Step 3: View helpers** in `src/admin/views.rs`, below `ago`:

```rust
/// `YYYY-MM-DD HH:MM` (UTC) for static times on public pages; "" when
/// unparsable.
pub fn minute<S: Stamp>(ts: S) -> String {
    ts.utc()
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

/// Longest path "Recent requests" shows, "…" included.
const PUBLIC_PATH_MAX: usize = 80;

/// A request path for the public "Recent requests": whole up to
/// [`PUBLIC_PATH_MAX`] characters, else cut to fit with a trailing "…".
pub fn public_path<S: AsRef<str>>(path: S) -> String {
    let p = path.as_ref();
    if p.chars().count() <= PUBLIC_PATH_MAX {
        return p.to_string();
    }
    let cut: String = p.chars().take(PUBLIC_PATH_MAX - 1).collect();
    format!("{cut}…")
}
```

- [ ] **Step 4: Wall handler.** In `src/admin/public.rs`, replace
  `WallPage`'s `recent_max_id` field with:

```rust
    /// "Recent requests": the newest `[public] recent_rows` of `stats.recent`.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// Shortest and longest publication delay, in minutes.
    delay_min: u32,
    delay_max: u32,
```

  In `wall`, replace `recent_max_id: …` with:

```rust
        recent: stats
            .recent
            .iter()
            .take(state.cfg.public.recent_rows)
            .cloned()
            .collect(),
        delay_min: state.cfg.public.delay_minutes,
        delay_max: state.cfg.public.delay_minutes + state.cfg.public.jitter_minutes,
```

  (The `recent` field must be set before `stats` is moved into the struct.
  Bind `let recent = …;` above `render(&WallPage { … })` and use
  `recent,` inside.)

- [ ] **Step 5: Wall template** `templates/wall.html`:
  - line 5: remove ` data-refresh="{{ crate::store::stats::ttl(range.clone()).as_secs() }}"`.
  - line 9: replace the whole `<p class="pulse" …>…</p>` with

```html
    <p class="muted">{% if chrome.authed %}Live view (signed in); the public sees this {{ delay_min }}–{{ delay_max }} min later.{% else %}Data delayed by about {{ delay_min }}–{{ delay_max }} min.{% endif %}</p>
```

  - replace the `{% if chrome.authed %}<section class="card">…Recent activity…</section>{% endif %}` block with:

```html
  <section class="card">
    <div class="card-head"><h2>Recent requests</h2><span class="muted">last 24 h · UTC</span></div>
    <div class="table-wrap wide"><table>
      <thead><tr><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Path</th><th>Sev</th>{% if labels %}<th>Labels</th>{% endif %}</tr></thead>
      <tbody>
      {% for r in recent %}
        <tr data-sev="{{ r.severity }}">
          <td class="ts">{{ crate::admin::views::minute(r.ts) }}</td>
          <td class="ip"><a href="/ip/{{ r.ip }}">{{ r.ip }}</a>{% if let Some(c) = r.country %} <span class="flag" title="{{ crate::admin::countries::country_name(c) }}">{{ crate::admin::countries::flag(c) }}</span>{% endif %}</td>
          <td class="mono">{{ r.method }}</td>
          <td class="path">{{ crate::admin::views::public_path(r.path) }}</td>
          <td>{% let sev = r.severity %}{% include "_severity.html" %}</td>
          {% if labels %}<td><span class="chips">{% for l in r.labels %}<span class="badge badge-label {{ crate::admin::views::label_class(l) }}">{{ l }}</span>{% endfor %}{% for o in r.owasp %}<span class="badge badge-owasp" title="{{ crate::admin::views::owasp_name(o) }}">{{ o }}</span>{% endfor %}</span></td>{% endif %}
        </tr>
      {% endfor %}
      {% if recent.is_empty() %}<tr><td colspan="{{ 5 + labels as usize }}" class="empty">Nothing yet.</td></tr>{% endif %}
      </tbody>
    </table></div>
  </section>
```

  The OWASP badges show with the labels: the public JSON already hides
  OWASP when labels are hidden.

- [ ] **Step 6: Static times.** `templates/ip.html` lines 11–12:

```html
      <span>first seen <span class="mono">{{ crate::admin::views::minute(ov.ip.first_seen) }}</span> UTC</span>
      <span>last seen <span class="mono">{{ crate::admin::views::minute(ov.ip.last_seen) }}</span> UTC</span>
```

  `templates/ips.html` lines 59–60:

```html
      <td class="ts">{{ crate::admin::views::minute(i.first_seen) }}</td>
      <td class="ts">{{ crate::admin::views::minute(i.last_seen) }}</td>
```

- [ ] **Step 7: Remove the soft refresh.** In `assets/js/charts.js`,
  `bootWall`, delete from the comment line `// Soft refresh: while the tab is visible, …`
  through `document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });`
  inclusive. If `load` or `map.update` end up unused, leave them: `load` is
  still called once on boot, and `map.update` is part of the chart API.

- [ ] **Step 8: Find leftovers**

Run: `grep -rn 'recent_max_id\|data-region\|data-updated' src templates assets`
Expected: no `recent_max_id`. `data-region` and `data-updated` may remain
only if something other than the deleted refresh reads them. Otherwise
remove them from `templates/wall.html`.

- [ ] **Step 9: Run tests**

Run: `cargo test --lib admin && cargo test --test integration`
Expected: PASS. If `wall_shows_aggregates_not_payloads` in
`tests/integration.rs` asserts that paths never appear on the anonymous
wall, update it: paths without query strings now appear in "Recent
requests". Keep its assertions that bodies, headers and query strings
never appear.

- [ ] **Step 10: Commit**

```bash
git add src/admin/views.rs src/admin/public.rs templates/wall.html templates/ip.html templates/ips.html assets/js/charts.js tests/integration.rs
git commit -m "Public pages: delayed Recent requests, static times, no live refresh

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Live "Recent activity" on `/admin`

**Files:**
- Modify: `src/admin/pages.rs` (`HomePage` ~line 67, `home` ~line 83, tests)
- Modify: `templates/admin_home.html`

**Interfaces:**
- Consumes: `Store::recent_requests(limit, Audience::Admin)` (Task 3), the SSE endpoint `/admin/api/recent?after=<id>` and `app.js`'s `[data-recent]` handling (unchanged).

- [ ] **Step 1: Write the failing test** in `src/admin/public.rs`'s tests
  (it has the helpers from Task 5):

```rust
    #[tokio::test]
    async fn admin_overview_has_the_live_feed() {
        let (st, _d) = delayed_state().await;
        let cookie = admin_cookie(&st).await;
        let app = crate::admin::full_router(st.clone());
        let (status, home) = get_with(&app, "/admin", Some(&cookie)).await;
        assert_eq!(status, 200);
        assert!(home.contains("data-recent"));
        assert!(home.contains("/admin/api/recent?after="));
        assert!(home.contains("/pending-path"), "admins see pending rows at once");
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib admin::public::tests::admin_overview_has_the_live_feed`
Expected: FAIL (`data-recent` missing).

- [ ] **Step 3: Handler.** In `src/admin/pages.rs` add to `HomePage`:

```rust
    /// "Recent activity": the newest requests, then live over SSE.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// The newest request id shown (the live feed's cursor).
    recent_max_id: i64,
```

  In `home`, before `render`:

```rust
    let recent = st
        .store
        .recent_requests(50, crate::store::browse::Audience::Admin)
        .await?;
    let recent_max_id = recent.iter().map(|r| r.id).max().unwrap_or(0);
```

  and pass `recent, recent_max_id,` into `HomePage`. (50 matches `rMax` in
  `assets/js/app.js`.)

- [ ] **Step 4: Template.** In `templates/admin_home.html`, insert as the
  first child of `<div class="stack">`:

```html
  <section class="card">
    <div class="card-head"><h2>Recent activity</h2><span class="row"><span class="live" data-live><span class="live-dot"></span><span data-live-label>connecting…</span></span><a href="/requests">search all →</a></span></div>
    <div class="table-wrap wide"><table data-recent data-src="/admin/api/recent?after={{ recent_max_id }}" data-labels="1">
      <thead><tr><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Path</th><th>Sev</th><th>Labels</th></tr></thead>
      <tbody>
      {% for r in recent %}
        <tr data-sev="{{ r.severity }}">
          <td class="ts">{{ r.ts }}</td>
          <td class="ip"><a href="/ip/{{ r.ip }}">{{ r.ip }}</a>{% if let Some(c) = r.country %} <span class="flag" title="{{ crate::admin::countries::country_name(c) }}">{{ crate::admin::countries::flag(c) }}</span>{% endif %}</td>
          <td class="mono">{{ r.method }}</td>
          <td class="path"><a href="/admin/requests/{{ r.id }}">{{ r.path }}</a></td>
          <td>{% let sev = r.severity %}{% include "_severity.html" %}</td>
          <td><span class="chips">{% for l in r.labels %}<span class="badge badge-label {{ crate::admin::views::label_class(l) }}">{{ l }}</span>{% endfor %}{% for o in r.owasp %}<span class="badge badge-owasp" title="{{ crate::admin::views::owasp_name(o) }}">{{ o }}</span>{% endfor %}</span></td>
        </tr>
      {% endfor %}
      {% if recent.is_empty() %}<tr data-empty><td colspan="6" class="empty">Nothing yet.</td></tr>{% endif %}
      </tbody>
    </table></div>
  </section>
```

  `admin_home.html` doesn't load `charts.js`, and `app.js` (which runs the
  `[data-recent]` feed) is loaded by `layout.html` on every page, so no
  script tag is needed. Confirm with
  `grep -n 'app.js' templates/layout.html`.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib admin && cargo test --test integration`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/admin/pages.rs templates/admin_home.html src/admin/public.rs
git commit -m "Admin overview: live Recent activity (moved from the wall)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Documentation and full verification

**Files:**
- Modify: `docs/operations.md` (section `## Day to day`, ~line 219)
- Modify: `CHANGELOG.md` (`## [Unreleased]`)

- [ ] **Step 1: Operations doc.** Add under `## Day to day`:

```markdown
### Public pages are delayed

The wall, the IP directory, IP pages, `/api/stats`, `/api/map` and
`/api/blocklist` show a request only after `[public] delay_minutes` plus
a random 0 to `jitter_minutes` (5 + 0–5 min by default), counted from when
this node stored it. Someone probing an address and watching the wall can't
tell from the timing whether it was one of yours. Signed-in admins see
everything at once; the live feed is on the admin Overview. A changed delay
applies to requests stored after the restart. Setting both to 0 publishes
at once (logged as a warning).
```

- [ ] **Step 2: Changelog.** Under `## [Unreleased]`:

```markdown
### Added

- The wall lists the newest requests of the last 24 hours ("Recent
  requests", `[public] recent_rows`, default 50): time, IP, method, path
  (no query string, cut at 80 characters), severity and, when shown,
  labels.

### Changed

- Public pages and feeds (wall, IP directory, IP pages, `/api/stats`,
  `/api/map`, `/api/blocklist`) show a request only after
  `[public] delay_minutes` plus a random 0–`jitter_minutes` (default
  5 + 0–5 min). Nothing on them updates live any more: no auto-refresh, no
  "last hit … ago", static UTC times.
- The live "Recent activity" feed moved from the wall to the admin
  Overview.
```

- [ ] **Step 3: Full verification**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all clean and PASS. Paste the final `test result:` lines in the
task report.

- [ ] **Step 4: Commit**

```bash
git add docs/operations.md CHANGELOG.md
git commit -m "Docs: delayed public pages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
