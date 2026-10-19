//! Exploit waves: a path shape no rule knows (`shapes.rule_hits = 0`)
//! asked for by many IPs within a short window. Detected on each node from
//! its own rows and kept in `waves`, node-local and never replicated, as
//! the campaigns are ([`super::campaigns`]). A shape forms a wave once.
use super::Store;
use super::shapes::ts_text;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// A detected wave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave {
    pub shape: i64,
    pub text: String,
    /// Start of the window the IPs were counted in (as `requests.ts`).
    pub window_start: String,
    /// Distinct IPs that asked for the shape in the window.
    pub ips: i64,
    pub detected_at: String,
}

/// What the pages show of a shape's wave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveMark {
    pub ips: i64,
    pub window_start: String,
    pub detected_at: String,
}

impl WaveMark {
    /// From the `LEFT JOIN waves` columns: a wave when `ips` is set.
    pub fn from_join(
        ips: Option<i64>,
        window_start: Option<String>,
        detected_at: Option<String>,
    ) -> Option<Self> {
        Some(Self {
            ips: ips?,
            window_start: window_start?,
            detected_at: detected_at?,
        })
    }

    /// Length of the window the IPs were counted in, in minutes.
    pub fn minutes(&self) -> i64 {
        let at = |s: &str| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok();
        match (at(&self.window_start), at(&self.detected_at)) {
            (Some(a), Some(b)) => (b - a).num_minutes(),
            _ => 0,
        }
    }
}

/// How long a shape counts as new on the live feed (a SQLite `datetime`
/// modifier): the server-rendered rows and the stream both read it.
pub const NEW_SHAPE_WINDOW: &str = "-24 hours";

/// The SQL of a feed row's two flags, for a query over `requests r`:
/// whether its shape was first seen within [`NEW_SHAPE_WINDOW`] and
/// whether it formed a wave. Binds nothing; the window is inlined.
pub(crate) fn feed_flags_sql() -> String {
    format!(
        "COALESCE((SELECT sh.first_seen >= datetime('now', '{NEW_SHAPE_WINDOW}')
                   FROM shapes sh WHERE sh.hash = r.shape), 0),
         EXISTS(SELECT 1 FROM waves w WHERE w.shape = r.shape)"
    )
}

/// A row of the New paths page.
#[derive(Debug, Clone, PartialEq)]
pub struct PathRow {
    pub hash: i64,
    pub text: String,
    pub first_seen: String,
    pub last_seen: String,
    pub ips: i64,
    /// Requests that hit a rule; 0: no rule knows it, `None`: not counted
    /// yet.
    pub rule_hits: Option<i64>,
    pub wave: Option<WaveMark>,
    /// The campaigns whose members asked for it.
    pub campaigns: ShapeCampaigns,
}

/// The campaigns of a shape: the [`SHAPE_CAMPAIGNS`] with the most members
/// that asked for it, as `(num, key, members)`, and how many more.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShapeCampaigns {
    pub top: Vec<(i64, String, i64)>,
    pub more: usize,
}

/// Campaigns listed per shape before "+K".
pub const SHAPE_CAMPAIGNS: usize = 3;

type PathTuple = (
    i64,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

type WaveRow = (i64, String, String, i64, String);

fn wave((shape, text, window_start, ips, detected_at): WaveRow) -> Wave {
    Wave {
        shape,
        text,
        window_start,
        ips,
        detected_at,
    }
}

impl Store {
    /// Record and return the new waves at `now`: unknown shapes asked for
    /// by at least `min_ips` distinct IPs, in requests and light rows,
    /// within `window` before `now`, that have not formed a wave before.
    /// Shapes whose rule hits are not counted yet (`NULL`) are skipped.
    pub async fn detect_waves(
        &self,
        now: DateTime<Utc>,
        window: Duration,
        min_ips: i64,
    ) -> Result<Vec<Wave>> {
        let start = now - window;
        let (start_ts, now_ts) = (
            ts_text(start.timestamp_millis()),
            ts_text(now.timestamp_millis()),
        );
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(i64, String, i64)> = sqlx::query_as(
            "WITH asked(shape, ip_id) AS (
               SELECT shape, ip_id FROM requests
               WHERE ts >= ?1 AND ts <= ?2 AND shape IS NOT NULL
               UNION
               SELECT s.shape, b.ip_id FROM skipped_requests s
               JOIN skipped_batches b ON b.id = s.batch_id
               WHERE s.ts_ms >= ?3 AND s.ts_ms <= ?4 AND s.shape IS NOT NULL
             )
             SELECT a.shape, sh.text, COUNT(DISTINCT a.ip_id) AS n
             FROM asked a JOIN shapes sh ON sh.hash = a.shape
             WHERE sh.rule_hits = 0
               AND NOT EXISTS(SELECT 1 FROM waves w WHERE w.shape = a.shape)
             GROUP BY a.shape HAVING n >= ?5
             ORDER BY a.shape",
        )
        .bind(&start_ts)
        .bind(&now_ts)
        .bind(start.timestamp_millis())
        .bind(now.timestamp_millis())
        .bind(min_ips)
        .fetch_all(&mut *tx)
        .await?;
        let mut waves = Vec::with_capacity(rows.len());
        for (shape, text, ips) in rows {
            sqlx::query(
                "INSERT INTO waves (shape, detected_at, window_start, ips) VALUES (?,?,?,?)",
            )
            .bind(shape)
            .bind(&now_ts)
            .bind(&start_ts)
            .bind(ips)
            .execute(&mut *tx)
            .await?;
            waves.push(wave((shape, text, start_ts.clone(), ips, now_ts.clone())));
        }
        tx.commit().await?;
        Ok(waves)
    }

    /// Shapes first seen at or after `since` (all when `None`), newest
    /// first, at most `limit`; with `unknown_only` only those no rule knows.
    /// The campaigns are left empty: see [`Self::campaigns_of_shapes`].
    pub async fn new_paths(
        &self,
        since: Option<&str>,
        unknown_only: bool,
        limit: i64,
    ) -> Result<Vec<PathRow>> {
        let rows: Vec<PathTuple> = sqlx::query_as(
            "SELECT s.hash, s.text, s.first_seen, s.last_seen, s.ips, s.rule_hits,
                    w.ips, w.window_start, w.detected_at
             FROM shapes s LEFT JOIN waves w ON w.shape = s.hash
             WHERE (?1 IS NULL OR s.first_seen >= ?1) AND (?2 = 0 OR s.rule_hits = 0)
             ORDER BY s.first_seen DESC, s.hash LIMIT ?3",
        )
        .bind(since)
        .bind(unknown_only)
        .bind(limit)
        .fetch_all(&self.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(hash, text, first_seen, last_seen, ips, rule_hits, wi, ws, wd)| PathRow {
                    hash,
                    text,
                    first_seen,
                    last_seen,
                    ips,
                    rule_hits,
                    wave: WaveMark::from_join(wi, ws, wd),
                    campaigns: ShapeCampaigns::default(),
                },
            )
            .collect())
    }

    /// The campaigns whose members asked for each of `shapes` (light rows
    /// included), in one query: shapes no member asked for are absent.
    pub async fn campaigns_of_shapes(
        &self,
        shapes: &[i64],
    ) -> Result<HashMap<i64, ShapeCampaigns>> {
        let rows: Vec<(i64, i64, String, i64)> = sqlx::query_as(
            "WITH x(shape, ip_id) AS (
               SELECT r.shape, r.ip_id FROM requests r
               JOIN campaign_members m ON m.ip_id = r.ip_id
               WHERE r.shape IN (SELECT value FROM json_each(?1)) AND r.shape IS NOT NULL
               UNION
               SELECT q.shape, b.ip_id FROM skipped_requests q
               JOIN skipped_batches b ON b.id = q.batch_id
               JOIN campaign_members m ON m.ip_id = b.ip_id
               WHERE q.shape IN (SELECT value FROM json_each(?1)) AND q.shape IS NOT NULL
             )
             SELECT x.shape, c.num, c.key, COUNT(*) AS members
             FROM x JOIN campaign_members m ON m.ip_id = x.ip_id
             JOIN campaigns c ON c.key = m.campaign_key
             GROUP BY x.shape, c.key ORDER BY x.shape, members DESC, c.num",
        )
        .bind(serde_json::to_string(shapes)?)
        .fetch_all(&self.read)
        .await?;
        let mut out: HashMap<i64, ShapeCampaigns> = HashMap::new();
        for (shape, num, key, members) in rows {
            let c = out.entry(shape).or_default();
            if c.top.len() < SHAPE_CAMPAIGNS {
                c.top.push((num, key, members));
            } else {
                c.more += 1;
            }
        }
        Ok(out)
    }

    /// Waves not pushed yet that failed fewer than `max_attempts` pushes,
    /// oldest first, at most `limit`.
    pub async fn waves_to_notify(&self, max_attempts: i64, limit: i64) -> Result<Vec<Wave>> {
        let rows: Vec<WaveRow> = sqlx::query_as(
            "SELECT w.shape, s.text, w.window_start, w.ips, w.detected_at
             FROM waves w JOIN shapes s ON s.hash = w.shape
             WHERE w.notified_at IS NULL AND w.notify_attempts < ?
             ORDER BY w.detected_at, w.shape LIMIT ?",
        )
        .bind(max_attempts)
        .bind(limit)
        .fetch_all(&self.read)
        .await?;
        Ok(rows.into_iter().map(wave).collect())
    }

    /// Record a push of these waves at `at`: done, or one more failed
    /// attempt.
    pub async fn mark_notified(&self, shapes: &[i64], ok: bool, at: &str) -> Result<()> {
        let q = if ok {
            sqlx::query(
                "UPDATE waves SET notified_at = ? WHERE shape IN (SELECT value FROM json_each(?))",
            )
            .bind(at)
        } else {
            sqlx::query(
                "UPDATE waves SET notify_attempts = notify_attempts + 1
                 WHERE shape IN (SELECT value FROM json_each(?))",
            )
        };
        q.bind(serde_json::to_string(shapes)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::model::shape::shape;
    use crate::store::data::{Ctx, apply};

    const CTX: Ctx<'static> = Ctx {
        origin: None,
        hlc: 1,
    };
    const PATH: &str = "/cgi-bin/luci/;stok=/locale";

    fn req(uid: &str, ts: &str, ip: &str, path: &str, labels: &str) -> Record {
        Record::Request(Box::new(RequestRec {
            uid: uid.into(),
            ts: ts.into(),
            ip: ip.into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: labels.into(),
            ..Default::default()
        }))
    }

    fn light(uid: &str, ip: &str, ts_ms: i64, path: &str) -> Record {
        Record::SkipBatch(SkipBatchRec {
            uid: uid.into(),
            ip: ip.into(),
            dropped: 0,
            rows: vec![SkipRow {
                ts_ms,
                method: "GET".into(),
                path: path.into(),
                page_token: None,
                host: None,
                answer: None,
                decoy_v: None,
                decoy_site: None,
                held_ms: None,
                decoy_in: None,
                persona: None,
            }],
            build: String::new(),
        })
    }

    fn now() -> DateTime<Utc> {
        "2026-10-04T13:00:00Z".parse().unwrap()
    }

    fn hour() -> Duration {
        Duration::minutes(60)
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    /// `n` IPs ask for `path` in requests at 12:30, with these labels.
    async fn asked(s: &Store, n: usize, path: &str, labels: &str) {
        let mut conn = s.pool.acquire().await.unwrap();
        for i in 0..n {
            let r = req(
                &format!("{path}-{i}"),
                "2026-10-04 12:30:00",
                &format!("198.51.100.{}", i + 1),
                path,
                labels,
            );
            apply(&mut conn, CTX, &r).await.unwrap();
        }
    }

    #[tokio::test]
    async fn ten_ips_on_an_unknown_shape_form_one_wave_once() {
        let (s, _dir) = store().await;
        asked(&s, 10, PATH, r#"["probe"]"#).await;
        let waves = s.detect_waves(now(), hour(), 10).await.unwrap();
        assert_eq!(
            waves,
            vec![Wave {
                shape: shape(PATH).0,
                text: shape(PATH).1,
                window_start: "2026-10-04 12:00:00".into(),
                ips: 10,
                detected_at: "2026-10-04 13:00:00".into(),
            }]
        );
        assert!(s.detect_waves(now(), hour(), 10).await.unwrap().is_empty());
        // Outside the window nothing counts.
        let later = now() + Duration::minutes(31);
        let (s2, _dir2) = store().await;
        asked(&s2, 10, PATH, r#"["probe"]"#).await;
        assert!(s2.detect_waves(later, hour(), 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nine_ips_are_no_wave() {
        let (s, _dir) = store().await;
        asked(&s, 9, PATH, r#"["probe"]"#).await;
        assert!(s.detect_waves(now(), hour(), 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_shape_a_rule_knows_is_no_wave() {
        let (s, _dir) = store().await;
        asked(&s, 9, PATH, r#"["probe"]"#).await;
        let mut conn = s.pool.acquire().await.unwrap();
        let hit = req(
            "known",
            "2026-10-04 12:40:00",
            "198.51.100.200",
            PATH,
            r#"["rce"]"#,
        );
        apply(&mut conn, CTX, &hit).await.unwrap();
        drop(conn);
        assert!(s.detect_waves(now(), hour(), 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn light_rows_count_toward_the_ips() {
        let (s, _dir) = store().await;
        asked(&s, 5, PATH, r#"["probe"]"#).await;
        let mut conn = s.pool.acquire().await.unwrap();
        // 12:45, five other IPs, light rows only.
        let ms = now().timestamp_millis() - 15 * 60_000;
        for i in 0..5 {
            let b = light(&format!("l{i}"), &format!("203.0.113.{}", i + 1), ms, PATH);
            apply(&mut conn, CTX, &b).await.unwrap();
        }
        drop(conn);
        let waves = s.detect_waves(now(), hour(), 10).await.unwrap();
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0].ips, 10);
    }

    #[tokio::test]
    async fn shapes_not_counted_yet_are_skipped() {
        let (s, _dir) = store().await;
        asked(&s, 10, PATH, r#"["probe"]"#).await;
        sqlx::query("UPDATE shapes SET rule_hits = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(s.detect_waves(now(), hour(), 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_shape_new_after_the_backfill_starts_at_zero_and_can_form_a_wave() {
        let (s, _dir) = store().await;
        super::super::shapes::backfill(&s.pool).await.unwrap();
        asked(&s, 1, PATH, "[]").await;
        let hits: Option<i64> = sqlx::query_scalar("SELECT rule_hits FROM shapes WHERE hash = ?")
            .bind(shape(PATH).0)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(hits, Some(0));
        let mut conn = s.pool.acquire().await.unwrap();
        for i in 2..=10 {
            let r = req(
                &format!("n{i}"),
                "2026-10-04 12:50:00",
                &format!("192.0.2.{i}"),
                PATH,
                r#"["probe"]"#,
            );
            apply(&mut conn, CTX, &r).await.unwrap();
        }
        drop(conn);
        assert_eq!(s.detect_waves(now(), hour(), 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn pushes_are_marked_and_attempts_bounded() {
        let (s, _dir) = store().await;
        asked(&s, 10, PATH, r#"["probe"]"#).await;
        asked(&s, 10, "/HNAP1/", r#"["probe"]"#).await;
        let waves = s.detect_waves(now(), hour(), 10).await.unwrap();
        assert_eq!(waves.len(), 2);
        assert_eq!(s.waves_to_notify(3, 10).await.unwrap(), waves);
        assert_eq!(s.waves_to_notify(3, 1).await.unwrap().len(), 1);
        let (a, b) = (waves[0].shape, waves[1].shape);
        s.mark_notified(&[a], true, "2026-10-04 13:00:01")
            .await
            .unwrap();
        for _ in 0..3 {
            assert_eq!(s.waves_to_notify(3, 10).await.unwrap().len(), 1);
            s.mark_notified(&[b], false, "2026-10-04 13:00:01")
                .await
                .unwrap();
        }
        assert!(s.waves_to_notify(3, 10).await.unwrap().is_empty());
    }
}
