//! One address's (or one campaign's) observations as a single stream, newest first: its
//! requests, webshell commands, uploads, canaries, probes, scans, browser
//! fingerprints and intel fetches (the IP page's Timeline).
//!
//! One statement: every kind is a `UNION ALL` branch bounded by its own
//! `ORDER BY … LIMIT` on its `ip_id` index, so the outer sort sees at most
//! `kinds × limit` rows whatever the address's history. SQLite refuses
//! `ORDER BY`/`LIMIT` in a bare compound branch, so each branch is wrapped
//! as `SELECT * FROM (…)`. Only the branches of the asked kinds are built:
//! the public call never reads uploads, canaries, fingerprints, intel or
//! webshell requests.
//!
//! Paging is a keyset on the sort order `(ts DESC, k, id DESC)`: the cursor
//! is the last shown row's `ts` plus its `k` and `id`, so a page boundary
//! inside one second neither repeats nor skips a row. A cursor without the
//! `k.id` part pages by `ts < before`.
use super::Store;
use super::browse::Audience;
use anyhow::Result;

/// Rows a page may ask for.
pub const MAX_LIMIT: i64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Request,
    Webshell,
    Upload,
    Canary,
    Probe,
    Scan,
    Fingerprint,
    Intel,
}

impl EventKind {
    pub const ALL: [Self; 8] = [
        Self::Request,
        Self::Webshell,
        Self::Upload,
        Self::Canary,
        Self::Probe,
        Self::Scan,
        Self::Fingerprint,
        Self::Intel,
    ];
    /// What the public IP page shows (owner, MIK-497): no uploads, commands,
    /// canaries, fingerprints or intel fetches.
    pub const PUBLIC: [Self; 3] = [Self::Request, Self::Scan, Self::Probe];

    /// The `k` column: also the second sort key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Webshell => "webshell",
            Self::Upload => "upload",
            Self::Canary => "canary",
            Self::Probe => "probe",
            Self::Scan => "scan",
            Self::Fingerprint => "fingerprint",
            Self::Intel => "intel",
        }
    }

    fn from_key(k: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.key() == k)
    }
}

/// Where a page starts: strictly after this row in the sort order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// `YYYY-MM-DD HH:MM:SS`.
    pub ts: String,
    /// The row at `ts` it follows; None: every row at `ts` is on the page.
    pub at: Option<(EventKind, i64)>,
}

impl Cursor {
    /// `before` must be `YYYY-MM-DD HH:MM:SS`, `at` `<kind>.<id>`; a bad
    /// `before` is no cursor (the first page), a bad `at` is dropped.
    pub fn parse(before: Option<&str>, at: Option<&str>) -> Option<Self> {
        let ts = before?;
        chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S").ok()?;
        if ts.len() != 19 {
            return None;
        }
        let at = at.and_then(|s| {
            let (k, id) = s.split_once('.')?;
            Some((EventKind::from_key(k)?, id.parse().ok()?))
        });
        Some(Self {
            ts: ts.to_string(),
            at,
        })
    }

    /// The `at` query value.
    pub fn at_param(&self) -> Option<String> {
        self.at.map(|(k, id)| format!("{}.{id}", k.key()))
    }
}

/// One observation of an address.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Event {
    pub ts: String,
    /// The member it is of, on a campaign's events; None on one address's.
    pub ip: Option<String>,
    /// [`EventKind::key`]; read through [`Event::kind`].
    pub k: String,
    /// Of its own table (canaries: the rowid; intel: the hlc).
    pub id: i64,
    /// Requests and commands only.
    pub severity: Option<i64>,
    /// Kind-specific text: the command, the upload, the canary kind, the
    /// probe's vantage IP, the scan level, the fingerprint hash, the intel
    /// provider. Attacker-controlled for commands and uploads.
    pub summary: Option<String>,
    /// Admin only: the cluster node that recorded it.
    pub node: Option<String>,
    /// The upload uid, fingerprint hash or canary's request id, for `href`.
    #[sqlx(rename = "ref")]
    pub reference: Option<String>,
    /// Requests and commands only, as in [`super::browse::RequestListRow`].
    pub method: Option<String>,
    pub path: Option<String>,
    /// Admin only.
    pub query: Option<String>,
    pub labels_json: Option<String>,
    pub owasp_json: Option<String>,
    /// Admin only, as in `RequestListRow` (`_canary_marks.html`).
    pub canary_served: bool,
    pub canary_used: Option<i64>,
    pub canary_from: Option<i64>,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        // Every branch writes a known key.
        EventKind::from_key(&self.k).unwrap_or(EventKind::Request)
    }
    /// A request row (plain or webshell): rendered like the Requests table.
    pub fn is_request(&self) -> bool {
        matches!(self.kind(), EventKind::Request | EventKind::Webshell)
    }
    pub fn labels(&self) -> Vec<String> {
        json_list(self.labels_json.as_deref())
    }
    pub fn owasp(&self) -> Vec<String> {
        json_list(self.owasp_json.as_deref())
    }
    /// Its admin page; None for probes and intel fetches. Every renderer
    /// links through this, so they link alike.
    pub fn href(&self) -> Option<String> {
        let r = self.reference.as_deref().unwrap_or("");
        match self.kind() {
            EventKind::Request | EventKind::Webshell => {
                Some(format!("/admin/requests/{}", self.id))
            }
            EventKind::Upload => Some(format!(
                "/admin/uploads/{}",
                crate::admin::public::urlencode(r)
            )),
            EventKind::Scan => Some(format!("/admin/scans/{}", self.id)),
            EventKind::Fingerprint if !r.is_empty() => Some(format!(
                "/admin/links/fp/{}",
                crate::admin::public::urlencode(r)
            )),
            EventKind::Canary if !r.is_empty() => Some(format!(
                "/admin/links/canaries/served/{}",
                crate::admin::public::urlencode(r)
            )),
            _ => None,
        }
    }
}

fn json_list(s: Option<&str>) -> Vec<String> {
    s.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// A page of events and the cursor of the next one.
#[derive(Debug, Clone, Default)]
pub struct EventPage {
    pub items: Vec<Event>,
    pub next: Option<Cursor>,
}

impl EventPage {
    /// Intel-lookup rows on the page, which the Timeline folds away.
    pub fn intel_count(&self) -> usize {
        self.items.iter().filter(|e| e.k == "intel").count()
    }
}

enum Bind {
    I(i64),
    S(String),
}

/// One branch: its statement up to the cursor condition, with `ts`/`id`
/// naming its time and id columns.
struct Branch {
    sql: String,
    ts: &'static str,
    id: &'static str,
    /// The address condition binds the IP's text form, not its id.
    by_text: bool,
}

/// Whose events: one address, or every member of a campaign.
#[derive(Clone, Copy)]
enum Subject<'a> {
    Ip { id: i64, ip: &'a str },
    Campaign(&'a str),
}

impl Subject<'_> {
    /// The condition on `alias`'s address: `alias.ip_id`, or the address
    /// text `alias.ip` when `by_text`. One `?`, bound by [`Self::bind`].
    fn cond(self, alias: &str, by_text: bool) -> String {
        match (self, by_text) {
            (Self::Ip { .. }, false) => format!("{alias}.ip_id = ?"),
            (Self::Ip { .. }, true) => format!("{alias}.ip = ?"),
            (Self::Campaign(_), false) => format!(
                "{alias}.ip_id IN (SELECT ip_id FROM campaign_members WHERE campaign_key = ?)"
            ),
            (Self::Campaign(_), true) => format!(
                "{alias}.ip IN (SELECT i.ip FROM campaign_members cm JOIN ips i ON i.id = cm.ip_id \
                 WHERE cm.campaign_key = ?)"
            ),
        }
    }

    /// The `ip` column: the member's address on a campaign's events.
    fn ip_col(self, alias: &str, by_text: bool) -> String {
        match (self, by_text) {
            (Self::Ip { .. }, _) => "NULL".into(),
            (Self::Campaign(_), true) => format!("{alias}.ip"),
            (Self::Campaign(_), false) => format!("(SELECT ip FROM ips WHERE id = {alias}.ip_id)"),
        }
    }

    fn bind(self, by_text: bool) -> Bind {
        match self {
            Self::Ip { id, ip } => {
                if by_text {
                    Bind::S(ip.to_string())
                } else {
                    Bind::I(id)
                }
            }
            Self::Campaign(key) => Bind::S(key.to_string()),
        }
    }
}

const NO_REQ: &str = "NULL AS method, NULL AS path, NULL AS query, NULL AS labels_json, NULL AS owasp_json, \
     0 AS canary_served, NULL AS canary_used, NULL AS canary_from";

fn node(a: Audience, alias: &str) -> String {
    match a {
        Audience::Admin => format!("(SELECT name FROM members m WHERE m.id = {alias}.origin)"),
        Audience::Public => "NULL".into(),
    }
}

fn branch(kind: EventKind, a: Audience, who: Subject) -> Branch {
    let admin = a == Audience::Admin;
    let w = |alias: &str| (who.ip_col(alias, false), who.cond(alias, false));
    let req = |webshell: bool| {
        let (served, used, from) = if admin {
            (
                "EXISTS (SELECT 1 FROM canaries c WHERE c.request_id = r.id)".to_string(),
                super::browse::CANARY_USED.replace("{}", "t.value_hash"),
                super::browse::CANARY_USED.replace("{}", "c.request_id"),
            )
        } else {
            ("0".into(), "NULL".into(), "NULL".into())
        };
        format!(
            "SELECT r.ts, {ip} AS ip, '{k}' AS k, r.id, r.severity, {summary} AS summary, {node} AS node, \
             NULL AS ref, r.method, r.path, {query} AS query, r.labels_json, r.owasp_json, \
             {served} AS canary_served, ({used}) AS canary_used, ({from}) AS canary_from \
             FROM requests r WHERE {cond} AND {answer}{released}",
            ip = w("r").0,
            cond = w("r").1,
            k = kind.key(),
            summary = if webshell { "r.cmd" } else { "NULL" },
            node = node(a, "r"),
            query = if admin { "r.query" } else { "NULL" },
            answer = if webshell {
                "r.answer = 'webshell'"
            } else {
                "r.answer IS NOT 'webshell'"
            },
            released = a.released("r"),
        )
    };
    let (sql, ts, id, by_text) = match kind {
        EventKind::Request => (req(false), "r.ts", "r.id", false),
        EventKind::Webshell => (req(true), "r.ts", "r.id", false),
        EventKind::Upload => (
            format!(
                "SELECT u.ts, {ip} AS ip, 'upload' AS k, u.id, NULL AS severity, \
                 u.kind || ': ' || COALESCE(u.filename || ' ', '') || u.sniffed_type || ', ' \
                 || u.size || ' bytes' AS summary, {} AS node, u.uid AS ref, {NO_REQ} \
                 FROM uploads u WHERE {cond}",
                node(a, "u"),
                ip = w("u").0,
                cond = w("u").1
            ),
            "u.ts",
            "u.id",
            false,
        ),
        EventKind::Canary => (
            format!(
                "SELECT c.ts, {ip} AS ip, 'canary' AS k, c.rowid AS id, NULL AS severity, \
                 c.kind AS summary, NULL AS node, CAST(c.request_id AS TEXT) AS ref, {NO_REQ} \
                 FROM canaries c WHERE {cond}",
                ip = w("c").0,
                cond = w("c").1
            ),
            "c.ts",
            "c.rowid",
            false,
        ),
        EventKind::Probe => (
            format!(
                "SELECT p.started_at AS ts, {ip} AS ip, 'probe' AS k, p.id, NULL AS severity, \
                 {} AS summary, {} AS node, NULL AS ref, {NO_REQ} \
                 FROM probes p WHERE {cond}{}",
                if admin { "p.vantage_ip" } else { "NULL" },
                node(a, "p"),
                // The public sees a probe once the publication delay has
                // passed, as it sees scans.
                if admin {
                    ""
                } else {
                    " AND p.finished_at <= datetime('now', '-' || \
                     (SELECT delay_s FROM publish_cfg WHERE id = 1) || ' seconds')"
                },
                ip = w("p").0,
                cond = w("p").1
            ),
            "p.started_at",
            "p.id",
            false,
        ),
        EventKind::Scan => (
            format!(
                "SELECT s.started_at AS ts, {ip} AS ip, 'scan' AS k, s.id, NULL AS severity, \
                 'level ' || s.level AS summary, {} AS node, NULL AS ref, {NO_REQ} \
                 FROM scans s WHERE {cond}{}",
                node(a, "s"),
                a.scans("s"),
                ip = w("s").0,
                cond = w("s").1
            ),
            "s.started_at",
            "s.id",
            false,
        ),
        EventKind::Fingerprint => (
            format!(
                "SELECT f.ts, {ip} AS ip, 'fingerprint' AS k, f.id, NULL AS severity, f.fp_hash AS summary, \
                 {} AS node, f.fp_hash AS ref, {NO_REQ} \
                 FROM fingerprints f WHERE {cond}",
                node(a, "f"),
                ip = w("f").0,
                cond = w("f").1
            ),
            "f.ts",
            "f.id",
            false,
        ),
        // Keyed by address text: the log's primary key leads with `ip`.
        EventKind::Intel => (
            format!(
                "SELECT l.fetched_at AS ts, {ip} AS ip, 'intel' AS k, l.hlc AS id, \
                 NULL AS severity, l.provider AS summary, {} AS node, NULL AS ref, {NO_REQ} \
                 FROM ip_intel_log l WHERE {cond}",
                node(a, "l"),
                ip = who.ip_col("l", true),
                cond = who.cond("l", true)
            ),
            "l.fetched_at",
            "l.hlc",
            true,
        ),
    };
    Branch {
        sql,
        ts,
        id,
        by_text,
    }
}

/// The statement for `kinds` (in `ALL` order, deduplicated) and its binds;
/// None when no kind is left.
fn events_sql(
    who: Subject,
    kinds: &[EventKind],
    a: Audience,
    cursor: Option<&Cursor>,
    limit: i64,
) -> Option<(String, Vec<Bind>)> {
    let mut parts = vec![];
    let mut binds = vec![];
    for kind in EventKind::ALL {
        if !kinds.contains(&kind) || (a == Audience::Public && !EventKind::PUBLIC.contains(&kind)) {
            continue;
        }
        let b = branch(kind, a, who);
        let mut sql = b.sql;
        binds.push(who.bind(b.by_text));
        if let Some(c) = cursor {
            // Rows after `c` in `(ts DESC, k, id DESC)`: earlier seconds,
            // and in `c`'s second the kinds sorting after it, or its own
            // kind with a smaller id.
            match c.at {
                Some((ck, cid)) if kind == ck => {
                    sql.push_str(&format!(
                        " AND {ts} <= ? AND ({ts} < ? OR {id} < ?)",
                        ts = b.ts,
                        id = b.id
                    ));
                    binds.push(Bind::S(c.ts.clone()));
                    binds.push(Bind::S(c.ts.clone()));
                    binds.push(Bind::I(cid));
                }
                Some((ck, _)) if kind.key() > ck.key() => {
                    sql.push_str(&format!(" AND {} <= ?", b.ts));
                    binds.push(Bind::S(c.ts.clone()));
                }
                _ => {
                    sql.push_str(&format!(" AND {} < ?", b.ts));
                    binds.push(Bind::S(c.ts.clone()));
                }
            }
        }
        sql.push_str(&format!(" ORDER BY {} DESC, {} DESC LIMIT ?", b.ts, b.id));
        binds.push(Bind::I(limit));
        parts.push(format!("SELECT * FROM ({sql})"));
    }
    if parts.is_empty() {
        return None;
    }
    let sql = format!(
        "SELECT * FROM ({}) ORDER BY ts DESC, k, id DESC LIMIT ?",
        parts.join(" UNION ALL ")
    );
    binds.push(Bind::I(limit));
    Some((sql, binds))
}

impl Store {
    /// The newest events of one address after `cursor` (None: from now),
    /// at most `limit` (≤ [`MAX_LIMIT`]), of the `kinds` asked. The public
    /// audience gets released requests, published scans and probes only,
    /// whatever `kinds` says, without node, query or vantage IP.
    pub async fn ip_events(
        &self,
        ip_id: i64,
        kinds: &[EventKind],
        a: Audience,
        cursor: Option<&Cursor>,
        limit: i64,
    ) -> Result<EventPage> {
        let ip: Option<String> = sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?")
            .bind(ip_id)
            .fetch_optional(&self.read)
            .await?;
        let Some(ip) = ip else {
            return Ok(EventPage::default());
        };
        let who = Subject::Ip { id: ip_id, ip: &ip };
        self.events(who, kinds, a, cursor, limit).await
    }

    /// The same over every member of the campaign `key`, for an admin:
    /// each event carries its member's address in `ip`. Every branch reads
    /// the members' `ip_id` index, so a page costs members × kinds probes
    /// at most, bounded by the per-branch limit.
    pub async fn campaign_events(
        &self,
        key: &str,
        cursor: Option<&Cursor>,
        limit: i64,
    ) -> Result<EventPage> {
        let who = Subject::Campaign(key);
        self.events(who, &EventKind::ALL, Audience::Admin, cursor, limit)
            .await
    }

    async fn events(
        &self,
        who: Subject<'_>,
        kinds: &[EventKind],
        a: Audience,
        cursor: Option<&Cursor>,
        limit: i64,
    ) -> Result<EventPage> {
        let limit = limit.clamp(1, MAX_LIMIT);
        let Some((sql, binds)) = events_sql(who, kinds, a, cursor, limit + 1) else {
            return Ok(EventPage::default());
        };
        let mut q = sqlx::query_as::<_, Event>(sqlx::AssertSqlSafe(sql.as_str()));
        for b in binds {
            q = match b {
                Bind::I(v) => q.bind(v),
                Bind::S(v) => q.bind(v),
            };
        }
        let mut items = q.fetch_all(&self.read).await?;
        let next = if items.len() as i64 > limit {
            items.truncate(limit as usize);
            items.last().map(|e| Cursor {
                ts: e.ts.clone(),
                at: Some((e.kind(), e.id)),
            })
        } else {
            None
        };
        Ok(EventPage { items, next })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::nmap_xml::parse_nmap_xml;
    use crate::store::requests::NewRequest;

    const IP: &str = "203.0.113.50";

    async fn exec(s: &Store, sql: &str) {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&s.pool)
            .await
            .unwrap();
    }

    async fn request(s: &Store, ip_id: i64, path: &str, answer: Option<&str>) -> i64 {
        s.insert_request(&NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            query: answer.map(|_| "cmd=whoami".into()),
            headers_json: "[]".into(),
            labels_json: "[\"scanner\"]".into(),
            answer: answer.map(Into::into),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// One address with one event of every kind, a second apart, and a
    /// request of another address. Returns (store, ip id, ids by kind).
    async fn seeded() -> (Store, i64, Vec<(EventKind, i64)>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let ip = s.upsert_ip(IP.parse().unwrap()).await.unwrap().id;
        let other = s
            .upsert_ip("203.0.113.51".parse().unwrap())
            .await
            .unwrap()
            .id;
        request(&s, other, "/other", None).await;
        let r1 = request(&s, ip, "/a", None).await;
        let r2 = request(&s, ip, "/b", None).await;
        let r3 = request(&s, ip, "/c", None).await;
        let ws = request(&s, ip, "/s.php", Some("webshell")).await;
        let uid = crate::store::uploads::seed_upload(&s, IP, "/u.php", b"<?php").await;
        let (up_req, up): (i64, i64) = sqlx::query_as(
            "SELECT r.id, u.id FROM uploads u JOIN requests r ON r.uid = u.request_uid WHERE u.uid = ?",
        )
        .bind(&uid)
        .fetch_one(&s.pool)
        .await
        .unwrap();
        exec(
            &s,
            &format!(
                "INSERT INTO canaries (value_hash, kind, request_id, ts, ip_id) \
                 VALUES (77, 'git-token', {r1}, '2026-10-01 10:00:07', {ip})"
            ),
        )
        .await;
        s.enqueue_scan(ip, 2, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = parse_nmap_xml(include_bytes!("../../tests/fixtures/nmap-hostkeys.xml")).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();
        let fp = s
            .insert_fingerprint(Some(r1), ip, "F", None, "{}", "{}", b"[]")
            .await
            .unwrap();
        exec(
            &s,
            &format!(
                "INSERT INTO probes (uid, group_uid, ip_id, asker, vantage_ip, started_at, finished_at) \
                 VALUES ('p1', 'g1', {ip}, x'00', '192.0.2.9', '2026-10-01 10:00:10', '2026-10-01 10:00:11')"
            ),
        )
        .await;
        exec(
            &s,
            &format!(
                "INSERT INTO ip_intel_log (ip, provider, origin, hlc, fetched_at, data_json) \
                 VALUES ('{IP}', 'rdap', x'00', 4242, '2026-10-01 10:00:11', '{{}}')"
            ),
        )
        .await;
        for (id, sec) in [(r1, 1), (r2, 2), (r3, 3), (ws, 4), (up_req, 5)] {
            exec(
                &s,
                &format!("UPDATE requests SET ts = '2026-10-01 10:00:0{sec}' WHERE id = {id}"),
            )
            .await;
        }
        exec(
            &s,
            &format!("UPDATE uploads SET ts = '2026-10-01 10:00:06' WHERE id = {up}"),
        )
        .await;
        exec(
            &s,
            &format!(
                "UPDATE scans SET started_at = '2026-10-01 10:00:08', \
                 finished_at = '2026-10-01 10:00:08' WHERE ip_id = {ip}"
            ),
        )
        .await;
        exec(
            &s,
            &format!("UPDATE fingerprints SET ts = '2026-10-01 10:00:09' WHERE id = {fp}"),
        )
        .await;
        let scan: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let probe: i64 = sqlx::query_scalar("SELECT id FROM probes")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let canary: i64 = sqlx::query_scalar("SELECT rowid FROM canaries")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        use EventKind::*;
        let ids = vec![
            (Intel, 4242),
            (Probe, probe),
            (Fingerprint, fp),
            (Scan, scan),
            (Canary, canary),
            (Upload, up),
            (Request, up_req),
            (Webshell, ws),
            (Request, r3),
            (Request, r2),
            (Request, r1),
        ];
        (s, ip, ids)
    }

    fn ids(p: &EventPage) -> Vec<(EventKind, i64)> {
        p.items.iter().map(|e| (e.kind(), e.id)).collect()
    }

    #[tokio::test]
    async fn every_kind_interleaves_newest_first() {
        let (s, ip, want) = seeded().await;
        let p = s
            .ip_events(ip, &EventKind::ALL, Audience::Admin, None, 50)
            .await
            .unwrap();
        assert_eq!(ids(&p), want);
        assert!(p.next.is_none());
        // The command is its own row, once, with the command as summary.
        let ws: Vec<_> = p
            .items
            .iter()
            .filter(|e| e.path.as_deref() == Some("/s.php"))
            .collect();
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0].kind(), EventKind::Webshell);
        assert_eq!(ws[0].summary.as_deref(), Some("whoami"));
        // A request row carries what the Requests table showed.
        let r1 = p.items.last().unwrap();
        assert_eq!(r1.labels(), vec!["scanner".to_string()]);
        assert!(r1.canary_served);
        assert_eq!(r1.href(), Some(format!("/admin/requests/{}", r1.id)));
        let probe = &p.items[1];
        assert_eq!(probe.summary.as_deref(), Some("192.0.2.9"));
        assert_eq!(probe.href(), None);
        assert_eq!(p.items[2].href().as_deref(), Some("/admin/links/fp/F"));
    }

    #[tokio::test]
    async fn the_cursor_and_the_limit_page_without_repeats() {
        let (s, ip, want) = seeded().await;
        let all = EventKind::ALL;
        // `before` alone excludes its second.
        let c = Cursor::parse(Some("2026-10-01 10:00:11"), None);
        let p = s
            .ip_events(ip, &all, Audience::Admin, c.as_ref(), 50)
            .await
            .unwrap();
        assert_eq!(ids(&p), want[1..]);
        let p = s
            .ip_events(ip, &all, Audience::Admin, None, 2)
            .await
            .unwrap();
        assert_eq!(ids(&p), want[..2]);
        assert_eq!(
            p.next,
            Some(Cursor {
                ts: "2026-10-01 10:00:10".into(),
                at: Some(want[1])
            })
        );
        // Everything in one second: the keyset still walks it exactly.
        exec(&s, "UPDATE requests SET ts = '2026-10-01 10:00:00'").await;
        exec(&s, "UPDATE uploads SET ts = '2026-10-01 10:00:00'").await;
        exec(&s, "UPDATE scans SET started_at = '2026-10-01 10:00:00'").await;
        exec(&s, "UPDATE fingerprints SET ts = '2026-10-01 10:00:00'").await;
        exec(&s, "UPDATE canaries SET ts = '2026-10-01 10:00:00'").await;
        exec(&s, "UPDATE probes SET started_at = '2026-10-01 10:00:00'").await;
        exec(
            &s,
            "UPDATE ip_intel_log SET fetched_at = '2026-10-01 10:00:00'",
        )
        .await;
        let whole = s
            .ip_events(ip, &all, Audience::Admin, None, 50)
            .await
            .unwrap();
        for limit in 1..=4 {
            let mut walked = vec![];
            let mut cur = None;
            loop {
                let p = s
                    .ip_events(ip, &all, Audience::Admin, cur.as_ref(), limit)
                    .await
                    .unwrap();
                walked.extend(ids(&p));
                match p.next {
                    Some(n) => {
                        // Through the query string, as the page does.
                        let at = n.at_param();
                        cur = Cursor::parse(Some(&n.ts), at.as_deref());
                    }
                    None => break,
                }
            }
            assert_eq!(walked, ids(&whole), "limit {limit}");
        }
    }

    #[tokio::test]
    async fn the_public_cut_is_requests_scans_and_probes() {
        let (s, ip, want) = seeded().await;
        let p = s
            .ip_events(ip, &EventKind::ALL, Audience::Public, None, 50)
            .await
            .unwrap();
        let public: Vec<_> = want
            .iter()
            .copied()
            .filter(|(k, _)| EventKind::PUBLIC.contains(k))
            .collect();
        assert_eq!(ids(&p), public);
        for e in &p.items {
            assert!(
                e.node.is_none() && e.query.is_none() && !e.canary_served,
                "{e:?}"
            );
        }
        let probe = p
            .items
            .iter()
            .find(|e| e.kind() == EventKind::Probe)
            .unwrap();
        assert_eq!(probe.summary, None);
        // An unreleased request stays off it.
        exec(
            &s,
            "UPDATE requests SET public_at = '2999-01-01 00:00:00' WHERE path = '/c'",
        )
        .await;
        let p = s
            .ip_events(ip, &EventKind::PUBLIC, Audience::Public, None, 50)
            .await
            .unwrap();
        assert!(p.items.iter().all(|e| e.path.as_deref() != Some("/c")));
        assert_eq!(p.items.len(), public.len() - 1);
    }

    #[test]
    fn the_public_statement_reads_only_its_tables() {
        let (sql, _) = events_sql(
            Subject::Ip { id: 1, ip: IP },
            &EventKind::ALL,
            Audience::Public,
            None,
            51,
        )
        .unwrap();
        for t in [
            "uploads",
            "canaries",
            "fingerprints",
            "ip_intel_log",
            "members",
            "'webshell' AS k",
        ] {
            assert!(!sql.contains(t), "{t}: {sql}");
        }
        assert!(
            events_sql(
                Subject::Ip { id: 1, ip: IP },
                &[],
                Audience::Admin,
                None,
                51
            )
            .is_none()
        );
        assert!(
            events_sql(
                Subject::Ip { id: 1, ip: IP },
                &[EventKind::Upload],
                Audience::Public,
                None,
                51
            )
            .is_none()
        );
    }

    #[test]
    fn a_cursor_is_a_timestamp_and_an_optional_row() {
        assert_eq!(Cursor::parse(Some("garbage"), None), None);
        assert_eq!(Cursor::parse(Some("2026-10-01 10:00"), None), None);
        assert_eq!(Cursor::parse(Some("2026-10-01T10:00:00"), None), None);
        assert_eq!(Cursor::parse(None, Some("request.1")), None);
        let c = Cursor::parse(Some("2026-10-01 10:00:00"), Some("scan.7")).unwrap();
        assert_eq!(c.at, Some((EventKind::Scan, 7)));
        assert_eq!(c.at_param().as_deref(), Some("scan.7"));
        for bad in ["nope.1", "scan.x", "scan", ""] {
            let c = Cursor::parse(Some("2026-10-01 10:00:00"), Some(bad)).unwrap();
            assert_eq!(c.at, None, "{bad}");
        }
    }

    /// Every branch reads its `ip_id` (intel: `ip`) index, never the table,
    /// for one address and for a campaign's members.
    #[tokio::test]
    async fn every_branch_searches_an_index() {
        let (s, ip, _) = seeded().await;
        let c = Cursor::parse(Some("2026-10-01 10:00:05"), Some("request.3"));
        let one = Subject::Ip { id: ip, ip: IP };
        let campaign = Subject::Campaign(IP);
        for (who, a, cur) in [
            (one, Audience::Admin, None),
            (one, Audience::Admin, c.as_ref()),
            (one, Audience::Public, c.as_ref()),
            (campaign, Audience::Admin, None),
            (campaign, Audience::Admin, c.as_ref()),
        ] {
            let (sql, binds) = events_sql(who, &EventKind::ALL, a, cur, 51).unwrap();
            let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(format!(
                "EXPLAIN QUERY PLAN {sql}"
            )));
            for b in binds {
                q = match b {
                    Bind::I(v) => q.bind(v),
                    Bind::S(v) => q.bind(v),
                };
            }
            let plan: Vec<String> = q
                .fetch_all(&s.read)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.3)
                .collect();
            let plan = plan.join("\n");
            // Only the materialised branches are scanned; every table is
            // searched (`SCAN r` would be a full read of `requests`).
            for line in plan.lines().filter(|l| l.starts_with("SCAN ")) {
                assert!(line.starts_with("SCAN (subquery-"), "{a:?}: {line}\n{plan}");
            }
            // A campaign's branches read each member through an `ip_id`
            // index (SQLite may pick `idx_requests_ip_severity`: the IN
            // list needs the sort either way).
            let req = match who {
                Subject::Ip { .. } => "SEARCH r USING INDEX idx_requests_ip_ts",
                Subject::Campaign(_) => "SEARCH r USING INDEX idx_requests_ip_",
            };
            for t in [req, "SEARCH u USING INDEX idx_uploads_ip"] {
                assert!(a == Audience::Public || plan.contains(t), "{t}\n{plan}");
            }
        }
    }
}
