//! New paths: the path shapes this node saw first most recently, whether a
//! rule knows them, the exploit waves they formed and the campaigns whose
//! members asked for them. Read-only and admin-only: shape text is request
//! content.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::store::shapes::ts_text;
use crate::store::waves::PathRow;
use askama::Template;
use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use chrono::{Duration, Utc};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/paths", get(index))
}

/// Rows on the page.
pub const PATHS_LIMIT: i64 = 200;

/// The `?since=` choices, as (key, label, hours; `None`: all).
pub const SINCE: [(&str, &str, Option<i64>); 4] = [
    ("24h", "24 h", Some(24)),
    ("7d", "7 days", Some(24 * 7)),
    ("30d", "30 days", Some(24 * 30)),
    ("all", "all", None),
];

#[derive(Debug, Default, serde::Deserialize)]
pub struct PathsQuery {
    pub since: Option<String>,
    pub unknown: Option<String>,
    /// Keyset cursor `<first_seen>~<hash>`: the last row of the previous
    /// page. Anything else means the first page.
    pub before: Option<String>,
}

/// The `(first_seen, hash)` in a `?before=` cursor; `None` when malformed.
fn parse_cursor(c: &str) -> Option<(&str, i64)> {
    let (ts, hash) = c.rsplit_once('~')?;
    let ok = !ts.is_empty()
        && ts.len() <= 40
        && ts
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" :.+-".contains(&b));
    if !ok {
        return None;
    }
    Some((ts, hash.parse().ok()?))
}

#[derive(Template)]
#[template(path = "admin_paths.html")]
struct PathsPage {
    chrome: Chrome,
    /// The `SINCE` key in effect.
    since: &'static str,
    unknown: bool,
    rows: Vec<PathRow>,
    /// Shapes in the window and filter, on every page.
    total: i64,
    /// Rows above this page (0: the first page).
    ahead: i64,
    /// The cursor of the next page, when there is one.
    older: Option<String>,
    /// `retention_days` of this node; 0: it keeps everything.
    keeps_days: u32,
}

impl PathsPage {
    fn href(since: &str, unknown: bool) -> String {
        format!(
            "/admin/paths?since={since}{}",
            if unknown { "&unknown=1" } else { "" }
        )
    }

    /// This page with another `since`.
    fn since_href(&self, since: &str) -> String {
        Self::href(since, self.unknown)
    }

    fn is_since(&self, since: &str) -> bool {
        self.since == since
    }

    /// This page with the "no rule only" filter flipped.
    fn unknown_href(&self) -> String {
        Self::href(self.since, !self.unknown)
    }

    /// The first page of this window and filter.
    fn newest_href(&self) -> String {
        Self::href(self.since, self.unknown)
    }

    /// The next page, when there is one.
    fn older_href(&self) -> Option<String> {
        let c = self.older.as_deref()?;
        let q = serde_urlencoded::to_string([("before", c)]).ok()?;
        Some(format!("{}&{q}", self.newest_href()))
    }

    /// "Showing 200 of 13,834 shapes", or "rows 201–400 of 13,834" past
    /// the first page.
    fn count_line(&self) -> String {
        use crate::admin::views::thousands;
        let total = thousands(self.total);
        if self.ahead == 0 {
            let n = thousands(self.rows.len());
            if self.total > PATHS_LIMIT {
                format!("Showing {n} of {total} shapes · newest first, {PATHS_LIMIT} per page")
            } else {
                format!("Showing {n} of {total} shapes")
            }
        } else {
            let first = self.ahead + 1;
            let last = self.ahead + self.rows.len() as i64;
            format!("rows {}–{} of {total}", thousands(first), thousands(last))
        }
    }
}

async fn index(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<PathsQuery>,
) -> AppResult<Html<String>> {
    let (since, _, hours) = SINCE
        .iter()
        .find(|(k, ..)| Some(*k) == q.since.as_deref())
        .unwrap_or(&SINCE[1]);
    let from = hours.map(|h| ts_text((Utc::now() - Duration::hours(h)).timestamp_millis()));
    let unknown = q.unknown.as_deref() == Some("1");
    let before = q.before.as_deref().and_then(parse_cursor);
    let mut rows = st
        .store
        .new_paths(from.as_deref(), unknown, before, PATHS_LIMIT + 1)
        .await?;
    let older = (rows.len() as i64 > PATHS_LIMIT).then(|| {
        rows.truncate(PATHS_LIMIT as usize);
        let last = rows.last().expect("a full page");
        format!("{}~{}", last.first_seen, last.hash)
    });
    let total = st.store.count_paths(from.as_deref(), unknown).await?;
    let ahead = match before {
        Some(b) => {
            st.store
                .count_paths_ahead(from.as_deref(), unknown, b)
                .await?
        }
        None => 0,
    };
    let hashes: Vec<i64> = rows.iter().map(|r| r.hash).collect();
    let mut campaigns = st.store.campaigns_of_shapes(&hashes).await?;
    for r in &mut rows {
        if let Some(c) = campaigns.remove(&r.hash) {
            r.campaigns = c;
        }
    }
    render(&PathsPage {
        chrome: Chrome::new(true, "admin"),
        since,
        unknown,
        rows,
        total,
        ahead,
        older,
        keeps_days: st.recorder.node().map_or(0, |n| n.retention_days),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::devices::tests::{app, send};
    use crate::store::campaigns::tests::{feed, fixture};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn paths_page_lists_shapes_and_needs_a_session() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        state.store.recompute_campaigns(true).await.unwrap();
        // A rule knows /beta; /gamma formed a wave.
        sqlx::query("UPDATE shapes SET rule_hits = 2 WHERE text = '/beta'")
            .execute(&state.store.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO waves (shape, detected_at, window_start, ips)
             SELECT hash, '2026-09-01 11:00:00', '2026-09-01 10:00:00', 12
             FROM shapes WHERE text = '/gamma'",
        )
        .execute(&state.store.pool)
        .await
        .unwrap();
        let get = |path: &str, authed: bool| {
            let r = Request::get(path).header("sec-fetch-site", "same-origin");
            if authed {
                r.header("cookie", &cookie)
            } else {
                r
            }
        };

        for p in ["/admin/paths", "/admin/paths?since=all&unknown=1"] {
            let (st, h, _) = send(&app, get(p, false), Body::empty()).await;
            assert_eq!(st, StatusCode::SEE_OTHER, "{p}");
            assert_eq!(h["location"], "/login", "{p}");
        }
        let (st, _, page) = send(&app, get("/admin/paths", true), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "aria-current=\"true\">New paths",
            "<th>Rule</th><th>Wave</th><th>Campaigns</th>",
            "aria-current=\"true\">7 days",
        ] {
            assert!(page.contains(want), "{want} missing:\n{page}");
        }
        // The nav entry follows Campaigns.
        assert!(page.find(">Campaigns</a>").unwrap() < page.find(">New paths</a>").unwrap());

        let (_, _, all) = send(&app, get("/admin/paths?since=all", true), Body::empty()).await;
        let row = |page: &str, text: &str| -> String {
            let at = page
                .find(&format!("<td class=\"mono\">{text}</td>"))
                .unwrap_or_else(|| panic!("{text} missing:\n{page}"));
            page[at..at + page[at..].find("</tr>").unwrap()].to_string()
        };
        let alpha = row(&all, "/alpha");
        assert!(alpha.contains("badge-wave\">none</span>"), "{alpha}");
        assert!(
            alpha.contains("<a href=\"/admin/campaigns/192.0.2.3\" title=\"members: 1\">#1</a>"),
            "{alpha}"
        );
        assert!(row(&all, "/beta").contains("<td>known</td>"));
        assert!(row(&all, "/gamma").contains("12 IPs in 60 min</span>"));

        let (_, _, unknown) = send(
            &app,
            get("/admin/paths?since=all&unknown=1", true),
            Body::empty(),
        )
        .await;
        assert!(
            unknown.contains("<td class=\"mono\">/alpha</td>"),
            "{unknown}"
        );
        assert!(
            !unknown.contains("<td class=\"mono\">/beta</td>"),
            "{unknown}"
        );
        // The fixture is older than a day.
        let (_, _, day) = send(&app, get("/admin/paths?since=24h", true), Body::empty()).await;
        assert!(!day.contains("/alpha"), "{day}");
        assert!(day.contains("No new path."), "{day}");
    }

    /// The shape texts, the count line and the "older →" link of a page.
    fn page_parts(page: &str) -> (Vec<String>, String, Option<String>) {
        let texts = page
            .split("<td class=\"mono\">")
            .skip(1)
            .map(|t| t[..t.find("</td>").unwrap()].to_string())
            .collect();
        let at = page.find("data-count>").expect("count line") + "data-count>".len();
        let count = page[at..at + page[at..].find("</p>").unwrap()].to_string();
        let older = page.find("\" rel=\"next\"").map(|end| {
            let start = page[..end].rfind("href=\"").unwrap() + "href=\"".len();
            page[start..end].replace("&#38;", "&")
        });
        (texts, count, older)
    }

    #[tokio::test]
    async fn pages_walk_every_shape_once_per_window() {
        let (state, cookie, app, _d) = app().await;
        // 260 shapes in the last day, 3 per second so `first_seen` ties
        // across page edges, and 200 from long ago; every 4th known to a
        // rule. Hashes run negative and positive.
        let now = Utc::now().timestamp_millis();
        for i in 0..460i64 {
            let ts = if i < 260 {
                ts_text(now - (i / 3) * 1000)
            } else {
                ts_text(now - 90 * 24 * 3_600_000 - (i / 3) * 1000)
            };
            sqlx::query(
                "INSERT INTO shapes (hash, text, first_seen, last_seen, ips, rule_hits)
                 VALUES (?, ?, ?, ?, 1, ?)",
            )
            .bind((i * 7919) % 461 - 230)
            .bind(format!("/p{i}"))
            .bind(&ts)
            .bind(&ts)
            .bind(i64::from(i % 4 == 0))
            .execute(&state.store.pool)
            .await
            .unwrap();
        }
        let get = |path: String| {
            Request::get(path)
                .header("sec-fetch-site", "same-origin")
                .header("cookie", &cookie)
        };
        let walk = |start: &'static str| {
            let app = app.clone();
            let get = &get;
            async move {
                let (mut seen, mut counts, mut next) = (vec![], vec![], Some(start.to_string()));
                while let Some(path) = next.take() {
                    assert!(seen.len() < 5, "the pager does not end");
                    let (st, _, page) = send(&app, get(path), Body::empty()).await;
                    assert_eq!(st, StatusCode::OK);
                    let (texts, count, older) = page_parts(&page);
                    assert!(texts.len() as i64 <= PATHS_LIMIT);
                    if older.is_some() {
                        assert_eq!(texts.len() as i64, PATHS_LIMIT, "{count}");
                    }
                    seen.push(texts);
                    counts.push(count);
                    next = older;
                }
                (seen, counts)
            }
        };
        let check = |pages: &[Vec<String>], want: Vec<i64>| {
            let mut all: Vec<String> = pages.concat();
            let n = all.len();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), n, "a shape on two pages");
            let mut want: Vec<String> = want.iter().map(|i| format!("/p{i}")).collect();
            want.sort();
            assert_eq!(all, want, "a shape missing");
        };

        let (pages, counts) = walk("/admin/paths?since=all").await;
        check(&pages, (0..460).collect());
        assert_eq!(
            counts,
            [
                "Showing 200 of 460 shapes · newest first, 200 per page",
                "rows 201–400 of 460 · <a href=\"/admin/paths?since=all\">← newest</a>",
                "rows 401–460 of 460 · <a href=\"/admin/paths?since=all\">← newest</a>",
            ]
        );
        let (day, day_counts) = walk("/admin/paths?since=24h").await;
        check(&day, (0..260).collect());
        assert_eq!(
            day_counts[0],
            "Showing 200 of 260 shapes · newest first, 200 per page"
        );
        assert_eq!(
            day_counts[1],
            "rows 201–260 of 260 · <a href=\"/admin/paths?since=24h\">← newest</a>"
        );
        assert_ne!(day[1], pages[1], "the window changes page 2");
        // The filter keeps the cursor's window and filter.
        let (unknown, unknown_counts) = walk("/admin/paths?since=all&unknown=1").await;
        check(&unknown, (0..460).filter(|i| i % 4 != 0).collect());
        assert_eq!(
            unknown_counts[0],
            "Showing 200 of 345 shapes · newest first, 200 per page"
        );
        let (week, week_counts) = walk("/admin/paths?since=7d&unknown=1").await;
        check(&week, (0..260).filter(|i| i % 4 != 0).collect());
        assert_eq!(week_counts, ["Showing 195 of 195 shapes"]);
    }

    #[tokio::test]
    async fn a_malformed_cursor_is_the_first_page() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        let get = |path: &str| {
            Request::get(path)
                .header("sec-fetch-site", "same-origin")
                .header("cookie", &cookie)
        };
        let (_, _, first) = send(&app, get("/admin/paths?since=all"), Body::empty()).await;
        for bad in [
            "x",
            "~",
            "2026-09-01~",
            "~12",
            "2026-09-01~twelve",
            "2026-09-01%2012:00:00~99999999999999999999",
            "2026-09-01'%20OR%201=1--~1",
        ] {
            let (st, _, page) = send(
                &app,
                get(&format!("/admin/paths?since=all&before={bad}")),
                Body::empty(),
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{bad}");
            assert_eq!(page_parts(&page), page_parts(&first), "{bad}");
        }
        let (_, count, older) = page_parts(&first);
        assert!(count.starts_with("Showing ") && older.is_none(), "{count}");
    }

    #[test]
    fn retention_line_only_when_the_node_prunes() {
        let page = |keeps_days| {
            PathsPage {
                chrome: Chrome::new(true, "admin"),
                since: "7d",
                unknown: false,
                rows: vec![],
                total: 0,
                ahead: 0,
                older: None,
                keeps_days,
            }
            .render()
            .unwrap()
        };
        assert!(!page(0).contains("data-retention"));
        assert!(page(30).contains("First seen on this node (keeps 30 days)."));
    }
}
