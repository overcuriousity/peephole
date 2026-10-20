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
    Router::new().route("/admin/evidence/paths", get(index))
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
}

#[derive(Template)]
#[template(path = "admin_paths.html")]
struct PathsPage {
    chrome: Chrome,
    /// The `SINCE` key in effect.
    since: &'static str,
    unknown: bool,
    rows: Vec<PathRow>,
    /// `retention_days` of this node; 0: it keeps everything.
    keeps_days: u32,
}

impl PathsPage {
    fn href(since: &str, unknown: bool) -> String {
        format!(
            "/admin/evidence/paths?since={since}{}",
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
    let mut rows = st
        .store
        .new_paths(from.as_deref(), unknown, PATHS_LIMIT)
        .await?;
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

        for p in [
            "/admin/evidence/paths",
            "/admin/evidence/paths?since=all&unknown=1",
        ] {
            let (st, h, _) = send(&app, get(p, false), Body::empty()).await;
            assert_eq!(st, StatusCode::SEE_OTHER, "{p}");
            assert_eq!(h["location"], "/login", "{p}");
        }
        let (st, _, page) = send(&app, get("/admin/evidence/paths", true), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "aria-current=\"page\">New paths",
            "<th>Rule</th><th>Wave</th><th>Campaigns</th>",
            "aria-current=\"true\">7 days",
        ] {
            assert!(page.contains(want), "{want} missing:\n{page}");
        }
        // The nav entry follows Campaigns.
        assert!(page.find(">Campaigns</a>").unwrap() < page.find(">New paths</a>").unwrap());

        let (_, _, all) = send(
            &app,
            get("/admin/evidence/paths?since=all", true),
            Body::empty(),
        )
        .await;
        let row = |page: &str, text: &str| -> String {
            let at = page
                .find(&format!("<td class=\"mono\">{text}</td>"))
                .unwrap_or_else(|| panic!("{text} missing:\n{page}"));
            page[at..at + page[at..].find("</tr>").unwrap()].to_string()
        };
        let alpha = row(&all, "/alpha");
        assert!(alpha.contains("badge-wave\">none</span>"), "{alpha}");
        assert!(
            alpha.contains(
                "<a href=\"/admin/evidence/campaigns/192.0.2.3\" title=\"members: 1\">#1</a>"
            ),
            "{alpha}"
        );
        assert!(row(&all, "/beta").contains("<td>known</td>"));
        assert!(row(&all, "/gamma").contains("12 IPs in 60 min</span>"));

        let (_, _, unknown) = send(
            &app,
            get("/admin/evidence/paths?since=all&unknown=1", true),
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
        let (_, _, day) = send(
            &app,
            get("/admin/evidence/paths?since=24h", true),
            Body::empty(),
        )
        .await;
        assert!(!day.contains("/alpha"), "{day}");
        assert!(day.contains("No new path."), "{day}");
    }

    #[test]
    fn retention_line_only_when_the_node_prunes() {
        let page = |keeps_days| {
            PathsPage {
                chrome: Chrome::new(true, "admin"),
                since: "7d",
                unknown: false,
                rows: vec![],
                keeps_days,
            }
            .render()
            .unwrap()
        };
        assert!(!page(0).contains("data-retention"));
        assert!(page(30).contains("First seen on this node (keeps 30 days)."));
    }
}
