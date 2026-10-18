//! The Campaigns area: source IPs the recompute (`store::campaigns`) tied
//! together by typed evidence. A list and a page per campaign, read-only:
//! every route is a `GET`, and nothing here changes a campaign.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::{Chrome, link_href};
use crate::store::browse::{CALENDAR_DAYS, CalendarDay, canonical_ip};
use crate::store::campaigns::{
    Campaign, CampaignFilter, CampaignListItem, CampaignShape, Edge, HARD_FANOUT_MAX, ORDER_AGREE,
    Report,
};
use crate::store::links::LinkKind;
use askama::Template;
use axum::{
    Router,
    extract::{Path, Query, State},
    response::Html,
    routing::get,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/campaigns", get(index))
        .route("/admin/campaigns/{key}", get(campaign))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

/// Countries and ASNs shown in a list cell before "+N".
pub const SPREAD_TOP: usize = 3;

#[derive(Template)]
#[template(path = "admin_campaigns.html")]
struct CampaignsPage {
    chrome: Chrome,
    f: CampaignFilter,
    items: Vec<CampaignListItem>,
    /// The last pass, if one ran.
    report: Option<Report>,
    fanout_max: usize,
}

async fn index(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(f): Query<CampaignFilter>,
) -> AppResult<Html<String>> {
    let items = st.store.campaign_index(&f).await?;
    let report = st.store.campaign_report().await?;
    render(&CampaignsPage {
        chrome: chrome(),
        f,
        items,
        report,
        fanout_max: HARD_FANOUT_MAX,
    })
}

/// An evidence edge as the campaign page lists it.
pub struct EdgeView {
    pub e: Edge,
    pub kind_name: &'static str,
    /// Why the two are tied, in words.
    pub reason: String,
    /// The shared value and its Links page (hard kinds).
    pub value: Option<(String, String)>,
}

impl EdgeView {
    pub fn new(e: Edge) -> Self {
        let kind = LinkKind::parse(&e.kind);
        let kind_name = kind.map_or("Path similarity", |k| k.name());
        let reason = match e.kind.as_str() {
            "paths" => format!(
                "path similarity {:.2}, {} shared shapes{}{}",
                e.score.unwrap_or(0.0),
                e.shared.unwrap_or(0),
                if e.fp_support { ", JA4/JA4H match" } else { "" },
                if e.agreement.is_some_and(|x| x >= ORDER_AGREE) {
                    ", order agrees"
                } else {
                    ""
                }
            ),
            "canary" => "canary served here, used there".into(),
            _ => format!("shared {}", kind_name.to_lowercase()),
        };
        let value = kind
            .filter(|_| !e.value.is_empty())
            .map(|k| (e.value.clone(), link_href(k.key(), &e.value)));
        Self {
            e,
            kind_name,
            reason,
            value,
        }
    }

    /// Paths edges are soft; the rest point to one operator.
    pub fn hard(&self) -> bool {
        self.e.kind != "paths"
    }
}

#[derive(Template)]
#[template(path = "campaign.html")]
struct CampaignPage {
    chrome: Chrome,
    c: Campaign,
    edges: Vec<EdgeView>,
    calendar: Vec<CalendarDay>,
    calendar_json: String,
    calendar_days: i64,
    shapes: Vec<CampaignShape>,
}

async fn campaign(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(key): Path<String>,
) -> AppResult<Html<String>> {
    // A key is an IP address; anything else is not looked up.
    if key.trim().parse::<std::net::IpAddr>().is_err() {
        return Err(AppError::NotFound);
    }
    let key = canonical_ip(&key);
    let Some(mut c) = st.store.campaign(&key).await? else {
        return Err(AppError::NotFound);
    };
    let edges = std::mem::take(&mut c.edges)
        .into_iter()
        .map(EdgeView::new)
        .collect();
    let calendar = st.store.campaign_calendar(&key).await?;
    let shapes = st.store.campaign_shapes(&key).await?;
    render(&CampaignPage {
        chrome: chrome(),
        calendar_json: serde_json::to_string(&calendar).unwrap_or_else(|_| "[]".into()),
        calendar,
        calendar_days: CALENDAR_DAYS,
        shapes,
        edges,
        c,
    })
}

#[cfg(test)]
mod tests {
    use crate::admin::devices::tests::{app, send};
    use crate::store::campaigns::tests::{feed, fixture, tls_fixture};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn campaign_pages_render_and_need_a_session() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        tls_fixture(&state.store).await;
        state.store.recompute_campaigns(true).await.unwrap();
        let get = |path: &str, authed: bool| {
            let r = Request::get(path).header("sec-fetch-site", "same-origin");
            if authed {
                r.header("cookie", &cookie)
            } else {
                r
            }
        };

        let paths = [
            "/admin/campaigns",
            "/admin/campaigns?country=DE",
            "/admin/campaigns/192.0.2.3",
            "/admin/campaigns/nope",
        ];
        for p in paths {
            let (st, h, _) = send(&app, get(p, false), Body::empty()).await;
            assert_eq!(st, StatusCode::SEE_OTHER, "{p}");
            assert_eq!(h["location"], "/login", "{p}");
        }
        // Read-only: no route takes a POST.
        for p in ["/admin/campaigns", "/admin/campaigns/192.0.2.3"] {
            let (st, _, _) = send(
                &app,
                Request::post(p)
                    .header("cookie", &cookie)
                    .header("sec-fetch-site", "same-origin"),
                Body::empty(),
            )
            .await;
            assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED, "{p}");
        }

        let (st, _, list) = send(&app, get("/admin/campaigns", true), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "href=\"/admin/campaigns/192.0.2.3\"",
            "#1",
            "href=\"/admin/campaigns/198.51.100.10\"",
            "Excluded values",
            "SHA256:image",
            "Last recompute",
            "aria-current=\"true\">Campaigns",
        ] {
            assert!(list.contains(want), "{want} missing:\n{list}");
        }
        // Short strings (MIK-494): the edge rules live on /admin/links only.
        assert!(list.contains("recomputed hourly. <a href=\"/admin/links\">What counts →</a>"));
        assert!(list.contains("· no edge</span>"));
        assert!(!list.contains("not one operator"), "{list}");
        let (_, _, few) = send(&app, get("/admin/campaigns?min=3", true), Body::empty()).await;
        assert!(few.contains("/admin/campaigns/192.0.2.3"));
        assert!(!few.contains("/admin/campaigns/198.51.100.10"));

        let (st, _, a) = send(&app, get("/admin/campaigns/192.0.2.3", true), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "Campaign #1",
            "href=\"/ip/192.0.2.1\"",
            "shared ssh host key",
            "SHA256:operator",
            // The campaign graph (S4) sits between Members and Evidence.
            "data-focus=\"campaign:192.0.2.3\"",
            "<i class=\"line soft\"></i>shared paths",
        ] {
            assert!(a.contains(want), "{want} missing:\n{a}");
        }
        for want in [
            "<a href=\"/admin/campaigns\">← All campaigns</a>",
            "soft · <a href=\"/admin/links\">what counts →</a>",
            "<span class=\"muted\">per day, last 26 weeks, UTC</span>",
        ] {
            assert!(a.contains(want), "{want} missing:\n{a}");
        }
        for gone in [
            "Computed from the stored rows",
            "only ever support a path edge",
        ] {
            assert!(!a.contains(gone), "{gone} still there:\n{a}");
        }
        let at = |s: &str| a.find(s).unwrap_or_else(|| panic!("{s} missing"));
        assert!(at("<h2>Members</h2>") < at("data-link-graph"));
        assert!(at("data-link-graph") < at("<h2>Evidence</h2>"));
        let (_, _, b) = send(
            &app,
            get("/admin/campaigns/198.51.100.10", true),
            Body::empty(),
        )
        .await;
        assert!(b.contains("131 shared shapes"), "{b}");
        assert!(b.contains("/.env"), "shapes listed:\n{b}");
        assert!(b.contains("<th class=\"num\">IPs in dataset</th>"), "{b}");
        assert!(!b.contains("normalized paths most members"), "{b}");
        let (_, _, d) = send(
            &app,
            get("/admin/campaigns/198.51.100.30", true),
            Body::empty(),
        )
        .await;
        assert!(d.contains("JA4/JA4H match"), "{d}");

        for p in [
            "/admin/campaigns/nope",
            "/admin/campaigns/192.0.2.250",
            "/admin/campaigns/1'%20OR%201=1",
        ] {
            let (st, _, _) = send(&app, get(p, true), Body::empty()).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{p}");
        }

        // The IP page: a chip for a member, nothing for a singleton or
        // without a session.
        let (_, _, member) = send(&app, get("/ip/192.0.2.1", true), Body::empty()).await;
        assert!(
            member.contains("href=\"/admin/campaigns/192.0.2.3\">member of campaign #1"),
            "{member}"
        );
        let (_, _, single) = send(&app, get("/ip/203.0.113.20", true), Body::empty()).await;
        assert!(!single.contains("member of campaign"));
        let (_, _, public) = send(&app, get("/ip/192.0.2.1", false), Body::empty()).await;
        assert!(!public.contains("member of campaign"));
    }
}
