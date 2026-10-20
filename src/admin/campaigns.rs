//! The Campaigns area: source IPs the recompute (`store::campaigns`) tied
//! together by typed evidence. A list and a page per campaign, read-only:
//! every route is a `GET`, and nothing here changes a campaign.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::{Chrome, link_href};
use crate::store::browse::{CALENDAR_DAYS, CalendarDay, canonical_ip};
use crate::store::campaigns::{
    Campaign, CampaignCommand, CampaignFilter, CampaignListItem, CampaignShape, DF_RARE, Edge,
    EdgeDetail, HARD_FANOUT_MAX, MIN_SHARED_RARE, ORDER_AGREE, PATHS_T, PATHS_T_SUPPORTED, Report,
};
use crate::store::events::EventPage;
use crate::store::links::LinkKind;
use crate::store::uploads::UploadRow;
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
        .route("/admin/evidence/campaigns", get(index))
        .route("/admin/evidence/campaigns/{key}", get(campaign))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

/// Uploads and commands listed on a campaign's page.
pub const CAMPAIGN_ARTIFACTS: i64 = 50;
/// Events in a campaign's merged Timeline (no older pages).
pub const CAMPAIGN_EVENTS: i64 = 100;

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
    /// What tied a `paths` edge, as the pass stored it.
    pub detail: EdgeDetail,
}

impl EdgeView {
    pub fn new(e: Edge, detail: EdgeDetail) -> Self {
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
            detail,
        }
    }

    /// Whether a JA4/JA4H match or the order agreement lowered the score
    /// a `paths` edge needs.
    fn supported(&self) -> bool {
        self.e.fp_support || self.e.agreement.is_some_and(|x| x >= ORDER_AGREE)
    }

    /// The score test a `paths` edge passed, in words.
    pub fn score_rule(&self) -> String {
        let score = self.e.score.unwrap_or(0.0);
        if self.supported() {
            format!("score {score:.2} ≥ {PATHS_T_SUPPORTED:.2} (supported)")
        } else {
            format!(
                "score {score:.2} ≥ {PATHS_T:.2} (unsupported; {PATHS_T_SUPPORTED:.2} with support)"
            )
        }
    }

    /// The order agreement and the threshold it met, in words.
    pub fn agreement_rule(&self) -> String {
        match self.e.agreement {
            Some(x) if x >= ORDER_AGREE => {
                format!("order agreement {x:+.2} ≥ {ORDER_AGREE:.2}: supports")
            }
            Some(x) => format!("order agreement {x:+.2} < {ORDER_AGREE:.2}: no support"),
            None => "order agreement unknown (too few shared shapes in order)".into(),
        }
    }

    /// The shared shapes listed, with their document frequency, whether
    /// rare, and how many more the edge shares.
    pub fn shapes(&self) -> Vec<(&str, i64, bool)> {
        self.detail
            .shapes
            .iter()
            .map(|(t, df)| (t.as_str(), *df, *df as usize <= DF_RARE))
            .collect()
    }

    pub fn more_shapes(&self) -> i64 {
        self.e.shared.unwrap_or(0) - self.detail.shapes.len() as i64
    }

    /// The rule for rare shapes, in words.
    pub fn rare_rule(&self) -> String {
        format!("rare: on at most {DF_RARE} IPs; an edge needs {MIN_SHARED_RARE}")
    }

    /// The shared (JA4, JA4H) pairs with their Links pages.
    pub fn tls(&self) -> Vec<(&str, String, &str, String)> {
        self.detail
            .tls
            .iter()
            .map(|(x, y)| {
                (
                    x.as_str(),
                    link_href("ja4", x),
                    y.as_str(),
                    link_href("ja4h", y),
                )
            })
            .collect()
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
    uploads: Vec<UploadRow>,
    commands: Vec<CampaignCommand>,
    /// The merged Timeline, as `_events.html` reads it.
    t: CampaignTimeline,
    /// Agent-driven: a member carries an agent label.
    agent: bool,
    /// The members' property strips, by address.
    props: std::collections::HashMap<String, crate::store::evidence::IpProps>,
}

/// Wave lines on a campaign's page, at most.
pub const CAMPAIGN_WAVES: usize = 3;

impl CampaignPage {
    /// What ties the group, for the header line (MIK-689 #3): with no hard
    /// link, the strongest path similarity it rests on.
    fn strength(&self) -> String {
        let (hard, soft) = (self.c.row.hard_edges, self.c.row.soft_edges);
        if hard > 0 {
            return format!(
                "{hard} hard link{}, {soft} soft",
                if hard == 1 { "" } else { "s" }
            );
        }
        let best = self
            .edges
            .iter()
            .filter(|v| !v.hard())
            .filter_map(|v| v.e.score)
            .fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x))));
        let links = if soft == 1 {
            "soft link only"
        } else {
            "soft links only"
        };
        match best {
            Some(x) => format!("{links}: path similarity {x:.2}"),
            None => links.to_string(),
        }
    }

    /// The listed shapes that formed a wave, for the Shapes card.
    fn waves(&self) -> Vec<&CampaignShape> {
        self.shapes
            .iter()
            .filter(|s| s.wave.is_some())
            .take(CAMPAIGN_WAVES)
            .collect()
    }
}

/// The members' events for `_events.html`: an IP column, no older pages.
pub struct CampaignTimeline {
    pub events: EventPage,
    pub labels: bool,
}

impl CampaignTimeline {
    pub fn older_link(&self) -> Option<String> {
        None
    }

    pub fn ip_column(&self) -> bool {
        true
    }
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
    let mut detail = st.store.campaign_edge_detail(&key).await?;
    let edges = std::mem::take(&mut c.edges)
        .into_iter()
        .map(|e| {
            let d = match e.kind.as_str() {
                "paths" => detail.remove(&(e.a_id, e.b_id)).unwrap_or_default(),
                _ => EdgeDetail::default(),
            };
            EdgeView::new(e, d)
        })
        .collect();
    let calendar = st.store.campaign_calendar(&key).await?;
    let shapes = st.store.campaign_shapes(&key).await?;
    let uploads = st.store.campaign_uploads(&key, CAMPAIGN_ARTIFACTS).await?;
    let commands = st.store.campaign_commands(&key, CAMPAIGN_ARTIFACTS).await?;
    let events = st
        .store
        .campaign_events(&key, None, CAMPAIGN_EVENTS)
        .await?;
    let agent = !st.store.agent_campaigns(Some(&key)).await?.is_empty();
    let props =
        crate::admin::public::page_props(&st, true, c.members.iter().map(|m| m.ip.as_str()))
            .await?;
    render(&CampaignPage {
        props,
        chrome: chrome(),
        calendar_json: serde_json::to_string(&calendar).unwrap_or_else(|_| "[]".into()),
        calendar,
        calendar_days: CALENDAR_DAYS,
        shapes,
        uploads,
        commands,
        t: CampaignTimeline {
            events,
            labels: true,
        },
        edges,
        agent,
        c,
    })
}

#[cfg(test)]
mod tests {
    use crate::admin::devices::tests::{app, send};
    use crate::store::campaigns::tests::{feed, fixture, seed_artifacts, tls_fixture};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    /// The agent marks (MIK-566): "agent-driven" on the list and the page
    /// of a campaign with an agent-labelled member, the badge on that IP's
    /// page; none on the unlabelled campaign or IP.
    #[tokio::test]
    async fn agent_marks_follow_ip_labels() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        state.store.recompute_campaigns(true).await.unwrap();
        sqlx::query(
            "INSERT INTO ip_labels (ip_id, label, count)
             SELECT id, 'ai-agent-tooling', 1 FROM ips WHERE ip = '192.0.2.1'",
        )
        .execute(&state.store.pool)
        .await
        .unwrap();
        let get = |path: &str| {
            Request::get(path)
                .header("sec-fetch-site", "same-origin")
                .header("cookie", &cookie)
        };
        let page = |p: &'static str| {
            let app = app.clone();
            let r = get(p);
            async move {
                let (st, _, body) = send(&app, r, Body::empty()).await;
                assert_eq!(st, StatusCode::OK, "{p}");
                body
            }
        };
        let list = page("/admin/evidence/campaigns").await;
        assert_eq!(list.matches("badge-agent").count(), 1, "{list}");
        let row = list
            .split("<tr>")
            .find(|r| r.contains("badge-agent"))
            .unwrap();
        assert!(row.contains("/admin/evidence/campaigns/192.0.2.3"), "{row}");
        assert!(
            page("/admin/evidence/campaigns/192.0.2.3")
                .await
                .contains(">agent-driven</span>")
        );
        assert!(
            !page("/admin/evidence/campaigns/198.51.100.10")
                .await
                .contains("badge-agent")
        );
        assert!(page("/ip/192.0.2.1").await.contains(">agent traces</span>"));
        // MIK-697: each member row carries its property strip; the
        // header says what ties the group (MIK-689 #3).
        let camp = page("/admin/evidence/campaigns/192.0.2.3").await;
        let row = camp
            .split("<tr>")
            .find(|r| r.contains("href=\"/ip/192.0.2.1\">192.0.2.1</a>"))
            .unwrap();
        assert!(row.contains("class=\"ip-props\""), "{row}");
        assert!(row.contains(">agent traces</span>"), "{row}");
        assert!(camp.contains("class=\"campaign-strength"), "{camp}");
        assert!(!page("/ip/192.0.2.2").await.contains("badge-agent"));
    }

    #[tokio::test]
    async fn campaign_pages_render_and_need_a_session() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        tls_fixture(&state.store).await;
        state.store.recompute_campaigns(true).await.unwrap();
        seed_artifacts(&state.store).await;
        // A member's shape formed a wave.
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

        let paths = [
            "/admin/evidence/campaigns",
            "/admin/evidence/campaigns?country=DE",
            "/admin/evidence/campaigns/192.0.2.3",
            "/admin/evidence/campaigns/nope",
        ];
        for p in paths {
            let (st, h, _) = send(&app, get(p, false), Body::empty()).await;
            assert_eq!(st, StatusCode::SEE_OTHER, "{p}");
            assert_eq!(h["location"], "/login", "{p}");
        }
        // Read-only: no route takes a POST.
        for p in [
            "/admin/evidence/campaigns",
            "/admin/evidence/campaigns/192.0.2.3",
        ] {
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

        let (st, _, list) = send(&app, get("/admin/evidence/campaigns", true), Body::empty()).await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "href=\"/admin/evidence/campaigns/192.0.2.3\"",
            "#1",
            "href=\"/admin/evidence/campaigns/198.51.100.10\"",
            "Excluded values",
            "SHA256:image",
            "Last recompute",
            "aria-current=\"page\">Campaigns",
            "<dt>Soft edge</dt><dd class=\"plain\">The two IPs behave alike",
        ] {
            assert!(list.contains(want), "{want} missing:\n{list}");
        }
        // Short strings (MIK-494): the edge rules live on /admin/evidence/links only.
        assert!(
            list.contains("recomputed hourly. <a href=\"/admin/evidence/links\">What counts →</a>")
        );
        assert!(list.contains("· no edge</span>"));
        assert!(!list.contains("not one operator"), "{list}");
        let (_, _, few) = send(
            &app,
            get("/admin/evidence/campaigns?min=3", true),
            Body::empty(),
        )
        .await;
        assert!(few.contains("/admin/evidence/campaigns/192.0.2.3"));
        assert!(!few.contains("/admin/evidence/campaigns/198.51.100.10"));

        let (st, _, a) = send(
            &app,
            get("/admin/evidence/campaigns/192.0.2.3", true),
            Body::empty(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        for want in [
            "Campaign #1",
            "href=\"/ip/192.0.2.1\"",
            "shared ssh host key",
            "SHA256:operator",
            // The campaign graph (S4) sits between Members and Evidence.
            "data-focus=\"campaign:192.0.2.3\"",
            "<i class=\"line soft\"></i>soft: shared paths",
            // The edge legend and the fingerprint glossary (MIK-710).
            "<dt>Hard edge</dt><dd class=\"plain\">The two IPs share an identity",
            "on more than 50 IPs is shared infrastructure",
            "active within 30 days of each other",
            "join only on 2 soft edges",
            "<summary>What the fingerprints mean</summary>",
        ] {
            assert!(a.contains(want), "{want} missing:\n{a}");
        }
        for want in [
            "<a href=\"/admin/evidence/campaigns\">← All campaigns</a>",
            "soft · <a href=\"/admin/evidence/links\">what counts →</a>",
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
        // Artifacts (MIK-500): the members' uploads and commands, after
        // Evidence; the outsider's are not listed.
        assert!(at("<h2>Evidence</h2>") < at("data-section=\"artifacts\""));
        assert!(at("data-section=\"artifacts\"") < at("data-section=\"timeline\""));
        for want in [
            "<td class=\"path\">/drop.php</td>",
            "href=\"/admin/traps/uploads?sha256=",
            "<a href=\"/requests?cmd=ls%20-la\">ls -la</a></td><td class=\"num\">3</td><td class=\"num\">2</td>",
            "<a href=\"/requests?cmd=id\">id</a>",
        ] {
            assert!(a.contains(want), "{want} missing:\n{a}");
        }
        for gone in ["/out.php", "uname", "203.0.113.9"] {
            assert!(!a.contains(gone), "{gone} listed:\n{a}");
        }
        // The merged Timeline: the calendar and one events table with the
        // member's address on every row, no older pages.
        let tl = &a[at("data-section=\"timeline\"")..at("Shapes</h2>")];
        for want in [
            "data-calendar=",
            "<table class=\"events\">",
            "<th>IP</th>",
            "<td class=\"ip\"><a href=\"/ip/192.0.2.2\">192.0.2.2</a></td>",
            "data-kind=\"webshell\"",
            "data-kind=\"upload\"",
            "<td class=\"path\">/gamma</td>",
        ] {
            assert!(tl.contains(want), "{want} missing:\n{tl}");
        }
        assert!(!tl.contains("Older →"), "{tl}");
        // The wave line sits in the Shapes card.
        let shapes = &a[at("Shapes</h2>")..];
        assert!(
            shapes.contains(
                "started probing a path no rule knows: <code>/gamma</code> (12 IPs in 60 min, first seen 2026-09-01 10:00)"
            ),
            "{shapes}"
        );
        assert_eq!(shapes.matches("data-wave").count(), 1, "{shapes}");
        let (_, _, b) = send(
            &app,
            get("/admin/evidence/campaigns/198.51.100.10", true),
            Body::empty(),
        )
        .await;
        assert!(b.contains("131 shared shapes"), "{b}");
        // A campaign without artifacts keeps the empty states.
        assert!(b.contains("No file dropped by a member."), "{b}");
        assert!(b.contains("No webshell command run by a member."), "{b}");
        assert!(b.contains("/.env"), "shapes listed:\n{b}");
        assert!(b.contains("<th class=\"num\">IPs in dataset</th>"), "{b}");
        assert!(!b.contains("normalized paths most members"), "{b}");
        let (_, _, d) = send(
            &app,
            get("/admin/evidence/campaigns/198.51.100.30", true),
            Body::empty(),
        )
        .await;
        assert!(d.contains("JA4/JA4H match"), "{d}");

        for p in [
            "/admin/evidence/campaigns/nope",
            "/admin/evidence/campaigns/192.0.2.250",
            "/admin/evidence/campaigns/1'%20OR%201=1",
        ] {
            let (st, _, _) = send(&app, get(p, true), Body::empty()).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{p}");
        }

        // The IP page: a chip for a member, nothing for a singleton or
        // without a session.
        let (_, _, member) = send(&app, get("/ip/192.0.2.1", true), Body::empty()).await;
        assert!(
            member.contains("href=\"/admin/evidence/campaigns/192.0.2.3\">member of campaign #1"),
            "{member}"
        );
        let (_, _, single) = send(&app, get("/ip/203.0.113.20", true), Body::empty()).await;
        assert!(!single.contains("member of campaign"));
        let (_, _, public) = send(&app, get("/ip/192.0.2.1", false), Body::empty()).await;
        assert!(!public.contains("member of campaign"));
    }

    /// MIK-635: a soft edge's row expands to what tied it, the same shapes
    /// and (JA4, JA4H) pair the pass used.
    #[tokio::test]
    async fn soft_edges_show_what_tied_them() {
        let (state, cookie, app, _d) = app().await;
        feed(&state.store, fixture()).await;
        tls_fixture(&state.store).await;
        state.store.recompute_campaigns(true).await.unwrap();
        // The shapes both IPs of pair (d) asked for, with how many IPs did,
        // from the request rows (pair (d) has no light rows).
        let want: Vec<(String, i64)> = sqlx::query_as(
            "SELECT s.text, (SELECT COUNT(DISTINCT r.ip_id) FROM requests r WHERE r.shape = s.hash)
             FROM shapes s WHERE s.hash IN (
               SELECT shape FROM requests WHERE ip_id = (SELECT id FROM ips WHERE ip = ?1)
               INTERSECT
               SELECT shape FROM requests WHERE ip_id = (SELECT id FROM ips WHERE ip = ?2))
             ORDER BY 2, s.hash",
        )
        .bind("198.51.100.30")
        .bind("198.51.100.31")
        .fetch_all(&state.store.pool)
        .await
        .unwrap();
        assert_eq!(want.len(), 8, "{want:?}");
        let page = |p: &'static str| {
            let app = app.clone();
            let r = Request::get(p)
                .header("sec-fetch-site", "same-origin")
                .header("cookie", &cookie);
            async move {
                let (st, _, body) = send(&app, r, Body::empty()).await;
                assert_eq!(st, StatusCode::OK, "{p}");
                body
            }
        };
        let d = page("/admin/evidence/campaigns/198.51.100.30").await;
        let details = d
            .split("<details class=\"edge-detail\">")
            .nth(1)
            .and_then(|x| x.split("</details>").next())
            .unwrap_or_else(|| panic!("no edge detail:\n{d}"));
        let rows: Vec<(String, i64)> = details
            .split("<td class=\"mono break\">")
            .skip(1)
            .map(|r| {
                let (text, rest) = r.split_once("</td><td class=\"num\">").unwrap();
                let df = rest.split_once("</td>").unwrap().0.parse().unwrap();
                (text.to_string(), df)
            })
            .collect();
        assert_eq!(rows, want, "{details}");
        assert_eq!(details.matches("<td>rare</td>").count(), 8, "{details}");
        for want in [
            "href=\"/admin/evidence/links/ja4/t13d1516h2_x\">t13d1516h2_x</a>",
            "href=\"/admin/evidence/links/ja4h/ge11nn05enus_y\">ge11nn05enus_y</a>",
            "(supported)</li>",
            "≥ 0.45",
            "order agreement unknown",
            "rare: on at most 50 IPs; an edge needs 3",
        ] {
            assert!(details.contains(want), "{want} missing:\n{details}");
        }
        assert!(!details.contains("more shared"), "{details}");
        // No pair, and only the rarest EDGE_SHAPES_MAX of 131 listed.
        let b = page("/admin/evidence/campaigns/198.51.100.10").await;
        assert!(!b.contains("/admin/evidence/links/ja4/"), "{b}");
        assert!(b.contains("≥ 0.60 (unsupported; 0.45 with support)"), "{b}");
        assert!(
            b.contains("31 more shared, more common shapes not listed"),
            "{b}"
        );
        assert_eq!(
            b.matches("<td class=\"mono break\">").count(),
            crate::store::campaigns::EDGE_SHAPES_MAX,
            "{b}"
        );
        // Hard edges stay a plain row.
        assert!(
            !page("/admin/evidence/campaigns/192.0.2.3")
                .await
                .contains("edge-detail")
        );
    }
}
