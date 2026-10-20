//! The Campaigns area: source IPs the recompute (`store::campaigns`) tied
//! together by typed evidence. A list and a page per campaign, read-only:
//! every route is a `GET`, and nothing here changes a campaign.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::{Chrome, link_href};
use crate::store::browse::{CALENDAR_DAYS, CalendarDay, canonical_ip};
use crate::store::campaigns::{
    Campaign, CampaignCommand, CampaignFilter, CampaignListItem, CampaignShape, Edge,
    HARD_FANOUT_MAX, ORDER_AGREE, Report,
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
    let edges = std::mem::take(&mut c.edges)
        .into_iter()
        .map(EdgeView::new)
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
}
