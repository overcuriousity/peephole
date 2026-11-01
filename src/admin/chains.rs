//! The Chains list, and the strip that shows a chain on the request, upload,
//! address, campaign and piece pages. Read-only: a chain is read from its
//! sightings ([`crate::store::chains`]) and nothing here changes one.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::public::urlencode;
use crate::admin::views::Chrome;
use crate::store::browse::{Page, canonical_ip, lenient_i64, page_num};
use crate::store::chains::{Anchor, Chain, ChainFilter, ChainRow, DeadEnd};
use askama::Template;
use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use std::sync::Arc;

/// Strips on an address, request or upload page.
pub const STRIPS: usize = 5;
/// Strips on a campaign's page.
pub const CAMPAIGN_STRIPS: usize = 32;
/// Rows a stage shows before the rest fold away.
pub const STAGE_ROWS: usize = 8;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/evidence/chains", get(index))
}

/// What `_chain_strip.html` draws. Empty, it draws nothing, not even a card.
#[derive(Default)]
pub struct Strips {
    /// Newest first; the first is open.
    pub chains: Vec<Chain>,
    /// The list, when there are more than are drawn.
    pub rest: Option<String>,
    /// A chain with no joiner: the chains its address is in, as title and
    /// page.
    pub elsewhere: Vec<(String, String)>,
}

impl Strips {
    /// `chains`, read with one more than `max`, cut to `max`.
    fn upto(mut chains: Vec<Chain>, max: usize, rest: String) -> Self {
        let more = chains.len() > max;
        chains.truncate(max);
        Self {
            chains,
            rest: more.then_some(rest),
            elsewhere: vec![],
        }
    }
}

fn address_list(ip: &str) -> String {
    format!("/admin/evidence/chains?ip={}", urlencode(ip))
}

/// A request's or upload's chains. With no joiner, its own, and links to
/// the chains of the address that sent it.
pub async fn of_source(
    st: &AdminState,
    anchor: Anchor<'_>,
    ip_id: i64,
    ip: &str,
) -> AppResult<Strips> {
    let chains = st.store.chains_upto(anchor, STRIPS + 1).await?;
    let mut strips = Strips::upto(chains, STRIPS, address_list(ip));
    if strips.chains.first().is_some_and(|c| c.key.is_none()) {
        let of_address = st.store.chains_upto(Anchor::Ip(ip_id), STRIPS + 1).await?;
        strips.rest = (of_address.len() > STRIPS).then(|| address_list(ip));
        strips.elsewhere = of_address
            .iter()
            .take(STRIPS)
            .filter_map(|c| c.href().map(|h| (c.title(), h.to_string())))
            .collect();
    }
    Ok(strips)
}

/// An address's chains, newest first, the rest behind a link.
pub async fn of_address(st: &AdminState, ip_id: i64, ip: &str) -> AppResult<Strips> {
    let chains = st.store.chains_upto(Anchor::Ip(ip_id), STRIPS + 1).await?;
    Ok(Strips::upto(chains, STRIPS, address_list(ip)))
}

/// A campaign's chains.
pub async fn of_campaign(st: &AdminState, key: &str) -> AppResult<Strips> {
    let anchor = Anchor::Campaign(key);
    let chains = st.store.chains_upto(anchor, CAMPAIGN_STRIPS + 1).await?;
    let rest = format!("/admin/evidence/chains?campaign={}", urlencode(key));
    Ok(Strips::upto(chains, CAMPAIGN_STRIPS, rest))
}

/// A piece's chain, or the sources sharing it.
pub async fn of_piece(st: &AdminState, hash: i64) -> AppResult<Strips> {
    Ok(Strips {
        chains: st.store.chains_of(Anchor::Piece(hash)).await?,
        ..Strips::default()
    })
}

#[derive(serde::Deserialize, Default)]
pub struct ChainsQuery {
    #[serde(default, deserialize_with = "lenient_i64")]
    page: Option<i64>,
    /// Only this address's chains (address pages link here).
    #[serde(default)]
    ip: Option<String>,
    /// Only the chains of this campaign's members.
    #[serde(default)]
    campaign: Option<String>,
    /// `dead-ends`: the paths asked for after an upload, found empty.
    #[serde(default)]
    tab: Option<String>,
}

/// Dead ends the tab lists.
const DEAD_END_ROWS: i64 = 200;

#[derive(Template)]
#[template(path = "admin_chains.html")]
struct ChainsPage {
    chrome: Chrome,
    page: Page<ChainRow>,
    /// Query string for the pager (ends in `&`).
    qs: String,
    ip: Option<String>,
    campaign: Option<String>,
    /// The Dead ends tab is open, with these rows.
    dead_ends: Option<Vec<DeadEnd>>,
}

async fn index(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<ChainsQuery>,
) -> AppResult<Html<String>> {
    let ip =
        q.ip.filter(|s| !s.trim().is_empty())
            .map(|s| canonical_ip(&s));
    let campaign = q.campaign.filter(|s| !s.trim().is_empty());
    if q.tab.as_deref() == Some("dead-ends") {
        return render(&ChainsPage {
            chrome: Chrome::new(true, "admin"),
            page: Page::from_rows(vec![], 1),
            qs: String::new(),
            ip: None,
            campaign: None,
            dead_ends: Some(st.store.dead_ends_all(DEAD_END_ROWS).await?),
        });
    }
    // An address the store does not know matches no row (id 0 is never
    // used), rather than dropping the filter.
    let ip_id = match &ip {
        Some(a) => Some(st.store.ip_by_addr(a).await?.map_or(0, |i| i.id)),
        None => None,
    };
    let filter = ChainFilter {
        ip: ip_id,
        campaign: campaign.as_deref(),
    };
    let page = st.store.chains_page(page_num(q.page), filter).await?;
    let qs = crate::admin::public::qs_without_page(&[
        ("ip", ip.clone()),
        ("campaign", campaign.clone()),
    ]);
    render(&ChainsPage {
        chrome: Chrome::new(true, "admin"),
        page,
        qs,
        ip,
        campaign,
        dead_ends: None,
    })
}

#[cfg(test)]
mod tests {
    use crate::admin::AdminState;
    use crate::admin::devices::tests::{app, send};
    use crate::store::pieces::piece_hash;
    use crate::store::requests::NewRequest;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    const IP: &str = "203.0.113.70";
    const OTHER: &str = "203.0.113.71";
    const LINK: &str = "chain-card";
    /// What the public address page has before its first card, as it did
    /// before the strip's line in `_target.html`.
    const GAP_BEFORE_TARGET: &str = "\n  \n\n";

    async fn request(st: &AdminState, ip: &str, path: &str) -> (i64, i64) {
        let ip_id = st.store.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
        let id = st
            .store
            .insert_request(&NewRequest {
                ip_id,
                method: "POST".into(),
                path: path.into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        (id, ip_id)
    }

    /// `(kind, value, role)` sighted in a request, with its grade.
    async fn sight(
        st: &AdminState,
        (kind, value, role, grade): (&str, &str, &str, &str),
        id: i64,
        ip_id: i64,
        ts: &str,
    ) -> i64 {
        let hash = piece_hash(kind, value);
        sqlx::query(
            "INSERT OR IGNORE INTO pieces (hash, kind, value, first_seen, last_seen, ips, sources)
             VALUES (?, ?, ?, ?, ?, 1, 1)",
        )
        .bind(hash)
        .bind(kind)
        .bind(value)
        .bind(ts)
        .bind(ts)
        .execute(&st.store.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO piece_sightings VALUES (?, 'request', ?, ?, ?, ?, ?)")
            .bind(hash)
            .bind(id)
            .bind(ip_id)
            .bind(role)
            .bind(grade)
            .bind(ts)
            .execute(&st.store.pool)
            .await
            .unwrap();
        hash
    }

    async fn pass(st: &AdminState) {
        st.store.recompute_campaigns(true).await.unwrap();
    }

    async fn page(app: &axum::Router, cookie: Option<&str>, uri: &str) -> (StatusCode, String) {
        let mut r = Request::get(uri).header("sec-fetch-site", "same-origin");
        if let Some(c) = cookie {
            r = r.header("cookie", c);
        }
        let (status, _, body) = send(app, r, Body::empty()).await;
        (status, body)
    }

    #[tokio::test]
    async fn request_page_shows_its_chain_at_the_top() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            id,
            ip,
            "2026-10-01 00:00:00",
        )
        .await;
        pass(&st).await;
        let (status, html) = page(&app, Some(&cookie), &format!("/admin/requests/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(LINK), "{html}");
        assert!(html.find(LINK) < html.find("req-line"), "{html}");
        for name in ["Exploit", "Command", "Delivery", "Payload", "Follow-up"] {
            assert!(
                html.contains(&format!("<h3>{name}</h3>")),
                "{name}:\n{html}"
            );
        }
        assert!(html.contains("a[.]example[.]org"), "{html}");
        assert!(!html.contains(">a.example.org<"), "{html}");
        assert!(html.contains("you are here"), "{html}");
        assert!(html.contains("never ran here"), "{html}");
        assert!(html.contains("href=\"/admin/evidence/links/stager/a.example.org\""));
    }

    #[tokio::test]
    async fn request_without_pieces_shows_no_strip() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        // A queried URL is a piece, and no strip.
        let queried = ("stager", "q.example.org", "queried", "claimed");
        sight(&st, queried, id, ip, "2026-10-01 00:00:00").await;
        let (bare, _) = request(&st, OTHER, "/b").await;
        pass(&st).await;
        for r in [id, bare] {
            let (status, html) = page(&app, Some(&cookie), &format!("/admin/requests/{r}")).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!html.contains("chain-card"), "{html}");
            assert!(!html.contains("Attack chain"), "{html}");
            assert!(!html.contains("data-section=\"chains\""), "{html}");
        }
    }

    #[tokio::test]
    async fn joinerless_request_links_to_its_addresses_chains() {
        let (st, cookie, app, _d) = app().await;
        let (a, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            a,
            ip,
            t,
        )
        .await;
        let (b, _) = request(&st, IP, "/b").await;
        sight(&st, ("recipe", "fetch|run", "recipe", "claimed"), b, ip, t).await;
        pass(&st).await;
        let (_, html) = page(&app, Some(&cookie), &format!("/admin/requests/{b}")).await;
        assert!(html.contains(">no joiner</span>"), "{html}");
        assert!(html.contains("fetch|run"), "{html}");
        assert!(html.contains("Its address is in:"), "{html}");
        assert!(
            html.contains(
                "<a class=\"mono\" href=\"/admin/evidence/links/stager/a.example.org\">a[.]example[.]org</a>"
            ),
            "{html}"
        );
    }

    #[tokio::test]
    async fn address_page_opens_the_newest_and_caps_at_5() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        for i in 0..6 {
            let value = format!("{i}.example.org");
            let ts = format!("2026-10-0{} 00:00:00", i + 1);
            sight(
                &st,
                ("stager", &value, "stager", "claimed"),
                id + i,
                ip,
                &ts,
            )
            .await;
        }
        pass(&st).await;
        let (status, html) = page(&app, Some(&cookie), &format!("/ip/{IP}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            html.matches("<details class=\"chain\"").count(),
            5,
            "{html}"
        );
        assert_eq!(
            html.matches("<details class=\"chain\" open>").count(),
            1,
            "{html}"
        );
        let open = html.find("<details class=\"chain\" open>").unwrap();
        assert!(html[open..].starts_with("<details class=\"chain\" open>\n    <summary><span class=\"chain-name\">5[.]example[.]org"), "{html}");
        assert!(
            !html.contains("0[.]example[.]org"),
            "the oldest is past the cap"
        );
        assert!(
            html.contains(&format!("href=\"/admin/evidence/chains?ip={IP}\"")),
            "{html}"
        );
        // The strip is the first section of the target.
        assert!(html.find("data-section=\"chains\"") < html.find("data-section=\"neighbourhood\""));
        // And the link holds the rest.
        let (_, rest) = page(
            &app,
            Some(&cookie),
            &format!("/admin/evidence/chains?ip={IP}"),
        )
        .await;
        assert!(rest.contains("0[.]example[.]org"), "{rest}");
    }

    #[tokio::test]
    async fn address_strip_is_admin_only() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            id,
            ip,
            t,
        )
        .await;
        pass(&st).await;
        let (status, public) = page(&app, None, &format!("/ip/{IP}")).await;
        assert_eq!(status, StatusCode::OK);
        for gone in ["chain-", "Attack chain", "a[.]example", "a.example.org"] {
            assert!(!public.contains(gone), "{gone}:\n{public}");
        }
        let (_, admin) = page(&app, Some(&cookie), &format!("/ip/{IP}")).await;
        assert!(admin.contains("Attack chain"), "{admin}");
        assert!(admin.contains("a[.]example[.]org"), "{admin}");
    }

    /// `_target.html`'s strip line leaves nothing behind on the public page.
    #[tokio::test]
    async fn the_public_page_gains_no_blank_line() {
        let (st, _cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            id,
            ip,
            t,
        )
        .await;
        pass(&st).await;
        let (_, public) = page(&app, None, &format!("/ip/{IP}")).await;
        assert!(!public.contains("chain"), "{public}");
        let open = "<div class=\"stack\">";
        let after = &public[public.find(open).expect("the target") + open.len()..];
        let gap = &after[..after.find('<').unwrap()];
        assert_eq!(gap, GAP_BEFORE_TARGET);
    }

    #[tokio::test]
    async fn strip_escapes_a_hostile_value() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        let evil = "</a><script>alert(1)</script>";
        for piece in [
            ("stager", evil, "stager", "claimed"),
            ("recipe", evil, "recipe", "claimed"),
            ("tag", evil, "tag", "claimed"),
            ("exploit", evil, "exploit", "seen"),
        ] {
            sight(&st, piece, id, ip, t).await;
        }
        pass(&st).await;
        for uri in [
            format!("/admin/requests/{id}"),
            format!("/ip/{IP}"),
            "/admin/evidence/chains".to_string(),
        ] {
            let (status, html) = page(&app, Some(&cookie), &uri).await;
            assert_eq!(status, StatusCode::OK);
            assert!(!html.contains("<script>alert(1)"), "{uri}:\n{html}");
            assert!(html.contains("&#60;script&#62;alert(1)"), "{uri}:\n{html}");
        }
    }

    #[tokio::test]
    async fn strip_marks_evidence_in_text() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            id,
            ip,
            t,
        )
        .await;
        sight(&st, ("exploit", "POST /a", "exploit", "seen"), id, ip, t).await;
        pass(&st).await;
        let (_, html) = page(&app, Some(&cookie), &format!("/admin/requests/{id}")).await;
        let strip: String = html.split_whitespace().collect::<Vec<_>>().join(" ");
        for want in [
            "<span class=\"chain-mark\">claimed · joiner · you are here</span>",
            "<span class=\"chain-mark\">seen · you are here</span>",
            "<span class=\"chain-mark\">gap</span>",
        ] {
            assert!(strip.contains(want), "{want}:\n{strip}");
        }
    }

    #[tokio::test]
    async fn a_long_stage_folds_the_rest() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        let stager = ("stager", "a.example.org", "stager", "claimed");
        sight(&st, stager, id, ip, t).await;
        let extra = 3;
        for i in 0..super::STAGE_ROWS + extra {
            let value = format!("step-{i}");
            sight(&st, ("recipe", &value, "recipe", "claimed"), id, ip, t).await;
        }
        pass(&st).await;
        let (_, html) = page(&app, Some(&cookie), &format!("/admin/requests/{id}")).await;
        assert!(
            html.contains(&format!("<summary>{extra} more</summary>")),
            "{html}"
        );
        assert_eq!(
            html.matches(">step-").count(),
            super::STAGE_ROWS + extra,
            "{html}"
        );
    }

    #[tokio::test]
    async fn chains_page_lists_newest_first() {
        let (st, cookie, app, _d) = app().await;
        let (old, a) = request(&st, IP, "/a").await;
        let (new, b) = request(&st, OTHER, "/b").await;
        let older = "2026-10-01 00:00:00";
        let newer = "2026-10-02 00:00:00";
        sight(
            &st,
            ("stager", "old.example.org", "stager", "claimed"),
            old,
            a,
            older,
        )
        .await;
        sight(
            &st,
            ("stager", "new.example.org", "stager", "claimed"),
            new,
            b,
            newer,
        )
        .await;
        sight(
            &st,
            ("exploit", "POST /b", "exploit", "seen"),
            new,
            b,
            newer,
        )
        .await;
        pass(&st).await;
        let (status, html) = page(&app, Some(&cookie), "/admin/evidence/chains").await;
        assert_eq!(status, StatusCode::OK);
        let first = html.find("new[.]example[.]org").expect("the new chain");
        let second = html.find("old[.]example[.]org").expect("the old chain");
        assert!(first < second, "{html}");
        assert!(html.contains("aria-current=\"page\">Chains"), "{html}");
        assert!(html.contains("<td>gap</td>"), "{html}");
        assert!(html.contains("href=\"/admin/evidence/links/stager/new.example.org\""));
    }

    #[tokio::test]
    async fn the_list_needs_a_session_and_takes_no_post() {
        let (_st, cookie, app, _d) = app().await;
        let (status, _) = page(&app, None, "/admin/evidence/chains").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let r = Request::post("/admin/evidence/chains")
            .header("cookie", &cookie)
            .header("sec-fetch-site", "same-origin");
        let (status, _, _) = send(&app, r, Body::empty()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, html) = page(&app, Some(&cookie), "/admin/evidence/chains").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("No chain yet."), "{html}");
    }

    #[tokio::test]
    async fn the_list_pages_keep_their_filter() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        for i in 0..101 {
            let value = format!("{i}.example.org");
            sight(
                &st,
                ("stager", &value, "stager", "claimed"),
                id + i,
                ip,
                "2026-10-01 00:00:00",
            )
            .await;
        }
        pass(&st).await;
        let (_, html) = page(
            &app,
            Some(&cookie),
            &format!("/admin/evidence/chains?ip={IP}"),
        )
        .await;
        assert!(html.contains(&format!("?ip={IP}&#38;page=2")), "{html}");
    }

    #[tokio::test]
    async fn piece_page_shows_its_chain_and_a_campaign_page_each_of_its_members() {
        let (st, cookie, app, _d) = app().await;
        let (id, ip) = request(&st, IP, "/a").await;
        let t = "2026-10-01 00:00:00";
        sight(
            &st,
            ("stager", "a.example.org", "stager", "claimed"),
            id,
            ip,
            t,
        )
        .await;
        sight(&st, ("recipe", "fetch|run", "recipe", "claimed"), id, ip, t).await;
        pass(&st).await;
        for uri in [
            "/admin/evidence/links/stager/a.example.org",
            "/admin/evidence/links/recipe/fetch%7Crun",
        ] {
            let (status, html) = page(&app, Some(&cookie), uri).await;
            assert_eq!(status, StatusCode::OK);
            assert!(html.contains("Attack chain"), "{uri}:\n{html}");
            assert!(html.contains("you are here"), "{uri}:\n{html}");
        }
        sqlx::query(
            "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
               hard_edges, soft_edges, v, computed_at)
             VALUES (?1, 1, ?2, 1, ?3, ?3, 0, 0, 1, ?3)",
        )
        .bind(IP)
        .bind(ip)
        .bind(t)
        .execute(&st.store.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, ?)")
            .bind(ip)
            .bind(IP)
            .execute(&st.store.pool)
            .await
            .unwrap();
        let (status, html) = page(
            &app,
            Some(&cookie),
            &format!("/admin/evidence/campaigns/{IP}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            html.matches("<details class=\"chain\"").count(),
            1,
            "{html}"
        );
        assert!(
            html.find("data-section=\"chains\"") < html.find("<h2>Members</h2>"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn upload_page_shows_its_chain() {
        let (st, cookie, app, _d) = app().await;
        let content = b"<?php echo 'a file of at least thirty-two bytes'; ?>";
        crate::admin::uploads::tests::upload(&st, "u1", "a.php", content, true).await;
        crate::store::pieces::extract(&st.store.pool).await.unwrap();
        pass(&st).await;
        let (status, html) = page(&app, Some(&cookie), "/admin/traps/uploads/u1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Attack chain"), "{html}");
        assert!(html.contains("a[.]php"), "{html}");
        assert!(html.contains("uploaded text"), "{html}");
        assert!(
            html.find("data-section=\"chains\"") < html.find("Time (UTC)"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn dead_end_tab_lists_a_404_after_upload() {
        let (st, cookie, app, _d) = app().await;
        let ip_id = st.store.upsert_ip(IP.parse().unwrap()).await.unwrap().id;
        sqlx::query(
            "INSERT INTO uploads (uid, ts, ip_id, kind, filename, sniffed_type, size, truncated,
               sha256, answered_path, path_is_prefix, content_state, request_uid)
             VALUES ('u1', '2026-10-01 00:00:00', ?, 'script', 's.php', 'php', 3, 0,
               x'00', '/uploads/s.php', 0, 'held', 'r1')",
        )
        .bind(ip_id)
        .execute(&st.store.pool)
        .await
        .unwrap();
        for (path, status) in [("/x/s.php", 404), ("/found/s.php", 200)] {
            st.store
                .insert_request(&NewRequest {
                    ip_id,
                    method: "GET".into(),
                    path: path.into(),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    status: Some(status),
                    ts: Some("2026-10-01 00:00:10".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let (status, html) =
            page(&app, Some(&cookie), "/admin/evidence/chains?tab=dead-ends").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("/x/s[.]php"), "{html}");
        assert!(!html.contains("/found/"), "{html}");
    }
}
