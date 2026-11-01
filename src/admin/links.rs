//! The Links area: what ties source IPs together. An index of every value
//! per kind, a page per value (or IP) with its neighbourhood graph, the
//! canary reuses, a page per decoy with the canaries it served and their
//! uses, and the graph's JSON.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::chains::Strips;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::admin::views::{Chrome, link_href};
use crate::store::browse::{Page, canonical_ip};
use crate::store::links::{Focus, LinkFilter, LinkItem, LinkKind, LinkRow};
use crate::store::pieces::piece_hash;
use crate::store::stats::Range;
use askama::Template;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/evidence/links", get(index))
        .route("/admin/evidence/canaries", get(canaries))
        .route("/admin/evidence/canaries/served/{id}", get(decoy_canaries))
        .route("/admin/evidence/links/{kind}/{value}", get(item))
        .route(
            "/admin/evidence/links/{kind}/{value}/results",
            post(add_result),
        )
        .route("/admin/api/links/graph", get(graph))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

#[derive(Template)]
#[template(path = "admin_links.html")]
struct LinksPage {
    chrome: Chrome,
    f: LinkFilter,
    kind: LinkKind,
    page: Page<LinkRow>,
    /// Query string of the filter without `page`, for the pager.
    qs: String,
    /// Each kind and the page listing it with the other filters kept
    /// (not "starts with", which is a value of the old kind), and whether
    /// it opens the software group.
    kind_tabs: Vec<(LinkKind, String, bool)>,
    /// An old anchor that matched nothing.
    not_found: Option<String>,
}

async fn index(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(f): Query<LinkFilter>,
) -> AppResult<Response> {
    let mut not_found = None;
    if let Some(a) = f.anchor.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        match st.store.resolve_anchor(a).await? {
            Some((k, v)) => return Ok(Redirect::to(&link_href(k.key(), &v)).into_response()),
            None => not_found = Some(a.to_string()),
        }
    }
    let page = st.store.links_list(&f).await?;
    let qs = crate::admin::public::qs_without_page(&[
        ("kind", f.kind.clone()),
        ("q", f.q.clone()),
        ("shared", f.shared.clone()),
        ("from", f.from.clone()),
        ("to", f.to.clone()),
        ("country", f.country.clone()),
        ("node", f.node.clone()),
        ("sort", f.sort.clone()),
    ]);
    let kind_tabs = LinkKind::LIST
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let qs = crate::admin::public::qs_without_page(&[
                ("kind", Some(k.key().to_string())),
                ("shared", f.shared.clone()),
                ("from", f.from.clone()),
                ("to", f.to.clone()),
                ("country", f.country.clone()),
                ("node", f.node.clone()),
                ("sort", f.sort.clone()),
            ]);
            let group_start = i > 0 && !k.identity() && LinkKind::LIST[i - 1].identity();
            (
                *k,
                format!("/admin/evidence/links?{}", qs.trim_end_matches('&')),
                group_start,
            )
        })
        .collect();
    Ok(render(&LinksPage {
        chrome: chrome(),
        kind: f.kind(),
        kind_tabs,
        f,
        page,
        qs,
        not_found,
    })?
    .into_response())
}

/// The graph's options, from the page URL or the API call.
#[derive(serde::Deserialize, Default)]
pub struct GraphQuery {
    pub focus: Option<String>,
    pub depth: Option<String>,
    /// Comma-separated kind keys; unknown ones are ignored.
    pub types: Option<String>,
    pub all: Option<String>,
}

impl GraphQuery {
    fn depth(&self) -> u32 {
        self.depth
            .as_deref()
            .and_then(|d| d.parse().ok())
            .unwrap_or(2)
            .clamp(1, 3)
    }

    fn types(&self) -> Vec<LinkKind> {
        match self.types.as_deref() {
            None => LinkKind::IDENTITY.to_vec(),
            Some(t) => t
                .split(',')
                .filter_map(|k| LinkKind::parse(k.trim()))
                .collect(),
        }
    }
}

#[derive(Template)]
#[template(path = "admin_link.html")]
struct LinkPage {
    chrome: Chrome,
    /// `ip` or a kind's key.
    kind_key: String,
    kind_name: &'static str,
    value: String,
    /// Graph focus, as the API names it.
    focus: String,
    item: Option<LinkItem>,
    /// A stager's URLs, newest first.
    urls: Vec<StagerUrl>,
    /// `ip` pages: the address is stored.
    ip_seen: bool,
    /// A piece's chain, or the sources sharing it.
    strips: Strips,
    /// Sandbox results entered for a stager or file.
    results: Vec<ResultView>,
    /// A stager or file that joins a chain: the form is shown.
    can_add_result: bool,
    /// Where the form posts.
    results_action: String,
    kinds: Vec<LinkKind>,
    types: Vec<LinkKind>,
    depth: u32,
    /// `{key: name}` of every kind, for the graph's labels.
    kinds_json: String,
    /// Keys of the identity kinds.
    identity_json: String,
}

/// A URL a stager came from: shown defanged, and held raw only by the
/// "Copy for sandbox" button, which is never a link.
struct StagerUrl {
    shown: String,
    raw: String,
    last_seen: String,
    sources: i64,
}

/// A sandbox result as the page shows it. The URL is text, defanged.
struct ResultView {
    sha256: Option<String>,
    family: Option<String>,
    url: Option<String>,
    note: Option<String>,
    by: String,
    at: String,
}

impl LinkPage {
    fn seen(&self) -> bool {
        self.item.is_some() || self.ip_seen
    }

    /// The requests filter for this value, when there is one.
    fn requests_href(&self) -> Option<String> {
        let enc = crate::admin::public::urlencode(&self.value);
        match self.kind_key.as_str() {
            "ja4" => Some(format!("/requests?ja4={enc}")),
            "ja4h" => Some(format!("/requests?ja4h={enc}")),
            "ua" => Some(format!("/requests?ua={enc}")),
            _ => None,
        }
    }
}

async fn item(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path((kind, value)): Path<(String, String)>,
    Query(gq): Query<GraphQuery>,
) -> AppResult<Html<String>> {
    let mut urls = vec![];
    let mut strips = Strips::default();
    let mut results = vec![];
    let mut can_add_result = false;
    let (kind_name, value, shown, item, ip_seen) = if kind == "ip" {
        let addr = canonical_ip(&value);
        let seen = st.store.ip_by_addr(&addr).await?.is_some();
        ("IP", addr.clone(), addr, None, seen)
    } else {
        let k = LinkKind::parse(&kind).ok_or(AppError::NotFound)?;
        let item = st.store.link_item(k, &value).await?;
        if k == LinkKind::Stager && item.is_some() {
            urls = st
                .store
                .stager_urls(&value)
                .await?
                .into_iter()
                .map(|u| StagerUrl {
                    shown: crate::model::defang::defang(&u.url),
                    raw: u.url,
                    last_seen: u.last_seen,
                    sources: u.sources,
                })
                .collect();
        }
        if let Some(piece) = k.piece_kind() {
            let hash = piece_hash(piece, &value);
            strips = crate::admin::chains::of_piece(&st, hash).await?;
            if results_kind(piece) {
                results = st
                    .store
                    .piece_results(hash)
                    .await?
                    .into_iter()
                    .map(|r| ResultView {
                        sha256: r.sha256,
                        family: r.family,
                        url: r.source_url.as_deref().map(crate::model::defang::defang),
                        note: r.note,
                        by: r.added_by,
                        at: r.added_at,
                    })
                    .collect();
                can_add_result = strips.chains.iter().any(|c| {
                    c.stages[2]
                        .rows
                        .iter()
                        .any(|r| r.joiner && r.piece == Some(hash))
                });
            }
        }
        let shown = k.shown(&value);
        (k.name(), value, shown, item, false)
    };
    let kinds_json = serde_json::to_string(
        &LinkKind::ALL
            .iter()
            .map(|k| (k.key(), k.name()))
            .collect::<std::collections::BTreeMap<_, _>>(),
    )
    .unwrap_or_else(|_| "{}".into());
    let identity_json =
        serde_json::to_string(&LinkKind::IDENTITY.map(|k| k.key())).unwrap_or_else(|_| "[]".into());
    let (kind_key_raw, raw) = (kind.clone(), value.clone());
    render(&LinkPage {
        chrome: chrome(),
        focus: format!("{kind}:{value}"),
        kind_key: kind,
        kind_name,
        value: shown,
        item,
        urls,
        ip_seen,
        strips,
        results,
        can_add_result,
        results_action: format!("{}/results", link_href(&kind_key_raw, &raw)),
        kinds: LinkKind::ALL.to_vec(),
        types: gq.types(),
        depth: gq.depth(),
        kinds_json,
        identity_json,
    })
}

/// The kinds of piece a sandbox result can be entered for.
fn results_kind(piece: &str) -> bool {
    matches!(piece, "stager" | "file")
}

#[derive(serde::Deserialize)]
struct ResultForm {
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    note: String,
}

/// Record a sandbox result on a stager or file. Admin only, same-origin
/// only (the router's guard), and logged with who entered it.
async fn add_result(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    jar: axum_extra::extract::CookieJar,
    Path((kind, value)): Path<(String, String)>,
    axum::extract::Form(f): axum::extract::Form<ResultForm>,
) -> AppResult<Response> {
    let k = LinkKind::parse(&kind).ok_or(AppError::NotFound)?;
    let piece = k
        .piece_kind()
        .filter(|p| results_kind(p))
        .ok_or(AppError::NotFound)?;
    let back = link_href(k.key(), &value);
    let hash = piece_hash(piece, &value);
    let new = crate::store::pieces::NewResult {
        sha256: Some(f.sha256),
        family: Some(f.family),
        source_url: Some(f.source_url),
        note: Some(f.note),
    };
    let new = match new.checked() {
        Ok(n) => n,
        Err(e) => return Ok(redirect_with_error(&back, &format!("Not saved: {e}."))),
    };
    let by = match crate::admin::auth::session_token(&st, &jar) {
        Some(t) => st.store.session_admin_label(&t).await?,
        None => "admin".to_string(),
    };
    match st.store.add_piece_result(hash, &new, &by).await {
        Ok(id) => {
            tracing::info!(%by, piece = hash, id, kind = piece, "admin: sandbox result recorded");
            Ok(redirect_with_notice(&back, "Result saved."))
        }
        Err(e) => Ok(redirect_with_error(&back, &format!("Not saved: {e}."))),
    }
}

async fn graph(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<GraphQuery>,
) -> AppResult<Response> {
    let Some(focus) = q.focus.as_deref().and_then(Focus::parse) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "focus: <kind>:<value>, ip:<addr> or campaign:<key>",
        )
            .into_response());
    };
    let g = st
        .store
        .link_graph(&focus, q.depth(), &q.types(), q.all.as_deref() == Some("1"))
        .await?;
    Ok(Json(g).into_response())
}

#[derive(serde::Deserialize, Default)]
pub struct CanaryQuery {
    pub range: Option<String>,
    pub kind: Option<String>,
    pub node: Option<String>,
    /// `same` | `other`; anything else: both.
    pub source: Option<String>,
    pub ip: Option<String>,
}

impl CanaryQuery {
    /// The filter without the range, ending in `&`: the range links keep it.
    pub fn keep(&self) -> String {
        crate::admin::public::qs_without_page(&[
            ("kind", self.kind.clone()),
            ("node", self.node.clone()),
            ("source", self.source.clone()),
            ("ip", self.ip.clone()),
        ])
    }
}

#[derive(Template)]
#[template(path = "admin_canaries.html")]
struct CanariesPage {
    chrome: Chrome,
    range: Range,
    q: CanaryQuery,
    sum: crate::store::canaries::CanarySummary,
    reuses: Vec<crate::store::canaries::Reuse>,
    kinds: Vec<&'static str>,
}

async fn canaries(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<CanaryQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    // An address the store does not know matches no row (id 0 is never
    // used), rather than dropping the filter.
    let ip_id = match q.ip.as_deref().filter(|s| !s.is_empty()) {
        Some(a) => Some(st.store.ip_by_addr(a).await?.map_or(0, |i| i.id)),
        None => None,
    };
    let filter = crate::store::canaries::ReuseFilter {
        kind: q.kind.clone().filter(|k| !k.is_empty()),
        node: q.node.clone().filter(|n| !n.is_empty()),
        same_source: match q.source.as_deref() {
            Some("same") => Some(true),
            Some("other") => Some(false),
            _ => None,
        },
        range,
        request: None,
        ip_id,
        limit: 500,
    };
    let reuses = st.store.reuses(&filter).await?;
    let sum = st.store.canary_summary(range).await?;
    render(&CanariesPage {
        chrome: chrome(),
        range,
        q,
        sum,
        reuses,
        kinds: crate::canary::Kind::ALL_V1
            .iter()
            .map(|k| k.name())
            .chain(["etag", "legacy"])
            .collect(),
    })
}

/// A canary a decoy served and how often it came back.
pub struct ServedCanary {
    pub kind: String,
    pub value: String,
    /// As the Links pages name it.
    pub hash: i64,
    pub uses: usize,
}

#[derive(Template)]
#[template(path = "admin_canary_decoy.html")]
struct DecoyCanariesPage {
    chrome: Chrome,
    d: crate::store::inspect::RequestDetail,
    served: Vec<ServedCanary>,
    /// Requests that used one of them, newest first.
    uses: Vec<crate::store::canaries::Reuse>,
    /// The IPs that used them and how many uses each, most first.
    ips: Vec<(String, usize)>,
}

/// Uses listed on a decoy's page.
pub const DECOY_USES: i64 = 500;

/// One decoy: the canaries it served and every request and IP that used
/// them again.
async fn decoy_canaries(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<Html<String>> {
    let Some(d) = st.store.request_detail(id).await? else {
        return Err(AppError::NotFound);
    };
    let served = d.served_canaries();
    if served.is_empty() {
        return Err(AppError::NotFound);
    }
    let uses: Vec<_> = st
        .store
        .reuses(&crate::store::canaries::ReuseFilter {
            request: Some(id),
            range: Range::All,
            limit: DECOY_USES,
            ..Default::default()
        })
        .await?
        .into_iter()
        .filter(|r| r.served_request_id == Some(id))
        .collect();
    let served = served
        .into_iter()
        .map(|(kind, value)| {
            let hash = crate::canary::hash(&value);
            let uses = uses.iter().filter(|r| r.value_hash == hash).count();
            ServedCanary {
                kind,
                value,
                hash,
                uses,
            }
        })
        .collect();
    let mut ips: Vec<(String, usize)> = vec![];
    for r in &uses {
        match ips.iter_mut().find(|(ip, _)| *ip == r.used_ip) {
            Some((_, n)) => *n += 1,
            None => ips.push((r.used_ip.clone(), 1)),
        }
    }
    ips.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    render(&DecoyCanariesPage {
        chrome: chrome(),
        d,
        served,
        uses,
        ips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::devices::tests::{app, send};
    use axum::body::Body;
    use axum::http::Request;

    const RAW: &str = "https://example.org:8080/x.sh";

    /// A stager piece on one address, with the URL it came from.
    async fn seed(st: &AdminState) -> i64 {
        let ip = st
            .store
            .upsert_ip("203.0.113.7".parse().unwrap())
            .await
            .unwrap()
            .id;
        let hash = crate::store::pieces::piece_hash("stager", "example.org:8080");
        for q in [
            "INSERT INTO pieces VALUES (?1, 'stager', 'example.org:8080', 't', 't', 1, 1)",
            "INSERT INTO piece_sightings VALUES (?1, 'request', 1, ?2, 'stager', 'seen', 't')",
            "INSERT INTO piece_urls VALUES (?1, 'https://example.org:8080/x.sh', 't', 't', 1)",
            "INSERT INTO piece_url_sources VALUES (?1, 'https://example.org:8080/x.sh', 'request', 1, 't')",
            "INSERT INTO piece_urls VALUES (?1, 'https://example.org:8080/q', 't', 't', 1)",
            "INSERT INTO piece_url_sources VALUES (?1, 'https://example.org:8080/q', 'request', 2, 't')",
        ] {
            sqlx::query(q)
                .bind(hash)
                .bind(ip)
                .execute(&st.store.pool)
                .await
                .unwrap();
        }
        hash
    }

    async fn page(cookie: &str, app: &axum::Router, uri: &str) -> (StatusCode, String) {
        let (status, _, body) = send(
            app,
            Request::get(uri).header("cookie", cookie),
            Body::empty(),
        )
        .await;
        (status, body)
    }

    #[tokio::test]
    async fn piece_page_shows_defanged_value() {
        let (st, cookie, app, _d) = app().await;
        seed(&st).await;
        let (status, body) = page(
            &cookie,
            &app,
            "/admin/evidence/links/stager/example.org%3A8080",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("example[.]org"));
        assert!(!body.contains(">example.org:8080<"));
        // The value is never a link; `hxxps://` is how the URL reads.
        assert!(body.contains("hxxps://example[.]org:8080/x[.]sh"), "{body}");
        assert!(!body.contains("<a href=\"https://example.org"));
        assert!(!body.contains("<a href=\"hxxp"));
        // The list shows it defanged too.
        let (_, list) = page(&cookie, &app, "/admin/evidence/links?kind=stager&shared=0").await;
        assert!(list.contains("example[.]org"), "{list}");
        assert!(!list.contains(">example.org:8080<"));
    }

    /// The stager of `seed`, made a chain joiner as a pass would.
    async fn join(st: &AdminState, hash: i64) {
        sqlx::query("INSERT INTO chains VALUES ('k', 't', 't', 1, 1, 1)")
            .execute(&st.store.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO chain_pieces VALUES ('k', ?)")
            .bind(hash)
            .execute(&st.store.pool)
            .await
            .unwrap();
    }

    const STAGER_PAGE: &str = "/admin/evidence/links/stager/example.org%3A8080";
    const RESULTS: &str = "/admin/evidence/links/stager/example.org%3A8080/results";

    fn form(uri: &str, cookie: Option<&str>, site: Option<&str>, body: &str) -> Request<Body> {
        let mut r = Request::post(uri).header("content-type", "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            r = r.header("cookie", c);
        }
        if let Some(s) = site {
            r = r.header("sec-fetch-site", s);
        }
        r.body(Body::from(body.to_string())).unwrap()
    }

    async fn results_in(st: &AdminState) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM piece_results")
            .fetch_one(&st.store.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn result_form_only_on_stager_and_file() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        // Seen, but not a joiner: no form.
        let (_, body) = page(&cookie, &app, STAGER_PAGE).await;
        assert!(!body.contains("Add result"), "{body}");
        join(&st, hash).await;
        let (_, body) = page(&cookie, &app, STAGER_PAGE).await;
        assert!(body.contains("Add result"), "{body}");
        assert!(body.contains(&format!("action=\"{RESULTS}\"")), "{body}");
        // Other kinds never carry it, and refuse the post.
        for kind in ["key", "recipe", "exploit-tag", "ssh"] {
            let uri = format!("/admin/evidence/links/{kind}/x");
            let (_, body) = page(&cookie, &app, &uri).await;
            assert!(!body.contains("Add result"), "{kind}");
            let (status, _, _) = send(
                &app,
                Request::post(format!("{uri}/results"))
                    .header("cookie", &cookie)
                    .header("sec-fetch-site", "same-origin")
                    .header("content-type", "application/x-www-form-urlencoded"),
                Body::from("family=x"),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{kind}");
        }
        assert_eq!(results_in(&st).await, 0);
    }

    #[tokio::test]
    async fn result_needs_csrf_and_a_session() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        join(&st, hash).await;
        let body = "family=Mirai";
        for (c, site) in [
            (Some(cookie.as_str()), Some("cross-site")),
            (Some(cookie.as_str()), None),
        ] {
            let (status, _, _) = send_form(&app, form(RESULTS, c, site, body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{site:?}");
        }
        let (status, headers, _) =
            send_form(&app, form(RESULTS, None, Some("same-origin"), body)).await;
        assert!(status.is_redirection());
        assert_eq!(headers["location"], "/login");
        assert_eq!(results_in(&st).await, 0);
        let (status, _, _) =
            send_form(&app, form(RESULTS, Some(&cookie), Some("same-origin"), body)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(results_in(&st).await, 1);
    }

    async fn send_form(
        app: &axum::Router,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        use tower::ServiceExt;
        let r = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (r.status(), r.headers().clone());
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8_lossy(&b).into_owned())
    }

    #[tokio::test]
    async fn result_is_audit_logged() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        join(&st, hash).await;
        let (status, _, _) = send_form(
            &app,
            form(RESULTS, Some(&cookie), Some("same-origin"), "family=Mirai&note=n"),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let got = st.store.piece_results(hash).await.unwrap();
        assert_eq!(got.len(), 1);
        // The session is a bare one: who entered it is kept with it.
        assert!(!got[0].added_by.is_empty());
        assert!(!got[0].added_at.is_empty());
        assert_eq!(got[0].family.as_deref(), Some("Mirai"));
    }

    #[tokio::test]
    async fn a_refused_entry_is_not_saved() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        join(&st, hash).await;
        for body in ["sha256=zz", "family=", &format!("family={}", "f".repeat(65))] {
            let (status, headers, _) =
                send_form(&app, form(RESULTS, Some(&cookie), Some("same-origin"), body)).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
            assert!(
                headers
                    .get_all("set-cookie")
                    .iter()
                    .any(|c| c.to_str().unwrap().starts_with("peephole_flash_error")),
                "{body}"
            );
        }
        assert_eq!(results_in(&st).await, 0);
    }

    #[tokio::test]
    async fn source_url_renders_as_text_not_a_link() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        join(&st, hash).await;
        let body = "family=%3Cb%3Ex%3C%2Fb%3E&source_url=https%3A%2F%2Fexample.org%2Freport%3Fa%3D1&note=%3Cscript%3E";
        send_form(&app, form(RESULTS, Some(&cookie), Some("same-origin"), body)).await;
        let (_, html) = page(&cookie, &app, STAGER_PAGE).await;
        assert!(html.contains("hxxps://example[.]org/report?a=1"), "{html}");
        assert!(!html.contains("https://example.org/report"), "{html}");
        assert!(!html.contains("href=\"hxxp"));
        assert!(!html.contains("<script>") && !html.contains("<b>x"), "{html}");
        assert!(html.contains("&lt;b&gt;x"), "{html}");
    }

    #[tokio::test]
    async fn a_result_stays_when_no_sighting_is_left() {
        let (st, cookie, app, _d) = app().await;
        let hash = seed(&st).await;
        join(&st, hash).await;
        st.store
            .add_piece_result(
                hash,
                &crate::store::pieces::NewResult {
                    family: Some("Mirai".into()),
                    ..Default::default()
                },
                "admin",
            )
            .await
            .unwrap();
        sqlx::query("DELETE FROM piece_sightings")
            .execute(&st.store.pool)
            .await
            .unwrap();
        let (status, html) = page(&cookie, &app, STAGER_PAGE).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Mirai") && html.contains("Not seen"), "{html}");
        assert!(!html.contains("Add result"));
    }

    #[tokio::test]
    async fn stager_page_lists_urls_with_copy_for_sandbox() {
        let (st, cookie, app, _d) = app().await;
        seed(&st).await;
        let (_, body) = page(
            &cookie,
            &app,
            "/admin/evidence/links/stager/example.org%3A8080",
        )
        .await;
        assert!(body.contains("Copy for sandbox"));
        // The raw URL only as the button's text to copy, not as a link or
        // visible text.
        assert!(body.contains(r#"data-copy-value="https://example.org:8080/x.sh""#));
        assert_eq!(body.matches("https://example.org:8080/x.sh").count(), 1);
        assert!(!body.contains(r#"href="https://example.org"#));
        // A URL only a non-stager sighting named is not listed.
        assert!(!body.contains("8080/q"));
    }

    #[test]
    fn sha256_pivot_redirects_to_file_page() {
        let h = "ab".repeat(32);
        assert_eq!(
            crate::admin::views::pivot_href("sha256", &h),
            format!("/admin/evidence/links/file/{h}")
        );
        // The old address still names the uploads list.
        assert_eq!(
            crate::admin::views::uploads_by_hash_href(&h),
            format!("/admin/traps/uploads?sha256={h}")
        );
    }

    #[tokio::test]
    async fn the_file_page_without_a_piece_links_to_the_uploads() {
        let (_st, cookie, app, _d) = app().await;
        let h = "ab".repeat(32);
        let (status, body) = page(&cookie, &app, &format!("/admin/evidence/links/file/{h}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&format!("/admin/traps/uploads?sha256={h}")));
        let (status, _) = page(&cookie, &app, &format!("/admin/traps/uploads?sha256={h}")).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[derive(Template)]
    #[template(
        source = r#"{% let small = false %}{% include "_campaign_graph.html" %}"#,
        ext = "html"
    )]
    struct Embed {
        chrome: Chrome,
        campaign_key: String,
    }

    #[test]
    fn the_campaign_embed_draws_paths_edges_dashed() {
        let html = Embed {
            chrome: chrome(),
            campaign_key: "203.0.113.1".into(),
        }
        .render()
        .unwrap();
        assert!(html.contains(r#"data-focus="campaign:203.0.113.1""#));
        assert!(html.contains(r#"data-center="ip:203.0.113.1""#));
        assert!(html.contains("/assets/js/linkgraph.js"));
        // The legend's dashed line, and the class linkgraph.js gives a
        // non-identity edge, which the stylesheet dashes.
        assert!(html.contains(r#"<i class="line soft"></i>soft: shared paths"#));
        let js = include_str!("../../assets/js/linkgraph.js");
        assert!(js.contains(r#""edge" + (e.identity ? "" : " soft")"#));
        let css = include_str!("../../assets/css/45-viz.css");
        assert!(css.contains(".link-graph .edge.soft .line { stroke-dasharray"));
    }
}
