//! The Links area: what ties source IPs together. An index of every value
//! per kind, a page per value (or IP) with its neighbourhood graph, the
//! canary reuses, and the graph's JSON.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::{Chrome, link_href};
use crate::store::browse::{Page, canonical_ip};
use crate::store::links::{Focus, LinkFilter, LinkItem, LinkKind, LinkRow};
use crate::store::stats::Range;
use askama::Template;
use axum::{
    Json, Router,
    extract::{Path, Query, RawQuery, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/links", get(index))
        .route("/admin/links/canaries", get(canaries))
        .route("/admin/links/{kind}/{value}", get(item))
        .route("/admin/api/links/graph", get(graph))
        // Moved in the Links rework; the redirects reveal nothing.
        .route(
            "/admin/fingerprints",
            get(|| async { Redirect::permanent("/admin/links") }),
        )
        .route("/admin/canaries", get(canaries_moved))
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
    Ok(render(&LinksPage {
        chrome: chrome(),
        kind: f.kind(),
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
    /// `ip` pages: the address is stored.
    ip_seen: bool,
    kinds: Vec<LinkKind>,
    types: Vec<LinkKind>,
    depth: u32,
    /// `{key: name}` of every kind, for the graph's labels.
    kinds_json: String,
    /// Keys of the identity kinds.
    identity_json: String,
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
    let (kind_name, value, item, ip_seen) = if kind == "ip" {
        let addr = canonical_ip(&value);
        let seen = st.store.ip_by_addr(&addr).await?.is_some();
        ("IP", addr, None, seen)
    } else {
        let k = LinkKind::parse(&kind).ok_or(AppError::NotFound)?;
        let item = st.store.link_item(k, &value).await?;
        (k.name(), value, item, false)
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
    render(&LinkPage {
        chrome: chrome(),
        focus: format!("{kind}:{value}"),
        kind_key: kind,
        kind_name,
        value,
        item,
        ip_seen,
        kinds: LinkKind::ALL.to_vec(),
        types: gq.types(),
        depth: gq.depth(),
        kinds_json,
        identity_json,
    })
}

async fn graph(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<GraphQuery>,
) -> AppResult<Response> {
    let Some(focus) = q.focus.as_deref().and_then(Focus::parse) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "focus: <kind>:<value> or ip:<addr>",
        )
            .into_response());
    };
    let g = st
        .store
        .link_graph(&focus, q.depth(), &q.types(), q.all.as_deref() == Some("1"))
        .await?;
    Ok(Json(g).into_response())
}

/// Canaries moved under Links; the filter carries over.
async fn canaries_moved(RawQuery(q): RawQuery) -> Redirect {
    match q.filter(|q| !q.is_empty()) {
        Some(q) => Redirect::permanent(&format!("/admin/links/canaries?{q}")),
        None => Redirect::permanent("/admin/links/canaries"),
    }
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
            .chain(["legacy"])
            .collect(),
    })
}
