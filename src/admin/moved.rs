//! Old admin GET URLs (MIK-711 §3): each answers 308 to its place in
//! `views::ADMIN_TREE`, query kept; group roots 302 to their first child.
//! Behind the session like the pages. Keep for at least two releases.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::views::{ADMIN_TREE, moved};
use axum::{
    Router,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;

/// Old path prefix → new. A path moves by its longest matching prefix
/// (whole segments), the rest of the path carried over.
pub const MOVED: &[(&str, &str)] = &[
    ("/admin/analytics", "/admin/overview/analytics"),
    ("/admin/lookup", "/admin/investigate/lookup"),
    ("/admin/scans", "/admin/investigate/scans"),
    ("/admin/campaigns", "/admin/evidence/campaigns"),
    ("/admin/links/canaries", "/admin/evidence/canaries"),
    ("/admin/links", "/admin/evidence/links"),
    ("/admin/canaries", "/admin/evidence/canaries"),
    ("/admin/fingerprints", "/admin/evidence/links"),
    ("/admin/paths", "/admin/evidence/paths"),
    ("/admin/uploads", "/admin/traps/uploads"),
    ("/admin/cluster/node", "/admin/network/members"),
    ("/admin/cluster/access", "/admin/network/access"),
    ("/admin/cluster/ownership", "/admin/network/ownership"),
    ("/admin/cluster/credits", "/admin/network/credits"),
    ("/admin/market", "/admin/network/credits"),
    ("/admin/cluster", "/admin/network/members"),
    ("/admin/system", "/admin/system/status"),
    ("/admin/inbox", "/admin/system/inbox"),
    ("/admin/devices", "/admin/system/devices"),
];

/// The old GET routes this module answers. `/admin/lookup` and
/// `/admin/cluster/node/{key}` also take a POST, so their modules route
/// them to `redirect`; `/admin/queue` keeps its own (it maps old filters).
const ROUTES: &[&str] = &[
    "/admin/analytics",
    "/admin/scans",
    "/admin/scans/{id}",
    "/admin/scans/{id}/xml",
    "/admin/campaigns",
    "/admin/campaigns/{key}",
    "/admin/links",
    "/admin/links/canaries",
    "/admin/links/canaries/served/{id}",
    "/admin/links/{kind}/{value}",
    "/admin/canaries",
    "/admin/fingerprints",
    "/admin/paths",
    "/admin/uploads",
    "/admin/uploads/{uid}",
    "/admin/uploads/{uid}/content.zip",
    "/admin/cluster",
    "/admin/cluster/node/{key}/fork-proof",
    "/admin/cluster/access",
    "/admin/cluster/ownership",
    "/admin/cluster/credits",
    "/admin/market",
    "/admin/system",
    "/admin/inbox",
    "/admin/devices",
];

pub fn routes() -> Router<Arc<AdminState>> {
    let mut r = Router::new().route("/admin/decoys", get(decoys));
    for path in ROUTES {
        r = r.route(path, get(redirect));
    }
    for g in ADMIN_TREE.iter().filter(|g| g.key != "system") {
        let to = g.href();
        r = r.route(
            &format!("/admin/{}", g.key),
            get(move |_u: SessionUser| async move {
                (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
            }),
        );
    }
    r
}

/// Where an old path lives now, if it moved.
pub fn new_path(path: &str) -> Option<String> {
    MOVED
        .iter()
        .filter(|(old, _)| {
            path.strip_prefix(old)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .max_by_key(|(old, _)| old.len())
        .map(|(old, new)| format!("{new}{}", &path[old.len()..]))
}

/// 308 from an old path in `MOVED` to its new home.
pub async fn redirect(_u: SessionUser, uri: Uri) -> Response {
    match new_path(uri.path()) {
        Some(to) => moved(&to, &uri),
        None => crate::admin::error::not_found().await.into_response(),
    }
}

/// `/admin/decoys?tab=…` became one page per decoy; the rest of the query
/// carries over.
async fn decoys(_u: SessionUser, uri: Uri) -> Response {
    let mut tab = "mcp";
    let rest: Vec<&str> = uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|kv| match kv.strip_prefix("tab=") {
            Some(t) => {
                if let Some(k) = ["mcp", "llm", "web"].into_iter().find(|k| *k == t) {
                    tab = k;
                }
                false
            }
            None => !kv.is_empty(),
        })
        .collect();
    let to = if rest.is_empty() {
        format!("/admin/traps/{tab}")
    } else {
        format!("/admin/traps/{tab}?{}", rest.join("&"))
    };
    (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, to)]).into_response()
}
