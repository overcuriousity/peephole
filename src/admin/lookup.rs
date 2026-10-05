//! Admin → Lookup: on-demand enrichment of one address by every provider
//! the cluster can reach, shown once and never stored. See
//! [`crate::intel::lookup`].
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::public::{IntelCard, intel_cards};
use crate::admin::views::Chrome;
use crate::store::inspect::IpIntelRow;
use askama::Template;
use axum::{
    Router,
    extract::{Form, Query, State},
    response::Html,
    routing::get,
};
use std::net::IpAddr;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/lookup", get(page).post(lookup))
        .route("/admin/lookup/bulk", axum::routing::post(bulk))
}

/// The result for one address.
pub struct LookupResult {
    pub ip: String,
    /// Whether the dataset holds this address (then the IP page has the
    /// stored results).
    pub known: bool,
    /// Providers that answered, with the answering node.
    pub cards: Vec<IntelCard>,
    /// `(provider label, node, why)` for every provider without an answer.
    pub declined: Vec<(String, String, String)>,
}

#[derive(Template)]
#[template(path = "admin_lookup.html")]
struct LookupPage {
    chrome: Chrome,
    ip: String,
    error: Option<String>,
    result: Option<LookupResult>,
    per_peer: u32,
    cluster: bool,
    bulk: Option<Bulk>,
}

/// Addresses read from stored data only (no provider is asked).
pub struct Bulk {
    /// What was pasted, for the form.
    pub text: String,
    pub rows: Vec<crate::store::browse::IpSummary>,
    /// Single addresses not in the dataset.
    pub missing: Vec<String>,
    /// Pieces that are neither an address nor a network.
    pub unreadable: Vec<String>,
    /// More stored addresses matched than [`BULK_MAX`].
    pub capped: bool,
}

/// Most addresses one bulk lookup reads or lists.
pub const BULK_MAX: usize = 500;

#[derive(serde::Deserialize, Default)]
pub struct BulkForm {
    pub ips: Option<String>,
}

#[derive(serde::Deserialize, Default)]
pub struct IpForm {
    pub ip: Option<String>,
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

async fn page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<IpForm>,
) -> AppResult<Html<String>> {
    render(&LookupPage {
        chrome: chrome(),
        ip: q.ip.unwrap_or_default().trim().to_string(),
        error: None,
        result: None,
        per_peer: crate::intel::lookup::PER_PEER_PER_DAY,
        cluster: state.recorder.node().is_some(),
        bulk: None,
    })
}

async fn lookup(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<IpForm>,
) -> AppResult<Html<String>> {
    let text = f.ip.unwrap_or_default().trim().to_string();
    let cluster = state.recorder.node().is_some();
    let Ok(ip) = text.parse::<IpAddr>() else {
        return render(&LookupPage {
            chrome: chrome(),
            ip: text,
            error: Some("Not an IP address.".into()),
            result: None,
            per_peer: crate::intel::lookup::PER_PEER_PER_DAY,
            cluster,
            bulk: None,
        });
    };
    let ip = crate::net::canonical(ip);
    let result = run(&state, ip).await?;
    render(&LookupPage {
        chrome: chrome(),
        ip: ip.to_string(),
        error: None,
        result: Some(result),
        per_peer: crate::intel::lookup::PER_PEER_PER_DAY,
        cluster,
        bulk: None,
    })
}

/// Many addresses at once, from stored data: whether each is in the
/// dataset and what it did. Provider lookups stay one at a time (each
/// spends API budget).
async fn bulk(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<BulkForm>,
) -> AppResult<Html<String>> {
    let text = f.ips.unwrap_or_default();
    let (mut addrs, mut nets, mut unreadable) = (vec![], vec![], vec![]);
    for piece in text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|p| !p.is_empty())
        .take(BULK_MAX)
    {
        if let Ok(ip) = piece.parse::<IpAddr>() {
            addrs.push(crate::net::canonical(ip));
        } else if let Ok(n) = piece.parse::<ipnet::IpNet>() {
            nets.push(n.trunc());
        } else {
            unreadable.push(piece.to_string());
        }
    }
    let mut rows = state
        .store
        .ips_matching(&addrs, &nets, BULK_MAX as i64 + 1)
        .await?;
    let capped = rows.len() > BULK_MAX;
    rows.truncate(BULK_MAX);
    let missing = addrs
        .iter()
        .map(IpAddr::to_string)
        .filter(|a| !rows.iter().any(|r| &r.ip == a))
        .collect();
    render(&LookupPage {
        chrome: chrome(),
        ip: String::new(),
        error: None,
        result: None,
        per_peer: crate::intel::lookup::PER_PEER_PER_DAY,
        cluster: state.recorder.node().is_some(),
        bulk: Some(Bulk {
            text,
            rows,
            missing,
            unreadable,
            capped,
        }),
    })
}

/// Ask every reachable node and arrange the answers for the page.
pub async fn run(state: &AdminState, ip: IpAddr) -> anyhow::Result<LookupResult> {
    let answers = crate::intel::lookup::cluster(&state.recorder, &state.providers, ip).await;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut rows: Vec<IpIntelRow> = vec![];
    let mut declined = vec![];
    for a in &answers {
        for f in &a.resp.findings {
            rows.push(IpIntelRow {
                provider: f.provider.clone(),
                fetched_at: now.clone(),
                source_version: f.source_version.clone(),
                data_json: f.data.to_string(),
                node: Some(a.node.clone()),
            });
        }
        for (p, why) in &a.resp.declined {
            let label = crate::intel::provider_info(p)
                .map(|i| i.label.to_string())
                .unwrap_or_else(|| p.clone());
            declined.push((label, a.node.clone(), why.clone()));
        }
    }
    // Cards only for providers that answered; the rest is listed below.
    let cards = intel_cards(rows, true)
        .into_iter()
        .filter(|c| c.newest.is_some())
        .collect();
    let known = state.store.ip_by_addr(&ip.to_string()).await?.is_some();
    Ok(LookupResult {
        ip: ip.to_string(),
        known,
        cards,
        declined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    async fn app() -> (axum::Router, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        let token = store.create_session().await.unwrap();
        let cookie = format!("{}={token}", crate::admin::auth::session_cookie_name(&cfg));
        let geo: crate::intel::SharedGeo = Arc::new(std::sync::RwLock::new(None));
        std::fs::write(dir.path().join("tor-exit.txt"), "198.51.100.1\n").unwrap();
        let tor: crate::intel::SharedTor = Arc::new(std::sync::RwLock::new(
            crate::intel::tor::TorExitList::load(dir.path()).unwrap(),
        ));
        let providers: crate::intel::Providers = vec![
            Arc::new(crate::intel::provider::MaxMind(geo)),
            Arc::new(crate::intel::provider::TorExits(tor)),
        ];
        let state = Arc::new(AdminState::public_only(store, cfg).with_providers(providers));
        (crate::admin::full_router(state), cookie, dir)
    }

    async fn send(
        app: &axum::Router,
        req: axum::http::request::Builder,
        body: &str,
    ) -> (axum::http::StatusCode, String) {
        let r = app
            .clone()
            .oneshot(req.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&b).into_owned())
    }

    #[tokio::test]
    async fn the_page_needs_a_session_and_answers_from_local_providers() {
        let (app, cookie, _d) = app().await;
        // Anonymous: not even the form.
        let (status, _) = send(&app, axum::http::Request::get("/admin/lookup"), "").await;
        assert_ne!(status, 200);

        let (status, html) = send(
            &app,
            axum::http::Request::get("/admin/lookup?ip=203.0.113.9").header("cookie", &cookie),
            "",
        )
        .await;
        assert_eq!(status, 200);
        assert!(html.contains(r#"value="203.0.113.9""#));

        let post = || {
            axum::http::Request::post("/admin/lookup")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
        };
        let (status, html) = send(&app, post(), "ip=203.0.113.9").await;
        assert_eq!(status, 200);
        assert!(html.contains("Tor exit list"), "the exit list answered");
        assert!(html.contains("not listed"));
        assert!(html.contains("in the dataset"));
        // GeoLite2 is not loaded: listed as declined, with the reason.
        assert!(html.contains("MaxMind GeoLite2") && html.contains("not available on this node"));
        assert!(html.contains("no reachable node serves this provider"));

        let (status, html) = send(&app, post(), "ip=not-an-ip").await;
        assert_eq!(status, 200);
        assert!(html.contains("Not an IP address"));

        let (_, html) = send(&app, post(), "ip=2001:DB8::1").await;
        assert!(html.contains("2001:db8::1") && html.contains("not in the dataset"));
    }
}
