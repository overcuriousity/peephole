//! Admin → Lookup: what the dataset holds on one address, and what every
//! provider the cluster can reach says about it now (paid with credits in
//! a cluster). See [`crate::intel::lookup`] and [`crate::credits::pay`].
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
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

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

/// One provider as it would be asked: by whom, and at what price.
pub struct QuoteView {
    pub label: String,
    pub node: String,
    pub price: String,
}

/// What the form shows before a lookup: what this node can spend and what
/// the cluster asks.
#[derive(Default)]
pub struct Offer {
    /// The balance in credits (the fleet's, when this node has an owner).
    pub balance: Option<String>,
    pub fleet: bool,
    pub quotes: Vec<QuoteView>,
    /// What a lookup of every provider costs at most.
    pub total: String,
}

/// The offer box is information only: when the balance cannot be read, it
/// is left out and the page (and an answer already paid for) still shows.
async fn offer(state: &AdminState) -> Offer {
    let Some(node) = state.recorder.node() else {
        return Offer::default();
    };
    let balance = async {
        let book = crate::credits::book(node).await?;
        let siblings = crate::cluster::owner::fleet::siblings(&node.store).await?;
        let balance: u64 = std::iter::once(node.id())
            .chain(siblings.iter().copied())
            .map(|id| book.balance(&id))
            .sum();
        anyhow::Ok((balance, !siblings.is_empty()))
    }
    .await
    .inspect_err(|e| tracing::warn!(?e, "lookup: balance not read"))
    .ok();
    let all = crate::credits::pay::quotes(node, &state.providers);
    let mut quotes = vec![];
    let mut total = 0u64;
    for info in crate::intel::KNOWN_PROVIDERS {
        let Some(q) = all.get(info.name).and_then(|l| l.first()) else {
            continue;
        };
        total += q.price_mc as u64;
        quotes.push(QuoteView {
            label: info.label.to_string(),
            node: q.server_name.clone(),
            price: if q.price_mc == 0 {
                "free".into()
            } else {
                crate::credits::show(q.price_mc as u64)
            },
        });
    }
    Offer {
        balance: balance.map(|(b, _)| crate::credits::show(b)),
        fleet: balance.is_some_and(|(_, fleet)| fleet),
        quotes,
        total: crate::credits::show(total),
    }
}

/// A provider answer the dataset already held.
pub struct StoredView {
    pub card: IntelCard,
    pub provider: String,
    pub age: String,
}

/// The result for one address.
pub struct LookupResult {
    pub ip: String,
    /// What the dataset holds on the address; None: it is not in it.
    pub target: Option<crate::admin::target::Target>,
    /// For an address the dataset does not hold: what is near it.
    pub near: Option<crate::admin::target::Neighbourhood>,
    /// Provider answers from the dataset (under 24 hours old).
    pub stored: Vec<StoredView>,
    /// Answers asked for now, with the node that served and its charge.
    pub cards: Vec<IntelCard>,
    /// `(node, charged)` for every node that charged something.
    pub charges: Vec<(String, String)>,
    /// `(provider label, node, why)` for every provider without an answer.
    pub declined: Vec<(String, String, String)>,
    /// A serving node kept the answers in the dataset.
    pub kept: bool,
}

#[derive(Template)]
#[template(path = "admin_lookup.html")]
struct LookupPage {
    chrome: Chrome,
    ip: String,
    error: Option<String>,
    result: Option<LookupResult>,
    cluster: bool,
    offer: Offer,
    bulk: Option<Bulk>,
}

#[derive(serde::Deserialize, Default)]
pub struct IpForm {
    pub ip: Option<String>,
    /// A provider to ask although the dataset has a fresh answer.
    pub again: Option<String>,
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
        cluster: state.recorder.node().is_some(),
        offer: offer(&state).await,
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
            cluster,
            offer: offer(&state).await,
            bulk: None,
        });
    };
    let ip = crate::net::canonical(ip);
    let again: Vec<String> = f.again.into_iter().filter(|a| !a.is_empty()).collect();
    let result = run(&state, ip, &again).await?;
    render(&LookupPage {
        chrome: chrome(),
        ip: ip.to_string(),
        error: None,
        result: Some(result),
        cluster,
        // After the lookup: the balance it left.
        offer: offer(&state).await,
        bulk: None,
    })
}

fn age(secs: i64) -> String {
    match secs {
        s if s < 120 => "just now".into(),
        s if s < 7200 => format!("{} min old", s / 60),
        s => format!("{} h old", s / 3600),
    }
}

/// Look the address up and arrange the three parts of the page: what the
/// dataset knows, provider answers from the dataset, and live answers.
pub async fn run(state: &AdminState, ip: IpAddr, again: &[String]) -> AppResult<LookupResult> {
    let out = crate::intel::lookup::run(&state.recorder, &state.providers, ip, again).await;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let label = |p: &str| {
        crate::intel::provider_info(p)
            .map(|i| i.label.to_string())
            .unwrap_or_else(|| p.to_string())
    };
    let (mut rows, mut declined, mut charges) = (vec![], vec![], vec![]);
    for a in &out.answers {
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
            declined.push((label(p), a.node.clone(), why.clone()));
        }
        if a.charged_mc > 0 {
            charges.push((a.node.clone(), crate::credits::show(a.charged_mc as u64)));
        }
    }
    // Cards only for providers that answered; the rest is listed below.
    let cards = intel_cards(rows, true)
        .into_iter()
        .filter(|c| c.newest.is_some())
        .collect();
    let stored = out
        .stored
        .iter()
        .flat_map(|s| {
            let row = IpIntelRow {
                provider: s.provider.clone(),
                fetched_at: s.fetched_at.clone(),
                source_version: s.source_version.clone(),
                data_json: s.data.to_string(),
                node: s.node.clone(),
            };
            intel_cards(vec![row], true)
                .into_iter()
                .filter(|c| c.newest.is_some())
                .map(|card| StoredView {
                    card,
                    provider: s.provider.clone(),
                    age: age(s.age_secs),
                })
        })
        .collect();
    // The answers are paid for: what the dataset adds is shown when it can
    // be read, and its failure does not throw them away.
    let held = async {
        let row = state.store.ip_by_addr(&ip.to_string()).await?;
        let target = match &row {
            Some(r) => crate::admin::target::load(state, r, true, 1, false).await?,
            None => None,
        };
        let near = match target {
            Some(_) => None,
            None => Some(crate::admin::target::neighbourhood(state, ip).await?),
        };
        Ok::<_, AppError>((target, near))
    }
    .await;
    let (target, near) = held
        .inspect_err(|e| tracing::warn!(?e, %ip, "lookup: dataset not read"))
        .unwrap_or_default();
    Ok(LookupResult {
        ip: ip.to_string(),
        target,
        near,
        stored,
        cards,
        charges,
        declined,
        kept: out.kept,
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
        cluster: state.recorder.node().is_some(),
        offer: offer(&state).await,
        bulk: Some(Bulk {
            text,
            rows,
            missing,
            unreadable,
            capped,
        }),
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
