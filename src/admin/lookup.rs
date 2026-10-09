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
    extract::{Form, RawQuery, State},
    response::Html,
    routing::get,
};
use std::collections::HashMap;
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
    /// The provider's name, as the `ask` field carries it.
    pub provider: String,
    pub label: String,
    pub node: String,
    pub price: String,
}

/// What the page shows about spending: what this node can spend and what
/// the cluster asks.
#[derive(Default)]
pub struct Offer {
    /// The balance in credits (the fleet's, when this node has an owner).
    pub balance: Option<String>,
    pub fleet: bool,
    /// This node's own providers (free here), asked by every lookup.
    pub quotes: Vec<QuoteView>,
    /// What a lookup costs at most: their total.
    pub total: String,
    /// The providers asked only when told to, with their prices.
    pub paid: Vec<QuoteView>,
    /// What asking all of them costs.
    pub paid_total: String,
}

impl Offer {
    /// Split the cluster's quotes (the cheapest of each provider) into
    /// what this node answers itself and the others (`me` is this node).
    pub fn from_quotes(
        me: crate::cluster::identity::NodeId,
        all: &HashMap<String, Vec<crate::credits::pay::Quote>>,
    ) -> Offer {
        let cheap = crate::intel::lookup::cheap(me, all);
        let (mut quotes, mut paid) = (vec![], vec![]);
        let (mut total, mut paid_total) = (0u64, 0u64);
        for info in crate::intel::KNOWN_PROVIDERS {
            // This node's own quote when it serves the provider itself,
            // otherwise the cheapest.
            let Some(q) = all
                .get(info.name)
                .and_then(|l| l.iter().find(|q| q.server == me).or(l.first()))
            else {
                continue;
            };
            let view = QuoteView {
                provider: info.name.to_string(),
                label: info.label.to_string(),
                node: q.server_name.clone(),
                price: if q.price_mc == 0 {
                    "free".into()
                } else {
                    crate::credits::show(q.price_mc as u64)
                },
            };
            if cheap.iter().any(|c| c == info.name) {
                total += q.price_mc as u64;
                quotes.push(view);
            } else {
                paid_total += q.price_mc as u64;
                paid.push(view);
            }
        }
        Offer {
            quotes,
            total: crate::credits::show(total),
            paid,
            paid_total: crate::credits::show(paid_total),
            ..Default::default()
        }
    }
}

impl Offer {
    /// What asking `provider` costs: "free", "0.10 credits", or "" when no
    /// quote is known (standalone).
    pub fn price_of(&self, provider: &str) -> String {
        self.quotes
            .iter()
            .chain(&self.paid)
            .find(|q| q.provider == provider)
            .map(|q| match q.price.as_str() {
                "free" => "free".to_string(),
                p => format!("{p} credits"),
            })
            .unwrap_or_default()
    }
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
    Offer {
        balance: balance.map(|(b, _)| crate::credits::show(b)),
        fleet: balance.is_some_and(|(_, fleet)| fleet),
        ..Offer::from_quotes(
            node.id(),
            &crate::credits::pay::quotes(node, &state.providers),
        )
    }
}

/// A provider answer the dataset already held.
pub struct StoredView {
    pub card: IntelCard,
    pub provider: String,
    pub age: String,
}

/// Where a provider card on the Lookup page comes from.
pub enum GridSource {
    /// Asked just now (paid, or free from this node).
    Fresh,
    /// An answer of the last 24 hours from the dataset, shown free.
    Stored { provider: String, age: String },
    /// What the dataset holds, however old; `newest` None: nothing yet.
    Held,
}

pub struct GridCard {
    pub card: IntelCard,
    pub source: GridSource,
}

/// One card per provider: the fresh answer, else the stored one, else
/// what the dataset holds. Providers in the dataset's order, then the
/// rest; answered ones first, the rest are listed as waiting.
pub fn merge_grid(
    fresh: Vec<IntelCard>,
    stored: Vec<StoredView>,
    held: Vec<IntelCard>,
) -> Vec<GridCard> {
    let mut fresh: Vec<Option<IntelCard>> = fresh.into_iter().map(Some).collect();
    let mut stored: Vec<Option<StoredView>> = stored.into_iter().map(Some).collect();
    let mut take_fresh = |name: &str| {
        fresh
            .iter_mut()
            .find(|c| c.as_ref().is_some_and(|c| c.name == name))
            .and_then(Option::take)
    };
    let mut take_stored = |name: &str| {
        stored
            .iter_mut()
            .find(|c| c.as_ref().is_some_and(|c| c.card.name == name))
            .and_then(Option::take)
    };
    let mut out: Vec<GridCard> = held
        .into_iter()
        .map(|h| {
            if let Some(mut f) = take_fresh(&h.name) {
                f.others.extend(h.newest);
                f.others.extend(h.others);
                GridCard {
                    card: f,
                    source: GridSource::Fresh,
                }
            } else if let Some(s) = take_stored(&h.name) {
                GridCard {
                    card: s.card,
                    source: GridSource::Stored {
                        provider: s.provider,
                        age: s.age,
                    },
                }
            } else {
                GridCard {
                    card: h,
                    source: GridSource::Held,
                }
            }
        })
        .collect();
    out.extend(fresh.into_iter().flatten().map(|card| GridCard {
        card,
        source: GridSource::Fresh,
    }));
    out.extend(stored.into_iter().flatten().map(|s| GridCard {
        card: s.card,
        source: GridSource::Stored {
            provider: s.provider,
            age: s.age,
        },
    }));
    out.sort_by_key(|g| g.card.newest.is_none());
    out
}

/// The result for one address.
pub struct LookupResult {
    pub ip: String,
    /// What the dataset holds on the address; None: it is not in it.
    pub target: Option<crate::admin::target::Target>,
    /// For an address the dataset does not hold: what is near it.
    pub near: Option<crate::admin::target::Neighbourhood>,
    /// One card per provider: asked now, from the dataset under 24 hours,
    /// or what the dataset holds (its Intelligence section, moved here).
    pub grid: Vec<GridCard>,
    /// Some provider was asked now.
    pub asked: bool,
    /// `(node, charged)` for every node that charged something.
    pub charges: Vec<(String, String)>,
    /// `(provider label, node, why)` for every provider without an answer.
    pub declined: Vec<(String, String, String)>,
    /// A serving node kept the answers in the dataset.
    pub kept: bool,
}

impl LookupResult {
    pub fn signals(&self) -> Vec<crate::admin::signals::Signal> {
        crate::admin::signals::of(self.grid.iter().map(|g| &g.card))
    }

    /// Providers without a result, as "A, B".
    pub fn pending(&self) -> String {
        crate::admin::target::pending(self.grid.iter().map(|g| &g.card))
    }
}

/// One address a name resolved to.
pub struct AddrVote {
    pub ip: String,
    pub agreed: bool,
    /// "agreed by 4 of 5", "only from bob (DE), disputed", …
    pub verdict: String,
}

/// A name resolved by several nodes (see [`crate::intel::dns`]).
pub struct NamesView {
    pub name: String,
    /// How far the answer can be trusted, when not by a majority of several.
    pub note: Option<String>,
    pub rows: Vec<AddrVote>,
    /// Every node asked, as "name (country)".
    pub resolvers: Vec<String>,
    /// `(node, why)` for every node that did not answer.
    pub errors: Vec<(String, String)>,
    /// Agreed addresses past the first [`crate::intel::dns::MAX_FOLLOWED`]:
    /// not looked up.
    pub also: Vec<String>,
}

#[derive(Template)]
#[template(path = "admin_lookup.html")]
struct LookupPage {
    chrome: Chrome,
    ip: String,
    error: Option<String>,
    /// The resolved name, when a name was looked up.
    names: Option<NamesView>,
    /// One per address looked up: the address asked for, or the agreed
    /// addresses of a name.
    results: Vec<LookupResult>,
    cluster: bool,
    offer: Offer,
    bulk: Option<Bulk>,
}

/// The lookup form. `ask` and `again` may repeat, which the plain form
/// extractors cannot read, so the fields are taken from the pairs.
#[derive(Default)]
pub struct IpForm {
    pub ip: Option<String>,
    /// A provider to ask although the dataset has a fresh answer.
    pub again: Option<String>,
    /// The paid providers to ask now (`*`: all of them).
    pub ask: Option<Vec<String>>,
}

impl IpForm {
    fn parse(raw: &[u8]) -> IpForm {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(raw).unwrap_or_default();
        let mut f = IpForm::default();
        for (k, v) in pairs {
            match k.as_str() {
                "ip" => f.ip = Some(v),
                "again" => f.again = Some(v),
                "ask" => f.ask.get_or_insert_with(Vec::new).push(v),
                _ => {}
            }
        }
        f
    }

    /// The providers named, `*` standing for every known one: those this
    /// node answers itself are asked here first, free, and of members
    /// only as a fallback.
    fn asked(&self) -> Vec<String> {
        let ask = self.ask.as_deref().unwrap_or_default();
        if ask.iter().any(|a| a == "*") {
            return crate::intel::KNOWN_PROVIDERS
                .iter()
                .map(|p| p.name.to_string())
                .collect();
        }
        ask.iter().filter(|a| !a.is_empty()).cloned().collect()
    }
}

async fn page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    RawQuery(q): RawQuery,
) -> AppResult<Html<String>> {
    let q = IpForm::parse(q.unwrap_or_default().as_bytes());
    render(&LookupPage {
        chrome: chrome(),
        ip: q.ip.unwrap_or_default().trim().to_string(),
        error: None,
        names: None,
        results: vec![],
        cluster: state.recorder.node().is_some(),
        offer: offer(&state).await,
        bulk: None,
    })
}

async fn lookup(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    body: axum::body::Bytes,
) -> AppResult<Html<String>> {
    let f = IpForm::parse(&body);
    let ask = f.asked();
    let text = f.ip.unwrap_or_default().trim().to_string();
    let cluster = state.recorder.node().is_some();
    if text.parse::<IpAddr>().is_err() && is_list(&text) {
        return bulk_page(&state, text).await;
    }
    let Ok(ip) = text.parse::<IpAddr>() else {
        let (names, results, error) = match crate::intel::dns::valid_name(&text) {
            None => (None, vec![], Some("Not an IP address or host name.".into())),
            Some(name) => match by_name(&state, &name, async |n: &str| {
                crate::intel::dns::resolve_here(n).await
            })
            .await?
            {
                Ok((view, results)) => (Some(view), results, None),
                Err(e) => (None, vec![], Some(e)),
            },
        };
        return render(&LookupPage {
            chrome: chrome(),
            ip: text,
            error,
            names,
            results,
            cluster,
            offer: offer(&state).await,
            bulk: None,
        });
    };
    let ip = crate::net::canonical(ip);
    let again: Vec<String> = f.again.into_iter().filter(|a| !a.is_empty()).collect();
    let result = run(&state, ip, &ask, &again).await?;
    render(&LookupPage {
        chrome: chrome(),
        ip: ip.to_string(),
        error: None,
        names: None,
        results: vec![result],
        cluster,
        // After the lookup: the balance it left.
        offer: offer(&state).await,
        bulk: None,
    })
}

/// Resolve `name` with several nodes (`resolve` standing in for this
/// node's resolver), and look up the first [`crate::intel::dns::MAX_FOLLOWED`]
/// addresses they agree on (the cheap tier). The inner error: the name
/// was not resolved or not stored.
pub async fn by_name(
    state: &AdminState,
    name: &str,
    resolve: impl AsyncFn(&str) -> Result<Vec<IpAddr>, String>,
) -> AppResult<Result<(NamesView, Vec<LookupResult>), String>> {
    use crate::intel::dns;
    let (tally, record) = match dns::lookup_with(&state.recorder, &state.geo, name, resolve).await {
        Ok(x) => x,
        Err(e) => return Ok(Err(e)),
    };
    let label = |id: &crate::cluster::identity::NodeId| match state.recorder.node() {
        Some(node) => match dns::describe(node, &state.geo, id) {
            (n, Some(c)) => format!("{n} ({c})"),
            (n, None) => n,
        },
        None => "this node".to_string(),
    };
    let answers = record
        .as_ref()
        .map(|r| r.answers.as_slice())
        .unwrap_or_default();
    // Agreed addresses past those looked up go under "also resolves to".
    let past: Vec<IpAddr> = tally
        .votes
        .iter()
        .filter(|v| v.agreed)
        .skip(dns::MAX_FOLLOWED)
        .map(|v| v.addr)
        .collect();
    let rows = tally
        .votes
        .iter()
        .filter(|v| !past.contains(&v.addr))
        .map(|v| {
            let from: Vec<String> = answers
                .iter()
                .filter(|(_, a)| {
                    a.as_ref()
                        .is_ok_and(|l| l.iter().any(|x| crate::net::canonical(*x) == v.addr))
                })
                .map(|(id, _)| label(id))
                .collect();
            let verdict = match (v.agreed, v.votes) {
                (true, n) => format!("agreed by {n} of {}", tally.answered),
                (false, 1) => format!("only from {}, disputed", from.join(", ")),
                (false, n) => format!("{n} of {} ({}), disputed", tally.answered, from.join(", ")),
            };
            AddrVote {
                ip: v.addr.to_string(),
                agreed: v.agreed,
                verdict,
            }
        })
        .collect();
    let note = match (state.recorder.node(), tally.answered) {
        (_, 0) => Some("No resolver answered; nothing was stored.".to_string()),
        (None, _) => Some("resolved locally, unverified".to_string()),
        (Some(_), 1) => Some("unverified — single resolver".to_string()),
        _ => None,
    };
    let resolvers = match record.as_ref() {
        Some(r) => r.answers.iter().map(|(id, _)| label(id)).collect(),
        None => tally.errors.iter().map(|(id, _)| label(id)).collect(),
    };
    let agreed: Vec<IpAddr> = tally
        .votes
        .iter()
        .filter(|v| v.agreed)
        .map(|v| v.addr)
        .collect();
    let followed = futures::future::join_all(
        agreed
            .iter()
            .take(dns::MAX_FOLLOWED)
            .map(|ip| run(state, *ip, &[], &[])),
    )
    .await
    .into_iter()
    .collect::<AppResult<Vec<_>>>()?;
    Ok(Ok((
        NamesView {
            name: name.to_string(),
            note,
            rows,
            resolvers,
            errors: tally
                .errors
                .iter()
                .map(|(id, why)| (label(id), why.clone()))
                .collect(),
            also: past.iter().map(IpAddr::to_string).collect(),
        },
        followed,
    )))
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
pub async fn run(
    state: &AdminState,
    ip: IpAddr,
    ask: &[String],
    again: &[String],
) -> AppResult<LookupResult> {
    let out = crate::intel::lookup::run(&state.recorder, &state.providers, ip, ask, again).await;
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
    let cards: Vec<IntelCard> = intel_cards(rows, true)
        .into_iter()
        .filter(|c| c.newest.is_some())
        .collect();
    let stored: Vec<StoredView> = out
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
            None => {
                let asn = crate::admin::target::asn_named(
                    out.answers
                        .iter()
                        .flat_map(|a| &a.resp.findings)
                        .map(|f| &f.data)
                        .chain(out.stored.iter().map(|s| &s.data)),
                );
                Some(crate::admin::target::neighbourhood(state, ip, asn).await?)
            }
        };
        Ok::<_, AppError>((target, near))
    }
    .await;
    let (mut target, near) = held
        .inspect_err(|e| tracing::warn!(?e, %ip, "lookup: dataset not read"))
        .unwrap_or_default();
    let asked = !cards.is_empty();
    let held_cards = target
        .as_mut()
        .map(|t| std::mem::take(&mut t.intel))
        .unwrap_or_default();
    Ok(LookupResult {
        ip: ip.to_string(),
        target,
        near,
        grid: merge_grid(cards, stored, held_cards),
        asked,
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
    bulk_page(&state, f.ips.unwrap_or_default()).await
}

/// Several addresses or a network, as typed or pasted into the one field.
fn is_list(text: &str) -> bool {
    text.contains(|c: char| c.is_whitespace() || c == ',' || c == ';')
        || text.parse::<ipnet::IpNet>().is_ok()
}

async fn bulk_page(state: &AdminState, text: String) -> AppResult<Html<String>> {
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
        names: None,
        results: vec![],
        cluster: state.recorder.node().is_some(),
        offer: offer(state).await,
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

    fn card(name: &str, answered: bool) -> IntelCard {
        IntelCard {
            label: "L",
            name: name.into(),
            newest: answered.then(|| crate::admin::public::IntelResult {
                facts: vec![],
                fetched_at: format!("{name}-at"),
                source_version: None,
                node: None,
            }),
            others: vec![],
        }
    }

    #[test]
    fn grid_prefers_fresh_then_stored_then_held() {
        let held = vec![card("tor", true), card("rdap", true), card("shodan", false)];
        let fresh = vec![card("rdap", true), card("abuse", true)];
        let stored = vec![StoredView {
            card: card("shodan", true),
            provider: "shodan".into(),
            age: "2 h".into(),
        }];
        let g = merge_grid(fresh, stored, held);
        let names: Vec<_> = g.iter().map(|c| c.card.name.as_str()).collect();
        assert_eq!(names, ["tor", "rdap", "shodan", "abuse"]);
        assert!(matches!(g[0].source, GridSource::Held));
        assert!(matches!(g[1].source, GridSource::Fresh));
        // The held answer a fresh one replaces stays, as an older result.
        assert_eq!(g[1].card.others.len(), 1);
        assert!(matches!(&g[2].source, GridSource::Stored { age, .. } if age == "2 h"));
        assert!(matches!(g[3].source, GridSource::Fresh));
        // Answered first, then the providers without a result.
        let g = merge_grid(vec![], vec![], vec![card("a", false), card("b", true)]);
        assert_eq!(g[0].card.name, "b");
    }
    use tower::ServiceExt;

    async fn app() -> (axum::Router, String, tempfile::TempDir) {
        let (state, cookie, dir) = state().await;
        (crate::admin::full_router(state), cookie, dir)
    }

    async fn state() -> (Arc<AdminState>, String, tempfile::TempDir) {
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
        (state, cookie, dir)
    }

    #[tokio::test]
    async fn a_domain_lookup_shows_votes_and_the_agreed_addresses() {
        let (state, _cookie, _d) = state().await;
        let (view, results) = by_name(&state, "www.example.com", async |_: &str| {
            Ok(vec![
                "203.0.113.9".parse().unwrap(),
                "10.0.0.1".parse().unwrap(),
            ])
        })
        .await
        .unwrap()
        .unwrap();
        let html = LookupPage {
            chrome: chrome(),
            ip: "www.example.com".into(),
            error: None,
            names: Some(view),
            results,
            cluster: false,
            offer: Offer::default(),
            bulk: None,
        }
        .render()
        .unwrap();
        assert!(html.contains("resolved locally, unverified"), "{html}");
        assert!(html.contains("203.0.113.9") && html.contains("agreed by 1 of 1"));
        assert!(!html.contains("10.0.0.1"), "a private answer is dropped");
        assert!(
            html.contains("Tor exit list"),
            "the agreed address was looked up"
        );
        // The name is in the dataset, and on the address's admin view.
        let ip = state
            .store
            .ip_by_addr("203.0.113.9")
            .await
            .unwrap()
            .unwrap();
        let names = state.store.names_for_ip(ip.id).await.unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            (names[0].name.as_str(), names[0].agreed),
            ("www.example.com", true)
        );
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
        assert!(html.contains(r#"autofocus>203.0.113.9</textarea>"#));

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
        // Standalone: nothing paid is offered.
        assert!(!html.contains(r#"name="ask""#));

        let (status, html) = send(&app, post(), "ip=not-an-ip").await;
        assert_eq!(status, 200);
        assert!(html.contains("Not an IP address"));

        let (_, html) = send(&app, post(), "ip=2001:DB8::1").await;
        assert!(html.contains("2001:db8::1") && html.contains("not in the dataset"));
    }

    #[test]
    fn a_lookup_asks_the_cheap_tier_and_offers_the_rest() {
        use crate::credits::pay::Quote;
        let node = crate::cluster::identity::NodeId::from_slice(&[7u8; 32]).unwrap();
        let member = crate::cluster::identity::NodeId::from_slice(&[8u8; 32]).unwrap();
        let quote = |p: &str, mc: u32, server| {
            (
                p.to_string(),
                vec![Quote {
                    provider: p.into(),
                    server,
                    server_name: "n1".into(),
                    price_mc: mc,
                }],
            )
        };
        // This node answers Tor, GeoLite2 and InternetDB itself (free);
        // AbuseIPDB only a member serves.
        let all: HashMap<_, _> = [
            quote(crate::intel::TOR, 0, node),
            quote(crate::intel::MAXMIND, 0, node),
            quote(crate::intel::INTERNETDB, 0, node),
            quote(crate::intel::ABUSEIPDB, 100, member),
            // A member's zero price is listed as free, but not asked by itself.
            quote(crate::intel::SHODAN, 0, member),
        ]
        .into();
        let offer = Offer::from_quotes(node, &all);
        assert_eq!(offer.total, crate::credits::show(0));
        assert_eq!(offer.quotes.len(), 3);
        assert_eq!(offer.paid.len(), 2);
        assert_eq!(offer.price_of(crate::intel::SHODAN), "free");
        let abuse = offer
            .paid
            .iter()
            .find(|q| q.provider == crate::intel::ABUSEIPDB)
            .unwrap();
        assert_eq!(abuse.price, "0.10");
        assert_eq!(offer.paid_total, "0.10");
        // What an "Ask again" button shows.
        assert_eq!(offer.price_of(crate::intel::ABUSEIPDB), "0.10 credits");
        assert_eq!(offer.price_of(crate::intel::TOR), "free");
        assert_eq!(offer.price_of("nope"), "");
        let f = IpForm::parse(b"ip=203.0.113.9&ask=abuseipdb&ask=shodan");
        assert_eq!(f.asked(), ["abuseipdb", "shodan"]);
        // Every known provider, those this node answers itself included
        // (asked here first, free).
        let every = IpForm::parse(b"ask=*").asked();
        assert_eq!(every.len(), crate::intel::KNOWN_PROVIDERS.len());
        assert!(every.contains(&crate::intel::TOR.to_string()));
        assert!(every.contains(&crate::intel::ABUSEIPDB.to_string()));
        assert!(every.contains(&crate::intel::SHODAN.to_string()));
    }
}
