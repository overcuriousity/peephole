//! Probes in the admin: the Actions card (whether this address may be
//! probed, and from where at what price), `POST /admin/lookup/probe`, the
//! Probes section on the IP page and the lookup result, and the SSE stream
//! that refreshes the page when a result lands. See [`crate::scan::probe`].
//!
//! A request is answered at once (nothing waits for a probe); what was
//! asked and not yet answered by a result is kept in memory, in
//! [`AdminState::pending_probes`]. A restart forgets it: the page then
//! shows a request once its result arrives.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::AppResult;
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::cluster::identity::NodeId;
use crate::intel::geo::{Coords, haversine_km};
use crate::scan::probe::gate::LOCAL;
use crate::scan::probe::{ask, serve::Prober};
use crate::store::data::{new_uid, now_ts};
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    response::{
        Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::stream::Stream;
use serde_json::Value;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/lookup/probe", post(request))
        .route("/admin/api/probes", get(stream))
}

/// An accepted request without a result is `lapsed` after this long.
pub const LAPSE_AFTER: Duration = Duration::from_secs(15 * 60);
/// A pending request is forgotten after this long.
const FORGET_AFTER: Duration = Duration::from_secs(24 * 3600);
/// Vantages ticked by default.
const DEFAULT_VANTAGES: usize = 3;
/// How often the stream looks again without a log change.
const POLL: Duration = Duration::from_secs(3);
/// How often the stream re-checks the session.
const SESSION_EVERY: Duration = Duration::from_secs(30);

/// One scanner asked to probe, until its result is in.
pub struct Pending {
    pub ip_id: i64,
    pub node: NodeId,
    pub name: String,
    pub at: Instant,
    pub asked_at: String,
    pub price_mc: u32,
    /// None: the request is still on its way; `Ok`: accepted (with the
    /// probe uid when the scanner named it); `Err`: declined, and why.
    pub outcome: Option<Result<String, String>>,
}

/// Pending requests by group uid.
pub type PendingMap = HashMap<String, Vec<Pending>>;

/// The Actions card.
pub struct ActionsView {
    /// What the counter-scan found and what the evidence allows, or why a
    /// probe is unavailable.
    pub guard_line: String,
    pub allowed: bool,
    pub why_not: Option<String>,
    pub vantages: Vec<VantageView>,
    /// Node ids (text) ticked by default.
    pub default: Vec<String>,
    pub balance: Option<String>,
    pub standalone: bool,
}

pub struct VantageView {
    pub id: String,
    pub name: String,
    pub country: Option<String>,
    pub price: String,
    pub price_mc: u32,
}

impl ActionsView {
    pub fn ticked(&self, id: &str) -> bool {
        self.default.iter().any(|d| d == id)
    }

    /// The total of the default pick.
    pub fn default_total(&self) -> String {
        let mc: u64 = self
            .vantages
            .iter()
            .filter(|v| self.ticked(&v.id))
            .map(|v| v.price_mc as u64)
            .sum();
        crate::credits::show(mc)
    }
}

/// The form: the address and repeated `vantage=` node ids.
#[derive(Debug, Default, PartialEq)]
pub struct ProbeForm {
    pub ip: String,
    pub vantage: Vec<String>,
}

impl ProbeForm {
    fn parse(body: &[u8]) -> Self {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).unwrap_or_default();
        let mut f = Self::default();
        for (k, v) in pairs {
            match k.as_str() {
                "ip" => f.ip = v,
                "vantage" => f.vantage.push(v),
                _ => {}
            }
        }
        f
    }
}

/// One request: its vantages and what each said or saw.
pub struct GroupView {
    pub group: String,
    pub asked_at: String,
    pub by: String,
    /// What was offered; empty when not known here.
    pub cost: String,
    pub members: Vec<ProbeView>,
    /// Some when at least two members are done.
    pub diff: Option<DiffView>,
    /// One per done member with an RTT and known coordinates on both sides.
    pub verdicts: Vec<RttVerdict>,
}

/// About two thirds of c in fibre: the optimistic bound.
pub const LIGHT_KM_PER_MS: f64 = 200.0;

/// Whether a vantage's RTT leaves room for the distance to where the
/// target is said to be. Never a positive claim about the location.
pub struct RttVerdict {
    pub vantage: String,
    pub rtt_ms: i64,
    pub bound_km: f64,
    pub distance_km: Option<f64>,
    pub impossible: bool,
    pub text: String,
}

/// The one-way light-speed bound from the RTT against the distance, less
/// the accuracy radius of the target's location.
pub fn rtt_verdict(
    name: &str,
    rtt_ms: i64,
    vantage: Option<Coords>,
    target: Option<Coords>,
) -> RttVerdict {
    let bound_km = rtt_ms as f64 / 2.0 * LIGHT_KM_PER_MS;
    let distance_km = match (vantage, target) {
        (Some(v), Some(t)) => {
            Some(haversine_km((v.lat, v.lon), (t.lat, t.lon)) - t.accuracy_km as f64)
        }
        _ => None,
    };
    let impossible = distance_km.is_some_and(|d| d > bound_km);
    let text = match distance_km {
        Some(d) if impossible => {
            format!("impossible: claimed {d:.0} km away, light-speed bound {bound_km:.0} km")
        }
        Some(d) => format!("plausible: {d:.0} km within {bound_km:.0} km"),
        None => "no coordinates".into(),
    };
    RttVerdict {
        vantage: name.to_string(),
        rtt_ms,
        bound_km,
        distance_km,
        impossible,
        text,
    }
}

/// One field of one port across the vantages.
pub struct DiffRow {
    pub port: i64,
    pub field: String,
    /// One per member; None: the port was not reached.
    pub values: Vec<Option<String>>,
    pub differs: bool,
}

pub struct DiffView {
    pub members: Vec<String>,
    pub rows: Vec<DiffRow>,
    /// Rows with at least two values, all equal.
    pub consistent: usize,
    /// Rows whose values differ.
    pub contradicted: usize,
}

const DIFF_FIELDS: &[&str] = &[
    "status",
    "server",
    "powered_by",
    "title",
    "body_sha256",
    "not_found.body_sha256",
    "favicon_mmh3",
    "redirects.last.url",
    "tls.leaf_sha256",
    "tls.chain_len",
    "tls.version",
    "tls.alpn",
    "jarm",
    "ssh.host_key_sha256",
    "ssh.hassh",
    "banner",
];

fn field_at(detail: &Value, path: &str) -> Option<String> {
    let mut v = detail;
    for key in path.split('.') {
        v = match key {
            "last" => v.as_array()?.last()?,
            k => v.get(k)?,
        };
    }
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The fields of every port, side by side. A port that was not `ok` says
/// nothing and never makes a row differ.
pub fn diff(members: &[ProbeView]) -> DiffView {
    let mut ports: Vec<i64> = members
        .iter()
        .flat_map(|m| m.ports.iter().map(|p| p.port))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    let mut rows = vec![];
    for port in ports {
        for field in DIFF_FIELDS {
            let values: Vec<Option<String>> = members
                .iter()
                .map(|m| {
                    m.ports
                        .iter()
                        .find(|p| p.port == port && p.outcome == "ok")
                        .and_then(|p| field_at(&p.detail, field))
                })
                .collect();
            let some: Vec<&String> = values.iter().flatten().collect();
            if some.is_empty() {
                continue;
            }
            let differs = some.len() >= 2 && some.iter().any(|v| *v != some[0]);
            rows.push(DiffRow {
                port,
                field: field.to_string(),
                values,
                differs,
            });
        }
    }
    let contradicted = rows.iter().filter(|r| r.differs).count();
    let consistent = rows
        .iter()
        .filter(|r| !r.differs && r.values.iter().flatten().count() >= 2)
        .count();
    DiffView {
        members: members.iter().map(|m| m.node.clone()).collect(),
        rows,
        consistent,
        contradicted,
    }
}

/// Diff and verdicts of a group, from its done members.
fn judge(g: &mut GroupView, geo: &crate::intel::SharedGeo, target: Option<IpAddr>) {
    let done: Vec<&ProbeView> = g.members.iter().filter(|m| m.state == "done").collect();
    let diffed = (done.len() >= 2).then(|| {
        let owned: Vec<ProbeView> = done.iter().map(|m| (*m).clone()).collect();
        diff(&owned)
    });
    let mut verdicts = vec![];
    if let Some(t) = target
        && let Ok(guard) = geo.read()
        && let Some(db) = guard.as_ref()
    {
        let tc = db.coords(&t);
        for m in &done {
            if let (Some(rtt), Some(v)) = (
                m.rtt_ms,
                m.vantage_ip
                    .as_deref()
                    .and_then(|v| v.parse::<IpAddr>().ok()),
            ) {
                verdicts.push(rtt_verdict(&m.node, rtt, db.coords(&v), tc));
            }
        }
    }
    g.diff = diffed;
    g.verdicts = verdicts;
}

impl GroupView {
    /// How many vantages found the location claim impossible.
    pub fn contradicted(&self) -> usize {
        self.verdicts.iter().filter(|v| v.impossible).count()
    }
}

impl RttVerdict {
    pub fn bound_text(&self) -> String {
        format!("{:.0} km", self.bound_km)
    }

    pub fn distance_text(&self) -> String {
        self.distance_km
            .map_or("-".into(), |d| format!("{d:.0} km"))
    }
}

/// One vantage of a request.
#[derive(Clone)]
pub struct ProbeView {
    pub node: String,
    /// The node id (text), or empty for a standalone node.
    pub node_id: String,
    pub state: &'static str,
    pub why: Option<String>,
    pub vantage_ip: Option<String>,
    pub rtt_ms: Option<i64>,
    pub started_at: Option<String>,
    pub ports: Vec<PortView>,
}

/// What one port showed.
#[derive(Clone)]
pub struct PortView {
    pub port: i64,
    pub protocol: String,
    pub outcome: String,
    /// `(label, value, mono)`.
    pub facts: Vec<(String, String, bool)>,
    /// `(link kind key, value)` for `/admin/links/{kind}/{value}`.
    pub links: Vec<(String, String)>,
    pub redirects: Vec<HopView>,
    /// The detail as recorded, for comparisons.
    pub detail: Value,
}

/// One redirect hop.
#[derive(Clone)]
pub struct HopView {
    pub url: String,
    pub status: Option<u64>,
    pub location: Option<String>,
    /// `protected`, `loop`, `limit` or `unresolved`.
    pub skipped: Option<String>,
    pub why: Option<String>,
    pub error: Option<String>,
}

fn str_at(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn num_at(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

/// A comma-separated list or an array, as one line.
fn list_at(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::Array(a) => {
            let items: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            (!items.is_empty()).then(|| items.join(", "))
        }
        Value::String(s) if !s.is_empty() => Some(s.replace(',', ", ")),
        _ => None,
    }
}

/// The link kind a probe host key is shown under in Links.
fn link_kind(host_key_kind: &str) -> &str {
    use crate::scan::hostkeys::{SSH_HOSTKEY, TLS_CERT};
    match host_key_kind {
        SSH_HOSTKEY => "ssh",
        TLS_CERT => "tls",
        k => k,
    }
}

/// Facts, links and redirect hops of one port's detail JSON.
pub fn port_view(port: i64, protocol: &str, outcome: &str, detail: &Value) -> PortView {
    let mut facts: Vec<(String, String, bool)> = vec![];
    let mut push = |label: &str, v: Option<String>, mono: bool| {
        if let Some(v) = v {
            facts.push((label.to_string(), v, mono));
        }
    };
    push("Error", str_at(detail, "error"), false);
    if let Some(status) = num_at(detail, "status") {
        push("Status", Some(status.to_string()), true);
        push("Server", str_at(detail, "server"), true);
        push("Powered by", str_at(detail, "powered_by"), true);
        push("Title", str_at(detail, "title"), false);
        push("Cookies", list_at(detail, "cookie_names"), true);
        push(
            "Body",
            str_at(detail, "body_sha256")
                .map(|h| format!("{h} · {} bytes", num_at(detail, "body_len").unwrap_or(0))),
            true,
        );
        push(
            "404",
            detail.get("not_found").and_then(|nf| {
                Some(format!(
                    "{} · {}",
                    num_at(nf, "status")?,
                    str_at(nf, "body_sha256")?
                ))
            }),
            true,
        );
        push(
            "Favicon",
            str_at(detail, "favicon_mmh3").map(|m| match str_at(detail, "favicon_sha256") {
                Some(s) => format!("{m} · {s}"),
                None => m,
            }),
            true,
        );
    }
    if let Some(tls) = detail.get("tls").filter(|t| t.is_object()) {
        push("Subject", str_at(tls, "subject"), false);
        push("Issuer", str_at(tls, "issuer"), false);
        push("SANs", list_at(tls, "sans"), true);
        push(
            "Valid",
            match (str_at(tls, "not_before"), str_at(tls, "not_after")) {
                (Some(a), Some(b)) => Some(format!("{a} → {b}")),
                _ => None,
            },
            true,
        );
        push(
            "Chain",
            num_at(tls, "chain_len").map(|n| n.to_string()),
            true,
        );
        push("Version", str_at(tls, "version"), true);
        push("ALPN", str_at(tls, "alpn"), true);
        push("Leaf sha256", str_at(tls, "leaf_sha256"), true);
    }
    push("JARM", str_at(detail, "jarm"), true);
    if let Some(ssh) = detail.get("ssh").filter(|s| s.is_object()) {
        push("Banner", str_at(ssh, "banner"), true);
        push(
            "Host key",
            str_at(ssh, "host_key_sha256").map(|fp| match str_at(ssh, "host_key_type") {
                Some(t) => format!("{t} SHA256:{fp}"),
                None => format!("SHA256:{fp}"),
            }),
            true,
        );
        push("HASSH", str_at(ssh, "hassh"), true);
        push("KEX", list_at(ssh, "kex_algorithms"), true);
        push("Host-key algos", list_at(ssh, "host_key_algorithms"), true);
        push("Ciphers", list_at(ssh, "ciphers"), true);
        push("MACs", list_at(ssh, "macs"), true);
    }
    push("Banner", str_at(detail, "banner"), true);
    let links = u16::try_from(port)
        .map(|p| crate::store::probes::keys_of(p, detail))
        .unwrap_or_default()
        .into_iter()
        .map(|k| (link_kind(k.kind).to_string(), k.fingerprint))
        .collect();
    let redirects = detail
        .get("redirects")
        .and_then(Value::as_array)
        .map(|hops| {
            hops.iter()
                .map(|h| HopView {
                    url: str_at(h, "url").unwrap_or_default(),
                    status: num_at(h, "status"),
                    location: str_at(h, "location"),
                    skipped: str_at(h, "skipped"),
                    why: str_at(h, "why"),
                    error: str_at(h, "error"),
                })
                .collect()
        })
        .unwrap_or_default();
    PortView {
        port,
        protocol: protocol.to_string(),
        outcome: outcome.to_string(),
        facts,
        links,
        redirects,
        detail: detail.clone(),
    }
}

/// Reasons that concern this node only: in a cluster the other scanners
/// judge for themselves.
fn this_node_only(why: &str) -> bool {
    why.starts_with("this node probed") || why == "probes are off on this node"
}

/// "Counter-scan found N open ports (date) · evidence allows level L", or
/// why this node's gate refuses the address.
async fn guard_line(state: &AdminState, ip: &IpAddr) -> Result<String, String> {
    let node = state.recorder.node().map(|n| &**n);
    let own;
    let prober: &Prober = match (&state.prober, node) {
        (Some(p), _) => p,
        (None, None) => return Err("this node does not probe".into()),
        // A member that does not probe still judges the address with the
        // shared rules: the scanners decide again when asked.
        (None, Some(n)) => {
            let mut cfg = state.cfg.clone();
            cfg.probe.enabled = true;
            own = Prober::new(&cfg, Some(n.id()));
            &own
        }
    };
    let target = prober.check(&state.store, node, ip).await?;
    let when = async {
        let row = state.store.ip_by_addr(&ip.to_string()).await.ok()??;
        let scans = state.store.scans_for_ip(row.id).await.ok()?;
        scans
            .into_iter()
            .find(|s| s.finished_at.is_some() && s.audit_of.is_none())?
            .finished_at
    }
    .await
    .unwrap_or_default();
    let n = target.ports.len();
    let level = match prober.allowed_level(&state.store, ip).await {
        Some(l) => format!("level {l}"),
        None => "a probe".to_string(),
    };
    Ok(format!(
        "Counter-scan found {n} open port{} ({when}) · evidence allows {level}",
        if n == 1 { "" } else { "s" }
    ))
}

/// The balance in credits (the fleet's, when this node has an owner).
async fn balance(node: &crate::cluster::Node) -> Option<String> {
    async {
        let book = crate::credits::book(node).await?;
        let siblings = crate::cluster::owner::fleet::siblings(&node.store).await?;
        let mc: u64 = std::iter::once(node.id())
            .chain(siblings.iter().copied())
            .map(|id| book.balance(&id))
            .sum();
        anyhow::Ok(crate::credits::show(mc))
    }
    .await
    .inspect_err(|e| tracing::warn!(?e, "probes: balance not read"))
    .ok()
}

pub async fn actions_for(state: &AdminState, ip: &IpAddr) -> ActionsView {
    let node = state.recorder.node();
    let (vantages, default, balance) = match node {
        None => (vec![], vec![], None),
        Some(n) => {
            let all = ask::vantages(n, &state.geo);
            let default = ask::default_pick(&all, DEFAULT_VANTAGES)
                .iter()
                .map(NodeId::to_string)
                .collect();
            let views = all
                .into_iter()
                .map(|v| VantageView {
                    id: v.node.to_string(),
                    name: v.name,
                    country: v.country,
                    price: crate::credits::show(v.price_mc as u64),
                    price_mc: v.price_mc,
                })
                .collect();
            (views, default, balance(n).await)
        }
    };
    let standalone = node.is_none();
    let (guard_line, why_not) = match guard_line(state, ip).await {
        Ok(line) => (line, None),
        Err(why) if !standalone && this_node_only(&why) => (why, None),
        Err(why) => (format!("No probe: {why}"), Some(why)),
    };
    let why_not = why_not.or_else(|| {
        (!standalone && vantages.is_empty())
            .then(|| "no live scanner announces a probe price".to_string())
    });
    ActionsView {
        guard_line,
        allowed: why_not.is_none(),
        why_not,
        vantages,
        default,
        balance,
        standalone,
    }
}

/// Set what `node` said in `group`.
fn settle(state: &AdminState, group: &str, node: NodeId, outcome: Result<String, String>) {
    let mut map = state.pending_probes.lock().unwrap();
    if let Some(p) = map
        .get_mut(group)
        .and_then(|l| l.iter_mut().find(|p| p.node == node))
    {
        p.outcome = Some(outcome);
    }
}

/// POST /admin/lookup/probe: offer and ask (cluster) or run here
/// (standalone), then back to the IP page's Probes section. Nothing waits
/// for a probe.
async fn request(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    body: Bytes,
) -> AppResult<Response> {
    let form = ProbeForm::parse(&body);
    let Ok(ip) = form.ip.trim().parse::<IpAddr>() else {
        return Ok(redirect_with_error("/admin/lookup", "Not an IP address."));
    };
    let ip = crate::net::canonical(ip);
    let back = format!("/ip/{ip}#probes");
    let Some(row) = state.store.ip_by_addr(&ip.to_string()).await? else {
        return Ok(redirect_with_error(
            &format!("/admin/lookup?ip={ip}"),
            "No probe: the address is not in the dataset.",
        ));
    };
    let group = new_uid();
    let pending = |node, name: String, price_mc, outcome| Pending {
        ip_id: row.id,
        node,
        name,
        at: Instant::now(),
        asked_at: now_ts(),
        price_mc,
        outcome,
    };
    let remember = |list: Vec<Pending>| {
        let mut map = state.pending_probes.lock().unwrap();
        map.retain(|_, l| l.iter().any(|p| p.at.elapsed() < FORGET_AFTER));
        map.insert(group.clone(), list);
    };
    let Some(node) = state.recorder.node().cloned() else {
        let Some(prober) = state.prober.clone() else {
            return Ok(redirect_with_error(
                &back,
                "No probe: this node does not probe.",
            ));
        };
        if let Err(why) = prober.check(&state.store, None, &ip).await {
            return Ok(redirect_with_error(&back, &format!("No probe: {why}")));
        }
        remember(vec![pending(
            LOCAL,
            "this node".into(),
            0,
            Some(Ok(String::new())),
        )]);
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(why) = prober.run_local(&st.store, ip, &group).await {
                settle(&st, &group, LOCAL, Err(why));
            }
        });
        return Ok(redirect_with_notice(
            &back,
            "Probe started; the result appears below when it is in.",
        ));
    };
    let all = ask::vantages(&node, &state.geo);
    let chosen: Vec<&ask::Vantage> = all
        .iter()
        .filter(|v| form.vantage.iter().any(|f| *f == v.node.to_string()))
        .collect();
    if chosen.is_empty() {
        return Ok(redirect_with_error(
            &back,
            "No probe: pick at least one live scanner.",
        ));
    }
    remember(
        chosen
            .iter()
            .map(|v| pending(v.node, v.name.clone(), v.price_mc, None))
            .collect(),
    );
    let ids: Vec<NodeId> = chosen.iter().map(|v| v.node).collect();
    let n = ids.len();
    let st = state.clone();
    tokio::spawn(async move {
        let prober = st.prober.clone();
        for a in ask::ask(&node, prober.as_ref(), ip, &ids, &group).await {
            settle(&st, &group, a.node, a.outcome);
        }
    });
    Ok(redirect_with_notice(
        &back,
        &format!(
            "Probe asked of {n} scanner{}; results appear below as they come in.",
            if n == 1 { "" } else { "s" }
        ),
    ))
}

/// The state of a request without a result.
fn pending_state(p: &Pending, now: Instant) -> (&'static str, Option<String>) {
    match &p.outcome {
        Some(Err(why)) => ("declined", Some(why.clone())),
        _ if now.saturating_duration_since(p.at) >= LAPSE_AFTER => {
            ("lapsed", Some("no result after 15 min".into()))
        }
        None => ("queued", None),
        Some(Ok(_)) => ("running", None),
    }
}

/// The probes of an address: its results grouped by request, and the
/// requests made here still waiting for theirs. Newest first.
pub async fn groups_for(state: &AdminState, ip_id: i64) -> Vec<GroupView> {
    let rows = state
        .store
        .probes_for_ip(ip_id)
        .await
        .inspect_err(|e| tracing::warn!(?e, "probes not read"))
        .unwrap_or_default();
    let node = state.recorder.node();
    let me = node.map(|n| n.id());
    let members = node.map(|n| n.members());
    let name_of = |id: &NodeId| {
        if *id == LOCAL || Some(*id) == me {
            return "this node".to_string();
        }
        members
            .as_ref()
            .and_then(|m| m.get(id))
            .map(|m| m.name.clone())
            .unwrap_or_else(|| id.short())
    };
    let id_text = |id: &NodeId| match *id == LOCAL {
        true => String::new(),
        false => id.to_string(),
    };
    let mut groups: Vec<GroupView> = vec![];
    for r in rows {
        let origin = r
            .origin
            .as_deref()
            .and_then(|b| NodeId::from_slice(b).ok())
            .unwrap_or(LOCAL);
        let asker = NodeId::from_slice(&r.asker).unwrap_or(LOCAL);
        let ports = state
            .store
            .probe_ports(r.id)
            .await
            .inspect_err(|e| tracing::warn!(?e, "probe ports not read"))
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                let detail = serde_json::from_str(&p.detail_json).unwrap_or(Value::Null);
                port_view(p.port, &p.protocol, &p.outcome, &detail)
            })
            .collect();
        let member = ProbeView {
            node: name_of(&origin),
            node_id: id_text(&origin),
            state: "done",
            why: None,
            vantage_ip: r.vantage_ip,
            rtt_ms: r.rtt_min_ms,
            started_at: Some(r.started_at.clone()),
            ports,
        };
        match groups.iter_mut().find(|g| g.group == r.group_uid) {
            Some(g) => {
                if r.started_at < g.asked_at {
                    g.asked_at = r.started_at;
                }
                g.members.push(member);
            }
            None => groups.push(GroupView {
                group: r.group_uid,
                asked_at: r.started_at,
                by: name_of(&asker),
                cost: match asker == LOCAL {
                    true => "free".into(),
                    false => String::new(),
                },
                members: vec![member],
                diff: None,
                verdicts: vec![],
            }),
        }
    }
    let now = Instant::now();
    {
        let map = state.pending_probes.lock().unwrap();
        for (group, list) in map.iter() {
            if list.first().is_none_or(|p| p.ip_id != ip_id) {
                continue;
            }
            let at = match groups.iter().position(|g| &g.group == group) {
                Some(i) => i,
                None => {
                    groups.push(GroupView {
                        group: group.clone(),
                        asked_at: list[0].asked_at.clone(),
                        by: "this node".into(),
                        cost: String::new(),
                        members: vec![],
                        diff: None,
                        verdicts: vec![],
                    });
                    groups.len() - 1
                }
            };
            let g = &mut groups[at];
            g.asked_at = list[0].asked_at.clone();
            let offered: u64 = list.iter().map(|p| p.price_mc as u64).sum();
            g.cost = match offered {
                0 => "free".into(),
                mc => crate::credits::show(mc),
            };
            for p in list {
                let text = id_text(&p.node);
                if g.members.iter().any(|m| m.node_id == text) {
                    continue;
                }
                let (st, why) = pending_state(p, now);
                g.members.push(ProbeView {
                    node: p.name.clone(),
                    node_id: text,
                    state: st,
                    why,
                    vantage_ip: None,
                    rtt_ms: None,
                    started_at: None,
                    ports: vec![],
                });
            }
        }
    }
    let target = match state.store.ip_overview(ip_id).await {
        Ok(Some(o)) => o.ip.ip.parse::<IpAddr>().ok(),
        _ => None,
    };
    for g in &mut groups {
        judge(g, &state.geo, target);
    }
    groups.sort_by(|a, b| b.asked_at.cmp(&a.asked_at));
    groups
}

/// `[group, node id, state]` per member: what the stream compares.
pub fn states_json(groups: &[GroupView]) -> String {
    let v: Vec<(&str, &str, &str)> = groups
        .iter()
        .flat_map(|g| {
            g.members
                .iter()
                .map(|m| (g.group.as_str(), m.node_id.as_str(), m.state))
        })
        .collect();
    serde_json::to_string(&v).unwrap_or_else(|_| "[]".into())
}

/// Some member still waits for its result.
pub fn any_waiting(groups: &[GroupView]) -> bool {
    groups
        .iter()
        .flat_map(|g| &g.members)
        .any(|m| matches!(m.state, "queued" | "running"))
}

#[derive(serde::Deserialize)]
pub struct ProbesQuery {
    ip: String,
}

/// GET /admin/api/probes?ip=…: a `probes` event with the states whenever
/// they change, while a member waits for its result.
async fn stream(
    _u: SessionUser,
    jar: axum_extra::extract::CookieJar,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<ProbesQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session = crate::admin::auth::session_token(&state, &jar);
    let ip_id = match q.ip.trim().parse::<IpAddr>() {
        Ok(ip) => state
            .store
            .ip_by_addr(&crate::net::canonical(ip).to_string())
            .await
            .ok()
            .flatten()
            .map(|r| r.id),
        Err(_) => None,
    };
    Sse::new(events(state, ip_id, session)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}

fn events(
    state: Arc<AdminState>,
    ip_id: Option<i64>,
    session: Option<String>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        ip_id: Option<i64>,
        session: Option<String>,
        changes: Option<tokio::sync::watch::Receiver<u64>>,
        last: Option<String>,
        done: bool,
        next_check: tokio::time::Instant,
    }
    let changes = state.recorder.node().map(|n| n.subscribe_changes());
    futures::stream::unfold(
        St {
            state,
            ip_id,
            session,
            changes,
            last: None,
            done: false,
            next_check: tokio::time::Instant::now() + SESSION_EVERY,
        },
        |mut st| async move {
            if st.done {
                return None;
            }
            loop {
                if st.last.is_some() {
                    let closing = async {
                        match st.state.closing.clone() {
                            Some(mut rx) => {
                                let _ = rx.wait_for(|v| *v).await;
                            }
                            None => std::future::pending().await,
                        }
                    };
                    let changed = async {
                        match st.changes.as_mut() {
                            Some(rx) => {
                                if rx.changed().await.is_err() {
                                    std::future::pending::<()>().await;
                                }
                            }
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = closing => return None,
                        _ = changed => {}
                        _ = tokio::time::sleep(POLL) => {}
                    }
                }
                if tokio::time::Instant::now() >= st.next_check {
                    st.next_check = tokio::time::Instant::now() + SESSION_EVERY;
                    if let Some(id) = &st.session
                        && !st.state.store.validate_session(id).await.unwrap_or(false)
                    {
                        return None;
                    }
                }
                let groups = match st.ip_id {
                    Some(id) => groups_for(&st.state, id).await,
                    None => vec![],
                };
                let states = states_json(&groups);
                // The last event once nothing waits: the page reloads and
                // opens no new stream.
                st.done = !any_waiting(&groups);
                if st.last.as_deref() != Some(&states) || st.done {
                    st.last = Some(states.clone());
                    let ev = Event::default().event("probes").data(states);
                    return Some((Ok(ev), st));
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::probe::gate::tests::{requests, scanned};
    use serde_json::json;
    use tower::ServiceExt;

    const IP: &str = "203.0.113.40";

    async fn web() -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                (
                    [(axum::http::header::SERVER, "probe-test/1.0")],
                    axum::response::Html("<title>t</title>"),
                )
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        addr
    }

    /// A standalone admin with a prober aimed at `connect`; `IP` holds
    /// three level-2 requests, and `scan` adds a finished scan of `port`.
    async fn state(scan: Option<u16>) -> (Arc<AdminState>, String, i64, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[scan]
tor_unknown = "scan"
verify_crawlers = false
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
        let ip = store.upsert_ip(IP.parse().unwrap()).await.unwrap();
        requests(&store, ip.id, 3, 2).await;
        if let Some(port) = scan {
            scanned(&store, IP, &[(port, "open", Some("http"))]).await;
        }
        let token = store.create_session().await.unwrap();
        let cookie = format!("{}={token}", crate::admin::auth::session_cookie_name(&cfg));
        let prober = Prober::new(&cfg, None).connecting_to("127.0.0.1".parse().unwrap());
        let state =
            Arc::new(AdminState::public_only(store, cfg).with_prober(Some(Arc::new(prober))));
        (state, cookie, ip.id, dir)
    }

    async fn send(
        app: &axum::Router,
        req: axum::http::request::Builder,
        body: &str,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
        let r = app
            .clone()
            .oneshot(req.body(axum::body::Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let (status, headers) = (r.status(), r.headers().clone());
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&b).into_owned())
    }

    #[test]
    fn an_impossible_claim_is_flagged_and_a_possible_one_is_not() {
        let berlin = Coords {
            lat: 52.52,
            lon: 13.40,
            accuracy_km: 50,
        };
        let sydney = Coords {
            lat: -33.87,
            lon: 151.21,
            accuracy_km: 50,
        };
        let v = rtt_verdict("a", 8, Some(berlin), Some(sydney));
        assert!(v.impossible);
        assert!(v.text.contains("impossible"), "{}", v.text);
        assert!((v.bound_km - 800.0).abs() < 1.0);
        let v = rtt_verdict("a", 200, Some(berlin), Some(sydney));
        assert!(!v.impossible, "20 000 km bound covers 16 000 km");
        let v = rtt_verdict("a", 8, Some(berlin), None);
        assert!(!v.impossible && v.distance_km.is_none());
    }

    #[test]
    fn the_accuracy_radius_is_subtracted_before_judging() {
        let a = Coords {
            lat: 52.52,
            lon: 13.40,
            accuracy_km: 0,
        };
        let b = Coords {
            lat: 48.86,
            lon: 2.35,
            accuracy_km: 1000,
        };
        assert!(
            !rtt_verdict("a", 1, Some(a), Some(b)).impossible,
            "878 - 1000 < 100"
        );
        let b = Coords {
            accuracy_km: 0,
            ..b
        };
        assert!(
            rtt_verdict("a", 1, Some(a), Some(b)).impossible,
            "878 > 100"
        );
    }

    fn member(name: &str, outcome: &str, cert: &str) -> ProbeView {
        ProbeView {
            node: name.into(),
            node_id: String::new(),
            state: "done",
            why: None,
            vantage_ip: None,
            rtt_ms: Some(1),
            started_at: None,
            ports: vec![port_view(
                443,
                "https",
                outcome,
                &json!({"status": 200, "server": "nginx", "tls": {"leaf_sha256": cert}}),
            )],
        }
    }

    #[test]
    fn the_diff_collapses_equal_rows_and_marks_different_ones() {
        let d = diff(&[member("a", "ok", "aa"), member("b", "ok", "bb")]);
        let server = d.rows.iter().find(|r| r.field == "server").unwrap();
        assert!(!server.differs);
        let leaf = d
            .rows
            .iter()
            .find(|r| r.field == "tls.leaf_sha256")
            .unwrap();
        assert!(leaf.differs);
        assert_eq!(leaf.values, vec![Some("aa".into()), Some("bb".into())]);
        assert!(d.consistent >= 2, "status and server");
    }

    #[test]
    fn a_timed_out_port_is_not_a_difference() {
        let d = diff(&[member("a", "ok", "aa"), member("b", "timeout", "bb")]);
        assert!(d.rows.iter().all(|r| !r.differs));
    }

    #[tokio::test]
    async fn the_actions_card_explains_why_a_probe_is_unavailable() {
        let (state, _c, _id, _d) = state(None).await;
        let a = actions_for(&state, &IP.parse().unwrap()).await;
        assert!(!a.allowed);
        let why = a.why_not.unwrap();
        assert!(why.contains("no finished counter-scan"), "{why}");
        assert!(a.guard_line.contains(&why));
    }

    #[tokio::test]
    async fn the_actions_card_offers_the_local_probe_standalone() {
        let (state, _c, _id, _d) = state(Some(8080)).await;
        let a = actions_for(&state, &IP.parse().unwrap()).await;
        assert!(a.allowed, "{:?}", a.why_not);
        assert!(a.standalone && a.vantages.is_empty());
        assert!(
            a.guard_line.starts_with("Counter-scan found 1 open port (")
                && a.guard_line.ends_with("evidence allows level 2"),
            "{}",
            a.guard_line
        );
    }

    #[tokio::test]
    async fn requesting_a_probe_standalone_redirects_and_a_result_appears() {
        let server = web().await;
        let (state, cookie, _id, _d) = state(Some(server.port())).await;
        let app = crate::admin::full_router(state);
        let (status, headers, _) = send(
            &app,
            axum::http::Request::post("/admin/lookup/probe")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded"),
            &format!("ip={IP}"),
        )
        .await;
        assert_eq!(status, 303);
        assert_eq!(headers["location"], format!("/ip/{IP}#probes").as_str());
        let mut html = String::new();
        for _ in 0..100 {
            (_, _, html) = send(
                &app,
                axum::http::Request::get(format!("/ip/{IP}")).header("cookie", &cookie),
                "",
            )
            .await;
            if html.contains("probe-test/1.0") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(html.contains(r#"data-section="probes""#), "{html}");
        assert!(html.contains("probe-test/1.0"), "{html}");
        assert!(html.contains(r#"data-section="actions""#));
    }

    #[tokio::test]
    async fn the_public_ip_page_shows_neither_card() {
        let (state, cookie, id, _d) = state(Some(8080)).await;
        state.pending_probes.lock().unwrap().insert(
            "g1".into(),
            vec![Pending {
                ip_id: id,
                node: LOCAL,
                name: "this node".into(),
                at: Instant::now(),
                asked_at: now_ts(),
                price_mc: 0,
                outcome: Some(Ok(String::new())),
            }],
        );
        let app = crate::admin::full_router(state);
        let (status, _, html) = send(&app, axum::http::Request::get(format!("/ip/{IP}")), "").await;
        assert_eq!(status, 200);
        assert!(!html.contains(r#"data-section="probes""#));
        assert!(!html.contains(r#"data-section="actions""#));
        // The admin sees both.
        let (_, _, html) = send(
            &app,
            axum::http::Request::get(format!("/ip/{IP}")).header("cookie", &cookie),
            "",
        )
        .await;
        assert!(
            html.contains(r#"data-section="probes""#) && html.contains(r#"data-section="actions""#)
        );
    }

    #[tokio::test]
    async fn an_accepted_probe_without_a_result_lapses() {
        let (state, _c, id, _d) = state(Some(8080)).await;
        state.pending_probes.lock().unwrap().insert(
            "g1".into(),
            vec![Pending {
                ip_id: id,
                node: LOCAL,
                name: "this node".into(),
                at: Instant::now() - Duration::from_secs(16 * 60),
                asked_at: now_ts(),
                price_mc: 0,
                outcome: Some(Ok("uid-1".into())),
            }],
        );
        let groups = groups_for(&state, id).await;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].members[0].state, "lapsed");
        assert!(!any_waiting(&groups));
        assert!(actions_for(&state, &IP.parse().unwrap()).await.allowed);
    }

    #[test]
    fn port_facts_are_built_from_the_detail_json() {
        let leaf = "a".repeat(64);
        let body = "b".repeat(64);
        let nf = "c".repeat(64);
        let jarm = format!("2ad2ad{}", "1".repeat(56));
        let p = port_view(
            443,
            "https",
            "ok",
            &json!({
                "status": 200, "server": "nginx", "powered_by": null, "title": "Hi",
                "cookie_names": ["sid"], "body_sha256": body, "body_len": 12,
                "not_found": {"status": 404, "body_sha256": nf, "body_len": 3},
                "favicon_mmh3": "-123", "favicon_sha256": "d".repeat(64),
                "tls": {"subject": "CN=x", "issuer": "CN=ca", "sans": ["x.test"],
                        "not_before": "2026-01-01", "not_after": "2027-01-01",
                        "chain_len": 2, "version": "TLSv1_3", "alpn": "h2", "leaf_sha256": leaf},
                "jarm": jarm,
                "redirects": [{"url": "https://x/", "status": 301, "location": "https://10.0.0.1/"},
                              {"url": "https://10.0.0.1/", "skipped": "protected", "why": "not global"}],
            }),
        );
        let labels: Vec<&str> = p.facts.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Status",
                "Server",
                "Title",
                "Cookies",
                "Body",
                "404",
                "Favicon",
                "Subject",
                "Issuer",
                "SANs",
                "Valid",
                "Chain",
                "Version",
                "ALPN",
                "Leaf sha256",
                "JARM"
            ]
        );
        let kinds: Vec<&str> = p.links.iter().map(|l| l.0.as_str()).collect();
        for k in ["tls", "jarm", "favicon", "http-body", "http-404"] {
            assert!(kinds.contains(&k), "{k} in {kinds:?}");
        }
        assert_eq!(p.redirects.len(), 2);
        assert_eq!(p.redirects[1].skipped.as_deref(), Some("protected"));
        let ssh = port_view(
            22,
            "ssh",
            "ok",
            &json!({"ssh": {"banner": "SSH-2.0-x", "host_key_type": "ssh-ed25519",
                            "host_key_sha256": "Zm9v", "hassh": "e".repeat(32),
                            "kex_algorithms": "a,b", "host_key_algorithms": "c",
                            "ciphers": "d", "macs": "e"}}),
        );
        let labels: Vec<&str> = ssh.facts.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Banner",
                "Host key",
                "HASSH",
                "KEX",
                "Host-key algos",
                "Ciphers",
                "MACs"
            ]
        );
        assert!(ssh.links.contains(&("ssh".into(), "SHA256:Zm9v".into())));
    }
}
