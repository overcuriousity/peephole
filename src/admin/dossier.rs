//! JSON dossiers (MIK-712): everything an admin sees on an IP, ASN,
//! request or campaign page, as one versioned object for scripts and AI
//! agents. This is the one place that decides what of an entity leaves the
//! node this way: `/api/v1/<kind>/<id>/dossier` and the pages' copy button
//! both serialize what is built here (`docs/api-v1.md` §Dossiers).
//!
//! Left out on purpose, whatever the pages show: token, key, session and
//! pairing hashes, cluster keys, peer addresses and node ids, upload
//! contents (metadata only), a request's page token and decoy input,
//! config values, credit balances and prices.
use crate::admin::AdminState;
use crate::admin::api_v1::{rfc3339, summaries_json};
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult};
use crate::store::browse::{CalendarDay, canonical_ip};
use crate::store::events::{Event, EventKind, EventPage};
use crate::store::requests::IpRow;
use crate::store::stats::Bucket;
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

pub fn routes() -> axum::Router<std::sync::Arc<AdminState>> {
    axum::Router::new().route(
        "/admin/api/dossier/{kind}/{id}",
        axum::routing::get(page_copy),
    )
}

/// `GET /admin/api/dossier/{ip,asn,request,campaign}/{id}`: what
/// `/api/v1/<kind>s/<id>/dossier` answers, for the admin session (the
/// pages' "Copy JSON dossier" link, MIK-750). A device token is no
/// session here, as on every admin page.
async fn page_copy(
    _u: SessionUser,
    axum::extract::State(st): axum::extract::State<std::sync::Arc<AdminState>>,
    axum::extract::Path((kind, id)): axum::extract::Path<(String, String)>,
) -> AppResult<axum::response::Response> {
    use axum::{Json, response::IntoResponse};
    let body = match kind.as_str() {
        "ip" => ip(&st, &id).await?.map(|d| Json(d).into_response()),
        "asn" => asn(&st, &id).await?.map(|d| Json(d).into_response()),
        "request" => request(&st, &id).await?.map(|d| Json(d).into_response()),
        "campaign" => campaign(&st, &id).await?.map(|d| Json(d).into_response()),
        _ => None,
    };
    body.ok_or(AppError::NotFound)
}

/// The schema version: bumped when a field changes meaning or goes away
/// (new fields do not bump it).
pub const DOSSIER_V: u32 = 1;
/// Newest timeline events per dossier (the store's page maximum).
pub const EVENTS: i64 = crate::store::events::MAX_LIMIT;
/// Campaign members per dossier.
pub const MEMBERS: usize = 500;
/// Every other capped list per dossier: an ASN's busiest IPs, a request's
/// same-IP and same-JA4 requests, uploads, commands, canary reuses.
pub const IPS: usize = 50;

/// What every dossier starts with; the kind's own fields follow at the
/// same level.
#[derive(Debug, Serialize)]
pub struct Envelope<T> {
    pub dossier_v: u32,
    pub kind: &'static str,
    /// As in the URL, canonical.
    pub id: String,
    pub generated_at: String,
    pub node: NodeInfo,
    /// The admin page it is the dossier of.
    pub page: String,
    pub limits: Limits,
    /// Per capped list: whether more existed than it carries.
    pub truncated: Counts<bool>,
    /// Per capped list: how many there are in all, where that is known
    /// without counting the whole history (events are not counted).
    pub totals: Counts<i64>,
    #[serde(flatten)]
    pub body: T,
}

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub version: &'static str,
    /// Days of history the node keeps; 0: all of it.
    pub window_days: u32,
}

#[derive(Debug, Serialize)]
pub struct Limits {
    pub events: i64,
    pub members: usize,
    pub ips: usize,
}

const LIMITS: Limits = Limits {
    events: EVENTS,
    members: MEMBERS,
    ips: IPS,
};

/// One value per capped list; a kind without that list leaves it out.
#[derive(Debug, Default, Serialize)]
pub struct Counts<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_ip: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_ja4: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploads: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<T>,
    /// `canaries.reuses`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuses: Option<T>,
}

/// The first `cap` of `v` (fetched with one more), and whether there were
/// more.
fn capped<T>(mut v: Vec<T>, cap: usize) -> (Vec<T>, bool) {
    let more = v.len() > cap;
    v.truncate(cap);
    (v, more)
}

/// Fetch limit for a list capped at [`IPS`]: one more, to tell.
const IPS_PLUS: i64 = IPS as i64 + 1;

fn envelope<T>(
    state: &AdminState,
    kind: &'static str,
    id: String,
    page: String,
    truncated: Counts<bool>,
    totals: Counts<i64>,
    body: T,
) -> Envelope<T> {
    Envelope {
        dossier_v: DOSSIER_V,
        kind,
        id,
        generated_at: rfc3339(chrono::Utc::now()),
        node: NodeInfo {
            version: env!("CARGO_PKG_VERSION"),
            window_days: state.recorder.node().map_or(0, |n| n.retention_days),
        },
        page,
        limits: LIMITS,
        truncated,
        totals,
        body,
    }
}

// ---------------------------------------------------------------- shared

/// One Timeline event. `summary` is attacker-controlled for commands and
/// uploads. No `node`: cluster node labels stay home.
#[derive(Debug, Serialize)]
pub struct EventJson {
    pub kind: &'static str,
    pub at: String,
    /// Of its own table (canaries: the rowid; intel: the hlc).
    pub id: i64,
    /// The member it is of (campaign dossiers only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub severity: Option<i64>,
    pub summary: Option<String>,
    /// The upload uid, fingerprint hash or canary's request id.
    pub reference: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub labels: Vec<String>,
    pub owasp: Vec<String>,
    pub canary_served: bool,
    pub canary_used: Option<i64>,
    pub canary_from: Option<i64>,
}

impl From<&Event> for EventJson {
    fn from(e: &Event) -> Self {
        Self {
            kind: e.kind().key(),
            at: rfc3339(&e.ts),
            id: e.id,
            ip: e.ip.clone(),
            severity: e.severity,
            summary: e.summary.clone(),
            reference: e.reference.clone(),
            method: e.method.clone(),
            path: e.path.clone(),
            query: e.query.clone(),
            labels: e.labels(),
            owasp: e.owasp(),
            canary_served: e.canary_served,
            canary_used: e.canary_used,
            canary_from: e.canary_from,
        }
    }
}

/// A page of the newest events: the list and whether older ones exist.
fn events_json(page: &EventPage) -> (Vec<EventJson>, bool) {
    (
        page.items.iter().map(EventJson::from).collect(),
        page.next.is_some(),
    )
}

/// One upload's metadata. Never its content: there is no field for it.
#[derive(Debug, Serialize)]
pub struct UploadJson {
    pub uid: String,
    pub at: String,
    pub ip: String,
    pub kind: String,
    pub filename: Option<String>,
    pub sniffed_type: String,
    pub size: i64,
    pub truncated: bool,
    pub sha256: String,
    pub answered_path: String,
    pub path_is_prefix: bool,
    pub content_state: String,
    pub request_id: Option<i64>,
}

impl From<&crate::store::uploads::UploadRow> for UploadJson {
    fn from(u: &crate::store::uploads::UploadRow) -> Self {
        Self {
            uid: u.uid.clone(),
            at: rfc3339(&u.ts),
            ip: u.ip.clone(),
            kind: u.kind.clone(),
            filename: u.filename.clone(),
            sniffed_type: u.sniffed_type.clone(),
            size: u.size,
            truncated: u.truncated,
            sha256: data_encoding::HEXLOWER.encode(&u.sha256),
            answered_path: u.answered_path.clone(),
            path_is_prefix: u.path_is_prefix,
            content_state: u.content_state.clone(),
            request_id: u.request_id,
        }
    }
}

/// At most [`IPS`] of `rows` (fetched with one more), and whether there
/// were more.
fn uploads_json(rows: Vec<crate::store::uploads::UploadRow>) -> (Vec<UploadJson>, bool) {
    let (rows, more) = capped(rows, IPS);
    (rows.iter().map(UploadJson::from).collect(), more)
}

/// A canary served on one side and used on the other. No value hash and
/// no node labels.
#[derive(Debug, Serialize)]
pub struct ReuseJson {
    pub kind: String,
    pub place: String,
    pub served_request_id: Option<i64>,
    pub served_ip: String,
    pub served_at: String,
    pub served_answer: Option<String>,
    pub used_request_id: i64,
    pub used_ip: String,
    pub used_at: String,
    pub delta_s: i64,
    pub same_source: bool,
}

impl From<&crate::store::canaries::Reuse> for ReuseJson {
    fn from(r: &crate::store::canaries::Reuse) -> Self {
        Self {
            kind: r.kind.clone(),
            place: r.place.clone(),
            served_request_id: r.served_request_id,
            served_ip: r.served_ip.clone(),
            served_at: rfc3339(&r.served_ts),
            served_answer: r.served_answer.clone(),
            used_request_id: r.used_request_id,
            used_ip: r.used_ip.clone(),
            used_at: rfc3339(&r.used_ts),
            delta_s: r.delta_s,
            same_source: r.same_source,
        }
    }
}

/// The newest [`IPS`] canary reuses `f` matches, and whether there were
/// more.
async fn reuses(
    state: &AdminState,
    f: crate::store::canaries::ReuseFilter,
) -> Result<(Vec<ReuseJson>, bool)> {
    let rows = state
        .store
        .reuses(&crate::store::canaries::ReuseFilter {
            range: crate::store::stats::Range::All,
            limit: IPS_PLUS,
            ..f
        })
        .await?;
    let (rows, more) = capped(rows, IPS);
    Ok((rows.iter().map(ReuseJson::from).collect(), more))
}

/// A chart bucket: the hour it starts, in RFC 3339.
#[derive(Debug, Serialize)]
pub struct BucketJson {
    pub ts: String,
    pub count: i64,
    pub by_severity: [i64; 5],
}

impl From<&Bucket> for BucketJson {
    fn from(b: &Bucket) -> Self {
        Self {
            // The store keys hours as `YYYY-MM-DDTHH:MM`.
            ts: chrono::NaiveDateTime::parse_from_str(&b.ts, "%Y-%m-%dT%H:%M")
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default(),
            count: b.count,
            by_severity: b.by_severity,
        }
    }
}

/// The (key, number) of a campaign.
#[derive(Debug, Serialize)]
pub struct CampaignRef {
    pub key: String,
    pub num: i64,
}

fn campaign_ref(c: Option<(String, i64)>) -> Option<CampaignRef> {
    c.map(|(key, num)| CampaignRef { key, num })
}

/// The summaries of `addrs` as `/api/v1/ips` lists them.
async fn summaries_of(state: &AdminState, addrs: &[&str]) -> Result<Vec<Value>> {
    let read = crate::admin::lookup::bulk_read(state, addrs.iter().copied()).await?;
    Ok(summaries_json(state, &read.rows).await)
}

// -------------------------------------------------------------------- ip

/// `GET /api/v1/ips/{addr}`'s body: the Android app's contract, so this
/// must not change shape (`ip_detail_body_is_byte_for_byte_stable`).
pub(crate) async fn ip_detail(
    store: &crate::store::Store,
    ip: &IpRow,
    ov: &crate::store::browse::IpOverview,
) -> Result<Value> {
    // Newest stored answer per provider (intel_for_ip is provider-major,
    // newest first). Tor is not an entry: is_tor comes from the exit list.
    let mut intel = serde_json::Map::new();
    for p in crate::intel::KNOWN_PROVIDERS
        .iter()
        .filter(|p| p.name != crate::intel::TOR)
    {
        intel.insert(p.name.to_string(), Value::Null);
    }
    for row in store.intel_for_ip(&ip.ip).await? {
        let taken = intel.get(&row.provider).is_some_and(|v| !v.is_null());
        if row.provider == crate::intel::TOR || taken {
            continue;
        }
        intel.insert(
            row.provider.clone(),
            json!({
                "fetched_at": rfc3339(&row.fetched_at),
                "data": serde_json::from_str::<Value>(&row.data_json).unwrap_or(Value::Null),
            }),
        );
    }
    let scans = store.scans_for_ip(ip.id).await?;
    let ids: Vec<i64> = scans.iter().map(|s| s.id).collect();
    let mut ports = store.ports_for_scans(&ids).await?;
    let scans: Vec<Value> = scans
        .into_iter()
        .filter_map(|s| {
            let ports = ports
                .remove(&s.id)
                .unwrap_or_default()
                .into_iter()
                .filter(|p| p.state == "open")
                .map(|p| json!({"port": p.port, "service": p.service, "product": p.product}))
                .collect::<Vec<_>>();
            Some(json!({"scanned_at": rfc3339(s.finished_at?), "ports": ports}))
        })
        .collect();
    let names: Vec<Value> = store
        .names_for_ip(ip.id)
        .await?
        .into_iter()
        .map(|n| json!({"name": n.name, "source": n.source, "agreed": n.agreed}))
        .collect();
    let is_tor_relay = intel
        .get(crate::intel::TOR_RELAYS)
        .and_then(|v| v.get("data")?.get("relay"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "ip": ip.ip,
        "geo": {"country": ip.country, "asn": ip.asn, "asn_org": ip.asn_org},
        "is_tor": ip.is_tor_exit,
        "is_tor_relay": is_tor_relay,
        "severity": ov.max_severity,
        "first_seen": rfc3339(ov.ip.first_seen),
        "last_seen": rfc3339(ov.ip.last_seen),
        "request_count": ov.request_count,
        "unseen": ip.unseen,
        "labels": ov.labels.iter().map(|l| &l.name).collect::<Vec<_>>(),
        "families": ov.families.iter().map(|f| json!({"name": f.name, "count": f.count})).collect::<Vec<_>>(),
        "intel": Value::Object(intel),
        "scans": scans,
        "names": names,
        "rank": ov.rank,
        "neighbours": {"net": ov.net, "other_ips": ov.net_count, "same_asn": ov.asn_count},
    }))
}

/// An address's dataset row and overview; None when it is not an address
/// or nothing is recorded about it.
pub(crate) async fn ip_row(
    store: &crate::store::Store,
    addr: &str,
) -> Result<Option<(IpRow, crate::store::browse::IpOverview)>> {
    let Ok(addr) = addr.trim().parse::<std::net::IpAddr>() else {
        return Ok(None);
    };
    let addr = crate::net::canonical(addr).to_string();
    let Some(ip) = store.ip_by_addr(&addr).await? else {
        return Ok(None);
    };
    Ok(store.ip_overview(ip.id).await?.map(|ov| (ip, ov)))
}

#[derive(Debug, Serialize)]
pub struct IpDossier {
    /// `GET /api/v1/ips/{addr}`, field for field.
    #[serde(flatten)]
    pub detail: Value,
    /// The page's charts: requests per hour this week, per day this half year.
    pub week: Vec<BucketJson>,
    /// `day` is a date, `YYYY-MM-DD` (UTC).
    pub calendar: Vec<CalendarDay>,
    /// Newest first, at most [`EVENTS`].
    pub events: Vec<EventJson>,
    pub probes: Vec<ProbeGroupJson>,
    pub campaign: Option<CampaignRef>,
    /// Agent traces in its labels.
    pub agent: bool,
    /// The property strip.
    pub props: Option<PropsJson>,
    pub evidence: Option<VerdictJson>,
    pub sharing: Option<VerdictJson>,
    /// Newest first, at most [`IPS`] each.
    pub uploads: Vec<UploadJson>,
    pub commands: Vec<CommandJson>,
    pub canaries: IpCanaries,
}

/// One probe request and what each vantage answered. The vantage is named
/// by its node; its address and id stay home.
#[derive(Debug, Serialize)]
pub struct ProbeGroupJson {
    pub group: String,
    pub asked_at: String,
    pub members: Vec<ProbeJson>,
}

#[derive(Debug, Serialize)]
pub struct ProbeJson {
    pub vantage: String,
    pub state: &'static str,
    pub why: Option<String>,
    pub rtt_ms: Option<i64>,
    pub started_at: Option<String>,
    pub ports: Vec<ProbePortJson>,
}

#[derive(Debug, Serialize)]
pub struct ProbePortJson {
    pub port: i64,
    pub protocol: String,
    pub outcome: String,
}

impl From<&crate::admin::probes::GroupView> for ProbeGroupJson {
    fn from(g: &crate::admin::probes::GroupView) -> Self {
        Self {
            group: g.group.clone(),
            asked_at: rfc3339(&g.asked_at),
            members: g
                .members
                .iter()
                .map(|m| ProbeJson {
                    vantage: m.node.clone(),
                    state: m.state,
                    why: m.why.clone(),
                    rtt_ms: m.rtt_ms,
                    started_at: m.started_at.as_deref().map(rfc3339),
                    ports: m
                        .ports
                        .iter()
                        .map(|p| ProbePortJson {
                            port: p.port,
                            protocol: p.protocol.clone(),
                            outcome: p.outcome.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PropsJson {
    pub tor: bool,
    /// hosting, cloud, scanner, fixed or mobile.
    pub net: Option<String>,
    pub scanner: bool,
    pub fleet: bool,
    pub agent: bool,
    pub scanned: bool,
    pub scan_pending: bool,
}

/// The evidence verdict or the shared-address reading: its label, its
/// sentence and the lines it rests on.
#[derive(Debug, Serialize)]
pub struct VerdictJson {
    pub label: &'static str,
    pub sentence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<&'static str>,
    pub lines: Vec<LineJson>,
}

#[derive(Debug, Serialize)]
pub struct LineJson {
    pub kind: String,
    pub what: String,
    pub port: Option<i64>,
    pub source: String,
    pub date: String,
}

fn lines_json(lines: &[crate::store::evidence::Line]) -> Vec<LineJson> {
    lines
        .iter()
        .map(|l| LineJson {
            kind: l.kind.clone(),
            what: l.what.clone(),
            port: l.port,
            source: l.source.clone(),
            date: l.date.clone(),
        })
        .collect()
}

/// A command sent to a dropped webshell.
#[derive(Debug, Serialize)]
pub struct CommandJson {
    pub request_id: i64,
    pub at: String,
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct IpCanaries {
    /// Other addresses that used a canary served here, and addresses whose
    /// canary was used here.
    pub used_elsewhere: i64,
    pub used_from: i64,
    /// Newest first, at most [`IPS`].
    pub reuses: Vec<ReuseJson>,
}

/// The dossier of `addr`; None when it is not an address in the dataset.
pub async fn ip(state: &AdminState, addr: &str) -> Result<Option<Envelope<IpDossier>>> {
    let store = &state.store;
    let Some((ip, ov)) = ip_row(store, addr).await? else {
        return Ok(None);
    };
    let detail = ip_detail(store, &ip, &ov).await?;
    let page = store
        .ip_events(
            ip.id,
            &EventKind::ALL,
            crate::store::browse::Audience::Admin,
            None,
            EVENTS,
        )
        .await?;
    let (events, more) = events_json(&page);
    let probes = crate::admin::probes::groups_for(state, ip.id)
        .await
        .iter()
        .map(ProbeGroupJson::from)
        .collect();
    let props = store.ip_props(&[ip.ip.as_str()]).await?.remove(&ip.ip);
    let evidence = store
        .evidence_view(ip.id, ip.is_tor_exit)
        .await?
        .map(|v| VerdictJson {
            label: v.label,
            sentence: v.sentence,
            note: v.as_note,
            caveat: v.caveat,
            lines: lines_json(&v.lines),
        });
    let sharing = store
        .sharing_view(ip.id, ip.is_tor_exit)
        .await?
        .map(|v| VerdictJson {
            label: v.label,
            sentence: v.sentence,
            note: None,
            caveat: None,
            lines: lines_json(&v.lines),
        });
    let (uploads, uploads_more) = uploads_json(store.uploads_for_ip(ip.id, IPS_PLUS).await?);
    let (commands, commands_more) = capped(store.webshell_hits_for_ip(ip.id, IPS_PLUS).await?, IPS);
    let commands = commands
        .into_iter()
        .map(|w| CommandJson {
            request_id: w.request_id,
            at: rfc3339(&w.ts),
            command: w.command,
        })
        .collect();
    let (used_elsewhere, used_from) = store.canary_links_for_ip(ip.id).await?;
    let (reuses, reuses_more) = reuses(
        state,
        crate::store::canaries::ReuseFilter {
            ip_id: Some(ip.id),
            ..Default::default()
        },
    )
    .await?;
    let body = IpDossier {
        detail,
        week: ov.week.iter().map(BucketJson::from).collect(),
        calendar: ov.calendar.clone(),
        events,
        probes,
        campaign: campaign_ref(store.campaign_of_ip(ip.id).await?),
        agent: props.as_ref().is_some_and(|p| p.agent),
        props: props.map(|p| PropsJson {
            tor: p.tor,
            net: p.net,
            scanner: p.scanner,
            fleet: p.fleet,
            agent: p.agent,
            scanned: p.scanned,
            scan_pending: p.scan_pending,
        }),
        evidence,
        sharing,
        uploads,
        commands,
        canaries: IpCanaries {
            used_elsewhere,
            used_from,
            reuses,
        },
    };
    Ok(Some(envelope(
        state,
        "ip",
        ip.ip.clone(),
        format!("/ip/{}", ip.ip),
        Counts {
            events: Some(more),
            uploads: Some(uploads_more),
            commands: Some(commands_more),
            reuses: Some(reuses_more),
            ..Default::default()
        },
        Counts::default(),
        body,
    )))
}

// ------------------------------------------------------------------- asn

#[derive(Debug, Serialize)]
pub struct AsnDossier {
    pub asn: u32,
    pub org: Option<String>,
    /// IPs recorded in it, and their requests.
    pub ips: i64,
    pub requests: i64,
    pub max_severity: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub labels: Vec<LabelCount>,
    pub open_ports: Vec<PortCount>,
    pub campaigns: Vec<CampaignCount>,
    /// The busiest, at most [`IPS`], as `/api/v1/ips` lists them.
    pub top_ips: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct LabelCount {
    pub label: String,
    pub ips: i64,
}

#[derive(Debug, Serialize)]
pub struct PortCount {
    pub port: i64,
    pub ips: i64,
}

#[derive(Debug, Serialize)]
pub struct CampaignCount {
    pub key: String,
    pub num: i64,
    pub ips: i64,
}

/// The dossier of AS `n`; None when it is not a number or no IP is
/// recorded in it.
pub async fn asn(state: &AdminState, n: &str) -> Result<Option<Envelope<AsnDossier>>> {
    let Ok(asn) = n.trim().parse::<u32>() else {
        return Ok(None);
    };
    let key = crate::store::asn::RollupKey::Asn(asn.into());
    let Some(r) = state.store.rollup(&key).await? else {
        return Ok(None);
    };
    let f = crate::store::browse::IpFilter {
        asn: Some(asn.into()),
        ..Default::default()
    };
    let mut top = state.store.list_ips(&f).await?.items;
    let more = top.len() > IPS || r.ips > IPS as i64;
    top.truncate(IPS);
    let body = AsnDossier {
        asn,
        org: r.org,
        ips: r.ips,
        requests: r.requests,
        max_severity: r.max_severity,
        first_seen: rfc3339(&r.first_seen),
        last_seen: rfc3339(&r.last_seen),
        labels: r
            .labels
            .into_iter()
            .map(|(label, ips)| LabelCount { label, ips })
            .collect(),
        open_ports: r
            .open_ports
            .into_iter()
            .map(|(port, ips)| PortCount { port, ips })
            .collect(),
        campaigns: r
            .campaigns
            .into_iter()
            .map(|(key, num, ips)| CampaignCount { key, num, ips })
            .collect(),
        top_ips: summaries_json(state, &top).await,
    };
    Ok(Some(envelope(
        state,
        "asn",
        asn.to_string(),
        crate::admin::asn::asn_href(asn.into()),
        Counts {
            ips: Some(more),
            ..Default::default()
        },
        Counts {
            ips: Some(r.ips),
            ..Default::default()
        },
        body,
    )))
}

// --------------------------------------------------------------- request

#[derive(Debug, Serialize)]
pub struct RequestDossier {
    pub request: RequestJson,
    /// Its address as `/api/v1/ips` lists it (null once deleted).
    pub ip: Option<Value>,
    /// Other requests of the address, newest first, at most [`IPS`]; as
    /// many in `same_ja4.recent` and `canaries.reuses`.
    pub same_ip: Vec<RelatedJson>,
    pub same_ja4: SameJa4,
    pub canaries: RequestCanaries,
    pub uploads: Vec<UploadJson>,
    /// The command it sent a dropped webshell, if it was answered as one.
    pub webshell_cmd: Option<String>,
    pub campaign: Option<CampaignRef>,
}

/// The request as recorded. `target`, `headers` and the body are
/// attacker-controlled. The body is what the page shows (`body_truncated`
/// as there).
#[derive(Debug, Serialize)]
pub struct RequestJson {
    pub id: i64,
    pub at: String,
    pub ip: String,
    pub method: String,
    /// Path and query as requested.
    pub target: String,
    pub host: Option<String>,
    pub answer: Option<String>,
    pub decoy: Option<String>,
    pub status: Option<i64>,
    pub held_ms: Option<i64>,
    pub persona: Option<String>,
    pub transport: Option<String>,
    pub via_proxy: Option<bool>,
    pub severity: i64,
    pub scan_level: i64,
    pub is_fp_claim: bool,
    pub labels: Vec<String>,
    pub owasp: Vec<String>,
    pub ja4: Option<String>,
    pub ja4h: Option<String>,
    /// The cluster node that recorded it, in distributed mode.
    pub node: Option<String>,
    pub rules_short: Option<String>,
    pub user_agent: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body_text: String,
    pub body_b64: String,
    pub body_len: usize,
    pub body_truncated: bool,
    pub fingerprint: Option<crate::store::inspect::FpSummary>,
}

#[derive(Debug, Serialize)]
pub struct RelatedJson {
    pub id: i64,
    pub at: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub severity: i64,
}

impl From<&crate::store::stats::RecentRequest> for RelatedJson {
    fn from(r: &crate::store::stats::RecentRequest) -> Self {
        Self {
            id: r.id,
            at: rfc3339(&r.ts),
            ip: r.ip.clone(),
            method: r.method.clone(),
            path: r.path.clone(),
            severity: r.severity,
        }
    }
}

/// Requests of other addresses with the same JA4 lately.
#[derive(Debug, Serialize)]
pub struct SameJa4 {
    pub ips: i64,
    pub days: i64,
    pub recent: Vec<RelatedJson>,
}

#[derive(Debug, Serialize)]
pub struct RequestCanaries {
    pub served: Vec<ServedCanary>,
    /// Where its decoy's links point.
    pub return_host: Option<String>,
    pub reuses: Vec<ReuseJson>,
}

#[derive(Debug, Serialize)]
pub struct ServedCanary {
    pub kind: String,
    pub value: String,
}

/// The dossier of request `id`; None when it is not a number or there is
/// no such request.
pub async fn request(state: &AdminState, id: &str) -> Result<Option<Envelope<RequestDossier>>> {
    let Ok(id) = id.trim().parse::<i64>() else {
        return Ok(None);
    };
    let store = &state.store;
    let Some(d) = store.request_detail(id).await? else {
        return Ok(None);
    };
    let user_agent = d
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    let host = crate::canary::site::request_host(&d.headers).map(str::to_string);
    let served = d.served_canaries();
    let return_host = d
        .row
        .decoy_site
        .as_deref()
        .filter(|_| !served.is_empty())
        .map(|w| {
            let site = format!("{w}.internal");
            crate::canary::site::return_host(host.as_deref(), &site)
        });
    let (same_ip, same_ip_more) = capped(
        store.related_by_ip(d.row.ip_id, d.row.id, IPS_PLUS).await?,
        IPS,
    );
    let (same_ja4, ja4_ips) = match &d.row.ja4 {
        Some(j) => store.related_by_ja4(j, d.row.ip_id, IPS_PLUS).await?,
        None => (vec![], 0),
    };
    let (same_ja4, same_ja4_more) = capped(same_ja4, IPS);
    let (reuses, reuses_more) = reuses(
        state,
        crate::store::canaries::ReuseFilter {
            request: Some(id),
            ..Default::default()
        },
    )
    .await?;
    let uploads = store.uploads_of_request(id).await?;
    let webshell_cmd = (d.row.answer.as_deref() == Some("webshell"))
        .then(|| {
            crate::model::webshell::extract_command(d.row.query.as_deref(), d.row.body.as_deref())
        })
        .flatten();
    let campaign = campaign_ref(store.campaign_of_ip(d.row.ip_id).await?);
    let ip = summaries_of(state, &[d.ip.as_str()])
        .await?
        .into_iter()
        .next();
    let target = match &d.row.query {
        Some(q) => format!("{}?{q}", d.row.path),
        None => d.row.path.clone(),
    };
    let request = RequestJson {
        id: d.row.id,
        at: rfc3339(d.row.ts),
        ip: d.ip.clone(),
        method: d.row.method.clone(),
        target,
        host,
        decoy: d.decoy().map(str::to_string),
        answer: d.row.answer.clone(),
        status: d.row.status,
        held_ms: d.row.held_ms,
        persona: d.row.persona.clone(),
        transport: d.row.transport.clone(),
        via_proxy: d.row.via_proxy,
        severity: d.row.severity,
        scan_level: d.row.scan_level,
        is_fp_claim: d.row.is_fp_claim,
        labels: serde_json::from_str(&d.row.labels_json).unwrap_or_default(),
        owasp: serde_json::from_str(&d.row.owasp_json).unwrap_or_default(),
        ja4: d.row.ja4.clone(),
        ja4h: d.row.ja4h.clone(),
        node: d.node.clone(),
        rules_short: d.rules_short.clone(),
        user_agent,
        headers: d.headers,
        body_text: d.body_text,
        body_b64: d.body_b64,
        body_len: d.body_len,
        body_truncated: d.body_truncated,
        fingerprint: d.fingerprint,
    };
    let body = RequestDossier {
        request,
        ip,
        same_ip: same_ip.iter().map(RelatedJson::from).collect(),
        same_ja4: SameJa4 {
            ips: ja4_ips,
            days: crate::store::analytics::RELATED_JA4_DAYS,
            recent: same_ja4.iter().map(RelatedJson::from).collect(),
        },
        canaries: RequestCanaries {
            served: served
                .into_iter()
                .map(|(kind, value)| ServedCanary { kind, value })
                .collect(),
            return_host,
            reuses,
        },
        uploads: uploads.iter().map(UploadJson::from).collect(),
        webshell_cmd,
        campaign,
    };
    Ok(Some(envelope(
        state,
        "request",
        id.to_string(),
        format!("/admin/requests/{id}"),
        Counts {
            same_ip: Some(same_ip_more),
            same_ja4: Some(same_ja4_more),
            reuses: Some(reuses_more),
            ..Default::default()
        },
        Counts::default(),
        body,
    )))
}

// -------------------------------------------------------------- campaign

#[derive(Debug, Serialize)]
pub struct CampaignDossier {
    pub campaign: CampaignJson,
    /// At most [`MEMBERS`]; `totals.members` is the campaign's size.
    pub members: Vec<MemberJson>,
    /// Those between two carried members.
    pub edges: Vec<EdgeJson>,
    pub shapes: Vec<ShapeJson>,
    pub calendar: Vec<CalendarDay>,
    /// At most [`IPS`] each.
    pub uploads: Vec<UploadJson>,
    pub commands: Vec<CampaignCommandJson>,
    /// The members' newest events, at most [`EVENTS`], each with its `ip`.
    pub events: Vec<EventJson>,
    /// A member carries an agent label.
    pub agent: bool,
}

/// [`crate::store::campaigns::CampaignRow`], times in RFC 3339.
#[derive(Debug, Serialize)]
pub struct CampaignJson {
    pub key: String,
    pub num: i64,
    pub size: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub hard_edges: i64,
    pub soft_edges: i64,
    pub v: i64,
    pub computed_at: String,
}

impl From<crate::store::campaigns::CampaignRow> for CampaignJson {
    fn from(r: crate::store::campaigns::CampaignRow) -> Self {
        Self {
            first_seen: rfc3339(&r.first_seen),
            last_seen: rfc3339(&r.last_seen),
            computed_at: rfc3339(&r.computed_at),
            key: r.key,
            num: r.num,
            size: r.size,
            hard_edges: r.hard_edges,
            soft_edges: r.soft_edges,
            v: r.v,
        }
    }
}

/// [`crate::store::campaigns::Member`], times in RFC 3339.
#[derive(Debug, Serialize)]
pub struct MemberJson {
    pub ip_id: i64,
    pub ip: String,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub requests: i64,
}

impl From<crate::store::campaigns::Member> for MemberJson {
    fn from(m: crate::store::campaigns::Member) -> Self {
        Self {
            first_seen: rfc3339(&m.first_seen),
            last_seen: rfc3339(&m.last_seen),
            ip_id: m.ip_id,
            ip: m.ip,
            country: m.country,
            asn: m.asn,
            asn_org: m.asn_org,
            requests: m.requests,
        }
    }
}

/// [`crate::store::campaigns::Edge`], times in RFC 3339.
#[derive(Debug, Serialize)]
pub struct EdgeJson {
    pub a_id: i64,
    pub a: String,
    pub b_id: i64,
    pub b: String,
    pub kind: String,
    pub value: String,
    pub score: Option<f64>,
    pub shared: Option<i64>,
    pub fp_support: bool,
    pub first_ts: String,
    pub last_ts: String,
    pub agreement: Option<f64>,
}

impl From<crate::store::campaigns::Edge> for EdgeJson {
    fn from(e: crate::store::campaigns::Edge) -> Self {
        Self {
            first_ts: rfc3339(&e.first_ts),
            last_ts: rfc3339(&e.last_ts),
            a_id: e.a_id,
            a: e.a,
            b_id: e.b_id,
            b: e.b,
            kind: e.kind,
            value: e.value,
            score: e.score,
            shared: e.shared,
            fp_support: e.fp_support,
            agreement: e.agreement,
        }
    }
}

/// The edges between two of `members`, and whether any was left out.
fn member_edges(
    edges: Vec<crate::store::campaigns::Edge>,
    members: &[crate::store::campaigns::Member],
) -> (Vec<EdgeJson>, bool) {
    let carried: std::collections::HashSet<i64> = members.iter().map(|m| m.ip_id).collect();
    let all = edges.len();
    let kept: Vec<EdgeJson> = edges
        .into_iter()
        .filter(|e| carried.contains(&e.a_id) && carried.contains(&e.b_id))
        .map(EdgeJson::from)
        .collect();
    let more = kept.len() < all;
    (kept, more)
}

#[derive(Debug, Serialize)]
pub struct ShapeJson {
    pub text: String,
    pub members: i64,
    pub df: i64,
    pub first_seen: String,
    pub wave: Option<WaveJson>,
}

#[derive(Debug, Serialize)]
pub struct WaveJson {
    pub ips: i64,
    pub window_start: String,
    pub detected_at: String,
}

#[derive(Debug, Serialize)]
pub struct CampaignCommandJson {
    pub command: String,
    pub count: i64,
    pub ips: i64,
    pub last_at: String,
}

/// The dossier of campaign `key` (an address); None when there is none.
pub async fn campaign(state: &AdminState, key: &str) -> Result<Option<Envelope<CampaignDossier>>> {
    if key.trim().parse::<std::net::IpAddr>().is_err() {
        return Ok(None);
    }
    let key = canonical_ip(key);
    let store = &state.store;
    let Some(mut c) = store.campaign(&key).await? else {
        return Ok(None);
    };
    let members_more = c.members.len() > MEMBERS;
    c.members.truncate(MEMBERS);
    let (edges, edges_more) = member_edges(c.edges, &c.members);
    let page = store.campaign_events(&key, None, EVENTS).await?;
    let (events, events_more) = events_json(&page);
    let (uploads, uploads_more) = uploads_json(store.campaign_uploads(&key, IPS_PLUS).await?);
    let (commands, commands_more) = capped(store.campaign_commands(&key, IPS_PLUS).await?, IPS);
    let body = CampaignDossier {
        shapes: store
            .campaign_shapes(&key)
            .await?
            .into_iter()
            .map(|s| ShapeJson {
                text: s.text,
                members: s.members,
                df: s.df,
                first_seen: rfc3339(&s.first_seen),
                wave: s.wave.map(|w| WaveJson {
                    ips: w.ips,
                    window_start: rfc3339(&w.window_start),
                    detected_at: rfc3339(&w.detected_at),
                }),
            })
            .collect(),
        calendar: store.campaign_calendar(&key).await?,
        uploads,
        commands: commands
            .into_iter()
            .map(|c| CampaignCommandJson {
                command: c.cmd,
                count: c.count,
                ips: c.ips,
                last_at: rfc3339(&c.last_ts),
            })
            .collect(),
        events,
        agent: !store.agent_campaigns(Some(&key)).await?.is_empty(),
        members: c.members.into_iter().map(MemberJson::from).collect(),
        edges,
        campaign: c.row.into(),
    };
    let size = body.campaign.size;
    Ok(Some(envelope(
        state,
        "campaign",
        key.clone(),
        format!("/admin/evidence/campaigns/{key}"),
        Counts {
            events: Some(events_more),
            members: Some(members_more),
            edges: Some(edges_more),
            uploads: Some(uploads_more),
            commands: Some(commands_more),
            ..Default::default()
        },
        Counts {
            members: Some(size),
            ..Default::default()
        },
        body,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::campaigns::tests::{feed, fixture, seed_artifacts};

    /// The campaign fixture with its artifacts, a network, and a request
    /// whose attacker-controlled header values spell forbidden key names:
    /// (state, the request's id, dir).
    async fn seeded() -> (std::sync::Arc<AdminState>, i64, tempfile::TempDir) {
        let (state, _cookie, _app, d) = crate::admin::devices::tests::app().await;
        let s = &state.store;
        feed(s, fixture()).await;
        s.recompute_campaigns(true).await.unwrap();
        seed_artifacts(s).await;
        let ip = s.ip_by_addr("192.0.2.1").await.unwrap().unwrap();
        s.set_ip_geo(ip.id, Some("DE"), Some(64500), Some("Example Net"))
            .await
            .unwrap();
        s.insert_request(&crate::store::requests::NewRequest {
            ip_id: ip.id,
            method: "POST".into(),
            path: "/token_hash".into(),
            query: Some("cred_id=1&content=x".into()),
            headers_json: r#"[["X-Code-Hash","passkey_json blob"]]"#.into(),
            body: Some(b"{\"token_hash\":\"x\"}".to_vec()),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        let id: i64 = sqlx::query_scalar("SELECT max(id) FROM requests")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        (state, id, d)
    }

    async fn all_four(state: &AdminState, request: i64) -> Vec<Value> {
        vec![
            serde_json::to_value(ip(state, "192.0.2.1").await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(asn(state, "64500").await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(request_dossier(state, request).await).unwrap(),
            serde_json::to_value(campaign(state, "192.0.2.3").await.unwrap().unwrap()).unwrap(),
        ]
    }

    async fn request_dossier(state: &AdminState, id: i64) -> Envelope<RequestDossier> {
        request(state, &id.to_string()).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn dossier_of_each_kind_builds_from_the_fixture() {
        let (state, req, _d) = seeded().await;
        let all = all_four(&state, req).await;
        let kinds: Vec<_> = all.iter().map(|d| d["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["ip", "asn", "request", "campaign"]);
        for d in &all {
            assert_eq!(d["dossier_v"], 1, "{d}");
            assert_eq!(
                d["limits"],
                json!({"events": 200, "members": 500, "ips": 50})
            );
            assert!(d["generated_at"].as_str().unwrap().ends_with('Z'));
            assert_eq!(d["node"]["version"], env!("CARGO_PKG_VERSION"));
        }
        let [ip, asn, request, campaign] = &all[..] else {
            unreachable!()
        };
        // The IP: the API body's fields and the page's admin extras.
        assert_eq!(ip["id"], "192.0.2.1");
        assert_eq!(ip["page"], "/ip/192.0.2.1");
        assert_eq!(ip["geo"]["asn"], 64500);
        assert_eq!(ip["campaign"]["key"], "192.0.2.3");
        assert_eq!(
            ip["truncated"],
            json!({"events": false, "uploads": false, "commands": false, "reuses": false})
        );
        assert!(!ip["events"].as_array().unwrap().is_empty(), "{ip}");
        assert_eq!(ip["uploads"][0]["answered_path"], "/drop.php");
        assert_eq!(ip["commands"][0]["command"], "ls -la");
        // The network: its one IP.
        assert_eq!((&asn["asn"], &asn["ips"]), (&json!(64500), &json!(1)));
        assert_eq!(asn["top_ips"][0]["ip"], "192.0.2.1");
        assert_eq!(asn["page"], "/admin/asn/64500");
        assert_eq!(
            (&asn["truncated"], &asn["totals"]),
            (&json!({"ips": false}), &json!({"ips": 1}))
        );
        // The request: as recorded, attacker text verbatim.
        assert_eq!(
            request["request"]["target"],
            "/token_hash?cred_id=1&content=x"
        );
        assert_eq!(request["request"]["method"], "POST");
        assert_eq!(request["ip"]["ip"], "192.0.2.1");
        assert_eq!(request["campaign"]["key"], "192.0.2.3");
        assert_eq!(
            request["truncated"],
            json!({"same_ip": false, "same_ja4": false, "reuses": false})
        );
        // The campaign: its members, events with their address.
        assert_eq!(campaign["campaign"]["size"], 3);
        assert_eq!(campaign["members"].as_array().unwrap().len(), 3);
        assert_eq!(campaign["totals"], json!({"members": 3}));
        assert_eq!(
            campaign["truncated"],
            json!({"events": false, "members": false, "edges": false,
                "uploads": false, "commands": false})
        );
        assert!(campaign["events"][0]["ip"].is_string(), "{campaign}");
        assert_eq!(campaign["uploads"][0]["answered_path"], "/drop.php");
    }

    #[tokio::test]
    async fn events_are_capped_at_200_and_say_so() {
        let (state, _cookie, _app, _d) = crate::admin::devices::tests::app().await;
        let s = &state.store;
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        for i in 0..201 {
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: format!("/{i}"),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let d = super::ip(&state, "203.0.113.9").await.unwrap().unwrap();
        assert_eq!(d.body.events.len(), 200);
        assert_eq!(d.truncated.events, Some(true));
        // 200 exactly is not truncated.
        sqlx::query("DELETE FROM requests WHERE path = '/0'")
            .execute(&s.pool)
            .await
            .unwrap();
        let d = super::ip(&state, "203.0.113.9").await.unwrap().unwrap();
        assert_eq!(d.body.events.len(), 200);
        assert_eq!(d.truncated.events, Some(false));
    }

    /// Every key of `v`, at any depth.
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    out.push(k.clone());
                    keys(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }

    /// What must never leave the node in a dossier, checked on the keys
    /// (values are attacker text and may spell anything; the fixture's
    /// request does).
    #[tokio::test]
    async fn dossiers_carry_no_secret_or_content_field() {
        let (state, req, _d) = seeded().await;
        const FORBIDDEN: [&str; 9] = [
            "token_hash",
            "cred_id",
            "code_hash",
            "passkey_json",
            "content",
            "page_token",
            "decoy_in",
            "node_id",
            "value_hash",
        ];
        for d in all_four(&state, req).await {
            let mut all = vec![];
            keys(&d, &mut all);
            assert!(all.len() > 20, "{d}");
            for k in &all {
                assert!(
                    !FORBIDDEN.contains(&k.as_str()) && !k.contains("blob"),
                    "{} dossier has key {k:?}",
                    d["kind"]
                );
            }
        }
        // The values did reach the dossier: the walk is over keys only.
        let d = serde_json::to_string(&request_dossier(&state, req).await).unwrap();
        assert!(d.contains("token_hash") && d.contains("passkey_json blob"));
    }

    /// Every non-null time in `v`: keys `at`, `ts` and `*_at`, `*_seen`,
    /// `*_ts`, as (key, value).
    fn times(v: &Value, out: &mut Vec<(String, Value)>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    let time = ["at", "ts"].contains(&k.as_str())
                        || ["_at", "_seen", "_ts"].iter().any(|s| k.ends_with(s));
                    if time && !v.is_null() {
                        out.push((k.clone(), v.clone()));
                    }
                    times(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| times(v, out)),
            _ => {}
        }
    }

    fn assert_rfc3339(d: &Value) -> usize {
        let mut all = vec![];
        times(d, &mut all);
        for (k, v) in &all {
            let ok = v
                .as_str()
                .is_some_and(|t| chrono::DateTime::parse_from_rfc3339(t).is_ok());
            assert!(ok, "{} dossier: {k} = {v} is not RFC 3339", d["kind"]);
        }
        all.len()
    }

    #[tokio::test]
    async fn every_time_in_a_dossier_is_rfc3339() {
        let (state, req, _d) = seeded().await;
        for d in all_four(&state, req).await {
            assert!(assert_rfc3339(&d) > 2, "{d}");
        }
        let c =
            serde_json::to_value(campaign(&state, "192.0.2.3").await.unwrap().unwrap()).unwrap();
        for k in ["first_seen", "last_seen", "computed_at"] {
            assert!(c["campaign"][k].as_str().unwrap().ends_with('Z'), "{k}");
        }
        assert!(
            c["members"][0]["first_seen"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        assert!(c["edges"][0]["first_ts"].as_str().unwrap().ends_with('Z'));
        // An address active this week has hour buckets.
        let (state, _cookie, _app, _d) = crate::admin::devices::tests::app().await;
        let ip = state
            .store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        state
            .store
            .insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let d =
            serde_json::to_value(super::ip(&state, "203.0.113.9").await.unwrap().unwrap()).unwrap();
        let ts = d["week"][0]["ts"].as_str().unwrap();
        assert!(ts.ends_with(":00:00Z"), "{ts}");
        assert_rfc3339(&d);
    }

    #[tokio::test]
    async fn capped_lists_fetch_one_more_and_say_so() {
        let (state, _cookie, _app, _d) = crate::admin::devices::tests::app().await;
        let s = &state.store;
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        // The newest request and 51 others.
        let mut newest = 0;
        for i in 0..52 {
            newest = s
                .insert_request(&crate::store::requests::NewRequest {
                    ip_id: ip.id,
                    method: "GET".into(),
                    path: format!("/{i}"),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let d = request_dossier(&state, newest).await;
        assert_eq!(d.body.same_ip.len(), 50);
        assert_eq!(d.truncated.same_ip, Some(true));
        // 50 others exactly: all of them, not truncated.
        sqlx::query("DELETE FROM requests WHERE path = '/0'")
            .execute(&s.pool)
            .await
            .unwrap();
        let d = request_dossier(&state, newest).await;
        assert_eq!(d.body.same_ip.len(), 50);
        assert_eq!(d.truncated.same_ip, Some(false));
    }

    fn member(ip_id: i64) -> crate::store::campaigns::Member {
        crate::store::campaigns::Member {
            ip_id,
            ip: format!("192.0.2.{ip_id}"),
            country: None,
            asn: None,
            asn_org: None,
            first_seen: "2026-01-02 03:04:05".into(),
            last_seen: "2026-01-02 03:04:05".into(),
            requests: 1,
        }
    }

    fn edge(a_id: i64, b_id: i64) -> crate::store::campaigns::Edge {
        crate::store::campaigns::Edge {
            a_id,
            a: format!("192.0.2.{a_id}"),
            b_id,
            b: format!("192.0.2.{b_id}"),
            kind: "paths".into(),
            value: String::new(),
            score: Some(0.9),
            shared: Some(3),
            fp_support: false,
            first_ts: "2026-01-02 03:04:05".into(),
            last_ts: "2026-01-02 03:04:05".into(),
            agreement: None,
        }
    }

    #[test]
    fn edges_name_carried_members_only() {
        let edges = vec![edge(1, 2), edge(2, 3), edge(3, 1)];
        let (kept, more) = member_edges(edges.clone(), &[member(1), member(2), member(3)]);
        assert_eq!((kept.len(), more), (3, false));
        // Member 3 cut off by the cap: its edges go with it.
        let (kept, more) = member_edges(edges, &[member(1), member(2)]);
        let pairs: Vec<_> = kept.iter().map(|e| (e.a_id, e.b_id)).collect();
        assert_eq!((pairs, more), (vec![(1, 2)], true));
        assert_eq!(kept[0].first_ts, "2026-01-02T03:04:05Z");
    }

    #[tokio::test]
    async fn unknown_or_malformed_ids_have_no_dossier() {
        let (state, _req, _d) = seeded().await;
        assert!(ip(&state, "203.0.113.77").await.unwrap().is_none());
        assert!(ip(&state, "not-an-ip").await.unwrap().is_none());
        assert!(asn(&state, "64501").await.unwrap().is_none());
        assert!(asn(&state, "AS64500").await.unwrap().is_none());
        assert!(request(&state, "999999").await.unwrap().is_none());
        assert!(request(&state, "x").await.unwrap().is_none());
        assert!(campaign(&state, "192.0.2.1").await.unwrap().is_none());
        assert!(campaign(&state, "nope").await.unwrap().is_none());
    }
}
