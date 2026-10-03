//! Admin → Cluster: members and their health, replication lag, scanner
//! pace, invites, joining and revocation, shared intel versions.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::admin::views::Chrome;
use crate::cluster::identity::NodeId;
use crate::cluster::status::PaceInfo;
use crate::cluster::{Node, invite, members, repl};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/cluster", get(page))
        .route("/admin/cluster/invite", post(create_invite))
        .route("/admin/cluster/invite/revoke", post(revoke_invite))
        .route("/admin/cluster/join", post(join))
        .route("/admin/cluster/leave", post(leave))
        .route("/admin/cluster/settings", post(set_own))
        .route("/admin/cluster/config-key/rotate", post(rotate_key))
        .route("/admin/cluster/config-key/add", post(add_key))
        .route("/admin/cluster/config-key/forget", post(forget_key))
        .route("/admin/cluster/node/{key}", get(node_page).post(node_set))
        .route("/admin/cluster/block", post(block))
        .route("/admin/cluster/unblock", post(unblock))
        .route("/admin/cluster/purge", post(purge))
        .route("/admin/cluster/pace", post(set_pace))
}

/// One member as the page shows it.
pub struct MemberView {
    pub key: String,
    pub short: String,
    pub name: String,
    pub roles: String,
    /// Enrichment providers it can look up, comma separated.
    pub providers: String,
    pub address: String,
    pub active: bool,
    /// The member's standing in words (badge on inactive members).
    pub state: &'static str,
    /// This node blocked it (local decision).
    pub blocked: bool,
    /// This node deleted its data and no longer relays it.
    pub purged: bool,
    /// It lets config key holders change its runtime settings.
    pub remote_config: bool,
    /// This node holds its config key.
    pub key_held: bool,
    pub is_self: bool,
    pub version: String,
    pub last_seen: String,
    pub live: bool,
    pub scanner: bool,
    pub pace: Option<PaceInfo>,
    pub timeout_min: String,
    pub active_scans: u32,
    pub lag: String,
    /// "full history", "keeps N days" (this node: and where its history
    /// starts), "?" when unknown.
    pub history: String,
    pub error: Option<String>,
    pub incompatible: bool,
    /// Clock difference worth a warning (cooldowns compare timestamps
    /// written by different nodes), e.g. "+3.5 min".
    pub skew: Option<String>,
}

/// A fresh heartbeat's creation time against our clock at receipt. Gossip
/// delay makes peers look behind by up to ~40 s, so only larger gaps count.
fn clock_skew(k: &crate::cluster::status::Known) -> Option<String> {
    const WARN_MS: i64 = 120_000;
    if k.advanced.elapsed() > std::time::Duration::from_secs(20) {
        return None;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as i64;
    let received_ms = now_ms - k.advanced.elapsed().as_millis() as i64;
    let skew = k.hb.at_ms as i64 - received_ms;
    (skew.abs() > WARN_MS).then(|| format!("{:+.1} min", skew as f64 / 60_000.0))
}

pub struct IntelView {
    pub kind: String,
    pub sha: String,
    pub size: String,
    pub fetched_at: String,
    pub by: String,
    pub local: bool,
}

#[derive(Template)]
#[template(path = "admin_cluster.html")]
struct ClusterPage {
    chrome: Chrome,
    /// None: standalone node.
    me: Option<MemberView>,
    members: Vec<MemberView>,
    intel: Vec<IntelView>,
    /// Why this node is out of its cluster, if it is.
    detached: Option<&'static str>,
    invite: Option<String>,
    invites: Vec<InviteView>,
    /// This node's config key, shown only when remote configuration is on.
    config_key: Option<String>,
    remote_config: bool,
    /// This node's runtime settings and why a role cannot be switched on.
    settings: SettingsView,
    audit: Vec<AuditView>,
    /// Members whose older history no reachable peer can give this node.
    unserved: Option<String>,
    contributions: Vec<ContribView>,
}

/// This node's runtime settings as its own page shows them.
pub struct SettingsView {
    pub version: u64,
    pub cooldown_hours: i64,
    pub listener: bool,
    pub scanner: bool,
    pub web: bool,
    /// Why a role that is off cannot be switched on here ("" = it can).
    pub listener_missing: String,
    pub scanner_missing: String,
    pub web_missing: String,
}

impl SettingsView {
    fn of(st: &AdminState) -> Self {
        let s = st.settings.snapshot();
        let p = st.settings.prereqs();
        Self {
            version: s.version,
            cooldown_hours: s.cooldown_hours,
            listener: s.roles.listener,
            scanner: s.roles.scanner,
            web: s.roles.web,
            listener_missing: p.listener.clone().unwrap_or_default(),
            scanner_missing: p.scanner.clone().unwrap_or_default(),
            web_missing: p.web.clone().unwrap_or_default(),
        }
    }
}

/// One settings change made by another node.
pub struct AuditView {
    pub at: String,
    pub by: String,
    pub changes: String,
}

/// The outcome shown on a remote node's page, which renders in place.
#[derive(Default)]
struct Flash {
    notice: Option<String>,
    error: Option<String>,
}

fn ago(d: std::time::Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=89 => format!("{s} s ago"),
        90..=5399 => format!("{} min ago", s / 60),
        _ => format!("{:.1} h ago", s as f64 / 3600.0),
    }
}

fn node(st: &AdminState) -> AppResult<&Arc<Node>> {
    st.recorder.node().ok_or(AppError::NotFound)
}

async fn views(node: &Node) -> AppResult<(MemberView, Vec<MemberView>)> {
    let rows = members::all(&node.store).await?;
    let heads = repl::head_map(&repl::heads(&node.store).await?);
    let purged = crate::cluster::block::purged(&node.store).await?;
    let statuses = node.peer_status.read().unwrap().clone();
    let me = node.id();
    let keys = crate::cluster::confkey::held(&node.store).await?;
    let mut out = vec![];
    let mut mine = None;
    for m in rows {
        let is_self = m.id == me;
        let known = node.status.known(&m.id);
        let hb = known.as_ref().map(|k| &k.hb);
        let (last_seen, live) = match (&known, is_self) {
            (_, true) => ("this node".to_string(), true),
            (Some(k), _) => (
                ago(k.advanced.elapsed()),
                k.advanced.elapsed() < std::time::Duration::from_secs(45),
            ),
            (None, _) => ("never".to_string(), false),
        };
        let held = heads.get(&m.id).copied().unwrap_or(0);
        let lag = match hb {
            _ if is_self => "—".to_string(),
            Some(h) if h.own_seq <= held => "in sync".to_string(),
            Some(h) => format!("{} behind", h.own_seq - held),
            None => format!("{held} held"),
        };
        let pace = if is_self {
            node.status.local.lock().unwrap().pace
        } else {
            hb.and_then(|h| h.pace)
        };
        let error = statuses.get(&m.id).and_then(|s| s.last_error.clone());
        let v = MemberView {
            key: m.id.to_string(),
            short: m.id.short(),
            name: m.name.clone(),
            roles: m.roles.join(", "),
            providers: hb.map(|h| h.providers.join(", ")).unwrap_or_default(),
            address: m
                .address
                .clone()
                .unwrap_or_else(|| "outbound-only".to_string()),
            active: m.active,
            state: m.standing.label(),
            blocked: node.is_blocked(&m.id),
            purged: purged.contains(&m.id),
            remote_config: m.remote_config,
            key_held: keys.contains(&m.id),
            is_self,
            version: hb.map(|h| h.version.clone()).unwrap_or_else(|| {
                if is_self {
                    crate::VERSION.into()
                } else {
                    "?".into()
                }
            }),
            last_seen,
            live,
            scanner: m.roles.iter().any(|r| r == "scanner"),
            timeout_min: pace
                .map(|p| format!("{}", p.timeout_secs / 60))
                .unwrap_or_default(),
            pace,
            active_scans: if is_self {
                node.status.local.lock().unwrap().active_scans
            } else {
                hb.map_or(0, |h| h.active_scans)
            },
            lag,
            history: if is_self {
                own_history(node).await?
            } else {
                match hb.map(|h| h.retention_days) {
                    Some(0) => "full history".into(),
                    Some(d) => format!("keeps {d} days"),
                    None => "?".into(),
                }
            },
            incompatible: error
                .as_deref()
                .is_some_and(|e| e.contains("incompatible protocol")),
            error,
            skew: known.as_ref().and_then(clock_skew),
        };
        if is_self {
            mine = Some(v);
        } else {
            out.push(v);
        }
    }
    let own = own_history(node).await?;
    let mine = mine.unwrap_or_else(|| MemberView {
        key: me.to_string(),
        short: me.short(),
        name: node.cfg.node_name.clone(),
        roles: node.roles().names().join(", "),
        providers: node.providers().join(", "),
        address: node.cfg.advertise.clone().unwrap_or_default(),
        active: true,
        state: "active",
        blocked: false,
        purged: false,
        remote_config: node.cfg.remote_config,
        key_held: false,
        is_self: true,
        version: crate::VERSION.into(),
        last_seen: "this node".into(),
        live: true,
        scanner: node.roles().scanner,
        pace: None,
        timeout_min: String::new(),
        active_scans: 0,
        lag: "—".into(),
        history: own,
        error: None,
        incompatible: false,
        skew: None,
    });
    Ok((mine, out))
}

/// How much history this node keeps, and from when it holds it.
async fn own_history(node: &Node) -> AppResult<String> {
    if !node.windowed() {
        return Ok("full history".into());
    }
    let oldest: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(l.hlc) FROM repl_floors f
         JOIN repl_log l ON l.origin = f.origin AND l.seq = f.seq",
    )
    .fetch_one(&node.store.pool)
    .await?;
    let from = oldest
        .and_then(|h| {
            chrono::DateTime::from_timestamp_millis(crate::cluster::hlc::physical_ms(
                crate::cluster::hlc::from_db(h),
            ) as i64)
        })
        .map(|t| format!(" (history from {})", t.format("%Y-%m-%d")))
        .unwrap_or_default();
    Ok(format!("keeps {} days{from}", node.retention_days))
}

/// Origins whose history this node waits for, by name.
async fn unserved(node: &Node) -> AppResult<Option<String>> {
    let ids = node.unserved_origins();
    if ids.is_empty() {
        return Ok(None);
    }
    let names: std::collections::HashMap<NodeId, String> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    Ok(Some(
        ids.iter()
            .map(|id| names.get(id).cloned().unwrap_or_else(|| id.short()))
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

async fn intel(node: &Node) -> AppResult<Vec<IntelView>> {
    let names: std::collections::HashMap<NodeId, String> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    let mut v: Vec<_> = crate::intel::share::manifests(&node.store)
        .await?
        .into_values()
        .map(|m| {
            let local = crate::intel::share::file_name(&m.kind)
                .map(|f| node.data_dir.join(f))
                .and_then(|p| crate::intel::share::file_hash(&p).ok())
                .is_some_and(|(h, _)| h == m.sha256);
            IntelView {
                sha: m.sha256.chars().take(12).collect(),
                size: size(m.size as i64),
                fetched_at: m.fetched_at.clone(),
                by: m
                    .origin
                    .and_then(|o| names.get(&o).cloned())
                    .unwrap_or_else(|| "?".into()),
                local,
                kind: m.kind,
            }
        })
        .collect();
    v.sort_by(|a, b| a.kind.cmp(&b.kind));
    Ok(v)
}

/// What one node contributed, as far as this node holds it.
pub struct ContribView {
    pub name: String,
    pub short: String,
    pub requests: i64,
    /// Light rows the flood gate kept instead of full requests, plus the
    /// requests past a batch's cap that were only counted.
    pub skipped: i64,
    pub fingerprints: i64,
    pub claims: i64,
    pub scans: i64,
    /// IPs it looked up with an enrichment provider.
    pub lookups: i64,
    pub log_entries: i64,
    pub log_size: String,
}

fn size(s: i64) -> String {
    match s {
        s if s >= 1_000_000 => format!("{:.1} MB", s as f64 / 1e6),
        s if s >= 1_000 => format!("{:.1} kB", s as f64 / 1e3),
        s => format!("{s} B"),
    }
}

/// Rows per origin in each replicated table, plus the log entries held.
/// Every member gets a row, contributors or not; rows not yet shared
/// (created before this node joined) come last as "not shared yet".
async fn contributions(node: &Node) -> AppResult<Vec<ContribView>> {
    use std::collections::HashMap;
    type Counts = HashMap<Vec<u8>, i64>;
    async fn by_origin(node: &Node, sql: &'static str) -> AppResult<Counts> {
        let rows: Vec<(Option<Vec<u8>>, i64)> =
            sqlx::query_as(sql).fetch_all(&node.store.pool).await?;
        Ok(rows
            .into_iter()
            .map(|(o, n)| (o.unwrap_or_default(), n))
            .collect())
    }
    let requests = by_origin(
        node,
        "SELECT origin, COUNT(*) FROM requests GROUP BY origin",
    )
    .await?;
    let skipped = by_origin(
        node,
        "SELECT origin, SUM(n) FROM (
           SELECT b.origin, b.dropped
             + (SELECT COUNT(*) FROM skipped_requests r WHERE r.batch_id = b.id) AS n
           FROM skipped_batches b)
         GROUP BY origin",
    )
    .await?;
    let fingerprints = by_origin(
        node,
        "SELECT origin, COUNT(*) FROM fingerprints GROUP BY origin",
    )
    .await?;
    let claims = by_origin(
        node,
        "SELECT origin, COUNT(*) FROM fp_claims GROUP BY origin",
    )
    .await?;
    let scans = by_origin(node, "SELECT origin, COUNT(*) FROM scans GROUP BY origin").await?;
    let lookups = by_origin(
        node,
        "SELECT origin, COUNT(DISTINCT ip) FROM ip_intel GROUP BY origin",
    )
    .await?;
    let usage: HashMap<Vec<u8>, (i64, i64)> =
        sqlx::query_as::<_, (Vec<u8>, i64, i64)>("SELECT origin, entries, bytes FROM origin_usage")
            .fetch_all(&node.store.pool)
            .await?
            .into_iter()
            .map(|(o, e, b)| (o, (e, b)))
            .collect();
    let row = |key: &[u8], name: String, short: String| {
        let get = |m: &Counts| m.get(key).copied().unwrap_or(0);
        let (log_entries, bytes) = usage.get(key).copied().unwrap_or((0, 0));
        ContribView {
            name,
            short,
            requests: get(&requests),
            skipped: get(&skipped),
            fingerprints: get(&fingerprints),
            claims: get(&claims),
            scans: get(&scans),
            lookups: get(&lookups),
            log_entries,
            log_size: size(bytes),
        }
    };
    let me = node.id();
    let mut out: Vec<ContribView> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| {
            let name = if m.id == me {
                format!("{} (this node)", m.name)
            } else {
                m.name
            };
            row(&m.id.0[..], name, m.id.short())
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.requests));
    let unshared = row(&[], "not shared yet".into(), String::new());
    if unshared.requests
        + unshared.skipped
        + unshared.fingerprints
        + unshared.claims
        + unshared.scans
        + unshared.lookups
        > 0
    {
        out.push(unshared);
    }
    Ok(out)
}

/// One invite as the page lists it.
pub struct InviteView {
    pub id: i64,
    pub label: String,
    pub created_at: String,
    pub expires: String,
    pub uses: String,
    pub state: &'static str,
    pub usable: bool,
    pub joined: String,
}

async fn invites(node: &Node) -> AppResult<Vec<InviteView>> {
    let names: std::collections::HashMap<NodeId, String> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    Ok(invite::list(&node.store)
        .await?
        .into_iter()
        .map(|i| InviteView {
            id: i.id,
            label: i.label,
            created_at: i.created_at,
            expires: i.expires_at.unwrap_or_else(|| "never".into()),
            uses: match i.max_uses {
                Some(m) => format!("{} of {m}", i.uses),
                None => i.uses.to_string(),
            },
            state: if i.usable {
                "usable"
            } else if i.revoked {
                "revoked"
            } else {
                "closed"
            },
            usable: i.usable,
            joined: i
                .joined
                .iter()
                .map(|n| names.get(n).cloned().unwrap_or_else(|| n.short()))
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect())
}

async fn render_page(st: &AdminState, invite: Option<String>) -> AppResult<Html<String>> {
    let Some(node) = st.recorder.node() else {
        return render(&ClusterPage {
            chrome: Chrome::new(true, "admin"),
            me: None,
            members: vec![],
            intel: vec![],
            detached: None,
            invite: None,
            invites: vec![],
            config_key: None,
            remote_config: false,
            settings: SettingsView::of(st),
            audit: vec![],
            unserved: None,
            contributions: vec![],
        });
    };
    let names: std::collections::HashMap<NodeId, String> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    let audit = st
        .settings
        .audit(20)
        .await?
        .into_iter()
        .map(|a| AuditView {
            at: a.at,
            by: match a.by {
                Some(id) => names.get(&id).cloned().unwrap_or_else(|| id.short()),
                None => "this node".into(),
            },
            changes: a.changes,
        })
        .collect();
    let config_key = if node.cfg.remote_config {
        Some(
            crate::cluster::confkey::ensure(&node.store, node.id())
                .await?
                .encode(),
        )
    } else {
        None
    };
    let (me, members) = views(node).await?;
    render(&ClusterPage {
        chrome: Chrome::new(true, "admin"),
        detached: node.detached().map(|d| d.label()),
        me: Some(me),
        members,
        intel: intel(node).await?,
        invite,
        invites: invites(node).await?,
        config_key,
        remote_config: node.cfg.remote_config,
        settings: SettingsView::of(st),
        audit,
        unserved: unserved(node).await?,
        contributions: contributions(node).await?,
    })
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&st, None).await
}

/// Back to the cluster page with a one-shot notice or error (in a cookie,
/// see [`redirect_with_notice`]).
fn back(notice: Option<String>, error: Option<String>) -> Response {
    const TO: &str = "/admin/cluster";
    match (error, notice) {
        (Some(e), _) => redirect_with_error(TO, &e),
        (None, Some(n)) => redirect_with_notice(TO, &n),
        (None, None) => Redirect::to(TO).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct InviteForm {
    label: Option<String>,
    ttl_hours: Option<String>,
    max_uses: Option<String>,
}

/// Create an invite and show it once (never stored in clear).
async fn create_invite(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<InviteForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    // Empty fields mean the defaults (a week, 10 uses); 0 means no limit.
    let Ok((ttl_hours, max_uses)) =
        invite::InviteOpts::parse_limits(f.ttl_hours.as_deref(), f.max_uses.as_deref())
    else {
        return Ok(back(
            None,
            Some("expiry and use limit must be numbers".into()),
        ));
    };
    let opts = invite::InviteOpts {
        label: f.label.unwrap_or_default(),
        ttl_hours,
        max_uses,
    };
    match invite::create(node, &opts).await {
        Ok(token) => Ok(render_page(&st, Some(token)).await?.into_response()),
        Err(e) => Ok(back(None, Some(format!("{e:#}")))),
    }
}

#[derive(serde::Deserialize)]
struct InviteRevokeForm {
    id: i64,
}

async fn revoke_invite(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<InviteRevokeForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(if invite::revoke(&node.store, f.id).await? {
        back(
            Some("Invite revoked. Members that joined with it stay.".into()),
            None,
        )
    } else {
        back(None, Some("No usable invite with that id.".into()))
    })
}

#[derive(serde::Deserialize)]
struct JoinForm {
    token: String,
}

async fn join(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<JoinForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match invite::join(node, &f.token).await {
        Ok(i) => back(
            Some(format!(
                "Joined the cluster via {}. Data now syncs.",
                i.name
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("Join failed: {e:#}"))),
    })
}

async fn leave(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match crate::cluster::leave(node).await {
        Ok(told) => back(
            Some(format!(
                "This node left the cluster ({told} peer(s) told). Its data stays here; it no longer syncs."
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("Leaving failed: {e:#}"))),
    })
}

#[derive(serde::Deserialize)]
struct KeyForm {
    key: String,
    /// Block: also every node it admitted, transitively.
    subtree: Option<String>,
}

async fn block(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    if f.subtree.is_some() {
        return Ok(match crate::cluster::block::block_subtree(node, id).await {
            Ok((ids, n)) => back(
                Some(format!(
                    "Blocked {} and the {} node(s) it admitted, directly or not ({n} records taken out of view). Other nodes are unaffected.",
                    id.short(),
                    ids.len() - 1
                )),
                None,
            ),
            Err(e) => back(None, Some(format!("{e:#}"))),
        });
    }
    Ok(match crate::cluster::block::block(node, id).await {
        Ok(n) => back(
            Some(format!(
                "Blocked {}. This node no longer talks to it and shows none of its records ({n} taken out of view). Other nodes are unaffected.",
                id.short()
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("{e:#}"))),
    })
}

async fn unblock(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    Ok(if crate::cluster::block::unblock(node, id).await? {
        back(
            Some(format!("Unblocked {}. Its records are back.", id.short())),
            None,
        )
    } else {
        back(None, Some("That node was not blocked.".into()))
    })
}

/// Delete a blocked node's data here and stop relaying it.
async fn purge(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    Ok(match crate::cluster::block::purge(node, id).await {
        Ok(n) => back(
            Some(format!(
                "Purged {}: {n} log entries deleted here. Its entries are no longer accepted or relayed; unblocking fetches them again.",
                id.short()
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("{e:#}"))),
    })
}

/// The settings form. A checkbox that is not ticked is not sent, so the
/// role fields always describe the wanted state in full.
#[derive(serde::Deserialize)]
struct SettingsForm {
    base_version: Option<u64>,
    max_workers: Option<String>,
    max_scans_per_hour: Option<String>,
    timeout_minutes: Option<String>,
    cooldown_hours: Option<String>,
    listener: Option<String>,
    scanner: Option<String>,
    web: Option<String>,
}

impl SettingsForm {
    fn changes(&self) -> Result<crate::settings::Changes, String> {
        fn num<T: std::str::FromStr>(v: &Option<String>, what: &str) -> Result<Option<T>, String> {
            match v.as_deref().map(str::trim) {
                None | Some("") => Ok(None),
                Some(s) => s
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("{what} must be a number")),
            }
        }
        let timeout_secs = match num::<f64>(&self.timeout_minutes, "timeout")? {
            Some(m) if !m.is_finite() || m <= 0.0 => return Err("timeout must be positive".into()),
            Some(m) => Some((m * 60.0).round() as u64),
            None => None,
        };
        Ok(crate::settings::Changes {
            max_workers: num(&self.max_workers, "workers")?,
            max_scans_per_hour: num(&self.max_scans_per_hour, "scans per hour")?,
            timeout_secs,
            cooldown_hours: num(&self.cooldown_hours, "cooldown")?,
            listener: Some(self.listener.is_some()),
            scanner: Some(self.scanner.is_some()),
            web: Some(self.web.is_some()),
        })
    }
}

async fn set_own(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Response> {
    let changes = match f.changes() {
        Ok(c) => c,
        Err(e) => return Ok(back(None, Some(e))),
    };
    // The form sends every role, so it must not overwrite a change made
    // elsewhere (CLI, a config key holder) after the page was loaded.
    let Some(base) = f.base_version else {
        return Ok(back(
            None,
            Some("Settings not saved: reload the page and try again".into()),
        ));
    };
    Ok(match st.settings.apply_at(base, &changes, None).await? {
        Ok(_) => back(
            Some("Settings saved. Roles switch within seconds.".into()),
            None,
        ),
        Err(e) => back(None, Some(format!("Settings not saved: {e}"))),
    })
}

async fn rotate_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    if !node.cfg.remote_config {
        return Ok(back(
            None,
            Some("Remote configuration is off on this node; there is no key to rotate.".into()),
        ));
    }
    crate::cluster::confkey::rotate(&node.store, node.id()).await?;
    Ok(back(
        Some(
            "Config key rotated. Everyone who held the old key can no longer configure this node."
                .into(),
        ),
        None,
    ))
}

async fn add_key(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(
        match crate::cluster::confkey::add(&node.store, node.id(), &f.key).await {
            Ok(id) => Redirect::to(&format!("/admin/cluster/node/{id}")).into_response(),
            Err(e) => back(None, Some(format!("{e:#}"))),
        },
    )
}

async fn forget_key(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    crate::cluster::confkey::forget(&node.store, &id).await?;
    Ok(back(
        Some(format!("Config key for {} forgotten.", id.short())),
        None,
    ))
}

#[derive(Template)]
#[template(path = "admin_cluster_node.html")]
struct NodePage {
    chrome: Chrome,
    key: String,
    name: String,
    short: String,
    /// None: the node did not answer.
    state: Option<crate::cluster::confkey::State>,
    timeout_min: String,
    rec: Option<(u32, i64, String)>,
    key_held: bool,
    has: (bool, bool, bool),
    notice: Option<String>,
    error: Option<String>,
}

async fn node_view(st: &AdminState, key: &str, flash: Flash) -> AppResult<Html<String>> {
    let node = node(st)?;
    let Ok(id) = NodeId::parse(key) else {
        return Err(AppError::NotFound);
    };
    let Some(m) = members::all(&node.store)
        .await?
        .into_iter()
        .find(|m| m.id == id)
    else {
        return Err(AppError::NotFound);
    };
    let (state, error) = match crate::cluster::confkey::get(node, id).await {
        Ok(s) => (Some(s), flash.error),
        Err(e) => (None, Some(format!("{} did not answer: {e:#}", m.name))),
    };
    let minutes = |secs: u64| {
        if secs.is_multiple_of(60) {
            (secs / 60).to_string()
        } else {
            format!("{:.1}", secs as f64 / 60.0)
        }
    };
    let has = |s: &crate::cluster::confkey::State, r: &str| s.roles.iter().any(|x| x == r);
    render(&NodePage {
        chrome: Chrome::new(true, "admin"),
        key: id.to_string(),
        name: m.name,
        short: id.short(),
        timeout_min: state
            .as_ref()
            .map(|s| minutes(s.pace.timeout_secs))
            .unwrap_or_default(),
        rec: state
            .as_ref()
            .and_then(|s| s.recommended)
            .map(|p| (p.max_workers, p.max_scans_per_hour, minutes(p.timeout_secs))),
        has: state
            .as_ref()
            .map(|s| (has(s, "listener"), has(s, "scanner"), has(s, "web")))
            .unwrap_or_default(),
        key_held: crate::cluster::confkey::held(&node.store)
            .await?
            .contains(&id),
        state,
        notice: flash.notice,
        error,
    })
}

async fn node_page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> AppResult<Html<String>> {
    node_view(&st, &key, Flash::default()).await
}

async fn node_set(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Html<String>> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let flash = match (f.changes(), f.base_version) {
        (Err(e), _) => Flash {
            notice: None,
            error: Some(e),
        },
        (_, None) => Flash {
            notice: None,
            error: Some("reload the page and try again".into()),
        },
        (Ok(c), Some(base)) => match crate::cluster::confkey::set(node, id, base, &c).await {
            Ok(Ok(_)) => Flash {
                notice: Some("Saved. Roles switch within seconds.".into()),
                error: None,
            },
            Ok(Err(e)) => Flash {
                notice: None,
                error: Some(format!("Not saved: {e}")),
            },
            Err(e) => Flash {
                notice: None,
                error: Some(format!("Not saved: {e:#}")),
            },
        },
    };
    node_view(&st, &key, flash).await
}

#[derive(serde::Deserialize)]
struct PaceForm {
    key: String,
    max_workers: String,
    max_scans_per_hour: String,
    timeout_minutes: String,
}

async fn set_pace(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<PaceForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    // Other nodes are changed from their own page, which carries the
    // settings version it showed (a change made meanwhile is refused).
    if id != node.id() {
        return Ok(back(
            None,
            Some(format!(
                "Change {}'s pace from its page: /admin/cluster/node/{}",
                id.short(),
                f.key
            )),
        ));
    }
    let parsed = (
        f.max_workers.trim().parse::<u32>(),
        f.max_scans_per_hour.trim().parse::<i64>(),
        f.timeout_minutes.trim().parse::<f64>(),
    );
    let (Ok(w), Ok(h), Ok(t)) = parsed else {
        return Ok(back(None, Some("pace values must be numbers".into())));
    };
    if !t.is_finite() || t <= 0.0 {
        return Ok(back(None, Some("timeout must be positive".into())));
    }
    let timeout_secs = (t * 60.0).round() as u64;
    let outcome = st
        .settings
        .apply(
            &crate::settings::Changes {
                max_workers: Some(w),
                max_scans_per_hour: Some(h),
                timeout_secs: Some(timeout_secs),
                ..Default::default()
            },
            None,
        )
        .await?
        .map(|_| ());
    if outcome.is_ok() {
        node.status.local.lock().unwrap().pace = Some(PaceInfo {
            max_workers: w,
            max_scans_per_hour: h,
            timeout_secs,
        });
        node.publish_status();
    }
    Ok(match outcome {
        Ok(()) => back(Some(format!("Pace of {} saved.", id.short())), None),
        Err(e) => back(None, Some(format!("Pace not saved: {e}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_travel_in_a_cookie_not_the_url() {
        let cookie = |r: &Response| {
            r.headers()[axum::http::header::SET_COOKIE]
                .to_str()
                .unwrap()
                .to_string()
        };
        let r = back(Some("Saved.".into()), None);
        assert_eq!(r.headers()[axum::http::header::LOCATION], "/admin/cluster");
        assert!(cookie(&r).starts_with("peephole_flash=Saved."));
        let r = back(None, Some("Join failed".into()));
        assert_eq!(r.headers()[axum::http::header::LOCATION], "/admin/cluster");
        assert!(cookie(&r).starts_with("peephole_flash_error=Join+failed"));
    }
}
