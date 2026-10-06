//! Admin → Cluster: members and their health, replication lag, scanner
//! pace, invites, joining and revocation, shared intel versions.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::pages::{redirect_with_error, redirect_with_notice};
use crate::admin::views::Chrome;
use crate::classify::stored::Agreement;
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
        .route("/admin/cluster/settings", post(set_own))
        .route("/admin/cluster/node/{key}", get(node_page).post(node_set))
        .route("/admin/cluster/node/{key}/owner", post(node_owner))
        .route("/admin/cluster/block", post(block))
        .route("/admin/cluster/unblock", post(unblock))
        .route("/admin/cluster/purge", post(purge))
        .route("/admin/cluster/pace", post(set_pace))
}

/// One member as the page shows it.
#[derive(Default, Clone)]
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
    /// One of this operator's nodes (same owner as this node).
    pub sibling: bool,
    /// A sibling this node can command: it keeps the ownership key.
    pub managed: bool,
    /// Its credits in this node's count ("5.00"); empty when not loaded.
    pub balance: String,
    /// Why its shares do not count in full here; empty: it earns.
    pub not_earning: Vec<String>,
    pub is_self: bool,
    pub version: String,
    pub last_seen: String,
    pub live: bool,
    pub scanner: bool,
    pub pace: Option<PaceInfo>,
    pub timeout_min: String,
    /// Scan levels it is weighted down at, against the other scanners
    /// (see `scan::weight`); "" when none.
    pub level_weights: String,
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
    /// How its recent requests compare with our rules ("rules agree
    /// 100%"); empty when not compared.
    pub rules: String,
    /// Some of them came out differently here.
    pub rules_differ: bool,
    /// The rules fingerprint its newest requests carry, short
    /// ("3f9a0c1d2e4b", "3f9a0c1d2e4b +1 other"), or "none recorded".
    pub ruleset: String,
    /// Whether that newest fingerprint is ours; None without one.
    pub ruleset_same: Option<bool>,
    /// Scans an hour it can do and did ("20.0"), and which setting binds it.
    pub can_do: String,
    pub did: String,
    pub limited_by: &'static str,
}

impl MemberView {
    /// What needs a look, in words; empty when nothing does. The Members
    /// table's badge and Overview's strip both read this.
    pub fn issues(&self) -> Vec<String> {
        let mut v = vec![];
        if self.incompatible {
            v.push("incompatible version".to_string());
        }
        if let Some(s) = &self.skew {
            v.push(format!("clock {s}"));
        }
        if !self.not_earning.is_empty() {
            v.push(format!("not earning here: {}", self.not_earning.join("; ")));
        }
        if let Some(e) = self.error.as_ref().filter(|_| !self.incompatible) {
            v.push(e.clone());
        }
        v
    }
}

use crate::credits::gates::RulesCheck;
pub(crate) use crate::credits::gates::SHORT_HASH;

/// The comparison of members' requests with this node's rules, made at
/// most every ten minutes (see [`crate::credits::gates::rules_check`]).
pub(crate) async fn rules_check(_st: &AdminState, node: &Node) -> AppResult<Arc<RulesCheck>> {
    Ok(crate::credits::gates::rules_check(node).await?)
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
    /// This node first, then the other members.
    rows: Vec<MemberView>,
    standalone: bool,
    /// Why this node is out of its cluster, if it is.
    detached: Option<&'static str>,
    /// Members whose older history no reachable peer can give this node.
    unserved: Option<String>,
    /// Requests and scans each member contributed, by member key, as
    /// "count · share"; the full breakdown is on the node page.
    shares: std::collections::HashMap<String, (String, String)>,
    /// The same for rows created before this node joined, if any.
    unshared: Option<(String, String)>,
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
    pub(crate) fn of(st: &AdminState) -> Self {
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

/// Settings changes, newest first, with the changing node's name.
pub(crate) async fn audit_views(st: &AdminState) -> AppResult<Vec<AuditView>> {
    let names: std::collections::HashMap<NodeId, String> = match st.recorder.node() {
        Some(node) => members::all(&node.store)
            .await?
            .into_iter()
            .map(|m| (m.id, m.name))
            .collect(),
        None => Default::default(),
    };
    Ok(st
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
        .collect())
}

fn ago(d: std::time::Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=89 => format!("{s} s ago"),
        90..=5399 => format!("{} min ago", s / 60),
        _ => format!("{:.1} h ago", s as f64 / 3600.0),
    }
}

pub(crate) fn node(st: &AdminState) -> AppResult<&Arc<Node>> {
    st.recorder.node().ok_or(AppError::NotFound)
}

pub(crate) async fn views(
    node: &Node,
    check: &RulesCheck,
    book: Option<&crate::credits::Book>,
) -> AppResult<(MemberView, Vec<MemberView>)> {
    let rows = members::all(&node.store).await?;
    let heads = repl::head_map(&repl::heads(&node.store).await?);
    let purged = crate::cluster::block::purged(&node.store).await?;
    let statuses = node.peer_status.read().unwrap().clone();
    let me = node.id();
    let sibs = crate::cluster::owner::fleet::siblings(&node.store).await?;
    let managing = crate::cluster::owner::load(&node.store, me)
        .await?
        .is_some_and(|o| o.managing());
    let ours = builtin_rules();
    let ruleset_of = |id: &NodeId| {
        check
            .carried
            .get(id)
            .cloned()
            .unwrap_or_default()
            .view(ours)
    };
    let tallies = crate::scan::weight::tallies(&node.store.pool).await?;
    // The arbiter's view: the scanners that could take a job now.
    let scanners = crate::scan::arbiter::scanners(node);
    let level_weights = |id: NodeId| {
        (1..=4)
            .filter_map(|l| {
                let w = crate::scan::weight::weight(&tallies, id, &scanners, l);
                let t = tallies.get(&(id, l)).copied().unwrap_or_default();
                (w < 1.0).then(|| format!("L{l} ×{w:.2} ({} ok, {} failed)", t.ok, t.failed))
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };
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
        let agreement = check.by_member.get(&m.id);
        let (ruleset, ruleset_same) = ruleset_of(&m.id);
        let v = MemberView {
            ruleset,
            ruleset_same,
            rules: agreement.map(Agreement::summary).unwrap_or_default(),
            rules_differ: agreement.is_some_and(|a| a.differing > 0),
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
            sibling: sibs.contains(&m.id),
            managed: managing && sibs.contains(&m.id),
            balance: book
                .map(|b| crate::credits::show(b.balance(&m.id)))
                .unwrap_or_default(),
            not_earning: book
                .map(|b| b.standing(&m.id).reasons())
                .unwrap_or_default(),
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
            level_weights: level_weights(m.id),
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
            can_do: String::new(),
            did: String::new(),
            limited_by: "",
        };
        if is_self {
            mine = Some(v);
        } else {
            out.push(v);
        }
    }
    let own = own_history(node).await?;
    let (ruleset, ruleset_same) = ruleset_of(&me);
    let mine = mine.unwrap_or_else(|| MemberView {
        ruleset,
        ruleset_same,
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
        sibling: false,
        managed: false,
        balance: book
            .map(|b| crate::credits::show(b.balance(&me)))
            .unwrap_or_default(),
        not_earning: book.map(|b| b.standing(&me).reasons()).unwrap_or_default(),
        is_self: true,
        version: crate::VERSION.into(),
        last_seen: "this node".into(),
        live: true,
        scanner: node.roles().scanner,
        pace: None,
        timeout_min: String::new(),
        level_weights: String::new(),
        active_scans: 0,
        lag: "—".into(),
        history: own,
        error: None,
        incompatible: false,
        skew: None,
        rules: String::new(),
        rules_differ: false,
        can_do: String::new(),
        did: String::new(),
        limited_by: "",
    });
    Ok((mine, out))
}

/// This node (when it scans) and the active scanner members, for the
/// Scans page's pace table. Empty on a standalone node.
pub(crate) async fn scanner_rows(st: &AdminState) -> AppResult<Vec<MemberView>> {
    let Some(node) = st.recorder.node() else {
        return Ok(vec![]);
    };
    // The pace table reads no rules fields: skip the (possibly cold)
    // comparison so the Scans page never waits on it.
    let none = RulesCheck {
        by_member: Default::default(),
        carried: Default::default(),
    };
    let (me, members) = views(node, &none, None).await?;
    let rows: Vec<MemberView> = std::iter::once(me)
        .filter(|m| m.scanner)
        .chain(members.into_iter().filter(|m| m.scanner && m.active))
        .collect();
    let left_out = std::collections::HashSet::new();
    let cap =
        crate::credits::price::capacity(&crate::credits::price::scanners(node, &left_out).await?);
    let mut rows = rows;
    for m in rows.iter_mut() {
        if let Some(c) = cap.scanners.iter().find(|c| c.node.to_string() == m.key) {
            m.can_do = format!("{:.1}", c.can_do);
            m.did = format!("{:.1}", c.did);
            m.limited_by = match c.limited_by {
                crate::credits::price::Limit::Workers => "workers",
                crate::credits::price::Limit::PerHour => "scans per hour",
            };
        }
    }
    Ok(rows)
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
pub(crate) async fn unserved(node: &Node) -> AppResult<Option<String>> {
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

pub(crate) async fn intel(node: &Node) -> AppResult<Vec<IntelView>> {
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
    /// The member's key; empty for rows not shared yet.
    pub key: String,
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
    let row = |key: &[u8], name: String, short: String, id: String| {
        let get = |m: &Counts| m.get(key).copied().unwrap_or(0);
        let (log_entries, bytes) = usage.get(key).copied().unwrap_or((0, 0));
        ContribView {
            key: id,
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
            row(&m.id.0[..], name, m.id.short(), m.id.to_string())
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.requests));
    let unshared = row(&[], "not shared yet".into(), String::new(), String::new());
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

pub(crate) async fn invites(node: &Node) -> AppResult<Vec<InviteView>> {
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

async fn render_page(st: &AdminState) -> AppResult<Html<String>> {
    let Some(node) = st.recorder.node() else {
        return render(&ClusterPage {
            chrome: Chrome::new(true, "admin"),
            rows: vec![],
            standalone: true,
            detached: None,
            unserved: None,
            shares: Default::default(),
            unshared: None,
        });
    };
    let check = rules_check(st, node).await?;
    let book = crate::credits::book(node).await?;
    let (me, members) = views(node, &check, Some(&book)).await?;
    let contrib = contributions(node).await?;
    let (shares, unshared) = share_cells(&contrib);
    render(&ClusterPage {
        chrome: Chrome::new(true, "admin"),
        rows: std::iter::once(me).chain(members).collect(),
        standalone: false,
        detached: node.detached().map(|d| d.label()),
        unserved: unserved(node).await?,
        shares,
        unshared,
    })
}

/// Requests and scans per member as "count · share of all", keyed by
/// member key, and the not-yet-shared row apart.
type Cells = (String, String);
fn share_cells(
    contrib: &[ContribView],
) -> (std::collections::HashMap<String, Cells>, Option<Cells>) {
    let (req, scans) = contrib
        .iter()
        .fold((0, 0), |(r, s), c| (r + c.requests, s + c.scans));
    let cell = |n: i64, of: i64| match of {
        0 => "0".to_string(),
        _ => format!(
            "{} · {} %",
            super::views::thousands(n),
            (n * 100 + of / 2) / of
        ),
    };
    let mut map = std::collections::HashMap::new();
    let mut unshared = None;
    for c in contrib {
        let v = (cell(c.requests, req), cell(c.scans, scans));
        if c.key.is_empty() {
            unshared = Some(v);
        } else {
            map.insert(c.key.clone(), v);
        }
    }
    (map, unshared)
}

/// The fingerprint of the rules built into this binary.
pub(crate) fn builtin_rules() -> &'static str {
    crate::classify::Classifier::builtin().fingerprint()
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&st).await
}

/// Back to `to` with a one-shot notice or error (in a cookie, see
/// [`redirect_with_notice`]).
pub(crate) fn back_to(to: &str, notice: Option<String>, error: Option<String>) -> Response {
    match (error, notice) {
        (Some(e), _) => redirect_with_error(to, &e),
        (None, Some(n)) => redirect_with_notice(to, &n),
        (None, None) => Redirect::to(to).into_response(),
    }
}

/// Back to the Members page.
fn back(notice: Option<String>, error: Option<String>) -> Response {
    back_to("/admin/cluster", notice, error)
}

#[derive(serde::Deserialize)]
pub(crate) struct KeyForm {
    pub(crate) key: String,
    /// Block: also every node it admitted, transitively.
    pub(crate) subtree: Option<String>,
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
    let to = format!("/admin/cluster/node/{id}");
    if f.subtree.is_some() {
        return Ok(match crate::cluster::block::block_subtree(node, id).await {
            Ok((ids, n)) => back_to(
                &to,
                Some(format!(
                    "Blocked {} and the {} node(s) it admitted, directly or not ({n} records taken out of view). Other nodes are unaffected.",
                    id.short(),
                    ids.len() - 1
                )),
                None,
            ),
            Err(e) => back_to(&to, None, Some(format!("{e:#}"))),
        });
    }
    Ok(match crate::cluster::block::block(node, id).await {
        Ok(n) => back_to(
            &to,
            Some(format!(
                "Blocked {}. This node no longer talks to it and shows none of its records ({n} taken out of view). Other nodes are unaffected.",
                id.short()
            )),
            None,
        ),
        Err(e) => back_to(&to, None, Some(format!("{e:#}"))),
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
    let to = format!("/admin/cluster/node/{id}");
    Ok(if crate::cluster::block::unblock(node, id).await? {
        back_to(
            &to,
            Some(format!("Unblocked {}. Its records are back.", id.short())),
            None,
        )
    } else {
        back_to(&to, None, Some("That node was not blocked.".into()))
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
    let to = format!("/admin/cluster/node/{id}");
    Ok(match crate::cluster::block::purge(node, id).await {
        Ok(n) => back_to(
            &to,
            Some(format!(
                "Purged {}: {n} log entries deleted here. Its entries are no longer accepted or relayed; unblocking fetches them again.",
                id.short()
            )),
            None,
        ),
        Err(e) => back_to(&to, None, Some(format!("{e:#}"))),
    })
}

/// The settings form. A checkbox that is not ticked is not sent, so the
/// role fields always describe the wanted state in full.
#[derive(serde::Deserialize)]
struct SettingsForm {
    counter: Option<u64>,
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
            // Not on this form: the Ownership page and the CLI set it.
            collect_to: None,
        })
    }
}

/// Where this node's own settings form lives.
const SETTINGS: &str = "/admin/system/settings";

async fn set_own(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Response> {
    let changes = match f.changes() {
        Ok(c) => c,
        Err(e) => return Ok(back_to(SETTINGS, None, Some(e))),
    };
    // The form sends every role, so it must not overwrite a change made
    // elsewhere (CLI, the owner) after the page was loaded.
    let Some(base) = f.base_version else {
        return Ok(back_to(
            SETTINGS,
            None,
            Some("Settings not saved: reload the page and try again".into()),
        ));
    };
    Ok(match st.settings.apply_at(base, &changes, None).await? {
        Ok(_) => back_to(
            SETTINGS,
            Some("Settings saved. Roles switch within seconds.".into()),
            None,
        ),
        Err(e) => back_to(SETTINGS, None, Some(format!("Settings not saved: {e}"))),
    })
}

/// The live part of a node page: its settings, for a node of this operator.
enum Remote {
    /// This node: settings live on System.
    Own,
    /// A member that is not one of this operator's nodes.
    NotYours,
    /// A sibling, but the ownership key is not kept on this node.
    NoKey,
    /// Asked, and it answered.
    Settings {
        status: Box<crate::cluster::owner::cmd::Status>,
        timeout_min: String,
        rec: Option<(u32, i64, String)>,
        has: (bool, bool, bool),
        /// `(key, name)` of the peers it blocks.
        blocked: Vec<(String, String)>,
        /// `(key, name)` of the members it could be told to block.
        peers: Vec<(String, String)>,
    },
    /// Asked; no answer.
    Silent(String),
    /// A managed sibling that is offline or blocked here: not asked.
    Offline,
}

/// A member's credits as this node counts them.
pub struct CreditsBlock {
    pub balance: String,
    pub earns: bool,
    /// Every reason it does not earn in full here.
    pub reasons: Vec<String>,
    /// Audits of its scans over 7 days as `(agrees, differs,
    /// inconclusive)`: by this node and its fleet (they count), and by
    /// other members (shown only).
    pub counted: (u32, u32, u32),
    pub others: (u32, u32, u32),
    /// Where it showed two histories, and the proof if one is known.
    pub fork: Option<String>,
}

async fn credits_block(node: &Node, id: NodeId) -> AppResult<CreditsBlock> {
    use crate::credits::audit::Outcome;
    let book = crate::credits::book(node).await?;
    let standing = book.standing(&id);
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let week = crate::cluster::hlc::wall_ms().saturating_sub(7 * crate::credits::DAY_MS) << 16;
    let (mut counted, mut others) = ((0, 0, 0), (0, 0, 0));
    for c in crate::credits::audit::counts(&node.store.pool, week).await? {
        if c.scanner != id {
            continue;
        }
        let t = if auditors.contains(&c.auditor) {
            &mut counted
        } else {
            &mut others
        };
        match c.outcome {
            Outcome::Agrees => t.0 += c.n,
            Outcome::Differs => t.1 += c.n,
            Outcome::Inconclusive => t.2 += c.n,
        }
    }
    let members = node.members();
    let fork = crate::cluster::seal::forked(&node.store.pool)
        .await?
        .into_iter()
        .find(|f| f.origin == id)
        .map(|f| match f.proof {
            Some((by, seq)) => format!(
                "two entries at position {} of its log; proof published by {} (entry {seq} of its log)",
                f.seq,
                members.get(&by).map_or_else(|| by.short(), |m| m.name.clone())
            ),
            None => format!(
                "its seal at entry {} does not match its log as held here; no proof yet",
                f.seq
            ),
        });
    Ok(CreditsBlock {
        balance: crate::credits::show(book.balance(&id)),
        earns: standing.earns_as_scanner(),
        reasons: standing.reasons(),
        counted,
        others,
        fork,
    })
}

#[derive(Template)]
#[template(path = "admin_cluster_node.html")]
struct NodePage {
    chrome: Chrome,
    m: MemberView,
    contrib: Vec<ContribView>,
    remote: Remote,
    credits: CreditsBlock,
}

/// Whether a node page asks the member for its status: only a live,
/// unblocked sibling this node can command (an offline one would hold the
/// page for the whole request timeout).
fn asks_remote(m: &MemberView) -> bool {
    !m.is_self && m.managed && m.live && !m.blocked
}

async fn node_view(st: &AdminState, key: &str) -> AppResult<Html<String>> {
    let node = node(st)?;
    let Ok(id) = NodeId::parse(key) else {
        return Err(AppError::NotFound);
    };
    let check = rules_check(st, node).await?;
    let book = crate::credits::book(node).await?;
    let (me, members) = views(node, &check, Some(&book)).await?;
    let all: Vec<MemberView> = std::iter::once(me).chain(members).collect();
    let key = id.to_string();
    let Some(m) = all.iter().find(|m| m.key == key).cloned() else {
        return Err(AppError::NotFound);
    };
    let contrib = contributions(node)
        .await?
        .into_iter()
        .filter(|c| c.key == m.key || (m.is_self && c.key.is_empty()))
        .collect();
    let remote = if m.is_self {
        Remote::Own
    } else if !m.sibling {
        Remote::NotYours
    } else if !m.managed {
        Remote::NoKey
    } else if !asks_remote(&m) {
        Remote::Offline
    } else {
        use crate::cluster::owner::cmd;
        let asked = async {
            let key = cmd::kept_key(node).await?;
            cmd::status(node, &key, id).await
        };
        match asked.await {
            Ok(st) => {
                let minutes = |secs: u64| {
                    if secs.is_multiple_of(60) {
                        (secs / 60).to_string()
                    } else {
                        format!("{:.1}", secs as f64 / 60.0)
                    }
                };
                let has = |r: &str| st.state.roles.iter().any(|x| x == r);
                let name_of = |k: &str| {
                    all.iter()
                        .find(|x| x.key == k)
                        .map(|x| x.name.clone())
                        .unwrap_or_else(|| k.chars().take(20).collect())
                };
                let blocked: Vec<(String, String)> = st
                    .blocked
                    .iter()
                    .map(|b| (b.to_string(), name_of(&b.to_string())))
                    .collect();
                Remote::Settings {
                    timeout_min: minutes(st.state.pace.timeout_secs),
                    rec: st
                        .state
                        .recommended
                        .map(|p| (p.max_workers, p.max_scans_per_hour, minutes(p.timeout_secs))),
                    has: (has("listener"), has("scanner"), has("web")),
                    peers: all
                        .iter()
                        .filter(|x| !x.is_self && x.key != m.key)
                        .filter(|x| !blocked.iter().any(|(k, _)| *k == x.key))
                        .map(|x| (x.key.clone(), x.name.clone()))
                        .collect(),
                    blocked,
                    status: Box::new(st),
                }
            }
            Err(e) => Remote::Silent(format!("{} did not answer: {e:#}", m.name)),
        }
    };
    render(&NodePage {
        chrome: Chrome::new(true, "admin"),
        credits: credits_block(node, id).await?,
        m,
        contrib,
        remote,
    })
}

async fn node_page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
) -> AppResult<Html<String>> {
    node_view(&st, &key).await
}

/// Why an owner command did nothing, or may not have.
#[derive(Debug, PartialEq)]
enum Unsent {
    /// Nothing was sent, or the node said no.
    Refused(String),
    /// Sent, but no answer came back in time.
    NoAnswer(String),
}

impl Unsent {
    /// The message for the page; `what`: "Not saved", "Not done".
    fn text(&self, what: &str) -> String {
        match self {
            Unsent::Refused(e) => format!("{what}: {e}"),
            Unsent::NoAnswer(e) => format!(
                "{e}. The command may still be carried out there (a block of a busy peer \
                 takes a while): reload this page to see."
            ),
        }
    }
}

/// Send `cmd` to sibling `id` with the key this node keeps. Ok: what the
/// node did.
async fn owner_run(
    node: &Arc<crate::cluster::Node>,
    id: NodeId,
    counter: u64,
    cmd: crate::cluster::owner::cmd::OwnerCmd,
) -> Result<String, Unsent> {
    use crate::cluster::owner::{cmd as oc, fleet};
    let refused = |e: anyhow::Error| Unsent::Refused(format!("{e:#}"));
    // Only to the operator's other nodes: the path names any member, and
    // this node would carry out a command it sent to itself.
    let sibs = fleet::siblings(&node.store).await.map_err(refused)?;
    if id == node.id() || !sibs.contains(&id) {
        return Err(Unsent::Refused(
            "that is not one of your other nodes".into(),
        ));
    }
    let key = oc::kept_key(node).await.map_err(refused)?;
    match oc::run(node, &key, id, counter, cmd).await {
        Ok(Ok(note)) => Ok(note),
        Ok(Err(e)) => Err(Unsent::Refused(e)),
        Err(e) => Err(Unsent::NoAnswer(format!("{e:#}"))),
    }
}

async fn node_set(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let to = format!("/admin/cluster/node/{id}");
    // Post/redirect/get: a reload of the page does not send the form again.
    Ok(match (f.changes(), f.base_version, f.counter) {
        (Err(e), _, _) => back_to(&to, None, Some(e)),
        (Ok(c), Some(base), Some(counter)) => {
            let cmd = crate::cluster::owner::cmd::OwnerCmd::Settings {
                base_version: base,
                changes: c,
            };
            match owner_run(node, id, counter, cmd).await {
                Ok(_) => back_to(
                    &to,
                    Some("Saved. Roles switch within seconds.".into()),
                    None,
                ),
                Err(e) => back_to(&to, None, Some(e.text("Not saved"))),
            }
        }
        _ => back_to(&to, None, Some("reload the page and try again".into())),
    })
}

/// An owner action on a sibling, from its page.
#[derive(serde::Deserialize)]
struct OwnerForm {
    counter: u64,
    action: String,
    /// The peer a block, unblock or purge is about.
    target: Option<String>,
    subtree: Option<String>,
    /// The invite to revoke.
    invite: Option<i64>,
    /// Credits to send, as typed ("0.5").
    amount: Option<String>,
}

async fn node_owner(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<OwnerForm>,
) -> AppResult<Response> {
    use crate::cluster::owner::cmd::OwnerCmd;
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let to = format!("/admin/cluster/node/{id}");
    let peer = f.target.as_deref().and_then(|t| NodeId::parse(t).ok());
    let cmd = match (f.action.as_str(), peer, f.invite) {
        ("block", Some(n), _) => OwnerCmd::Block {
            node: n,
            subtree: f.subtree.is_some(),
        },
        ("unblock", Some(n), _) => OwnerCmd::Unblock { node: n },
        ("purge", Some(n), _) => OwnerCmd::Purge { node: n },
        ("invite-revoke", _, Some(i)) => OwnerCmd::InviteRevoke { id: i },
        ("leave", _, _) => OwnerCmd::Leave,
        ("release", _, _) => OwnerCmd::Release,
        ("send-credits", Some(n), _) => {
            match f.amount.as_deref().and_then(crate::credits::parse_amount) {
                Some(mc) => OwnerCmd::SendCredits { to: n, mc },
                None => {
                    return Ok(back_to(
                        &to,
                        None,
                        Some("an amount like 0.5 is needed".into()),
                    ));
                }
            }
        }
        _ => return Ok(back_to(&to, None, Some("unknown action".into()))),
    };
    Ok(match owner_run(node, id, f.counter, cmd).await {
        Ok(note) => back_to(&to, Some(format!("Done: {note}.")), None),
        Err(e) => back_to(&to, None, Some(e.text("Not done"))),
    })
}

#[derive(serde::Deserialize)]
struct PaceForm {
    key: String,
    max_workers: String,
    max_scans_per_hour: String,
    timeout_minutes: String,
}

/// Where the scanner pace table lives.
const SCANNERS: &str = "/admin/scans#scanners";

async fn set_pace(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<PaceForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back_to(SCANNERS, None, Some("unknown node".into())));
    };
    // Other nodes are changed from their own page, which carries the
    // settings version it showed (a change made meanwhile is refused).
    if id != node.id() {
        return Ok(back_to(
            SCANNERS,
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
        return Ok(back_to(
            SCANNERS,
            None,
            Some("pace values must be numbers".into()),
        ));
    };
    if !t.is_finite() || t <= 0.0 {
        return Ok(back_to(
            SCANNERS,
            None,
            Some("timeout must be positive".into()),
        ));
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
        Ok(()) => back_to(
            SCANNERS,
            Some(format!("Pace of {} saved.", id.short())),
            None,
        ),
        Err(e) => back_to(SCANNERS, None, Some(format!("Pace not saved: {e}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::gates::{Carried, carried};

    /// The fingerprint a member's newest requests carry, read from the
    /// rows: claims and rows without one left out, others counted.
    #[tokio::test]
    async fn carried_rules_come_from_the_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let rec = store.local();
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        let ours = builtin_rules().to_string();
        let old = "ab".repeat(32);
        for (rules, claim) in [
            (Some(old.clone()), false),
            (Some(ours.clone()), false),
            (None, false),
            (Some(old.clone()), true),
        ] {
            rec.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                is_fp_claim: claim,
                rules,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let k = carried(&store.pool, None, 500).await.unwrap();
        assert_eq!(
            k,
            Carried {
                newest: Some(ours.clone()),
                others: 1
            }
        );
        assert_eq!(
            k.view(&ours),
            (format!("{} +1 other", &ours[..12]), Some(true))
        );
        assert_eq!(k.view(&old).1, Some(false));
        let none = carried(&store.pool, Some(&[1u8; 32][..]), 500)
            .await
            .unwrap();
        assert_eq!(none.view(&ours), ("none recorded".to_string(), None));
    }

    #[test]
    fn a_missing_answer_is_not_reported_as_a_refusal() {
        let said_no = Unsent::Refused("no usable invite 4".into());
        assert_eq!(said_no.text("Not done"), "Not done: no usable invite 4");
        let silent = Unsent::NoAnswer("no answer from 3f9a within 15s".into()).text("Not done");
        assert!(!silent.starts_with("Not done"), "{silent}");
        assert!(silent.contains("may still be carried out"), "{silent}");
    }

    #[test]
    fn only_a_live_managed_sibling_is_asked() {
        let held = MemberView {
            sibling: true,
            managed: true,
            live: true,
            active: true,
            ..Default::default()
        };
        assert!(asks_remote(&held));
        for m in [
            MemberView {
                live: false,
                ..held.clone()
            },
            MemberView {
                blocked: true,
                ..held.clone()
            },
            MemberView {
                managed: false,
                ..held.clone()
            },
            MemberView {
                is_self: true,
                ..held.clone()
            },
        ] {
            assert!(!asks_remote(&m));
        }
    }

    /// A member is flagged for its rules only when it does not earn here;
    /// another fingerprint or a few differing requests are information.
    #[test]
    fn issues_name_what_stops_a_member_from_earning() {
        let other_build = MemberView {
            ruleset_same: Some(false),
            rules_differ: true,
            rules: "disagree on <1% of 500".into(),
            ..Default::default()
        };
        assert!(
            other_build.issues().is_empty(),
            "{:?}",
            other_build.issues()
        );
        let gated = MemberView {
            not_earning: vec![
                "rules: disagree on 12% of 500".into(),
                "showed two histories (at entry 7 of its log)".into(),
            ],
            ..Default::default()
        };
        assert_eq!(
            gated.issues(),
            [
                "not earning here: rules: disagree on 12% of 500; showed two histories (at entry 7 of its log)"
            ]
        );
    }

    #[test]
    fn issues_list_what_needs_a_look() {
        let ok = MemberView {
            ruleset_same: Some(true),
            ..Default::default()
        };
        assert!(ok.issues().is_empty());
        let bad = MemberView {
            incompatible: true,
            error: Some("incompatible protocol 3".into()),
            skew: Some("+3.5 min".into()),
            ..Default::default()
        };
        assert_eq!(bad.issues(), ["incompatible version", "clock +3.5 min"]);
        let err = MemberView {
            error: Some("connection refused".into()),
            ..Default::default()
        };
        assert_eq!(err.issues(), ["connection refused"]);
    }

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
        let r = back_to(
            "/admin/cluster/access",
            Some("Invite revoked.".into()),
            None,
        );
        assert_eq!(
            r.headers()[axum::http::header::LOCATION],
            "/admin/cluster/access"
        );
    }
}
