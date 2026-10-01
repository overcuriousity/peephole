//! Admin → Cluster: members and their health, replication lag, scanner
//! pace, invites, joining and revocation, shared intel versions.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::identity::NodeId;
use crate::cluster::status::PaceInfo;
use crate::cluster::{Node, invite, members, repl};
use crate::scan::pace::Pace;
use askama::Template;
use axum::{
    Router,
    extract::{Form, Query, State},
    response::{Html, Redirect},
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
        .route("/admin/cluster/block", post(block))
        .route("/admin/cluster/unblock", post(unblock))
        .route("/admin/cluster/pace", post(set_pace))
}

/// One member as the page shows it.
pub struct MemberView {
    pub key: String,
    pub short: String,
    pub name: String,
    pub roles: String,
    pub address: String,
    pub active: bool,
    /// The member's standing in words (badge on inactive members).
    pub state: &'static str,
    /// This node blocked it (local decision).
    pub blocked: bool,
    pub is_self: bool,
    pub version: String,
    pub last_seen: String,
    pub live: bool,
    pub scanner: bool,
    pub pace: Option<PaceInfo>,
    pub timeout_min: String,
    pub active_scans: u32,
    pub lag: String,
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
    notice: Option<String>,
    error: Option<String>,
}

#[derive(serde::Deserialize, Default)]
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
    let heads = repl::heads(&node.store).await?;
    let statuses = node.peer_status.read().unwrap().clone();
    let me = node.id();
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
        let held = repl::head_in(&heads, &m.id);
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
            address: m
                .address
                .clone()
                .unwrap_or_else(|| "outbound-only".to_string()),
            active: m.active,
            state: m.standing.label(),
            blocked: node.is_blocked(&m.id),
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
    let mine = mine.unwrap_or_else(|| MemberView {
        key: me.to_string(),
        short: me.short(),
        name: node.cfg.node_name.clone(),
        roles: node.roles().names().join(", "),
        address: node.cfg.advertise.clone().unwrap_or_default(),
        active: true,
        state: "active",
        blocked: false,
        is_self: true,
        version: crate::VERSION.into(),
        last_seen: "this node".into(),
        live: true,
        scanner: node.roles().scanner,
        pace: None,
        timeout_min: String::new(),
        active_scans: 0,
        lag: "—".into(),
        error: None,
        incompatible: false,
        skew: None,
    });
    Ok((mine, out))
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
                size: match m.size {
                    s if s >= 1_000_000 => format!("{:.1} MB", s as f64 / 1e6),
                    s if s >= 1_000 => format!("{:.1} kB", s as f64 / 1e3),
                    s => format!("{s} B"),
                },
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

async fn render_page(
    st: &AdminState,
    invite: Option<String>,
    flash: Flash,
) -> AppResult<Html<String>> {
    let Some(node) = st.recorder.node() else {
        return render(&ClusterPage {
            chrome: Chrome::new(true, "admin"),
            me: None,
            members: vec![],
            intel: vec![],
            detached: None,
            invite: None,
            invites: vec![],
            notice: None,
            error: None,
        });
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
        notice: flash.notice,
        error: flash.error,
    })
}

async fn page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(flash): Query<Flash>,
) -> AppResult<Html<String>> {
    render_page(&st, None, flash).await
}

fn back(notice: Option<String>, error: Option<String>) -> Redirect {
    let qs = serde_urlencoded::to_string(
        [("notice", notice), ("error", error)]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default();
    Redirect::to(&format!("/admin/cluster?{qs}"))
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
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let node = node(&st)?;
    // Empty fields mean "no limit"; anything else must be a number.
    let number = |v: &Option<String>| match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<u64>().map(Some).map_err(|_| ()),
    };
    let (Ok(ttl), Ok(uses)) = (number(&f.ttl_hours), number(&f.max_uses)) else {
        return Ok(back(None, Some("expiry and use limit must be numbers".into())).into_response());
    };
    let opts = invite::InviteOpts {
        label: f.label.unwrap_or_default(),
        ttl_hours: ttl,
        max_uses: uses.map(|n| n.min(u32::MAX as u64) as u32),
    };
    match invite::create(node, &opts).await {
        Ok(token) => Ok(render_page(&st, Some(token), Flash::default())
            .await?
            .into_response()),
        Err(e) => Ok(back(None, Some(format!("{e:#}"))).into_response()),
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
) -> AppResult<Redirect> {
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
) -> AppResult<Redirect> {
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

async fn leave(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Redirect> {
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
}

async fn block(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
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
) -> AppResult<Redirect> {
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
) -> AppResult<Redirect> {
    let node = node(&st)?;
    let parsed = (
        f.max_workers.trim().parse::<usize>(),
        f.max_scans_per_hour.trim().parse::<i64>(),
        f.timeout_minutes.trim().parse::<f64>(),
    );
    let (Ok(w), Ok(h), Ok(t)) = parsed else {
        return Ok(back(None, Some("pace values must be numbers".into())));
    };
    if !t.is_finite() || t <= 0.0 {
        return Ok(back(None, Some("timeout must be positive".into())));
    }
    let p = Pace {
        max_workers: w,
        max_scans_per_hour: h,
        timeout_secs: (t * 60.0).round() as u64,
    };
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    let outcome = if id == node.id() {
        let r = st
            .settings
            .apply(
                &crate::settings::Changes {
                    max_workers: Some(w as u32),
                    max_scans_per_hour: Some(h),
                    timeout_secs: Some(p.timeout_secs),
                    ..Default::default()
                },
                None,
            )
            .await?
            .map(|_| ());
        if r.is_ok() {
            node.status.local.lock().unwrap().pace = Some(PaceInfo {
                max_workers: w as u32,
                max_scans_per_hour: h,
                timeout_secs: p.timeout_secs,
            });
            node.publish_status();
        }
        r
    } else {
        match crate::scan::pace::set_remote(node, id, p).await {
            Ok(r) => r,
            Err(e) => Err(format!("{e:#}")),
        }
    };
    Ok(match outcome {
        Ok(()) => back(Some(format!("Pace of {} saved.", id.short())), None),
        Err(e) => back(None, Some(format!("Pace not saved: {e}"))),
    })
}
