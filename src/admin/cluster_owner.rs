//! Cluster › Ownership: this node's owner, the nodes that share it, and
//! the owner commands this node received.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::cluster::{MemberView, back_to, node, rules_check, views};
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::owner::{self, OwnerKey, cmd, fleet};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

const PAGE: &str = "/admin/cluster/ownership";

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route(PAGE, get(page))
        .route("/admin/cluster/ownership/create", post(create))
        .route("/admin/cluster/ownership/adopt", post(adopt))
        .route("/admin/cluster/ownership/forget-key", post(forget_key))
        .route("/admin/cluster/ownership/release", post(release))
        .route("/admin/cluster/ownership/show-key", post(show_key))
        .route("/admin/cluster/ownership/rotate", post(rotate))
        .route("/admin/cluster/ownership/retry", post(retry))
        .route("/admin/cluster/ownership/discard", post(discard))
}

/// One of the operator's nodes.
struct NodeRow {
    key: String,
    name: String,
    short: String,
    roles: String,
    version: String,
    /// Its balance in this node's book.
    credits: String,
    seen: String,
    is_self: bool,
}

/// One received command.
struct LogView {
    at: String,
    from: String,
    command: String,
    result: String,
}

#[derive(Template)]
#[template(path = "admin_cluster_ownership.html")]
struct OwnershipPage {
    chrome: Chrome,
    /// The owner id, short; None: no owner.
    owner: Option<String>,
    /// This node keeps the key.
    managing: bool,
    /// The key itself: after creating or rotating it, or when asked for.
    shown_key: Option<String>,
    nodes: Vec<NodeRow>,
    /// Members not claimed with this node's key (when it has one).
    others: Vec<NodeRow>,
    /// Nodes still on the previous key after a rotation: name, and why
    /// each was not moved when last tried.
    pending: Vec<(String, String)>,
    /// A rotation was started here and cut short before this node switched.
    unfinished: bool,
    log: Vec<LogView>,
    /// Attempts that were not signed with the owner's key.
    refused: Vec<LogView>,
}

async fn render_page(st: &AdminState, shown_key: Option<String>) -> AppResult<Html<String>> {
    let node = node(st)?;
    let owned = owner::load(&node.store, node.id()).await?;
    let check = rules_check(st, node).await?;
    let book = crate::credits::book(node).await?;
    let (me, members) = views(node, &check, Some(&book)).await?;
    let sibs: Vec<String> = fleet::siblings(&node.store)
        .await?
        .iter()
        .map(|id| id.to_string())
        .collect();
    let names: HashMap<String, String> = members
        .iter()
        .map(|m| (m.key.clone(), m.name.clone()))
        .collect();
    let managing = owned.as_ref().is_some_and(|o| o.managing());
    let row = |m: &MemberView| NodeRow {
        credits: NodeId::parse(&m.key)
            .map(|id| crate::credits::show(book.balance(&id)))
            .unwrap_or_default(),
        key: m.key.clone(),
        name: m.name.clone(),
        short: m.short.clone(),
        roles: m.roles.clone(),
        version: m.version.clone(),
        seen: m.last_seen.clone(),
        is_self: m.is_self,
    };
    let (mut nodes, mut others) = (vec![], vec![]);
    if owned.is_some() {
        nodes.push(row(&me));
        // Candidates to claim: active, not blocked, and on a version that
        // knows ownership.
        let rows = node.members();
        let claimable = |m: &MemberView| {
            m.active
                && !m.blocked
                && NodeId::parse(&m.key).is_ok_and(|id| {
                    rows.get(&id)
                        .is_some_and(|r| r.proto_max >= crate::cluster::rpc::proto::OWNER_PROTO)
                })
        };
        for m in &members {
            if sibs.contains(&m.key) {
                nodes.push(row(m));
            } else if claimable(m) {
                others.push(row(m));
            }
        }
    }
    // A name is the member's own choice: the key's fingerprint goes with it.
    let who = |id: &NodeId| match names.get(&id.to_string()) {
        Some(name) => format!("{name} ({})", id.short()),
        None => id.short(),
    };
    let pending = cmd::pending_reasons(&node.store)
        .await?
        .iter()
        .map(|(id, why)| (who(id), why.clone()))
        .collect();
    let view = |r: cmd::LogRow| LogView {
        from: who(&r.from),
        at: r.at,
        command: r.command,
        result: r.result,
    };
    let log = cmd::log_rows(&node.store, 50)
        .await?
        .into_iter()
        .map(view)
        .collect();
    let refused = cmd::refused_rows(&node.store, 20)
        .await?
        .into_iter()
        .map(view)
        .collect();
    render(&OwnershipPage {
        chrome: Chrome::new(true, "admin"),
        owner: owned.as_ref().map(|o| o.id.short()),
        managing,
        shown_key,
        nodes,
        others,
        pending,
        unfinished: owner::rotation_unfinished(&node.store).await?,
        log,
        refused,
    })
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&st, None).await
}

/// Look for siblings now instead of at the loop's next tick.
fn discover_soon(node: &Arc<Node>) {
    let node = node.clone();
    tokio::spawn(async move {
        if let Err(e) = fleet::discover(&node).await {
            tracing::debug!(?e, "sibling discovery failed");
        }
    });
}

/// Generate a key, make this node owned and managing, show the key once.
async fn create(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    if owner::load(&node.store, node.id()).await?.is_some() {
        return Ok(back_to(
            PAGE,
            None,
            Some("This node is already claimed. Release it first.".into()),
        ));
    }
    let key = owner::create(&node.store, node.id()).await?;
    Ok(render_page(&st, Some(key.encode())).await?.into_response())
}

#[derive(serde::Deserialize)]
struct AdoptForm {
    key: String,
    /// "yes": this node keeps the key and manages the others.
    keep: Option<String>,
}

async fn adopt(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<AdoptForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let key = match OwnerKey::parse(&f.key) {
        Ok(k) => k,
        Err(e) => return Ok(back_to(PAGE, None, Some(format!("{e:#}")))),
    };
    owner::adopt(
        &node.store,
        node.id(),
        &key,
        f.keep.as_deref() == Some("yes"),
    )
    .await?;
    discover_soon(node);
    Ok(back_to(
        PAGE,
        Some(format!(
            "This node is now claimed with owner key {}. Your other nodes find it within a few minutes.",
            key.id.short()
        )),
        None,
    ))
}

async fn forget_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    // The key kept here is the only way to the nodes a rotation has not
    // moved yet (or has moved already, when it was cut short).
    if owner::rotation_unfinished(&node.store).await?
        || !cmd::pending(&node.store).await?.is_empty()
    {
        return Ok(back_to(
            PAGE,
            None,
            Some(
                "A key rotation is not finished: finish it, or retry or give up on the nodes \
                 still on the previous key, before the key is forgotten here."
                    .into(),
            ),
        ));
    }
    Ok(if owner::forget_key(&node.store).await? {
        back_to(
            PAGE,
            Some("The key is no longer kept on this node. It stays owned.".into()),
            None,
        )
    } else {
        back_to(PAGE, None, Some("No key was kept on this node.".into()))
    })
}

async fn release(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(if owner::release(&node.store).await? {
        back_to(PAGE, Some("This node has no owner now.".into()), None)
    } else {
        back_to(PAGE, None, Some("This node had no owner.".into()))
    })
}

async fn show_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match cmd::kept_key(node).await {
        Ok(k) => render_page(&st, Some(k.encode())).await?.into_response(),
        Err(e) => back_to(PAGE, None, Some(format!("{e:#}"))),
    })
}

/// Replace the key on every node that answers, then here; show the new
/// one. `skip` fields name the nodes to leave on the old key.
async fn rotate(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    body: axum::body::Bytes,
) -> AppResult<Response> {
    let node = node(&st)?.clone();
    let leave_out: Vec<NodeId> = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&body)
        .unwrap_or_default()
        .iter()
        .filter(|(k, _)| k == "skip")
        .filter_map(|(_, v)| NodeId::parse(v).ok())
        .collect();
    // In a task of its own: a rotation must not stop halfway because the
    // browser went away.
    let done = tokio::spawn(async move { cmd::rotate(&node, &leave_out).await }).await;
    Ok(match done {
        Ok(Ok(r)) => render_page(&st, Some(r.key.encode()))
            .await?
            .into_response(),
        Ok(Err(e)) => back_to(PAGE, None, Some(format!("Not rotated: {e:#}"))),
        Err(e) => back_to(PAGE, None, Some(format!("Not rotated: {e}"))),
    })
}

async fn retry(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match cmd::retry(node).await {
        Ok(results) => {
            let failed = results.iter().filter(|(_, r)| r.is_err()).count();
            back_to(
                PAGE,
                Some(format!(
                    "{} node(s) moved to the new key, {failed} still on the previous one.",
                    results.len() - failed
                )),
                None,
            )
        }
        Err(e) => back_to(PAGE, None, Some(format!("{e:#}"))),
    })
}

async fn discard(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    cmd::discard(&node.store).await?;
    Ok(back_to(
        PAGE,
        Some(
            "The previous key is deleted. Nodes still on it are no longer yours until you claim them again."
                .into(),
        ),
        None,
    ))
}
