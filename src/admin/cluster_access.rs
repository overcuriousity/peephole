//! Cluster › Access: who may join, who may configure this node, and
//! joining or leaving.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::cluster::{InviteView, KeyForm, back_to, invites, node};
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::invite;
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

const ACCESS: &str = "/admin/cluster/access";

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/cluster/access", get(page))
        .route("/admin/cluster/invite", post(create_invite))
        .route("/admin/cluster/invite/revoke", post(revoke_invite))
        .route("/admin/cluster/join", post(join))
        .route("/admin/cluster/leave", post(leave))
        .route("/admin/cluster/config-key/rotate", post(rotate_key))
        .route("/admin/cluster/config-key/add", post(add_key))
}

#[derive(Template)]
#[template(path = "admin_cluster_access.html")]
struct AccessPage {
    chrome: Chrome,
    /// A just-created invite, shown once.
    invite: Option<String>,
    invites: Vec<InviteView>,
    /// This node's config key, when remote configuration is on.
    config_key: Option<String>,
    remote_config: bool,
    detached: bool,
}

async fn render_access(st: &AdminState, invite: Option<String>) -> AppResult<Html<String>> {
    let node = node(st)?;
    let config_key = if node.cfg.remote_config {
        Some(
            crate::cluster::confkey::ensure(&node.store, node.id())
                .await?
                .encode(),
        )
    } else {
        None
    };
    render(&AccessPage {
        chrome: Chrome::new(true, "admin"),
        invite,
        invites: invites(node).await?,
        config_key,
        remote_config: node.cfg.remote_config,
        detached: node.detached().is_some(),
    })
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_access(&st, None).await
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
        return Ok(back_to(
            ACCESS,
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
        Ok(token) => Ok(render_access(&st, Some(token)).await?.into_response()),
        Err(e) => Ok(back_to(ACCESS, None, Some(format!("{e:#}")))),
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
        back_to(
            ACCESS,
            Some("Invite revoked. Members that joined with it stay.".into()),
            None,
        )
    } else {
        back_to(ACCESS, None, Some("No usable invite with that id.".into()))
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
        Ok(i) => back_to(
            ACCESS,
            Some(format!(
                "Joined the cluster via {}. Data now syncs.",
                i.name
            )),
            None,
        ),
        Err(e) => back_to(ACCESS, None, Some(format!("Join failed: {e:#}"))),
    })
}

async fn leave(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match crate::cluster::leave(node).await {
        Ok(told) => back_to(
            ACCESS,
            Some(format!(
                "This node left the cluster ({told} peer(s) told). Its data stays here; it no longer syncs."
            )),
            None,
        ),
        Err(e) => back_to(ACCESS, None, Some(format!("Leaving failed: {e:#}"))),
    })
}

async fn rotate_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    if !node.cfg.remote_config {
        return Ok(back_to(
            ACCESS,
            None,
            Some("Remote configuration is off on this node; there is no key to rotate.".into()),
        ));
    }
    crate::cluster::confkey::rotate(&node.store, node.id()).await?;
    Ok(back_to(
        ACCESS,
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
            Err(e) => back_to(ACCESS, None, Some(format!("{e:#}"))),
        },
    )
}
