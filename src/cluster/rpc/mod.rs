//! Node-to-node RPC: HTTP/2 + CBOR over pinned-key mutual TLS.
pub mod cbor;
pub mod proto;
pub mod server;

use super::Node;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::post};
use cbor::Cbor;
use proto::Hello;
use server::Peer;
use std::sync::Arc;

/// Largest RPC body (backfill batches are paced well below this).
const BODY_LIMIT: usize = 64 * 1024 * 1024;

pub fn router(node: Arc<Node>) -> Router {
    let members_only = Router::new()
        .route("/rpc/v1/hello", post(hello))
        .route_layer(axum::middleware::from_fn_with_state(
            node.clone(),
            require_member,
        ));
    members_only
        .layer(axum::extract::DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(node)
}

/// Only cluster members may call; unknown keys get 403.
async fn require_member(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    req: Request,
    next: Next,
) -> Response {
    if node.is_member(&peer) {
        next.run(req).await
    } else {
        tracing::debug!(peer = %peer.short(), "rpc from non-member refused");
        (StatusCode::FORBIDDEN, "not a cluster member").into_response()
    }
}

async fn hello(State(node): State<Arc<Node>>, Cbor(theirs): Cbor<Hello>) -> Response {
    let ours = node.local_hello();
    match proto::negotiate(
        (ours.proto_min, ours.proto_max),
        (theirs.proto_min, theirs.proto_max),
    ) {
        Some(_) => Cbor(ours).into_response(),
        None => (StatusCode::UPGRADE_REQUIRED, Cbor(ours)).into_response(),
    }
}
