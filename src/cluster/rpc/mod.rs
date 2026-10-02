//! Node-to-node RPC: HTTP/2 + CBOR over pinned-key mutual TLS.
pub mod cbor;
pub mod proto;
pub mod server;

use super::Node;
use super::invite::{self, JoinReq};
use super::msg::Envelope;
use super::repl;
use super::status::SignedHeartbeat;
use super::sync::{BATCH_BYTES, BATCH_ENTRIES, Batch, PullReq, WAIT_SECS, WaitReq};
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::post};
use cbor::Cbor;
use proto::Hello;
use server::Peer;
use std::sync::Arc;

/// Largest member RPC body (backfill batches are paced well below this).
const BODY_LIMIT: usize = 64 * 1024 * 1024;
/// `/join` is reachable by any key that completes the TLS handshake (not yet a
/// member), so its body is capped tightly — a JoinReq is a token plus small
/// node info — to deny an unauthenticated memory-exhaustion vector.
const JOIN_BODY_LIMIT: usize = 64 * 1024;

pub fn router(node: Arc<Node>) -> Router {
    let members_only = Router::new()
        .route("/rpc/v1/hello", post(hello))
        .route("/rpc/v1/heads", post(heads))
        .route("/rpc/v1/pull", post(pull))
        .route("/rpc/v1/push", post(push))
        .route("/rpc/v1/wait", post(wait))
        .route("/rpc/v1/gossip", post(gossip))
        .route("/rpc/v1/msg", post(message))
        .route("/rpc/v1/inbox", post(inbox))
        .route("/rpc/v1/intel", post(intel_chunk))
        .route_layer(axum::middleware::from_fn_with_state(
            node.clone(),
            require_member,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(BODY_LIMIT));
    // The only route open to keys that are not members yet, with a tight limit.
    let open = Router::new()
        .route("/rpc/v1/join", post(join))
        .layer(axum::extract::DefaultBodyLimit::max(JOIN_BODY_LIMIT));
    members_only.merge(open).with_state(node)
}

fn internal(e: anyhow::Error) -> Response {
    tracing::warn!(error = %format!("{e:#}"), "rpc handler failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

async fn heads(State(node): State<Arc<Node>>) -> Response {
    match repl::heads(&node.store).await {
        Ok(h) => Cbor(h).into_response(),
        Err(e) => internal(e),
    }
}

async fn pull(State(node): State<Arc<Node>>, Cbor(req): Cbor<PullReq>) -> Response {
    match repl::entries_after(
        &node.store,
        &req.wants,
        req.max_entries.clamp(1, 5 * BATCH_ENTRIES),
        req.max_bytes.clamp(1, 4 * BATCH_BYTES),
    )
    .await
    {
        Ok(v) => Cbor(v).into_response(),
        Err(e) => internal(e),
    }
}

async fn push(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(batch): Cbor<Batch>,
) -> Response {
    if batch.entries.len() > 5 * BATCH_ENTRIES || batch.proofs.len() > 5 * BATCH_ENTRIES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too many entries").into_response();
    }
    match repl::apply_batch(&node, batch).await {
        Ok(st) => {
            if st.rejected > 0 {
                tracing::debug!(peer = %peer.short(), ?st, "push had rejected entries");
            }
            match repl::heads(&node.store).await {
                Ok(h) => Cbor(h).into_response(),
                Err(e) => internal(e),
            }
        }
        Err(e) => internal(e),
    }
}

/// Exchange heartbeats: take theirs, answer with everything we know.
async fn gossip(
    State(node): State<Arc<Node>>,
    Cbor(theirs): Cbor<Vec<SignedHeartbeat>>,
) -> Response {
    node.merge_heartbeats(theirs);
    Cbor(node.status.all_signed()).into_response()
}

/// A directed message to deliver here or pass on. Routed in the
/// background; the caller only learns it was accepted.
/// Only messages signed by members and within the replay window are taken,
/// and only so many are routed at once.
async fn message(State(node): State<Arc<Node>>, Cbor(mut env): Cbor<Envelope>) -> Response {
    env.hops = env.hops.saturating_add(1);
    let body = match env.open() {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if !node.is_member(&body.from) {
        return (StatusCode::FORBIDDEN, "sender is not a member").into_response();
    }
    if !body.fresh() {
        return (StatusCode::BAD_REQUEST, "stale or future-dated message").into_response();
    }
    let Ok(permit) = node.route_slots.clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = node.route(env).await {
            tracing::debug!(?e, "message not routed");
        }
    });
    Cbor(true).into_response()
}

/// A chunk of a shared intel file (raw bytes), if we hold that version.
async fn intel_chunk(
    State(node): State<Arc<Node>>,
    Cbor(req): Cbor<crate::intel::share::ChunkReq>,
) -> Response {
    let dir = node.data_dir.clone();
    match tokio::task::spawn_blocking(move || crate::intel::share::read_chunk(&dir, &req)).await {
        Ok(Ok(Some(bytes))) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "version not held here").into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(e.into()),
    }
}

/// Long-poll for messages waiting for the caller.
async fn inbox(State(node): State<Arc<Node>>, Extension(Peer(peer)): Extension<Peer>) -> Response {
    Cbor(node.take_inbox(peer).await).into_response()
}

/// Long-poll: answer as soon as we hold something the caller lacks.
async fn wait(State(node): State<Arc<Node>>, Cbor(req): Cbor<WaitReq>) -> Response {
    let mut changes = node.subscribe_changes();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(WAIT_SECS);
    let theirs = repl::head_map(&req.heads);
    loop {
        changes.borrow_and_update();
        let ours = match repl::heads(&node.store).await {
            Ok(h) => h,
            Err(e) => return internal(e),
        };
        if repl::ahead_of_map(&ours, &theirs) {
            return Cbor(ours).into_response();
        }
        tokio::select! {
            _ = changes.changed() => {}
            _ = tokio::time::sleep_until(deadline) => return Cbor(ours).into_response(),
        }
    }
}

async fn join(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Extension(server::RemoteAddr(addr)): Extension<server::RemoteAddr>,
    Cbor(req): Cbor<JoinReq>,
) -> Response {
    if !node.join_allowed(peer, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
    match invite::redeem(&node, peer, req).await {
        Ok(resp) => Cbor(resp).into_response(),
        Err((code, msg)) => {
            tracing::info!(peer = %peer.short(), %msg, "join refused");
            (
                StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
                msg,
            )
                .into_response()
        }
    }
}

/// Only cluster members may call; unknown keys get 403.
async fn require_member(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    req: Request,
    next: Next,
) -> Response {
    if node.is_blocked(&peer) {
        return (StatusCode::FORBIDDEN, "blocked by this node").into_response();
    }
    if node.is_member(&peer) {
        node.status.touch_inbound(peer);
        next.run(req).await
    } else {
        let why = match node.standing_of(&peer) {
            Some(crate::cluster::members::Standing::Pruned) => {
                "pruned: no sign of life for 30 days; rejoin with an invite"
            }
            _ => "not a cluster member",
        };
        tracing::debug!(peer = %peer.short(), why, "rpc refused");
        (StatusCode::FORBIDDEN, why).into_response()
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
