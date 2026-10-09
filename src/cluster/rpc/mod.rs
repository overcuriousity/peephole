//! Node-to-node RPC: HTTP/2 + CBOR over pinned-key mutual TLS.
pub mod cbor;
pub mod proto;
pub mod routed;
pub mod server;

use super::Node;
use super::invite::{self, JoinReq};
use super::msg::Envelope;
use super::relay;
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
pub(crate) const BODY_LIMIT: usize = 64 * 1024 * 1024;
/// `/join` is reachable by any key that completes the TLS handshake (not yet a
/// member), so its body is capped tightly — a JoinReq is a token plus small
/// node info — to deny an unauthenticated memory-exhaustion vector.
pub(crate) const JOIN_BODY_LIMIT: usize = 64 * 1024;

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
        .route("/rpc/v1/lookup", post(lookup))
        .route("/rpc/v1/probe", post(probe))
        .route("/rpc/v1/resolve", post(resolve))
        .route("/rpc/v1/rdns", post(rdns))
        .route("/rpc/v1/relay", post(relay_lease))
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

/// Our heads, given the caller's. A purged origin is neither served nor
/// accepted here, so it is reported as far as the caller holds it: the
/// caller neither asks for it (and backs off on an empty batch) nor pushes it.
async fn heads(State(node): State<Arc<Node>>, Cbor(theirs): Cbor<repl::Heads>) -> Response {
    let r = async {
        let ours = repl::heads(&node.store).await?;
        let purged = super::block::purged(&node.store).await?;
        anyhow::Ok(repl::advertised(
            ours,
            &purged.into_iter().collect(),
            &repl::head_map(&theirs),
        ))
    };
    match r.await {
        Ok(h) => Cbor(h).into_response(),
        Err(e) => internal(e),
    }
}

/// A member's name as this node knows it ("" when unknown).
fn name_of(node: &Node, peer: &super::identity::NodeId) -> String {
    node.members()
        .get(peer)
        .map(|m| m.name.clone())
        .unwrap_or_default()
}

async fn pull(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<PullReq>,
) -> Response {
    // Only what is held here past each want, each origin once: the list
    // comes from the peer and may be as long as the body allows.
    let wants = match repl::heads(&node.store).await {
        Ok(h) => repl::servable_wants(req.wants, &repl::head_map(&h)),
        Err(e) => return internal(e),
    };
    match repl::entries_after(
        &node.store,
        &wants,
        req.since_hlc,
        req.max_entries.clamp(1, 5 * BATCH_ENTRIES),
        req.max_bytes.clamp(1, 4 * BATCH_BYTES),
        node.old_peer(&peer),
    )
    .await
    {
        Ok(v) => {
            let kinds = super::traffic::Kinds::of(&v.entries);
            if kinds.total() > 0 {
                node.traffic.sent(peer, &name_of(&node, &peer), &kinds);
            }
            Cbor(v).into_response()
        }
        Err(e) => internal(e),
    }
}

async fn push(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(batch): Cbor<Batch>,
) -> Response {
    // Floors and bounds: at most one per origin asked for in an honest batch.
    if [
        batch.entries.len(),
        batch.proofs.len(),
        batch.floors.len(),
        batch.bounds.len(),
    ]
    .iter()
    .any(|n| *n > 5 * BATCH_ENTRIES)
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too many entries").into_response();
    }
    let kinds = super::traffic::Kinds::of(&batch.entries);
    match repl::apply_batch(&node, batch).await {
        Ok(st) => {
            if kinds.total() > 0 {
                node.traffic
                    .received(peer, &name_of(&node, &peer), &kinds, st.applied);
            }
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
    // A request this node cannot pass on is refused at once, so the
    // sender tries its next relay or gives up without waiting: one for a
    // member that lists this node as a relay but holds no lease here, or
    // for an outbound-only member without relays. Answers are excepted
    // (they wait in the asker's outbox here, see `msg`).
    if body.to != node.id() && body.in_reply_to.is_none() && !node.routable(&body.to, &[]) {
        let relays = node
            .status
            .known(&body.to)
            .map(|k| k.hb.relays)
            .unwrap_or_default();
        let now = crate::cluster::hlc::wall_ms();
        if relays.contains(&node.id()) && !node.relay_leases.holds(&body.to, now) {
            return (StatusCode::SERVICE_UNAVAILABLE, relay::NO_LEASE).into_response();
        }
        if relays.contains(&node.id())
            || relays.is_empty()
                && node
                    .members()
                    .get(&body.to)
                    .is_some_and(|m| m.address.is_none())
        {
            return (StatusCode::SERVICE_UNAVAILABLE, "no route to that member").into_response();
        }
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

/// On-demand enrichment for a member, paid with the offer it names.
async fn lookup(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::intel::lookup::LookupReq>,
) -> Response {
    Cbor(crate::intel::lookup::serve(&node, peer, &req).await).into_response()
}

/// A host name resolved for a member, paid with the offer it names; it
/// never scans, probes or stores anything.
async fn resolve(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::intel::dns::ResolveReq>,
) -> Response {
    Cbor(crate::intel::dns::serve_resolve(&node, peer, &req).await).into_response()
}

/// A source's reverse names for a member, free at zero or paid with the
/// offer it names.
async fn rdns(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::intel::rdns::RdnsReq>,
) -> Response {
    Cbor(crate::intel::rdns::serve_rdns(&node, peer, &req).await).into_response()
}

/// An observational probe for a member, paid with the offer it names.
async fn probe(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::scan::probe::serve::ProbeReq>,
) -> Response {
    Cbor(routed::probe_answer(&node, peer, &req).await).into_response()
}

/// A relay lease for an outbound-only member (`cluster::relay`).
async fn relay_lease(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::cluster::relay::RelayReq>,
) -> Response {
    Cbor(crate::cluster::relay::serve(&node, peer, &req).await).into_response()
}

/// Long-poll for messages waiting for the caller.
async fn inbox(State(node): State<Arc<Node>>, Extension(Peer(peer)): Extension<Peer>) -> Response {
    // A lessee that lists this node holds no lease here (it restarted):
    // told at once, it leases another relay. Answers already queued for
    // it here are handed over first.
    if !node.has_queued(&peer)
        && node
            .status
            .known(&peer)
            .is_some_and(|k| k.hb.relays.contains(&node.id()))
        && !node
            .relay_leases
            .holds(&peer, crate::cluster::hlc::wall_ms())
    {
        return (StatusCode::SERVICE_UNAVAILABLE, relay::NO_LEASE).into_response();
    }
    Cbor(node.take_inbox(peer).await).into_response()
}

/// Long-poll: answer as soon as we hold something the caller lacks.
async fn wait(State(node): State<Arc<Node>>, Cbor(req): Cbor<WaitReq>) -> Response {
    let mut changes = node.subscribe_changes();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(WAIT_SECS);
    loop {
        changes.borrow_and_update();
        let ours = match repl::heads(&node.store).await {
            Ok(h) => h,
            Err(e) => return internal(e),
        };
        let ready = async {
            let purged = super::block::purged(&node.store).await?;
            let mut conn = node.store.pool.acquire().await?;
            let floors = super::history::floors(&mut conn).await?;
            anyhow::Ok(super::history::wait_ready(
                &ours,
                &floors,
                &purged.into_iter().collect(),
                &req,
            ))
        };
        match ready.await {
            Ok(true) => return Cbor(ours).into_response(),
            Ok(false) => {}
            Err(e) => return internal(e),
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
        if let Some(server::RemoteAddr(addr)) = req.extensions().get::<server::RemoteAddr>() {
            node.status.note_peer_ip(peer, addr.ip());
        }
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

async fn hello(
    State(node): State<Arc<Node>>,
    Extension(server::RemoteAddr(addr)): Extension<server::RemoteAddr>,
    Cbor(theirs): Cbor<Hello>,
) -> Response {
    // Tell the caller where it came from: its peer-observed public address.
    let ours = Hello {
        seen_from: Some(addr.ip()),
        ..node.local_hello()
    };
    match proto::negotiate(
        (ours.proto_min, ours.proto_max),
        (theirs.proto_min, theirs.proto_max),
    ) {
        Some(_) => Cbor(ours).into_response(),
        None => (StatusCode::UPGRADE_REQUIRED, Cbor(ours)).into_response(),
    }
}
