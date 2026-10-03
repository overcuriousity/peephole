//! TLS accept loop: every connection carries the verified peer key into
//! the axum handlers as an [`Peer`] extension.
//!
//! Any self-generated key passes the TLS handshake (joining needs that), so
//! connections are bounded: in total, per remote address and for keys that
//! are not members (also per address); a connection that sends no request
//! for a while is closed (for a non-member, no join request), HTTP/1
//! headers must arrive promptly and request bodies in time.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::tls::cert_node_id;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, warn};

/// The authenticated (key-verified, not necessarily member) peer.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub NodeId);

/// Remote socket address of the connection.
#[derive(Clone, Copy, Debug)]
pub struct RemoteAddr(pub SocketAddr);

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Open connections in total.
const MAX_CONNECTIONS: usize = 512;
/// Open connections from one address (IPv6: one /64).
const MAX_PER_ADDRESS: usize = 32;
/// Open connections from keys that are not members (joiners, strangers).
const MAX_NON_MEMBERS: usize = 32;
/// Of those, from one address (IPv6: one /64).
const MAX_NON_MEMBERS_PER_ADDRESS: usize = 4;
/// A request body must have arrived within this long: a member's batch
/// can be large, a join request is tiny.
const MEMBER_BODY_TIMEOUT: Duration = Duration::from_secs(120);
const NON_MEMBER_BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection without a request for this long is closed (sync loops
/// long-poll every 25 s, so a live peer never gets here).
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// After asking a connection to close, wait this long before dropping it.
const CLOSE_GRACE: Duration = Duration::from_secs(30);
/// HTTP/2 streams per connection.
const MAX_STREAMS: u32 = 64;

/// Connections per remote address (IPv4, or IPv6 /64), up to a limit.
struct PerAddress {
    max: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
}

fn address_key(ip: IpAddr) -> IpAddr {
    match crate::net::canonical(ip) {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// A slot held for one connection from one address; freed on drop.
struct AddressSlot(Arc<PerAddress>, IpAddr);

impl PerAddress {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max,
            open: Default::default(),
        })
    }

    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<AddressSlot> {
        let key = address_key(ip);
        let mut m = self.open.lock().unwrap();
        let n = m.entry(key).or_default();
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(AddressSlot(self.clone(), key))
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut m = self.0.open.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// When the connection last started a request, and how many are running.
#[derive(Default)]
struct Activity {
    last_ms: AtomicU64,
    running: AtomicUsize,
}

fn now_ms() -> u64 {
    crate::cluster::hlc::wall_ms()
}

/// The only route open to keys that are not members.
const JOIN_PATH: &str = "/rpc/v1/join";

/// Size and time a request body of a member (or a non-member) gets.
fn body_bounds(member: bool) -> (usize, Duration) {
    if member {
        (super::BODY_LIMIT, MEMBER_BODY_TIMEOUT)
    } else {
        (super::JOIN_BODY_LIMIT, NON_MEMBER_BODY_TIMEOUT)
    }
}

/// The request with its body read in full, at most `limit` bytes within
/// `timeout`; a slow or oversized body is answered here (with the error)
/// and never reaches a handler.
async fn read_body(
    req: axum::extract::Request,
    (limit, timeout): (usize, Duration),
) -> Result<axum::extract::Request, (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    let (parts, body) = req.into_parts();
    match tokio::time::timeout(timeout, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(axum::extract::Request::from_parts(
            parts,
            axum::body::Body::from(bytes),
        )),
        Ok(Err(_)) => Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large")),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "body too slow")),
    }
}

pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    node: Arc<Node>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let total = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let strangers = Arc::new(tokio::sync::Semaphore::new(MAX_NON_MEMBERS));
    let per_address = PerAddress::new(MAX_PER_ADDRESS);
    let strangers_per_address = PerAddress::new(MAX_NON_MEMBERS_PER_ADDRESS);
    loop {
        let (tcp, addr) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    warn!(?e, "rpc accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        // Over a limit: drop the connection before any TLS work.
        let Ok(slot) = total.clone().try_acquire_owned() else {
            debug!(%addr, "rpc connection refused: too many connections");
            continue;
        };
        let Some(addr_slot) = per_address.take(addr.ip()) else {
            debug!(%addr, "rpc connection refused: too many from this address");
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let node = node.clone();
        let strangers = strangers.clone();
        let strangers_per_address = strangers_per_address.clone();
        tokio::spawn(async move {
            let _slots = (slot, addr_slot);
            let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return debug!(%addr, ?e, "rpc tls handshake failed"),
                Err(_) => return debug!(%addr, "rpc tls handshake timed out"),
            };
            let Some(peer) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|c| cert_node_id(c).ok())
            else {
                return;
            };
            // Keys that are not members can only try to join: few at once,
            // and fewer from one address.
            let _stranger = if node.is_member(&peer) {
                None
            } else {
                let Ok(p) = strangers.try_acquire_owned() else {
                    return debug!(%addr, "rpc connection refused: too many non-members");
                };
                let Some(s) = strangers_per_address.take(addr.ip()) else {
                    return debug!(%addr, "rpc connection refused: too many non-members from this address");
                };
                Some((p, s))
            };
            let activity = Arc::new(Activity::default());
            activity.last_ms.store(now_ms(), Ordering::Relaxed);
            let seen = activity.clone();
            let member_of = node.clone();
            let svc = app
                .layer(axum::middleware::from_fn(
                    move |req: axum::extract::Request, next: axum::middleware::Next| {
                        let seen = seen.clone();
                        // Membership can change while a connection is open.
                        let member = member_of.is_member(&peer);
                        async move {
                            // Only what a key may do keeps its connection
                            // open: anything for a member, joining for others.
                            let counts = member || req.uri().path() == JOIN_PATH;
                            seen.running.fetch_add(1, Ordering::Relaxed);
                            if counts {
                                seen.last_ms.store(now_ms(), Ordering::Relaxed);
                            }
                            let resp = match read_body(req, body_bounds(member)).await {
                                Ok(req) => next.run(req).await,
                                Err(e) => axum::response::IntoResponse::into_response(e),
                            };
                            if counts {
                                seen.last_ms.store(now_ms(), Ordering::Relaxed);
                            }
                            seen.running.fetch_sub(1, Ordering::Relaxed);
                            resp
                        }
                    },
                ))
                .layer(axum::Extension(Peer(peer)))
                .layer(axum::Extension(RemoteAddr(addr)));
            let svc = hyper_util::service::TowerToHyperService::new(svc);
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10));
            builder
                .http2()
                .timer(TokioTimer::new())
                .max_concurrent_streams(MAX_STREAMS)
                .keep_alive_interval(Some(Duration::from_secs(30)))
                .keep_alive_timeout(Duration::from_secs(20));
            let conn = builder.serve_connection(TokioIo::new(stream), svc);
            tokio::pin!(conn);
            let mut closing: Option<tokio::time::Instant> = None;
            loop {
                tokio::select! {
                    r = conn.as_mut() => {
                        if let Err(e) = r {
                            debug!(%addr, ?e, "rpc connection ended with error");
                        }
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {
                        if let Some(t) = closing {
                            if t.elapsed() > CLOSE_GRACE {
                                return debug!(%addr, "rpc connection dropped after close grace");
                            }
                            continue;
                        }
                        let idle = activity.running.load(Ordering::Relaxed) == 0
                            && now_ms().saturating_sub(activity.last_ms.load(Ordering::Relaxed))
                                > IDLE_TIMEOUT.as_millis() as u64;
                        if idle {
                            debug!(%addr, "idle rpc connection closed");
                            conn.as_mut().graceful_shutdown();
                            closing = Some(tokio::time::Instant::now());
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use futures::StreamExt;

    #[test]
    fn connections_are_limited_per_address() {
        let per = PerAddress::new(2);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a = per.take(ip("203.0.113.1")).unwrap();
        let _b = per.take(ip("::ffff:203.0.113.1")).unwrap();
        assert!(per.take(ip("203.0.113.1")).is_none());
        assert!(per.take(ip("203.0.113.2")).is_some());
        drop(a);
        assert!(per.take(ip("203.0.113.1")).is_some());
        // One IPv6 /64 counts as one address.
        let _c = per.take(ip("2001:db8::1")).unwrap();
        let _d = per.take(ip("2001:db8::2")).unwrap();
        assert!(per.take(ip("2001:db8::3")).is_none());
    }

    /// A body that trickles in, or never ends, is cut off; one too large is
    /// refused before a handler sees it. Before, a key that was not even a
    /// member could hold a connection open with a body that never ended.
    #[tokio::test]
    async fn request_bodies_must_arrive_in_time_and_size() {
        let req = |body: Body| axum::extract::Request::new(body);
        let bounds = (8, Duration::from_millis(50));
        let ok = read_body(req(Body::from("small")), bounds).await.unwrap();
        let got = axum::body::to_bytes(ok.into_body(), 8).await.unwrap();
        assert_eq!(&got[..], b"small");
        let big = read_body(req(Body::from("far too large")), bounds)
            .await
            .unwrap_err();
        assert_eq!(big.0, axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        let stalled = futures::stream::once(async { Ok::<_, std::io::Error>(Bytes::from("x")) })
            .chain(futures::stream::pending());
        let slow = read_body(req(Body::from_stream(stalled)), bounds)
            .await
            .unwrap_err();
        assert_eq!(slow.0, axum::http::StatusCode::REQUEST_TIMEOUT);
        assert!(body_bounds(false).1 < body_bounds(true).1);
    }
}
