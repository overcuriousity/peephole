//! The trap's listeners: what happens on a connection before HTTP. The
//! TLS listener reads an optional PROXY header (required from trusted
//! proxies) and the ClientHello itself, so the raw handshake and its JA4
//! fingerprint are kept, then terminates TLS. Both listeners keep a copy of
//! the request head as received and answer one request per connection.
//!
//! Connections are capped per listener and per source (IPv6 by /64, see
//! [`crate::net::source_key`]); a connection has [`HEAD_TIMEOUT`] from
//! accept to send a complete request head and [`CONN_DEADLINE`] in all.
use super::proxy_proto::{self, Proxy};
use super::raw_head::{HeadBuf, Tee};
use super::tls_hello::{self, Hello};
use anyhow::{Context, Result};
use ipnet::IpNet;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Most of a request head kept (hyper refuses longer heads anyway).
const HEAD_CAP: usize = 64 * 1024;
/// Time a client has for its PROXY header and ClientHello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Simultaneous connections per listener; excess are dropped.
const MAX_CONNS: usize = 2048;
/// Simultaneous connections per source and listener; excess are dropped.
/// The source is the client a trusted proxy's PROXY header names: all
/// connections through that proxy share its address. Plain HTTP through a
/// trusted proxy carries no PROXY header (the client is known per request,
/// from `X-Forwarded-For`), so there only [`MAX_CONNS`] applies.
const MAX_CONNS_PER_SOURCE: usize = 64;
/// Time a connection has from accept to a complete first request head,
/// PROXY header and TLS handshake included. hyper's protocol detection has
/// no timeout of its own, and its HTTP/1 header timeout starts only once
/// HTTP/1 is chosen.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest a connection lasts; bounds slow bodies and HTTP/2 streams.
const CONN_DEADLINE: Duration = Duration::from_secs(120);
/// A trusted proxy whose PROXY header is refused is warned about at most
/// once per this long, so a misconfigured proxy is noticed without a log
/// line per connection.
const REFUSAL_WARN_EVERY: Duration = Duration::from_secs(3600);
/// Proxies remembered for that; past it those warned about over that long
/// ago are forgotten, or all of them.
const REFUSAL_TRACKED: usize = 1024;

/// When each trusted proxy was last warned about.
static REFUSALS_WARNED: LazyLock<Mutex<HashMap<IpAddr, Instant>>> = LazyLock::new(Default::default);

/// Whether a refusal from `peer` is worth a warning now (see
/// [`REFUSAL_WARN_EVERY`]); records it if so.
fn warn_refusal_now(warned: &mut HashMap<IpAddr, Instant>, peer: IpAddr, now: Instant) -> bool {
    if warned
        .get(&peer)
        .is_some_and(|t| now.duration_since(*t) < REFUSAL_WARN_EVERY)
    {
        return false;
    }
    if warned.len() >= REFUSAL_TRACKED {
        warned.retain(|_, t| now.duration_since(*t) < REFUSAL_WARN_EVERY);
        if warned.len() >= REFUSAL_TRACKED {
            warned.clear();
        }
    }
    warned.insert(peer, now);
    true
}

/// What the connection showed, attached to each request on it.
#[derive(Clone, Debug, Default)]
pub struct ConnMeta {
    /// `http` or `https`.
    pub transport: &'static str,
    /// The peer is a trusted proxy.
    pub via_proxy: bool,
    /// The client, as a trusted proxy's PROXY header named it.
    pub proxied_src: Option<SocketAddr>,
    pub client_hello: Option<Arc<Vec<u8>>>,
    pub ja4: Option<String>,
    /// The first bytes received (after TLS), for the raw request head.
    pub head: HeadBuf,
}

/// TLS settings for the trap: the configured certificate, or a
/// self-signed one for `localhost` made now (scanners do not check it).
pub fn trap_tls_config(
    cert: Option<&Path>,
    key: Option<&Path>,
) -> Result<Arc<rustls::ServerConfig>> {
    let (chain, key) = match (cert, key) {
        (Some(c), Some(k)) => (
            CertificateDer::pem_file_iter(c)
                .with_context(|| format!("reading {}", c.display()))?
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| format!("parsing {}", c.display()))?,
            PrivateKeyDer::from_pem_file(k).with_context(|| format!("reading {}", k.display()))?,
        ),
        _ => {
            let pair = rcgen::KeyPair::generate().context("trap key")?;
            let c = rcgen::CertificateParams::new(vec!["localhost".to_string()])?
                .self_signed(&pair)
                .context("self-signing the trap certificate")?;
            (
                vec![c.der().clone()],
                PrivateKeyDer::try_from(pair.serialize_der())
                    .map_err(|e| anyhow::anyhow!("trap key: {e}"))?,
            )
        }
    };
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .context("trap certificate and key")?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A listener's connection limits (see the constants of the same names).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_conns: usize,
    pub max_conns_per_source: usize,
    pub head_timeout: Duration,
    pub conn_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_conns: MAX_CONNS,
            max_conns_per_source: MAX_CONNS_PER_SOURCE,
            head_timeout: HEAD_TIMEOUT,
            conn_deadline: CONN_DEADLINE,
        }
    }
}

/// Open connections per source key.
#[derive(Default)]
struct Sources(Mutex<HashMap<IpAddr, usize>>);

/// A connection counted against its source until dropped.
struct SourceSlot {
    sources: Arc<Sources>,
    key: IpAddr,
}

impl Sources {
    /// Count a connection from `ip`; None when its source has `max` open.
    fn take(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<SourceSlot> {
        let key = crate::net::source_key(ip);
        let mut open = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let n = open.entry(key).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(SourceSlot {
            sources: self.clone(),
            key,
        })
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut open = self.sources.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = open.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.key);
            }
        }
    }
}

/// Serve a trap listener with slowloris protection: a deadline for the
/// first request head and one for the whole connection (hyper on its own
/// disables its default header timeout when no timer is installed), plus
/// caps on concurrent connections, in all and per source, that shed load
/// rather than exhausting file descriptors/tasks. With `tls`, connections
/// are TLS (see the module).
pub async fn serve_trap(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    trusted: Arc<Vec<IpNet>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    serve_trap_with(listener, app, tls, trusted, shutdown, Limits::default()).await
}

/// [`serve_trap`] with other limits (tests).
pub async fn serve_trap_with(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    trusted: Arc<Vec<IpNet>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    limits: Limits,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(limits.max_conns));
    let sources = Arc::new(Sources::default());
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    warn!(?e, "trap accept failed");
                    // Out of descriptors (EMFILE) fails at once: don't spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        let start = tokio::time::Instant::now();
        let (head_by, end) = (start + limits.head_timeout, start + limits.conn_deadline);
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            // At the connection cap: drop this one instead of piling up.
            continue;
        };
        let via_proxy = trusted
            .iter()
            .any(|n| n.contains(&crate::net::canonical(peer.ip())));
        // A trusted proxy's connections are counted against the client its
        // PROXY header names, once that is read.
        let source = if via_proxy {
            None
        } else {
            let Some(s) = sources.take(peer.ip(), limits.max_conns_per_source) else {
                debug!(%peer, "trap: at the per-source connection cap, dropped");
                continue;
            };
            Some(s)
        };
        let (app, acceptor, sources) = (app.clone(), acceptor.clone(), sources.clone());
        tokio::spawn(async move {
            let _held = (permit, source);
            let mut meta = ConnMeta {
                via_proxy,
                ..Default::default()
            };
            match acceptor {
                None => {
                    meta.transport = "http";
                    let io = Tee::new(stream, meta.head.clone(), HEAD_CAP);
                    serve_conn(io, peer, meta, app, head_by, end).await;
                }
                Some(acceptor) => {
                    meta.transport = "https";
                    let preface = tokio::time::timeout_at(head_by, preface(stream, via_proxy));
                    let (io, src, hello) = match preface.await.unwrap_or(Err(Unusable::Other)) {
                        Ok(v) => v,
                        // A trusted proxy that sends no usable header loses
                        // every TLS connection through it: say so.
                        Err(Unusable::Proxy(why)) => {
                            if warn_refusal_now(
                                &mut REFUSALS_WARNED.lock().unwrap(),
                                peer.ip(),
                                Instant::now(),
                            ) {
                                warn!(%peer, why, "trap: refused a trusted proxy's PROXY header, \
                                      dropping the connection (warned once an hour)");
                            } else {
                                debug!(%peer, why, "trap: PROXY header refused");
                            }
                            return;
                        }
                        Err(Unusable::Other) => {
                            debug!(%peer, "trap: no usable PROXY header or ClientHello");
                            return;
                        }
                    };
                    let _source = match src {
                        Some(client) => {
                            match sources.take(client.ip(), limits.max_conns_per_source) {
                                Some(slot) => Some(slot),
                                None => {
                                    debug!(%peer, %client, "trap: at the per-source connection cap, dropped");
                                    return;
                                }
                            }
                        }
                        None => None,
                    };
                    meta.proxied_src = src;
                    meta.ja4 = Some(tls_hello::ja4(&hello));
                    meta.client_hello = Some(Arc::new(hello.raw));
                    let Ok(Ok(tls)) = tokio::time::timeout_at(head_by, acceptor.accept(io)).await
                    else {
                        debug!(%peer, "trap: TLS handshake failed");
                        return;
                    };
                    let io = Tee::new(tls, meta.head.clone(), HEAD_CAP);
                    serve_conn(io, peer, meta, app, head_by, end).await;
                }
            }
        });
    }
}

/// Why [`preface`] gave up on a connection.
enum Unusable {
    /// A trusted proxy's PROXY header was refused, and why.
    Proxy(&'static str),
    /// No ClientHello, or the connection ended or timed out first.
    Other,
}

/// Read what comes before the TLS handshake proper: the PROXY header (from
/// a trusted proxy, required) and the whole ClientHello. Returns a stream
/// that replays the ClientHello to rustls.
async fn preface(
    mut stream: TcpStream,
    expect_proxy: bool,
) -> Result<
    (
        Replay<TcpStream>,
        Option<SocketAddr>,
        tls_hello::ClientHello,
    ),
    Unusable,
> {
    tokio::time::timeout(HELLO_TIMEOUT, async move {
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let mut src = None;
        if expect_proxy {
            loop {
                match proxy_proto::parse_proxy(&buf) {
                    // A header that names no client (UNKNOWN, LOCAL) is
                    // refused: the peer is a proxy, and the client's own
                    // X-Forwarded-For would be believed in its place.
                    Proxy::Done { src: None, .. } => {
                        return Err(Unusable::Proxy("names no client (LOCAL or UNKNOWN)"));
                    }
                    Proxy::Done {
                        src: Some(s),
                        consumed,
                    } => {
                        src = Some(s);
                        buf.drain(..consumed);
                        break;
                    }
                    Proxy::Invalid => return Err(Unusable::Proxy("missing or malformed")),
                    Proxy::Incomplete if buf.len() >= proxy_proto::MAX_HEADER => {
                        return Err(Unusable::Proxy("too long"));
                    }
                    Proxy::Incomplete => {
                        fill(&mut stream, &mut buf).await.ok_or(Unusable::Other)?
                    }
                }
            }
        }
        let mut hello = tls_hello::HelloParser::default();
        loop {
            match hello.advance(&buf) {
                Hello::Done { hello, .. } => {
                    return Ok((
                        Replay {
                            prefix: buf,
                            pos: 0,
                            inner: stream,
                        },
                        src,
                        hello,
                    ));
                }
                Hello::Invalid => return Err(Unusable::Other),
                Hello::Incomplete if buf.len() > tls_hello::MAX_HELLO + 5 => {
                    return Err(Unusable::Other);
                }
                Hello::Incomplete => fill(&mut stream, &mut buf).await.ok_or(Unusable::Other)?,
            }
        }
    })
    .await
    .unwrap_or(Err(Unusable::Other))
}

/// Read more bytes into `buf`; None at end of stream or on error.
async fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<()> {
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk).await {
        Ok(0) | Err(_) => None,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Some(())
        }
    }
}

/// A stream that first yields bytes already read from it.
struct Replay<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = out.remaining().min(self.prefix.len() - self.pos);
            let start = self.pos;
            out.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serve HTTP on one connection, dropping it if no complete request head
/// has arrived by `head_by`, and in any case at `end`. The client address
/// handlers see is the PROXY header's source when there is one.
async fn serve_conn<I>(
    io: I,
    peer: SocketAddr,
    meta: ConnMeta,
    app: axum::Router,
    head_by: tokio::time::Instant,
    end: tokio::time::Instant,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    let client = meta.proxied_src.unwrap_or(peer);
    // Told when hyper hands over a request: its head is complete.
    let headed = Arc::new(tokio::sync::Notify::new());
    let on_head = headed.clone();
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        on_head.notify_one();
        let (app, meta) = (app.clone(), meta.clone());
        async move {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(axum::extract::ConnectInfo(client));
            parts.extensions.insert(meta);
            let req = hyper::Request::from_parts(parts, axum::body::Body::new(body));
            app.oneshot(req).await
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Request heads must fit in 64 KiB (hyper's default allows ~400 KB)
    // and 100 headers; one request per HTTP/1 connection, so the head
    // copied from the connection is that request's. HTTP/2 gets the same
    // bounds plus a cap on parallel streams and an idle ping deadline.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(HEAD_CAP)
        .max_headers(100)
        .keep_alive(false);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(32)
        .max_header_list_size(64 * 1024)
        .max_pending_accept_reset_streams(16)
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(15));
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => return,
        _ = headed.notified() => {}
        _ = tokio::time::sleep_until(head_by) => {
            debug!(%peer, "trap: no complete request head in time, dropped");
            return;
        }
    }
    // Overall per-connection deadline bounds slow bodies and keep-alive
    // trickling as well as slow headers.
    let _ = tokio::time::timeout_at(end, conn).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_certificate_is_loaded_and_a_broken_one_refused() {
        let dir = tempfile::tempdir().unwrap();
        let pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["trap.test".into()])
            .unwrap()
            .self_signed(&pair)
            .unwrap();
        let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, pair.serialize_pem()).unwrap();
        trap_tls_config(Some(&c), Some(&k)).unwrap();
        std::fs::write(&k, "not a key").unwrap();
        assert!(trap_tls_config(Some(&c), Some(&k)).is_err());
        trap_tls_config(None, None).unwrap();
    }

    #[test]
    fn sources_are_capped_and_released() {
        let s = Arc::new(Sources::default());
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:1::2".parse().unwrap();
        let held: Vec<_> = (0..3).map(|_| s.take(a, 4).unwrap()).collect();
        let fourth = s.take(b, 4).unwrap();
        // The /64 is full, whichever address in it asks.
        assert!(s.take(a, 4).is_none() && s.take(b, 4).is_none());
        assert!(s.take("2001:db8:0:2::1".parse().unwrap(), 4).is_some());
        drop(fourth);
        let again = s.take(a, 4).unwrap();
        drop((held, again));
        assert_eq!(s.open(), 0, "nothing is left behind");
    }

    #[test]
    fn proxy_refusals_are_warned_about_at_most_hourly_per_peer() {
        let mut warned = HashMap::new();
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let t0 = Instant::now();
        assert!(warn_refusal_now(&mut warned, a, t0));
        assert!(!warn_refusal_now(
            &mut warned,
            a,
            t0 + Duration::from_secs(60)
        ));
        assert!(warn_refusal_now(
            &mut warned,
            b,
            t0 + Duration::from_secs(60)
        ));
        assert!(warn_refusal_now(&mut warned, a, t0 + REFUSAL_WARN_EVERY));
        // Bounded: a flood of peers never grows the map past the cap.
        for i in 0..(REFUSAL_TRACKED as u32 * 2) {
            warn_refusal_now(&mut warned, IpAddr::from(i.to_be_bytes()), t0);
        }
        assert!(warned.len() <= REFUSAL_TRACKED);
    }
}
