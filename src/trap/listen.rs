//! The trap's listeners: what happens on a connection before HTTP. The
//! TLS listener reads an optional PROXY header (required from trusted
//! proxies) and the ClientHello itself, so the raw handshake and its JA4
//! fingerprint are kept, then terminates TLS. Both listeners keep a copy of
//! the request head as received and answer one request per connection.
use super::proxy_proto::{self, Proxy};
use super::raw_head::{HeadBuf, Tee};
use super::tls_hello::{self, Hello};
use anyhow::{Context, Result};
use ipnet::IpNet;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Most of a request head kept (hyper refuses longer heads anyway).
const HEAD_CAP: usize = 64 * 1024;
/// Time a client has for its PROXY header and ClientHello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Simultaneous connections per listener; excess are dropped.
const MAX_CONNS: usize = 2048;

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

/// Serve a trap listener with slowloris protection: a per-connection
/// header-read timeout and overall deadline (hyper on its own disables its
/// default header timeout when no timer is installed), plus a cap on
/// concurrent connections that sheds load rather than exhausting file
/// descriptors/tasks. With `tls`, connections are TLS (see the module).
pub async fn serve_trap(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    trusted: Arc<Vec<IpNet>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
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
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            // At the connection cap: drop this one instead of piling up.
            continue;
        };
        let (app, trusted, acceptor) = (app.clone(), trusted.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let via_proxy = trusted
                .iter()
                .any(|n| n.contains(&crate::net::canonical(peer.ip())));
            let mut meta = ConnMeta {
                via_proxy,
                ..Default::default()
            };
            match acceptor {
                None => {
                    meta.transport = "http";
                    let io = Tee::new(stream, meta.head.clone(), HEAD_CAP);
                    serve_conn(io, peer, meta, app).await;
                }
                Some(acceptor) => {
                    meta.transport = "https";
                    let Some((io, src, hello)) = preface(stream, via_proxy).await else {
                        debug!(%peer, "trap: no usable PROXY header or ClientHello");
                        return;
                    };
                    meta.proxied_src = src;
                    meta.ja4 = Some(tls_hello::ja4(&hello));
                    meta.client_hello = Some(Arc::new(hello.raw));
                    let Ok(Ok(tls)) =
                        tokio::time::timeout(HELLO_TIMEOUT, acceptor.accept(io)).await
                    else {
                        debug!(%peer, "trap: TLS handshake failed");
                        return;
                    };
                    let io = Tee::new(tls, meta.head.clone(), HEAD_CAP);
                    serve_conn(io, peer, meta, app).await;
                }
            }
        });
    }
}

/// Read what comes before the TLS handshake proper: the PROXY header (from
/// a trusted proxy, required) and the whole ClientHello. Returns a stream
/// that replays the ClientHello to rustls.
async fn preface(
    mut stream: TcpStream,
    expect_proxy: bool,
) -> Option<(
    Replay<TcpStream>,
    Option<SocketAddr>,
    tls_hello::ClientHello,
)> {
    tokio::time::timeout(HELLO_TIMEOUT, async move {
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let mut src = None;
        if expect_proxy {
            loop {
                match proxy_proto::parse_proxy(&buf) {
                    // A header that names no client (UNKNOWN, AF_UNSPEC) is
                    // refused: the peer is a proxy, and the client's own
                    // X-Forwarded-For would be believed in its place.
                    Proxy::Done { src: None, .. } => return None,
                    // The proxy's own connection (a health check): the peer
                    // is the client.
                    Proxy::Local { consumed } => {
                        buf.drain(..consumed);
                        break;
                    }
                    Proxy::Done {
                        src: Some(s),
                        consumed,
                    } => {
                        src = Some(s);
                        buf.drain(..consumed);
                        break;
                    }
                    Proxy::Invalid => return None,
                    Proxy::Incomplete if buf.len() >= proxy_proto::MAX_HEADER => return None,
                    Proxy::Incomplete => fill(&mut stream, &mut buf).await?,
                }
            }
        }
        let mut hello = tls_hello::HelloParser::default();
        loop {
            match hello.advance(&buf) {
                Hello::Done { hello, .. } => {
                    return Some((
                        Replay {
                            prefix: buf,
                            pos: 0,
                            inner: stream,
                        },
                        src,
                        hello,
                    ));
                }
                Hello::Invalid => return None,
                Hello::Incomplete if buf.len() > tls_hello::MAX_HELLO + 5 => return None,
                Hello::Incomplete => fill(&mut stream, &mut buf).await?,
            }
        }
    })
    .await
    .ok()
    .flatten()
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

/// Serve HTTP on one connection. The client address handlers see is the
/// PROXY header's source when there is one.
async fn serve_conn<I>(io: I, peer: SocketAddr, meta: ConnMeta, app: axum::Router)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    let client = meta.proxied_src.unwrap_or(peer);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
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
    // Overall per-connection deadline bounds slow bodies and keep-alive
    // trickling as well as slow headers.
    let _ = tokio::time::timeout(
        Duration::from_secs(120),
        builder.serve_connection_with_upgrades(TokioIo::new(io), service),
    )
    .await;
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
}
