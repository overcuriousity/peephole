//! TLS accept loop: every connection carries the verified peer key into
//! the axum handlers as an [`Peer`] extension.
use crate::cluster::identity::NodeId;
use crate::cluster::tls::cert_node_id;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
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

pub async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
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
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
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
            let svc = app
                .layer(axum::Extension(Peer(peer)))
                .layer(axum::Extension(RemoteAddr(addr)));
            let svc = hyper_util::service::TowerToHyperService::new(svc);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                debug!(%addr, ?e, "rpc connection ended with error");
            }
        });
    }
}
