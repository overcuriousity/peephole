//! One TLS handshake that records what the server presents: its certificate
//! chain, the negotiated version and ALPN. Trust is not the question, so the
//! verifier accepts everything and only keeps the chain.

use super::{connect, sha256_hex, timed_out};
use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::time::{Instant, timeout_at};

/// Subject alternative names kept.
const MAX_SANS: usize = 50;

/// What one handshake showed.
#[derive(Debug, Clone)]
pub struct TlsSeen {
    /// The presented chain, leaf first, as DER.
    pub chain_der: Vec<Vec<u8>>,
    /// rustls' name for it, e.g. `TLSv1_3`.
    pub version: String,
    pub alpn: Option<String>,
}

/// Accepts any chain and keeps a copy of it.
#[derive(Debug)]
struct Keep {
    chain: Mutex<Vec<Vec<u8>>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Keep {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut chain = vec![end_entity.to_vec()];
        chain.extend(intermediates.iter().map(|c| c.to_vec()));
        *self.chain.lock().unwrap_or_else(|e| e.into_inner()) = chain;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Handshake with `ip:port` (SNI is the address, ALPN `h2, http/1.1`) and
/// record the chain, version and ALPN. Connection errors keep their
/// `io::Error` (refused, timed out) inside the `anyhow::Error`.
pub async fn capture(ip: IpAddr, port: u16, deadline: Instant) -> Result<TlsSeen> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let keep = Arc::new(Keep {
        chain: Mutex::new(Vec::new()),
        algs: provider.signature_verification_algorithms,
    });
    let mut cfg =
        rustls::ClientConfig::builder_with_provider(provider.clone() as Arc<CryptoProvider>)
            .with_protocol_versions(rustls::ALL_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(keep.clone())
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = connect(ip, port, deadline).await?;
    let tls = timeout_at(
        deadline,
        connector.connect(ServerName::IpAddress(ip.into()), tcp),
    )
    .await
    .map_err(|_| timed_out())??;
    let (_, conn) = tls.get_ref();
    let version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let chain_der = std::mem::take(&mut *keep.chain.lock().unwrap_or_else(|e| e.into_inner()));
    Ok(TlsSeen {
        chain_der,
        version,
        alpn,
    })
}

/// The handshake for people and the store: the leaf's SHA-256, subject,
/// issuer, names and validity (`YYYY-MM-DD`), the chain length, version and
/// ALPN. A leaf that does not parse still gives its hash.
pub fn json(seen: &TlsSeen) -> Value {
    let mut v = json!({
        "chain_len": seen.chain_der.len(),
        "version": seen.version,
        "alpn": seen.alpn,
    });
    let Some(leaf) = seen.chain_der.first() else {
        return v;
    };
    v["leaf_sha256"] = json!(sha256_hex(leaf));
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf) else {
        return v;
    };
    let day = |t: &x509_parser::time::ASN1Time| {
        chrono::DateTime::from_timestamp(t.timestamp(), 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    };
    let sans: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    x509_parser::extensions::GeneralName::IPAddress(b) => match b.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                        _ => None,
                    },
                    _ => None,
                })
                .take(MAX_SANS)
                .collect()
        })
        .unwrap_or_default();
    let validity = cert.validity();
    v["subject"] = json!(cert.subject().to_string());
    v["issuer"] = json!(cert.issuer().to_string());
    v["sans"] = json!(sans);
    v["not_before"] = json!(day(&validity.not_before));
    v["not_after"] = json!(day(&validity.not_after));
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A TLS server for `probe.test` (self-signed) offering `alpn`; returns
    /// its address and the certificate's DER. Each connection is held until
    /// the client leaves.
    pub(crate) async fn tls_server(alpn: &[&str]) -> (SocketAddr, Vec<u8>) {
        let pair = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["probe.test".into()])
            .unwrap()
            .self_signed(&pair)
            .unwrap();
        let der = cert.der().to_vec();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(pair.serialize_der()).unwrap(),
        )
        .unwrap();
        cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = acceptor.accept(s).await {
                        let mut buf = [0u8; 1024];
                        while matches!(t.read(&mut buf).await, Ok(n) if n > 0) {}
                    }
                });
            }
        });
        (addr, der)
    }

    #[tokio::test]
    async fn the_chain_version_and_alpn_are_captured() {
        let (addr, der) = tls_server(&["h2", "http/1.1"]).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = capture(addr.ip(), addr.port(), deadline).await.unwrap();
        assert_eq!(seen.chain_der, vec![der]);
        assert_eq!(seen.version, "TLSv1_3");
        assert_eq!(seen.alpn.as_deref(), Some("h2"));
        let j = json(&seen);
        assert_eq!(j["sans"], json!(["probe.test"]));
        assert_eq!(j["chain_len"], 1);
        assert_eq!(j["leaf_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(j["not_after"].as_str().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn a_port_without_tls_errors_quickly() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"SSH-2.0-OpenSSH_10.2\r\n").await.unwrap();
            let mut buf = [0u8; 1024];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        });
        let started = std::time::Instant::now();
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(capture(addr.ip(), addr.port(), deadline).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
