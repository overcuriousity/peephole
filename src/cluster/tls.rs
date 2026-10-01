//! Mutual TLS between nodes with pinned Ed25519 keys: no CA, no hostnames.
//! Each node presents a self-signed certificate for its node key; the TLS 1.3
//! CertificateVerify proves possession of that key. Clients pin the exact
//! key of the peer they dial; the server accepts any well-formed node key and
//! leaves authorization to the RPC layer (unknown keys may only `join`).
use super::identity::{Identity, NodeId};
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::sync::Arc;

/// ALPN: HTTP/2 preferred, HTTP/1.1 accepted.
const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The node key as a self-signed certificate plus its PKCS#8 private key.
#[derive(Clone)]
pub struct NodeCert {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl NodeCert {
    pub fn new(identity: &Identity) -> Result<Self> {
        let key = identity.pkcs8_der()?;
        let pair = rcgen::KeyPair::try_from(&PrivatePkcs8KeyDer::from(key.as_slice()))
            .context("node key for certificate")?;
        let mut params = rcgen::CertificateParams::new(vec!["peephole-node".to_string()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "peephole node");
        let cert = params.self_signed(&pair).context("self-signing")?;
        Ok(Self {
            cert: cert.der().clone(),
            key,
        })
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }
}

/// The Ed25519 key a node certificate is issued for.
pub fn cert_node_id(cert: &CertificateDer<'_>) -> Result<NodeId, Error> {
    let bad = || Error::InvalidCertificate(CertificateError::BadEncoding);
    let (_, x) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| bad())?;
    let spki = x.public_key();
    if spki.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
        return Err(Error::General(
            "node certificates must carry an Ed25519 key".into(),
        ));
    }
    NodeId::from_slice(&spki.subject_public_key.data).map_err(|_| bad())
}

/// Only Ed25519 handshake signatures, only TLS 1.3.
#[derive(Debug)]
struct Ed25519Only(WebPkiSupportedAlgorithms);

impl Ed25519Only {
    fn new() -> Self {
        Self(provider().signature_verification_algorithms)
    }
    fn verify13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(Error::PeerIncompatible(
                rustls::PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }
}

/// Client side: the server must present exactly the pinned node key.
#[derive(Debug)]
struct PinnedServer {
    expect: NodeId,
    algs: Ed25519Only,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if cert_node_id(end_entity)? == self.expect {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("nodes speak TLS 1.3 only".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.algs.verify13(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Server side: a client certificate is mandatory and must be a well-formed
/// node key; which keys may do what is decided per request.
#[derive(Debug)]
struct AnyNodeClient {
    algs: Ed25519Only,
}

impl ClientCertVerifier for AnyNodeClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        cert_node_id(end_entity).map(|_| ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("nodes speak TLS 1.3 only".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.algs.verify13(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub fn server_config(cert: &NodeCert) -> Result<Arc<rustls::ServerConfig>> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyNodeClient {
            algs: Ed25519Only::new(),
        }))
        .with_single_cert(vec![cert.cert.clone()], cert.private_key())?;
    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// Client TLS config that only completes a handshake with `peer`.
pub fn client_config(cert: &NodeCert, peer: NodeId) -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            expect: peer,
            algs: Ed25519Only::new(),
        }))
        .with_client_auth_cert(vec![cert.cert.clone()], cert.private_key())?;
    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_carries_the_node_key() {
        let id = Identity::generate().unwrap();
        let cert = NodeCert::new(&id).unwrap();
        assert_eq!(cert_node_id(&cert.cert).unwrap(), id.id);
        server_config(&cert).unwrap();
        client_config(&cert, id.id).unwrap();
    }
}
