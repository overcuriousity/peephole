//! Identifiers of the scanned source itself, from nmap's script output:
//! SSH host keys (`ssh-hostkey`), TLS certificates (`ssl-cert`) and the SSH
//! server's algorithm lists (`ssh2-enum-algos`). A host key or certificate
//! found on several sources ties them to one operator (or one firmware
//! image); HASSH-server and JA4X name the software, not the operator.
//!
//! Derived from the stored XML on every node, so they need no replication
//! of their own and older scans can be parsed after the fact.

use quick_xml::Reader;
use quick_xml::events::Event;
use sha2::{Digest, Sha256};

pub const SSH_HOSTKEY: &str = "ssh-hostkey";
pub const TLS_CERT: &str = "tls-cert";
pub const JA4X: &str = "ja4x";
pub const HASSH: &str = "hassh";

/// One identifier found on one port of a scanned source.
#[derive(Debug, Clone, PartialEq)]
pub struct HostKey {
    pub port: u16,
    /// [`SSH_HOSTKEY`], [`TLS_CERT`], [`JA4X`] or [`HASSH`].
    pub kind: &'static str,
    /// `SHA256:<base64>` as OpenSSH prints it; the certificate's SHA-256
    /// (hex, of the DER); the JA4X string; the HASSH-server MD5 (hex).
    pub fingerprint: String,
    /// For people: key type and size, certificate subject and validity, the
    /// algorithm lists HASSH was computed from.
    pub detail: String,
}

/// Structured script output: nmap's `<table>` and `<elem>`.
#[derive(Debug)]
enum Node {
    Table {
        key: Option<String>,
        children: Vec<Node>,
    },
    Elem {
        key: Option<String>,
        text: String,
    },
}

fn elem<'a>(nodes: &'a [Node], name: &str) -> Option<&'a str> {
    nodes.iter().find_map(|n| match n {
        Node::Elem { key: Some(k), text } if k == name => Some(text.as_str()),
        _ => None,
    })
}

fn table<'a>(nodes: &'a [Node], name: &str) -> Option<&'a [Node]> {
    nodes.iter().find_map(|n| match n {
        Node::Table {
            key: Some(k),
            children,
        } if k == name => Some(children.as_slice()),
        _ => None,
    })
}

fn texts(nodes: &[Node]) -> Vec<&str> {
    nodes
        .iter()
        .filter_map(|n| match n {
            Node::Elem { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn key_attr(e: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .map(|a| a.value.to_string())
}

/// Every identifier in an nmap XML report. Unparsable input yields what
/// was found before the error: the XML comes from nmap, but the values in
/// it from the scanned source.
pub fn extract(xml: &[u8]) -> Vec<HostKey> {
    let mut out = vec![];
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut port: u16 = 0;
    // Inside a script we read: its id and the open tables, root first.
    let mut script: Option<String> = None;
    let mut stack: Vec<(Option<String>, Vec<Node>)> = vec![];
    let mut text: Option<(Option<String>, String)> = None;
    while let Ok(ev) = reader.read_event_into(&mut buf) {
        match ev {
            Event::Start(e) => match e.name().as_ref() {
                "port" => {
                    port = key_attr(&e, "portid")
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(0)
                }
                "script" if port > 0 => {
                    let id = key_attr(&e, "id").unwrap_or_default();
                    if matches!(id.as_str(), "ssh-hostkey" | "ssl-cert" | "ssh2-enum-algos") {
                        script = Some(id);
                        stack = vec![(None, vec![])];
                    }
                }
                "table" if script.is_some() => stack.push((key_attr(&e, "key"), vec![])),
                "elem" if script.is_some() => text = Some((key_attr(&e, "key"), String::new())),
                _ => {}
            },
            Event::Empty(e) if script.is_some() && e.name().as_ref() == "elem" => {
                if let Some(top) = stack.last_mut() {
                    top.1.push(Node::Elem {
                        key: key_attr(&e, "key"),
                        text: String::new(),
                    });
                }
            }
            Event::Text(t) => {
                if let Some((_, s)) = text.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::CData(t) => {
                if let Some((_, s)) = text.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::GeneralRef(r) => {
                if let Some((_, s)) = text.as_mut() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) => s.push(c),
                        _ => s.push_str(match &*r {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "quot" => "\"",
                            "apos" => "'",
                            _ => "",
                        }),
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                "port" => port = 0,
                "elem" => {
                    if let (Some((key, s)), Some(top)) = (text.take(), stack.last_mut()) {
                        top.1.push(Node::Elem { key, text: s });
                    }
                }
                "table" if stack.len() > 1 => {
                    let (key, children) = stack.pop().expect("len > 1");
                    if let Some(top) = stack.last_mut() {
                        top.1.push(Node::Table { key, children });
                    }
                }
                "script" => {
                    if let (Some(id), Some((_, root))) = (script.take(), stack.pop()) {
                        match id.as_str() {
                            "ssh-hostkey" => ssh_hostkeys(port, &root, &mut out),
                            "ssl-cert" => tls_cert(port, &root, &mut out),
                            _ => hassh(port, &root, &mut out),
                        }
                    }
                    stack.clear();
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

fn ssh_hostkeys(port: u16, root: &[Node], out: &mut Vec<HostKey>) {
    use data_encoding::{BASE64, BASE64_NOPAD};
    for n in root {
        let Node::Table { children: k, .. } = n else {
            continue;
        };
        let Some(blob) = elem(k, "key").and_then(|b| BASE64.decode(b.trim().as_bytes()).ok())
        else {
            continue;
        };
        let typ = elem(k, "type").unwrap_or("unknown");
        let bits = elem(k, "bits").unwrap_or("");
        out.push(HostKey {
            port,
            kind: SSH_HOSTKEY,
            fingerprint: format!("SHA256:{}", BASE64_NOPAD.encode(&Sha256::digest(&blob))),
            detail: format!("{typ} {bits}").trim().to_string(),
        });
    }
}

fn tls_cert(port: u16, root: &[Node], out: &mut Vec<HostKey>) {
    let Some(pem) = elem(root, "pem") else {
        return;
    };
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
        .collect();
    let Ok(der) = data_encoding::BASE64.decode(body.as_bytes()) else {
        return;
    };
    let fingerprint = data_encoding::HEXLOWER.encode(&Sha256::digest(&der));
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) else {
        // Not a certificate we can read: still an identifier.
        out.push(HostKey {
            port,
            kind: TLS_CERT,
            fingerprint,
            detail: String::new(),
        });
        return;
    };
    let day = |t: &x509_parser::time::ASN1Time| {
        chrono::DateTime::from_timestamp(t.timestamp(), 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    };
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let v = cert.validity();
    let mut detail = if subject.is_empty() {
        "(no subject)".to_string()
    } else {
        subject.clone()
    };
    if subject == issuer {
        detail.push_str(" · self-signed");
    } else {
        detail.push_str(&format!(" · issuer {issuer}"));
    }
    detail.push_str(&format!(
        " · {} → {}",
        day(&v.not_before),
        day(&v.not_after)
    ));
    out.push(HostKey {
        port,
        kind: TLS_CERT,
        fingerprint,
        detail,
    });
    out.push(HostKey {
        port,
        kind: JA4X,
        fingerprint: ja4x(&cert),
        detail: String::new(),
    });
}

/// JA4X (FoxIO): how the certificate was built, not who it is for — the
/// OIDs of the issuer's and subject's RDNs and of the extensions, in
/// order, each list hashed (SHA-256, first 12 hex digits).
fn ja4x(cert: &x509_parser::certificate::X509Certificate) -> String {
    fn part(oids: Vec<Vec<u8>>) -> String {
        if oids.is_empty() {
            return "000000000000".into();
        }
        let joined = oids
            .iter()
            .map(|o| data_encoding::HEXLOWER.encode(o))
            .collect::<Vec<_>>()
            .join(",");
        data_encoding::HEXLOWER.encode(&Sha256::digest(joined.as_bytes()))[..12].to_string()
    }
    let rdns = |name: &x509_parser::x509::X509Name| {
        name.iter()
            .flat_map(|rdn| rdn.iter().map(|a| a.attr_type().as_bytes().to_vec()))
            .collect::<Vec<_>>()
    };
    let exts = cert
        .extensions()
        .iter()
        .map(|e| e.oid.as_bytes().to_vec())
        .collect();
    format!(
        "{}_{}_{}",
        part(rdns(cert.issuer())),
        part(rdns(cert.subject())),
        part(exts)
    )
}

/// HASSH-server (Salesforce): MD5 of the server's key exchange, cipher,
/// MAC and compression lists, comma-joined, `;` between them.
fn hassh(port: u16, root: &[Node], out: &mut Vec<HostKey>) {
    let list = |name| table(root, name).map(|t| texts(t).join(","));
    let (Some(kex), Some(enc), Some(mac), Some(comp)) = (
        list("kex_algorithms"),
        list("encryption_algorithms"),
        list("mac_algorithms"),
        list("compression_algorithms"),
    ) else {
        return;
    };
    let s = format!("{kex};{enc};{mac};{comp}");
    out.push(HostKey {
        port,
        kind: HASSH,
        fingerprint: data_encoding::HEXLOWER.encode(&md5::Md5::digest(s.as_bytes())),
        detail: s,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keys_certificates_and_hassh_from_a_scan() {
        let keys = extract(include_bytes!("../../tests/fixtures/nmap-hostkeys.xml"));
        let of = |kind| keys.iter().filter(|k| k.kind == kind).collect::<Vec<_>>();

        let ssh = of(SSH_HOSTKEY);
        assert_eq!(ssh.len(), 2, "{keys:?}");
        assert!(ssh.iter().all(|k| k.port == 22));
        // ssh-keygen -lf of the fixture's ed25519 key.
        assert_eq!(
            ssh[1].fingerprint,
            "SHA256:LvbxsAtrLqDESt7sCPrXK6n7L9j4J9myhtEO50ocsdM"
        );
        assert_eq!(ssh[1].detail, "ssh-ed25519 256");

        let cert = of(TLS_CERT);
        assert_eq!(cert.len(), 1);
        assert_eq!(cert[0].port, 443);
        assert_eq!(cert[0].fingerprint.len(), 64);
        assert!(
            cert[0].detail.contains("CN=trap.example"),
            "{}",
            cert[0].detail
        );
        assert!(cert[0].detail.contains("self-signed"), "{}", cert[0].detail);
        let ja4x = of(JA4X);
        assert_eq!(ja4x.len(), 1);
        assert_eq!(ja4x[0].fingerprint.len(), 38, "{}", ja4x[0].fingerprint);

        let h = of(HASSH);
        assert_eq!(h.len(), 1);
        assert_eq!(
            h[0].detail,
            "curve25519-sha256,ecdh-sha2-nistp256;aes128-ctr,chacha20-poly1305@openssh.com;hmac-sha2-256;none,zlib@openssh.com"
        );
        assert_eq!(
            h[0].fingerprint,
            data_encoding::HEXLOWER.encode(&md5::Md5::digest(h[0].detail.as_bytes()))
        );
    }

    /// Output of nmap 7.92 against OpenSSH 10.2 and `openssl s_server`;
    /// the expected values are what `ssh-keygen -lf` and
    /// `openssl x509 -fingerprint -sha256` print for the same keys.
    #[test]
    fn real_nmap_output() {
        let ssh = extract(include_bytes!("../../tests/fixtures/nmap-real-ssh.xml"));
        let fps: Vec<_> = ssh
            .iter()
            .filter(|k| k.kind == SSH_HOSTKEY)
            .map(|k| (k.port, k.fingerprint.as_str(), k.detail.as_str()))
            .collect();
        assert_eq!(
            fps,
            [
                (
                    18025,
                    "SHA256:aaslKLgLng8kiw+bsGf0eV1bL3uLG8OWrhLzEy9dKt0",
                    "ecdsa-sha2-nistp256 256"
                ),
                (
                    18025,
                    "SHA256:LvbxsAtrLqDESt7sCPrXK6n7L9j4J9myhtEO50ocsdM",
                    "ssh-ed25519 256"
                ),
            ]
        );
        let hassh = ssh.iter().find(|k| k.kind == HASSH).unwrap();
        assert!(
            hassh.detail.starts_with("mlkem768x25519-sha256,"),
            "{}",
            hassh.detail
        );
        assert_eq!(hassh.detail.matches(';').count(), 3);

        let tls = extract(include_bytes!("../../tests/fixtures/nmap-real-tls.xml"));
        let cert = tls.iter().find(|k| k.kind == TLS_CERT).unwrap();
        assert_eq!(
            cert.fingerprint,
            "f455ac3028f1374007e0447c17310669f206f405cdcac53281b4e907f1dd66ea"
        );
        assert_eq!(cert.port, 18443);
        let ja4x = tls.iter().find(|k| k.kind == JA4X).unwrap();
        // CN only, on both sides; SKI, AKI and basic constraints.
        assert_eq!(ja4x.fingerprint, "7022c563de38_7022c563de38_795797892f9c");
    }

    #[test]
    fn nothing_from_scans_without_scripts_or_from_garbage() {
        assert!(extract(include_bytes!("../../tests/fixtures/nmap-basic.xml")).is_empty());
        assert!(extract(b"<nmaprun><host><ports><port portid=\"22\"><script id=\"ssh-hostkey\"><table><elem key=\"key\">not base64!</elem></table></script></port></ports></host></nmaprun>").is_empty());
        assert!(extract(b"\x00\x01 not xml").is_empty());
    }
}
