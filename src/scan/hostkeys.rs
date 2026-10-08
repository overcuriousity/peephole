//! Identifiers of the scanned source itself, from nmap's script output:
//! SSH host keys (`ssh-hostkey`), TLS certificates (`ssl-cert`) and the SSH
//! server's algorithm lists (`ssh2-enum-algos`), and the ETags of
//! `http-headers`. A host key or certificate found on several sources ties
//! them to one operator (or one firmware image); HASSH-server and JA4X name
//! the software, not the operator; an ETag, the same file, not the same
//! operator.
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
pub const FAVICON: &str = "favicon";
pub const JARM: &str = "jarm";
pub const HTTP_BODY: &str = "http-body";
pub const HTTP_404: &str = "http-404";
pub const HTTP_ETAG: &str = "http-etag";
/// Version of what `extract` reads (`scans.keys_parsed`). A change bumps
/// it, and the backfill reads every stored scan again.
pub const HOSTKEYS_V: i64 = 2;
/// Longest ETag kept, in characters.
const MAX_ETAG: usize = 128;

/// One identifier found on one port of a scanned source.
#[derive(Debug, Clone, PartialEq)]
pub struct HostKey {
    pub port: u16,
    /// [`SSH_HOSTKEY`], [`TLS_CERT`], [`JA4X`], [`HASSH`], or from probes
    /// [`FAVICON`], [`JARM`], [`HTTP_BODY`] or [`HTTP_404`]; from `http-headers`
    /// [`HTTP_ETAG`].
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

/// Like `key_attr`, with the XML escapes resolved (nmap writes newlines as
/// `&#xa;` and quotes as `&quot;` in `output`).
fn text_attr(e: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .map(|a| {
            #[allow(deprecated)]
            a.unescape_value()
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| a.value.to_string())
        })
}

/// The PTR names nmap recorded for the host (`<hostname type="PTR">`),
/// as valid host names, without repeats. Unparsable input yields what was
/// found before the error.
pub fn ptr_names(xml: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    while let Ok(ev) = reader.read_event_into(&mut buf) {
        match ev {
            Event::Start(e) | Event::Empty(e)
                if e.name().as_ref() == "hostname"
                    && key_attr(&e, "type").as_deref() == Some("PTR") =>
            {
                if let Some(n) =
                    key_attr(&e, "name").and_then(|n| crate::intel::dns::valid_name(&n))
                    && !out.contains(&n)
                {
                    out.push(n);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    out
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
                    if id == "http-headers"
                        && let Some(o) = text_attr(&e, "output")
                    {
                        etags(port, &o, &mut out);
                    }
                    if matches!(
                        id.as_str(),
                        "ssh-hostkey" | "ssl-cert" | "ssh2-enum-algos" | "http-headers"
                    ) {
                        script = Some(id);
                        stack = vec![(None, vec![])];
                    }
                }
                "table" if script.is_some() => stack.push((key_attr(&e, "key"), vec![])),
                "elem" if script.is_some() => text = Some((key_attr(&e, "key"), String::new())),
                _ => {}
            },
            Event::Empty(e)
                if port > 0
                    && e.name().as_ref() == "script"
                    && key_attr(&e, "id").as_deref() == Some("http-headers") =>
            {
                if let Some(o) = text_attr(&e, "output") {
                    etags(port, &o, &mut out);
                }
            }
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
                            "http-headers" => etags(port, &texts(&root).join("\n"), &mut out),
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

/// The `ETag` lines of an `http-headers` result, once per port and value.
fn etags(port: u16, text: &str, out: &mut Vec<HostKey>) {
    for line in text.lines() {
        let Some((name, value)) = line.trim().split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("etag") {
            continue;
        }
        let value: String = value.trim().chars().take(MAX_ETAG).collect();
        if value.is_empty()
            || out
                .iter()
                .any(|k| k.kind == HTTP_ETAG && k.port == port && k.fingerprint == value)
        {
            continue;
        }
        out.push(HostKey {
            port,
            kind: HTTP_ETAG,
            detail: nginx_detail(&value),
            fingerprint: value,
        });
    }
}

/// nginx's ETag is `"<mtime hex>-<size hex>"`: when the first part is a
/// plausible time (2000 to tomorrow), when the file was written and its
/// size. Empty for any other form.
fn nginx_detail(etag: &str) -> String {
    let v = etag.strip_prefix("W/").unwrap_or(etag).trim_matches('"');
    let Some((t, n)) = v.split_once('-') else {
        return String::new();
    };
    let hex = |s: &str| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex(t) || !hex(n) {
        return String::new();
    }
    let (Ok(t), Ok(n)) = (i64::from_str_radix(t, 16), u64::from_str_radix(n, 16)) else {
        return String::new();
    };
    let tomorrow = chrono::Utc::now().timestamp() + 86_400;
    if !(946_684_800..=tomorrow).contains(&t) {
        return String::new();
    }
    match chrono::DateTime::from_timestamp(t, 0) {
        Some(d) => format!("nginx: modified {}, {n} bytes", d.format("%Y-%m-%d")),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_are_read_from_http_headers() {
        let keys = extract(include_bytes!("../../tests/fixtures/nmap-http-headers.xml"));
        let etags: Vec<_> = keys.iter().filter(|k| k.kind == HTTP_ETAG).collect();
        assert_eq!(etags.len(), 2, "{etags:?}");
        assert_eq!(etags[0].port, 80);
        assert_eq!(etags[0].fingerprint, "\"5e9efe7d-264\"");
        assert_eq!(etags[0].detail, "nginx: modified 2020-04-21, 612 bytes");
        assert_eq!(etags[1].port, 8080);
        assert_eq!(etags[1].fingerprint, "W/\"2aa6-5f3c9a4b1e2c0\"");
        assert_eq!(etags[1].detail, "", "Apache's size-mtime form is not dated");
    }

    #[test]
    fn etag_lines_are_capped_and_malformed_ones_skipped() {
        let mut out = vec![];
        let long = "a".repeat(400);
        etags(
            80,
            &format!("no colon here\nETag:\n  X-ETag: \"nope\"\nETag: \"{long}\"\n"),
            &mut out,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].fingerprint.chars().count(), MAX_ETAG);
    }

    #[test]
    fn nginx_etags_are_dated_when_plausible() {
        assert_eq!(
            nginx_detail("\"5e9efe7d-264\""),
            "nginx: modified 2020-04-21, 612 bytes"
        );
        assert_eq!(
            nginx_detail("W/\"5e9efe7d-264\""),
            "nginx: modified 2020-04-21, 612 bytes"
        );
        assert_eq!(nginx_detail("\"1-2\""), "", "before 2000");
        assert_eq!(nginx_detail("\"ffffffff-2\""), "", "far future");
        assert_eq!(nginx_detail("\"abc\""), "");
        assert_eq!(nginx_detail("\"5e9efe7d-zz\""), "");
    }

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
