//! The TLS ClientHello as the client sent it, and its JA4 fingerprint
//! (FoxIO, <https://github.com/FoxIO-LLC/ja4>, TCP variant).

use sha2::Digest;

/// Largest ClientHello (records included) the trap reads.
pub const MAX_HELLO: usize = 16 * 1024;

/// The fields of a ClientHello that JA4 and the dataset use.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientHello {
    /// The TLS records that carried it, as sent.
    pub raw: Vec<u8>,
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types in the order sent.
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub sig_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
}

pub enum Hello {
    /// Not enough bytes yet.
    Incomplete,
    /// Not a TLS ClientHello (or one past [`MAX_HELLO`]).
    Invalid,
    /// Parsed; `consumed` bytes of the input were its records.
    Done { hello: ClientHello, consumed: usize },
}

/// Parse a ClientHello from the start of a TCP stream, reassembling the
/// handshake message across TLS records.
pub fn parse_client_hello(buf: &[u8]) -> Hello {
    let mut msg: Vec<u8> = vec![];
    let mut pos = 0;
    loop {
        if pos > MAX_HELLO {
            return Hello::Invalid;
        }
        // Enough of the message to know its length?
        if msg.len() >= 4 {
            if msg[0] != 1 {
                return Hello::Invalid;
            }
            let len = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
            if len > MAX_HELLO {
                return Hello::Invalid;
            }
            if msg.len() >= 4 + len {
                return match parse_body(&msg[4..4 + len]) {
                    Some(mut hello) => {
                        hello.raw = buf[..pos].to_vec();
                        Hello::Done {
                            hello,
                            consumed: pos,
                        }
                    }
                    None => Hello::Invalid,
                };
            }
        }
        let Some(head) = buf.get(pos..pos + 5) else {
            return check_partial(&buf[pos..]);
        };
        if head[0] != 0x16 || head[1] != 3 {
            return Hello::Invalid;
        }
        let len = u16::from_be_bytes([head[3], head[4]]) as usize;
        if len == 0 || len > 16384 + 2048 {
            return Hello::Invalid;
        }
        let Some(frag) = buf.get(pos + 5..pos + 5 + len) else {
            return Hello::Incomplete;
        };
        msg.extend_from_slice(frag);
        pos += 5 + len;
    }
}

/// A record header cut short: still possibly TLS?
fn check_partial(rest: &[u8]) -> Hello {
    match rest {
        [] | [0x16] | [0x16, 3, ..] => Hello::Incomplete,
        _ => Hello::Invalid,
    }
}

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    /// A block with a 1- or 2-byte length prefix.
    fn block8(&mut self) -> Option<Cur<'a>> {
        let n = self.u8()? as usize;
        self.take(n).map(Cur)
    }
    fn block16(&mut self) -> Option<Cur<'a>> {
        let n = self.u16()? as usize;
        self.take(n).map(Cur)
    }
    fn u16s(mut self) -> Option<Vec<u16>> {
        if !self.0.len().is_multiple_of(2) {
            return None;
        }
        let mut v = vec![];
        while !self.0.is_empty() {
            v.push(self.u16()?);
        }
        Some(v)
    }
}

fn parse_body(body: &[u8]) -> Option<ClientHello> {
    let mut c = Cur(body);
    let mut h = ClientHello {
        legacy_version: c.u16()?,
        ..Default::default()
    };
    c.take(32)?;
    c.block8()?; // session id
    h.ciphers = c.block16()?.u16s()?;
    c.block8()?; // compression methods
    if c.0.is_empty() {
        return Some(h);
    }
    let mut exts = c.block16()?;
    while !exts.0.is_empty() {
        let t = exts.u16()?;
        let mut data = exts.block16()?;
        h.extensions.push(t);
        match t {
            0x0000 => {
                let mut list = data.block16()?;
                while !list.0.is_empty() {
                    let kind = list.u8()?;
                    let name = list.block16()?.0;
                    if kind == 0 && h.sni.is_none() {
                        h.sni = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            0x0010 => {
                let mut list = data.block16()?;
                while !list.0.is_empty() {
                    h.alpn.push(list.block8()?.0.to_vec());
                }
            }
            0x000d => h.sig_algs = data.block16()?.u16s()?,
            0x002b => h.supported_versions = data.block8()?.u16s()?,
            _ => {}
        }
    }
    Some(h)
}

/// GREASE values (RFC 8701): 0x0a0a, 0x1a1a, … 0xfafa.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn hash12(s: &str) -> String {
    data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(s.as_bytes()))[..12].to_string()
}

fn hex4(v: &[u16]) -> String {
    v.iter()
        .map(|x| format!("{x:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The JA4 fingerprint (TCP) of a ClientHello.
pub fn ja4(h: &ClientHello) -> String {
    let version = h
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !grease(*v))
        .max()
        .unwrap_or(h.legacy_version);
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let sni = if h.extensions.contains(&0x0000) {
        'd'
    } else {
        'i'
    };
    let mut ciphers: Vec<u16> = h.ciphers.iter().copied().filter(|v| !grease(*v)).collect();
    let exts: Vec<u16> = h
        .extensions
        .iter()
        .copied()
        .filter(|v| !grease(*v))
        .collect();
    let alpn = match h.alpn.first() {
        Some(a) if !a.is_empty() => {
            let (f, l) = (a[0], a[a.len() - 1]);
            if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
                format!("{}{}", f as char, l as char)
            } else {
                let fh = format!("{f:02x}");
                let lh = format!("{l:02x}");
                format!("{}{}", &fh[..1], &lh[1..])
            }
        }
        _ => "00".into(),
    };
    let a = format!(
        "t{version}{sni}{:02}{:02}{alpn}",
        ciphers.len().min(99),
        exts.len().min(99)
    );
    ciphers.sort_unstable();
    let b = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        hash12(&hex4(&ciphers))
    };
    let mut sorted: Vec<u16> = exts
        .into_iter()
        .filter(|v| *v != 0x0000 && *v != 0x0010)
        .collect();
    sorted.sort_unstable();
    let c = if sorted.is_empty() {
        "000000000000".to_string()
    } else {
        // Signature algorithms as sent, unsorted.
        let mut text = hex4(&sorted);
        if !h.sig_algs.is_empty() {
            text.push('_');
            text.push_str(&hex4(&h.sig_algs));
        }
        hash12(&text)
    };
    format!("{a}_{b}_{c}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn sha12(s: &str) -> String {
        data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(s.as_bytes()))[..12].to_string()
    }

    fn ext(t: u16, body: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend((body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    }

    fn list16(items: &[u16]) -> Vec<u8> {
        let mut v = ((items.len() * 2) as u16).to_be_bytes().to_vec();
        for i in items {
            v.extend(i.to_be_bytes());
        }
        v
    }

    /// A ClientHello handshake message (no record header) with the given
    /// ALPN values.
    fn hello_msg(alpn: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]); // random
        body.push(0); // session id
        body.extend(list16(&[0x1a1a, 0x1301, 0x1302, 0xc02b]));
        body.extend([1, 0]); // compression: null
        let mut exts = vec![];
        exts.extend(ext(0x0a0a, &[]));
        let name = b"example.com";
        let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        sni.push(0);
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name);
        exts.extend(ext(0x0000, &sni));
        let mut protos = vec![];
        for p in alpn {
            protos.push(p.len() as u8);
            protos.extend(*p);
        }
        let mut a = (protos.len() as u16).to_be_bytes().to_vec();
        a.extend(protos);
        exts.extend(ext(0x0010, &a));
        exts.extend(ext(0x000d, &list16(&[0x0403, 0x0804, 0x0401])));
        let mut sv = vec![6u8];
        for v in [0x1a1au16, 0x0304, 0x0303] {
            sv.extend(v.to_be_bytes());
        }
        exts.extend(ext(0x002b, &sv));
        exts.extend(ext(0x000a, &list16(&[0x001d, 0x0017])));
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut msg = vec![1u8];
        msg.extend(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend(body);
        msg
    }

    fn record(frag: &[u8]) -> Vec<u8> {
        let mut r = vec![0x16, 0x03, 0x01];
        r.extend((frag.len() as u16).to_be_bytes());
        r.extend(frag);
        r
    }

    fn build_hello() -> Vec<u8> {
        record(&hello_msg(&[b"h2", b"http/1.1"]))
    }

    #[test]
    fn ja4_of_a_built_hello() {
        let raw = build_hello();
        let Hello::Done { hello, consumed } = parse_client_hello(&raw) else {
            panic!("not parsed")
        };
        assert_eq!(consumed, raw.len());
        assert_eq!(hello.raw, raw);
        assert_eq!(hello.sni.as_deref(), Some("example.com"));
        let b = sha12("1301,1302,c02b");
        let c = sha12("000a,000d,002b_0403,0804,0401");
        assert_eq!(ja4(&hello), format!("t13d0305h2_{b}_{c}"));
    }

    #[test]
    fn a_hello_split_across_records_parses_only_when_complete() {
        let msg = hello_msg(&[b"h2"]);
        let (a, b) = msg.split_at(40);
        let mut raw = record(a);
        raw.extend(record(b));
        for n in 0..raw.len() {
            assert!(
                matches!(parse_client_hello(&raw[..n]), Hello::Incomplete),
                "prefix {n}"
            );
        }
        let Hello::Done { hello, consumed } = parse_client_hello(&raw) else {
            panic!()
        };
        assert_eq!(consumed, raw.len());
        assert_eq!(hello.raw, raw);
        assert_eq!(hello.ciphers, [0x1a1a, 0x1301, 0x1302, 0xc02b]);
    }

    #[test]
    fn bytes_after_the_hello_are_not_consumed() {
        let mut raw = build_hello();
        let n = raw.len();
        raw.extend(b"\x14\x03\x03\x00\x01\x01");
        let Hello::Done { consumed, .. } = parse_client_hello(&raw) else {
            panic!()
        };
        assert_eq!(consumed, n);
    }

    #[test]
    fn plain_http_is_invalid() {
        assert!(matches!(
            parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Hello::Invalid
        ));
    }

    #[test]
    fn alpn_that_is_not_alphanumeric_is_shown_as_hex() {
        let raw = record(&hello_msg(&[&[0xab, 0x01]]));
        let Hello::Done { hello, .. } = parse_client_hello(&raw) else {
            panic!()
        };
        assert_eq!(&ja4(&hello)[8..10], "a1");
    }

    #[test]
    fn no_alpn_no_sni_and_tls12() {
        let h = ClientHello {
            legacy_version: 0x0303,
            ciphers: vec![0xc02f],
            extensions: vec![0x000a],
            ..Default::default()
        };
        assert_eq!(&ja4(&h)[..10], "t12i010100");
        // No signature algorithms: no trailing underscore part.
        assert!(ja4(&h).ends_with(&sha12("000a")));
    }

    #[test]
    fn mutations_never_panic() {
        let raw = build_hello();
        for n in 0..raw.len() {
            let _ = parse_client_hello(&raw[..n]);
            for x in [0u8, 0xff, 0x7f] {
                let mut m = raw.clone();
                m[n] = x;
                if let Hello::Done { hello, .. } = parse_client_hello(&m) {
                    let _ = ja4(&hello);
                }
            }
        }
    }
}
