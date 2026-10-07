//! JARM (Salesforce): ten deliberately odd ClientHellos, each answer reduced
//! to `cipher|version|alpn|extensions`, then fuzzy-hashed into 62 hex
//! characters. Ported from the reference implementation (`jarm.py`,
//! salesforce/jarm, version 1.0) byte for byte, including its quirks, so the
//! result matches what JARM databases hold.

use super::{connect, connection_deadline};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

/// What the reference reads of a ServerHello (one `recv`).
const MAX_READ: usize = 1484;
/// The hash when nothing answered.
const ZERO: &str = "00000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Version {
    Tls11,
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Order {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Support {
    /// `supported_versions` up to TLS 1.2.
    Tls12,
    /// No `supported_versions` unless the version is TLS 1.3.
    None,
    /// `supported_versions` up to TLS 1.3.
    Tls13,
}

/// One of the ten ClientHello shapes.
#[derive(Debug, Clone)]
pub struct Probe {
    pub name: &'static str,
    host: String,
    version: Version,
    /// All ciphers, or none of the TLS 1.3 ones (`NO1.3`).
    all_ciphers: bool,
    cipher_order: Order,
    grease: bool,
    rare_alpn: bool,
    support: Support,
    /// Order of the ALPN and supported_versions lists.
    ext_order: Order,
}

/// The ten shapes in the reference's order; `host` goes into SNI.
pub fn probes(host: &str) -> Vec<Probe> {
    use Order::*;
    let p =
        |name, version, all_ciphers, cipher_order, grease, rare_alpn, support, ext_order| Probe {
            name,
            host: host.to_string(),
            version,
            all_ciphers,
            cipher_order,
            grease,
            rare_alpn,
            support,
            ext_order,
        };
    vec![
        p(
            "tls1_2_forward",
            Version::Tls12,
            true,
            Forward,
            false,
            false,
            Support::Tls12,
            Reverse,
        ),
        p(
            "tls1_2_reverse",
            Version::Tls12,
            true,
            Reverse,
            false,
            false,
            Support::Tls12,
            Forward,
        ),
        p(
            "tls1_2_top_half",
            Version::Tls12,
            true,
            TopHalf,
            false,
            false,
            Support::None,
            Forward,
        ),
        p(
            "tls1_2_bottom_half",
            Version::Tls12,
            true,
            BottomHalf,
            false,
            true,
            Support::None,
            Forward,
        ),
        p(
            "tls1_2_middle_out",
            Version::Tls12,
            true,
            MiddleOut,
            true,
            true,
            Support::None,
            Reverse,
        ),
        p(
            "tls1_1_middle_out",
            Version::Tls11,
            true,
            Forward,
            false,
            false,
            Support::None,
            Forward,
        ),
        p(
            "tls1_3_forward",
            Version::Tls13,
            true,
            Forward,
            false,
            false,
            Support::Tls13,
            Reverse,
        ),
        p(
            "tls1_3_reverse",
            Version::Tls13,
            true,
            Reverse,
            false,
            false,
            Support::Tls13,
            Forward,
        ),
        p(
            "tls1_3_invalid",
            Version::Tls13,
            false,
            Forward,
            false,
            false,
            Support::Tls13,
            Forward,
        ),
        p(
            "tls1_3_middle_out",
            Version::Tls13,
            true,
            MiddleOut,
            true,
            false,
            Support::Tls13,
            Reverse,
        ),
    ]
}

/// The reference's cipher list (`ALL`), in its order.
const CIPHERS: [u16; 69] = [
    0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045,
    0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
    0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
    0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
    0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d,
    0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
];

/// The ciphers of the fuzzy hash: a cipher's (1-based) index here is its
/// two hex characters; an unknown one is one past the end.
const CIPHER_INDEX: [u16; 69] = [
    0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041,
    0x0045, 0x0067, 0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be,
    0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024,
    0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077,
    0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
    0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
];

/// The ALPN list from weakest to strongest, and the rare one (without
/// `http/1.1` and `h2`).
const ALPNS: [&[u8]; 9] = [
    b"http/0.9",
    b"http/1.0",
    b"http/1.1",
    b"spdy/1",
    b"spdy/2",
    b"spdy/3",
    b"h2",
    b"h2c",
    b"hq",
];
const RARE_ALPNS: [&[u8]; 7] = [
    b"http/0.9",
    b"http/1.0",
    b"spdy/1",
    b"spdy/2",
    b"spdy/3",
    b"h2c",
    b"hq",
];

/// A random GREASE value (`0x?a?a`).
fn grease() -> [u8; 2] {
    let b = (rand::random::<u8>() & 0xf0) | 0x0a;
    [b, b]
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

/// The reference's `cipher_mung`.
fn mung<T: Clone>(items: &[T], order: Order) -> Vec<T> {
    let len = items.len();
    match order {
        Order::Forward => items.to_vec(),
        Order::Reverse => items.iter().rev().cloned().collect(),
        Order::BottomHalf => items[len / 2 + len % 2..].to_vec(),
        Order::TopHalf => {
            let mut out = Vec::new();
            if len % 2 == 1 {
                out.push(items[len / 2].clone());
            }
            out.extend(mung(&mung(items, Order::Reverse), Order::BottomHalf));
            out
        }
        Order::MiddleOut => {
            let middle = len / 2;
            let mut out = Vec::new();
            if len % 2 == 1 {
                out.push(items[middle].clone());
                for i in 1..=middle {
                    out.push(items[middle + i].clone());
                    out.push(items[middle - i].clone());
                }
            } else {
                for i in 1..=middle {
                    out.push(items[middle - 1 + i].clone());
                    out.push(items[middle - i].clone());
                }
            }
            out
        }
    }
}

fn u16be(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

impl Probe {
    /// The ClientHello as one TLS record, with fresh randoms and GREASE.
    pub fn build(&self) -> Vec<u8> {
        self.build_with(&mut || random::<32>(), &mut grease)
    }

    /// [`Probe::build`] with the randomness supplied (each 32-byte random
    /// and each GREASE value is drawn in the reference's order).
    fn build_with(
        &self,
        random32: &mut dyn FnMut() -> [u8; 32],
        grease: &mut dyn FnMut() -> [u8; 2],
    ) -> Vec<u8> {
        let (record_version, hello_version): (&[u8], &[u8]) = match self.version {
            Version::Tls13 => (b"\x03\x01", b"\x03\x03"),
            Version::Tls12 => (b"\x03\x03", b"\x03\x03"),
            Version::Tls11 => (b"\x03\x02", b"\x03\x02"),
        };
        let mut hello = hello_version.to_vec();
        hello.extend(random32());
        hello.push(32);
        hello.extend(random32());
        let ciphers = self.ciphers(grease);
        hello.extend(u16be(ciphers.len()));
        hello.extend(ciphers);
        hello.extend(b"\x01\x00"); // one compression method: null
        hello.extend(self.extensions(random32, grease));
        let mut handshake = vec![0x01, 0x00];
        handshake.extend(u16be(hello.len()));
        handshake.extend(hello);
        let mut record = vec![0x16];
        record.extend(record_version);
        record.extend(u16be(handshake.len()));
        record.extend(handshake);
        record
    }

    fn ciphers(&self, grease: &mut dyn FnMut() -> [u8; 2]) -> Vec<u8> {
        let list: Vec<u16> = CIPHERS
            .iter()
            .copied()
            .filter(|c| self.all_ciphers || !(0x1301..=0x1305).contains(c))
            .collect();
        let list = mung(&list, self.cipher_order);
        let mut out = Vec::new();
        if self.grease {
            out.extend(grease());
        }
        for c in list {
            out.extend(c.to_be_bytes());
        }
        out
    }

    fn extensions(
        &self,
        random32: &mut dyn FnMut() -> [u8; 32],
        grease: &mut dyn FnMut() -> [u8; 2],
    ) -> Vec<u8> {
        let mut all = Vec::new();
        if self.grease {
            all.extend(grease());
            all.extend(b"\x00\x00");
        }
        // server_name
        let host = self.host.as_bytes();
        all.extend(b"\x00\x00");
        all.extend(u16be(host.len() + 5));
        all.extend(u16be(host.len() + 3));
        all.push(0);
        all.extend(u16be(host.len()));
        all.extend(host);
        all.extend(b"\x00\x17\x00\x00"); // extended_master_secret
        all.extend(b"\x00\x01\x00\x01\x01"); // max_fragment_length
        all.extend(b"\xff\x01\x00\x01\x00"); // renegotiation_info
        all.extend(b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"); // groups
        all.extend(b"\x00\x0b\x00\x02\x01\x00"); // ec_point_formats
        all.extend(b"\x00\x23\x00\x00"); // session_ticket
        // ALPN
        let alpns: &[&[u8]] = if self.rare_alpn { &RARE_ALPNS } else { &ALPNS };
        let mut list = Vec::new();
        for a in mung(alpns, self.ext_order) {
            list.push(a.len() as u8);
            list.extend(a);
        }
        all.extend(b"\x00\x10");
        all.extend(u16be(list.len() + 2));
        all.extend(u16be(list.len()));
        all.extend(list);
        // signature_algorithms
        all.extend(
            b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01",
        );
        // key_share: x25519 with random bytes (after a GREASE share)
        let mut share = Vec::new();
        if self.grease {
            share.extend(grease());
            share.extend(b"\x00\x01\x00");
        }
        share.extend(b"\x00\x1d\x00\x20");
        share.extend(random32());
        all.extend(b"\x00\x33");
        all.extend(u16be(share.len() + 2));
        all.extend(u16be(share.len()));
        all.extend(share);
        all.extend(b"\x00\x2d\x00\x02\x01\x01"); // psk_key_exchange_modes
        if self.version == Version::Tls13 || self.support == Support::Tls12 {
            let tls: &[[u8; 2]] = if self.support == Support::Tls12 {
                &[[3, 1], [3, 2], [3, 3]]
            } else {
                &[[3, 1], [3, 2], [3, 3], [3, 4]]
            };
            let mut versions = Vec::new();
            if self.grease {
                versions.extend(grease());
            }
            for v in mung(tls, self.ext_order) {
                versions.extend(v);
            }
            all.extend(b"\x00\x2b");
            all.extend(u16be(versions.len() + 1));
            all.push(versions.len() as u8);
            all.extend(versions);
        }
        let mut out = u16be(all.len()).to_vec();
        out.extend(all);
        out
    }
}

/// One answer as the reference reduces it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerHelloSeen {
    /// Hex of the chosen cipher.
    pub cipher: String,
    /// Hex of the ServerHello's legacy version.
    pub version: String,
    pub alpn: String,
    /// Hex of each extension type, in the server's order.
    pub extensions: Vec<String>,
}

impl ServerHelloSeen {
    /// `cipher|version|alpn|ext-ext-…`, the reference's per-probe string.
    pub fn raw(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.cipher,
            self.version,
            self.alpn,
            self.extensions.join("-")
        )
    }
}

/// Python's clamped slice `data[a:b]`.
fn slice(data: &[u8], a: usize, b: usize) -> &[u8] {
    let b = b.min(data.len());
    if a >= b { &[] } else { &data[a..b] }
}

/// `int(hex, 16)` of a slice; the reference fails on an empty one.
fn be(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    Some(bytes.iter().fold(0usize, |n, &b| n << 8 | b as usize))
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// The reference's `read_packet`: `None` stands for `|||` (no ServerHello,
/// an alert, or bytes it could not read).
pub fn parse_server_hello(data: &[u8]) -> Option<ServerHelloSeen> {
    if *data.first()? != 22 || *data.get(5)? != 2 {
        return None;
    }
    let length = be(slice(data, 3, 5)).unwrap_or(0);
    let counter = *data.get(43)? as usize;
    let cipher = hex(slice(data, counter + 44, counter + 46));
    let version = hex(slice(data, 9, 11));
    let (alpn, extensions) = extensions(data, counter, length)?;
    Some(ServerHelloSeen {
        cipher,
        version,
        alpn,
        extensions,
    })
}

/// The reference's `extract_extension_info`: `Some(("", []))` where it gives
/// up with `|`, `None` where it fails outright.
fn extensions(data: &[u8], counter: usize, length: usize) -> Option<(String, Vec<String>)> {
    let none = Some((String::new(), Vec::new()));
    let Some(&first) = data.get(counter + 47) else {
        return none;
    };
    if first == 11
        || slice(data, counter + 50, counter + 53) == b"\x0e\xac\x0b"
        || slice(data, 82, 85) == b"\x0f\xf0\x0b"
        || counter + 42 >= length
    {
        return none;
    }
    let mut count = 49 + counter;
    let total = be(slice(data, counter + 47, counter + 49))?;
    let maximum = total + count - 1;
    // A zero-length value is Python's `""`, which has no `.decode()`.
    let mut found: Vec<(&[u8], Option<&[u8]>)> = Vec::new();
    while count < maximum {
        let kind = slice(data, count, count + 2);
        let len = be(slice(data, count + 2, count + 4))?;
        if len == 0 {
            found.push((kind, None));
            count += 4;
        } else {
            found.push((kind, Some(slice(data, count + 4, count + 4 + len))));
            count += len + 4;
        }
    }
    let alpn = match found.iter().find(|(k, _)| *k == b"\x00\x10") {
        None => String::new(),
        Some((_, None)) => return None,
        Some((_, Some(v))) => String::from_utf8(slice(v, 3, v.len()).to_vec()).ok()?,
    };
    Some((alpn, found.iter().map(|(k, _)| hex(k)).collect()))
}

/// Two hex characters: the cipher's 1-based index in [`CIPHER_INDEX`].
fn cipher_bytes(cipher: &str) -> String {
    if cipher.is_empty() {
        return "00".into();
    }
    let n = CIPHER_INDEX
        .iter()
        .position(|c| format!("{c:04x}") == cipher)
        .unwrap_or(CIPHER_INDEX.len())
        + 1;
    format!("{n:02x}")
}

/// One character for the version: its last digit as a letter from `a`.
fn version_byte(version: &str) -> char {
    version
        .get(3..4)
        .and_then(|d| d.parse::<usize>().ok())
        .and_then(|d| "abcdef".chars().nth(d))
        .unwrap_or('0')
}

/// The reference's `jarm_hash` over the ten answers, in probe order.
pub fn hash(answers: &[Option<ServerHelloSeen>]) -> String {
    let raws: Vec<String> = answers
        .iter()
        .map(|a| a.as_ref().map(|s| s.raw()).unwrap_or_else(|| "|||".into()))
        .collect();
    if raws.iter().all(|r| r == "|||") {
        return ZERO.into();
    }
    let mut fuzzy = String::new();
    let mut alpns_and_ext = String::new();
    for raw in &raws {
        let parts: Vec<&str> = raw.splitn(4, '|').collect();
        fuzzy.push_str(&cipher_bytes(parts[0]));
        fuzzy.push(version_byte(parts[1]));
        alpns_and_ext.push_str(parts[2]);
        alpns_and_ext.push_str(parts[3]);
    }
    let sha = data_encoding::HEXLOWER.encode(&Sha256::digest(alpns_and_ext.as_bytes()));
    fuzzy.push_str(&sha[..32]);
    fuzzy
}

/// Send one ClientHello on a fresh connection and read the answer once.
/// `Err(())` is a timeout, which (as in the reference) voids the whole run.
async fn ask(
    ip: IpAddr,
    port: u16,
    hello: &[u8],
    deadline: Instant,
) -> Result<Option<Vec<u8>>, ()> {
    let mut s = match connect(ip, port, deadline).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(()),
        Err(_) => return Ok(None),
    };
    let exchange = async {
        s.write_all(hello).await?;
        let mut buf = vec![0u8; MAX_READ];
        let n = s.read(&mut buf).await?;
        buf.truncate(n);
        std::io::Result::Ok(buf)
    };
    match timeout_at(deadline, exchange).await {
        Err(_) => Err(()),
        Ok(Ok(b)) => Ok(Some(b)),
        Ok(Err(_)) => Ok(None),
    }
}

/// JARM of `ip:port`: 62 hex characters, all zeros when nothing answered.
/// Each of the ten connections gets [`connection_deadline`] of `probe_end`.
pub async fn fingerprint(ip: IpAddr, port: u16, probe_end: Instant) -> String {
    let mut answers = Vec::new();
    for probe in probes(&ip.to_string()) {
        match ask(ip, port, &probe.build(), connection_deadline(probe_end)).await {
            Err(()) => return ZERO.into(),
            Ok(data) => answers.push(data.and_then(|d| parse_server_hello(&d))),
        }
    }
    hash(&answers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_ten_client_hellos_have_the_reference_names_and_valid_record_framing() {
        let ps = probes("192.0.2.1");
        let names: Vec<&str> = ps.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            [
                "tls1_2_forward",
                "tls1_2_reverse",
                "tls1_2_top_half",
                "tls1_2_bottom_half",
                "tls1_2_middle_out",
                "tls1_1_middle_out",
                "tls1_3_forward",
                "tls1_3_reverse",
                "tls1_3_invalid",
                "tls1_3_middle_out",
            ]
        );
        for p in &ps {
            let b = p.build();
            assert_eq!(b[0], 0x16, "{}", p.name);
            assert_eq!(be(&b[3..5]), Some(b.len() - 5), "{}", p.name);
            assert_eq!(b[5], 0x01, "{}", p.name);
            assert_eq!(be(&b[6..9]), Some(b.len() - 9), "{}", p.name);
        }
    }

    #[test]
    fn a_server_hello_is_reduced_to_cipher_version_and_extensions() {
        let mut exts: Vec<u8> = Vec::new();
        exts.extend(b"\x00\x10\x00\x05\x00\x03\x02h2"); // ALPN h2
        exts.extend(b"\x00\x00\x00\x00"); // server_name, empty
        let mut hello = b"\x03\x03".to_vec();
        hello.extend([7u8; 32]);
        hello.push(32);
        hello.extend([9u8; 32]);
        hello.extend(b"\xc0\x2f\x00");
        hello.extend(u16be(exts.len()));
        hello.extend(exts);
        let mut hs = vec![0x02, 0x00];
        hs.extend(u16be(hello.len()));
        hs.extend(hello);
        let mut rec = b"\x16\x03\x03".to_vec();
        rec.extend(u16be(hs.len()));
        rec.extend(hs);
        let seen = parse_server_hello(&rec).unwrap();
        assert_eq!(seen.raw(), "c02f|0303|h2|0010-0000");
        assert_eq!(parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28"), None);
    }

    #[test]
    fn the_hash_is_62_chars_and_all_zero_without_answers() {
        assert_eq!(hash(&vec![None; 10]), "0".repeat(62));
        let one = ServerHelloSeen {
            cipher: "c02f".into(),
            version: "0303".into(),
            alpn: "h2".into(),
            extensions: vec!["0010".into(), "0000".into()],
        };
        let mut answers = vec![None; 10];
        answers[0] = Some(one);
        let h = hash(&answers);
        assert_eq!(h.len(), 62);
        // c02f is the 41st cipher (0x29), 0303 is "d"; the rest are "000".
        assert_eq!(&h[..30], format!("29d{}", "000".repeat(9)));
        let sha = data_encoding::HEXLOWER.encode(&Sha256::digest(b"h20010-0000"));
        assert_eq!(&h[30..], &sha[..32]);
    }

    #[tokio::test]
    async fn a_real_tls_server_yields_a_non_zero_jarm_and_a_plain_port_yields_zeros() {
        let (addr, _) = super::super::tls::tests::tls_server(&["h2"]).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        let j = fingerprint(addr.ip(), addr.port(), deadline).await;
        assert_eq!(j.len(), 62);
        assert_ne!(j, "0".repeat(62));

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(b"220 plain\r\n").await;
            }
        });
        let j = fingerprint(plain.ip(), plain.port(), deadline).await;
        assert_eq!(j, "0".repeat(62));
    }
}
