//! The PROXY protocol header (v1 text, v2 binary) a TCP proxy puts in
//! front of a connection to pass on the client's address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The v2 header's fixed signature.
pub const SIG_V2: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// Longest v1 line, CRLF included.
const MAX_V1: usize = 107;
/// Longest v2 address block accepted (TLVs included).
const MAX_V2_LEN: usize = 216;
/// Most bytes a header can take.
pub const MAX_HEADER: usize = 16 + MAX_V2_LEN;

pub enum Proxy {
    Incomplete,
    Invalid,
    /// `src`: the client; None when the proxy speaks for itself (LOCAL,
    /// UNKNOWN). `consumed`: the header's length.
    Done {
        src: Option<SocketAddr>,
        consumed: usize,
    },
}

/// Parse a PROXY header at the start of `buf`.
pub fn parse_proxy(buf: &[u8]) -> Proxy {
    const V1: &[u8] = b"PROXY ";
    let n = buf.len().min(12);
    if buf.len() >= 12 && buf[..12] == SIG_V2[..] {
        return v2(buf);
    }
    if buf.len() >= V1.len() && buf.starts_with(V1) {
        return v1(buf);
    }
    if SIG_V2[..n] == buf[..n] || V1[..n.min(V1.len())] == buf[..n.min(V1.len())] {
        return Proxy::Incomplete;
    }
    Proxy::Invalid
}

fn v1(buf: &[u8]) -> Proxy {
    let window = &buf[..buf.len().min(MAX_V1)];
    let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() < MAX_V1 {
            Proxy::Incomplete
        } else {
            Proxy::Invalid
        };
    };
    let Ok(line) = std::str::from_utf8(&buf[..end]) else {
        return Proxy::Invalid;
    };
    let parts: Vec<&str> = line.split(' ').collect();
    let consumed = end + 2;
    let src = match parts.as_slice() {
        ["PROXY", "UNKNOWN", ..] => None,
        ["PROXY", fam @ ("TCP4" | "TCP6"), src, dst, sport, dport] => {
            let (Ok(src), Ok(_), Ok(sport), Ok(_)) = (
                src.parse::<IpAddr>(),
                dst.parse::<IpAddr>(),
                sport.parse::<u16>(),
                dport.parse::<u16>(),
            ) else {
                return Proxy::Invalid;
            };
            if (*fam == "TCP4") != src.is_ipv4() {
                return Proxy::Invalid;
            }
            Some(SocketAddr::new(src, sport))
        }
        _ => return Proxy::Invalid,
    };
    Proxy::Done { src, consumed }
}

fn v2(buf: &[u8]) -> Proxy {
    let Some(head) = buf.get(..16) else {
        return Proxy::Incomplete;
    };
    let (ver, cmd, fam) = (head[12] >> 4, head[12] & 0x0f, head[13]);
    let len = u16::from_be_bytes([head[14], head[15]]) as usize;
    if ver != 2 || cmd > 1 || len > MAX_V2_LEN {
        return Proxy::Invalid;
    }
    let Some(a) = buf.get(16..16 + len) else {
        return Proxy::Incomplete;
    };
    let consumed = 16 + len;
    if cmd == 0 {
        return Proxy::Done {
            src: None,
            consumed,
        };
    }
    let src = match fam {
        0x00 => None,
        0x11 | 0x12 if len >= 12 => {
            let ip = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            Some(SocketAddr::new(ip.into(), u16::from_be_bytes([a[8], a[9]])))
        }
        0x21 | 0x22 if len >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&a[..16]);
            let ip = Ipv6Addr::from(o);
            Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([a[32], a[33]]),
            ))
        }
        _ => return Proxy::Invalid,
    };
    Proxy::Done { src, consumed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(cmd: u8, fam: u8, addr: &[u8]) -> Vec<u8> {
        let mut v = SIG_V2.to_vec();
        v.push(0x20 | cmd);
        v.push(fam);
        v.extend((addr.len() as u16).to_be_bytes());
        v.extend(addr);
        v
    }

    #[test]
    fn v1_tcp4_and_tcp6() {
        let h = b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\nrest";
        let Proxy::Done { src, consumed } = parse_proxy(h) else {
            panic!()
        };
        assert_eq!(src, Some("203.0.113.9:5555".parse().unwrap()));
        assert_eq!(&h[consumed..], b"rest");
        let Proxy::Done { src, .. } = parse_proxy(b"PROXY TCP6 2001:db8::1 ::1 1 443\r\n") else {
            panic!()
        };
        assert_eq!(src, Some("[2001:db8::1]:1".parse().unwrap()));
        let Proxy::Done { src, .. } = parse_proxy(b"PROXY UNKNOWN\r\n") else {
            panic!()
        };
        assert_eq!(src, None);
    }

    #[test]
    fn v1_cut_short_is_incomplete_and_nonsense_invalid() {
        let h = b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\n";
        for n in 0..h.len() {
            assert!(matches!(parse_proxy(&h[..n]), Proxy::Incomplete), "{n}");
        }
        assert!(matches!(parse_proxy(b"PROXY BOGUS\r\n"), Proxy::Invalid));
        assert!(matches!(
            parse_proxy(b"PROXY TCP4 999.1.1.1 1.1.1.1 1 2\r\n"),
            Proxy::Invalid
        ));
        assert!(matches!(parse_proxy(&[b'P'; 120]), Proxy::Invalid));
        assert!(matches!(parse_proxy(b"\x16\x03\x01"), Proxy::Invalid));
    }

    #[test]
    fn v2_proxy_local_and_limits() {
        let mut a = vec![203, 0, 113, 9, 127, 0, 0, 1];
        a.extend(5555u16.to_be_bytes());
        a.extend(443u16.to_be_bytes());
        let h = v2(1, 0x11, &a);
        let Proxy::Done { src, consumed } = parse_proxy(&h) else {
            panic!()
        };
        assert_eq!(src, Some("203.0.113.9:5555".parse().unwrap()));
        assert_eq!(consumed, h.len());
        for n in 0..h.len() {
            assert!(matches!(parse_proxy(&h[..n]), Proxy::Incomplete), "{n}");
        }
        let mut a6 = vec![0x20, 0x01, 0x0d, 0xb8];
        a6.extend([0; 11]);
        a6.push(1);
        a6.extend([0; 16]);
        a6.extend(7u16.to_be_bytes());
        a6.extend(443u16.to_be_bytes());
        let Proxy::Done { src, .. } = parse_proxy(&v2(1, 0x21, &a6)) else {
            panic!()
        };
        assert_eq!(src, Some("[2001:db8::1]:7".parse().unwrap()));
        let Proxy::Done { src, .. } = parse_proxy(&v2(0, 0, &[])) else {
            panic!()
        };
        assert_eq!(src, None, "LOCAL: the proxy's own connection");
        assert!(matches!(parse_proxy(&v2(1, 0x11, &[1, 2])), Proxy::Invalid));
        assert!(matches!(
            parse_proxy(&v2(1, 0x11, &[0; 300])),
            Proxy::Invalid
        ));
    }
}
