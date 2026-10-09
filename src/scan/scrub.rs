//! The scanning node's own address and name kept out of its scans. A
//! scanned mail server greets the client by address and name, and nmap
//! keeps the greeting in `smtp-commands` and `banner`; the scan is
//! signed, replicated to every member and exported. Before a scanner
//! signs a result it replaces, in the raw XML, each of its own global
//! addresses and forward-confirmed names with [`MARK`]: exact values this
//! node knows about itself, never patterns. The command line in the XML
//! names the target, not the scanner, so `profiles::args_ok` is
//! unaffected; ports, identity keys and ETags are unchanged, so audits
//! agree as before.
use std::net::IpAddr;

/// What replaces an own address or name.
pub const MARK: &str = "[scanner]";

/// A byte that can be part of an IPv6 address as nmap prints one.
fn v6_byte(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b'.' || b == b':'
}

/// A byte that can be part of an IPv4 address. A colon is not: a port
/// follows an address as `1.2.3.4:25`.
fn v4_byte(b: u8) -> bool {
    b.is_ascii_digit() || b == b'.'
}

/// A byte that can be part of a host name.
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// `xml` with every own address (as nmap prints it: IPv4 dotted, IPv6
/// compressed) and every own name (case-insensitively) replaced by
/// [`MARK`], and how many replacements were made (saturating). A match
/// counts where the bytes around it cannot continue the token, and which
/// bytes can depends on the kind: digits and `.` for IPv4 (so `:port` may
/// follow), hex digits, `.` and `:` for IPv6, letters, digits, `.` and
/// `-` for a name. A `.` right after the match ends it when the byte after
/// that `.` cannot continue the token, so a root dot or a full stop
/// (`at 87.123.41.5.`, `host.example.net.`) does not hide it.
pub fn scrub(xml: &[u8], addrs: &[IpAddr], names: &[String]) -> (Vec<u8>, u16) {
    let mut out = xml.to_vec();
    let mut n: u32 = 0;
    for a in addrs {
        let part = if a.is_ipv4() { v4_byte } else { v6_byte };
        n = n.saturating_add(replace(&mut out, a.to_string().as_bytes(), false, part));
    }
    for name in names {
        n = n.saturating_add(replace(&mut out, name.as_bytes(), true, name_byte));
    }
    (out, n.min(u16::MAX as u32) as u16)
}

/// Whether a token ending before `buf[end]` ends there: nothing follows,
/// a byte `part` rejects follows, or a `.` follows that is itself followed
/// by nothing or by a byte `part` rejects.
fn ends(buf: &[u8], end: usize, part: fn(u8) -> bool) -> bool {
    match buf.get(end) {
        None => true,
        Some(b'.') => buf.get(end + 1).is_none_or(|&b| !part(b)),
        Some(&b) => !part(b),
    }
}

/// Replace each occurrence of `pat` in `buf` that is not surrounded by
/// bytes `part` accepts (see [`ends`] for the byte after); case-insensitively
/// when `ci`. An empty pattern matches nothing.
fn replace(buf: &mut Vec<u8>, pat: &[u8], ci: bool, part: fn(u8) -> bool) -> u32 {
    if pat.is_empty() {
        return 0;
    }
    let mut out = Vec::with_capacity(buf.len());
    let mut n = 0;
    let mut i = 0;
    while i < buf.len() {
        let end = i + pat.len();
        let hit = end <= buf.len()
            && {
                let w = &buf[i..end];
                if ci {
                    w.eq_ignore_ascii_case(pat)
                } else {
                    w == pat
                }
            }
            && !(i > 0 && part(buf[i - 1]))
            && ends(buf, end, part);
        if hit {
            out.extend_from_slice(MARK.as_bytes());
            n += 1;
            i = end;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    *buf = out;
    n
}

/// This node's own global addresses and names, as the pages and the
/// export scrub them from scans stored before scrubbing existed (and
/// from other nodes' scans that mention this node).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Own {
    pub addrs: Vec<IpAddr>,
    pub names: Vec<String>,
}

impl Own {
    /// Whether there is nothing to scrub: no address and no name known.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty() && self.names.is_empty()
    }

    /// `xml` scrubbed of this node's addresses and names.
    pub fn apply(&self, xml: &[u8]) -> Vec<u8> {
        if self.is_empty() {
            return xml.to_vec();
        }
        scrub(xml, &self.addrs, &self.names).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn run(xml: &str, addrs: &[&str], names: &[&str]) -> (String, u16) {
        let addrs: Vec<IpAddr> = addrs.iter().map(|a| ip(a)).collect();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let (out, n) = scrub(xml.as_bytes(), &addrs, &names);
        (String::from_utf8(out).unwrap(), n)
    }

    #[test]
    fn vuln_script_output_is_scrubbed_and_still_parses() {
        let xml = std::fs::read("tests/fixtures/nmap-vuln.xml").unwrap();
        let (out, n) = scrub(&xml, &[ip("198.51.100.5")], &[]);
        assert_eq!(n, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("probe from [scanner] succeeded"), "{text}");
        assert!(!text.contains("198.51.100.5"));
        // The vuln <script> elements are not parsed into ports, but the
        // ports themselves survive.
        let parsed = crate::scan::nmap_xml::parse_nmap_xml(text.as_bytes()).unwrap();
        assert_eq!(parsed.ports.len(), 2);
        assert_eq!(parsed.ports[0].port, 80);
    }

    #[test]
    fn own_addresses_and_names_become_the_mark_and_are_counted() {
        let xml = r#"<script id="smtp-commands" output="mail.example.org Hello i577b2938.versanet.de [87.123.41.56], pleased"/>"#;
        let (out, n) = run(xml, &["87.123.41.56"], &["i577b2938.versanet.de"]);
        assert_eq!(
            out,
            r#"<script id="smtp-commands" output="mail.example.org Hello [scanner] [[scanner]], pleased"/>"#
        );
        assert_eq!(n, 2);
    }

    #[test]
    fn an_address_inside_a_longer_one_is_left_alone() {
        let (out, n) = run(
            "a 87.123.41.56 b 187.123.41.5 c 87.123.41.5:25 d",
            &["87.123.41.5"],
            &[],
        );
        assert_eq!(out, "a 87.123.41.56 b 187.123.41.5 c [scanner]:25 d");
        assert_eq!(n, 1);
    }

    #[test]
    fn ipv6_is_matched_in_its_compressed_form() {
        let (out, n) = run(
            "from 2001:db8::1 and 2001:db8::10 and 2001:db8:0:0:0:0:0:1",
            &["2001:0db8:0000:0000:0000:0000:0000:0001"],
            &[],
        );
        assert_eq!(
            out,
            "from [scanner] and 2001:db8::10 and 2001:db8:0:0:0:0:0:1"
        );
        assert_eq!(n, 1);
    }

    #[test]
    fn a_name_is_matched_in_any_case_and_not_inside_a_longer_one() {
        let (out, n) = run(
            "Host.Example.NET, mail.host.example.net, host.example.net-1, (host.example.net)",
            &[],
            &["host.example.net"],
        );
        assert_eq!(
            out,
            "[scanner], mail.host.example.net, host.example.net-1, ([scanner])"
        );
        assert_eq!(n, 2);
    }

    #[test]
    fn a_trailing_dot_ends_the_token() {
        let (out, n) = run(
            "at 87.123.41.5. and 87.123.41.56 and 87.123.41.5.7 and 2001:db8::1. end",
            &["87.123.41.5", "2001:db8::1"],
            &[],
        );
        assert_eq!(
            out,
            "at [scanner]. and 87.123.41.56 and 87.123.41.5.7 and [scanner]. end"
        );
        assert_eq!(n, 2);
        let (out, n) = run(
            "Hello host.example.net. mail.host.example.net host.example.net.org host.example.net.",
            &[],
            &["host.example.net"],
        );
        assert_eq!(
            out,
            "Hello [scanner]. mail.host.example.net host.example.net.org [scanner]."
        );
        assert_eq!(n, 2);
    }

    #[test]
    fn nothing_to_scrub_leaves_the_bytes_untouched() {
        let xml = "<nmaprun args=\"nmap -oX - 203.0.113.7\"/>";
        assert_eq!(run(xml, &[], &[]), (xml.to_string(), 0));
        assert_eq!(
            run(xml, &["198.51.100.5"], &["", "x.example"]),
            (xml.to_string(), 0)
        );
    }

    #[test]
    fn the_count_saturates() {
        let xml = "1.2.3.4 ".repeat(70_000);
        let (_, n) = run(&xml, &["1.2.3.4"], &[]);
        assert_eq!(n, u16::MAX);
    }

    #[test]
    fn own_applies_without_a_count() {
        let own = Own {
            addrs: vec![ip("198.51.100.5")],
            names: vec!["scanner-5.example.net".into()],
        };
        assert_eq!(
            own.apply(b"x 198.51.100.5 SCANNER-5.example.net"),
            b"x [scanner] [scanner]"
        );
        assert!(Own::default().is_empty() && !own.is_empty());
    }
}
