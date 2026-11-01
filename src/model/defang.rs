//! Payload addresses and URLs for display: never clickable, and copying one
//! out of a page does not give a working link.

use std::net::Ipv6Addr;

/// `s` with its schemes and addresses written so nothing links them: `http`
/// as `hxxp`, `ftp` as `fxp`, every dot as `[.]`, the colons of an IPv6
/// address as `[:]`. Text already written so stays as it is.
pub fn defang(s: &str) -> String {
    dots(&ipv6(&schemes(s)))
}

fn schemes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut from = 0;
    while let Some(at) = s[from..].find("://") {
        let end = from + at;
        let start = from
            + s[from..end]
                .trim_end_matches(|c: char| c.is_ascii_alphanumeric())
                .len();
        out.push_str(&s[from..start]);
        let scheme = s[start..end].to_ascii_lowercase();
        out.push_str(&scheme.replace("http", "hxxp").replace("ftp", "fxp"));
        out.push_str("://");
        from = end + 3;
    }
    out.push_str(&s[from..]);
    out
}

/// Runs of the characters of an address, rewritten when they are one.
fn ipv6(s: &str) -> String {
    let is_part = |c: char| c.is_ascii_hexdigit() || c == ':' || c == '.';
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(is_part) {
        let run = &rest[start..];
        let end = run.find(|c| !is_part(c)).unwrap_or(run.len());
        let (run, tail) = run.split_at(end);
        out.push_str(&rest[..start]);
        let bare = run.trim_end_matches('.');
        if bare.parse::<Ipv6Addr>().is_ok() {
            out.push_str(&bare.replace(':', "[:]"));
            out.push_str(&run[bare.len()..]);
        } else {
            out.push_str(run);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

fn dots(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('.') {
        let open = at > 0 && rest.as_bytes()[at - 1] == b'[';
        let closed = rest.as_bytes().get(at + 1) == Some(&b']');
        out.push_str(&rest[..at]);
        out.push_str(if open && closed { "." } else { "[.]" });
        rest = &rest[at + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defang_handles_urls_and_addresses() {
        assert_eq!(defang("https://192.0.2.1/sh"), "hxxps://192[.]0[.]2[.]1/sh");
        assert_eq!(defang("example.org"), "example[.]org");
        assert_eq!(defang("HTTP://example.org/x"), "hxxp://example[.]org/x");
        assert_eq!(defang("ftp://example.org/"), "fxp://example[.]org/");
        assert_eq!(defang("tftp://example.org/"), "tfxp://example[.]org/");
        assert_eq!(
            defang("root@example.org:/tmp/x"),
            "root@example[.]org:/tmp/x"
        );
    }

    #[test]
    fn defang_writes_ipv6_with_no_bare_colon() {
        assert_eq!(defang("2001:db8::1"), "2001[:]db8[:][:]1");
        assert_eq!(
            defang("http://[2001:db8::1]:8080/x"),
            "hxxp://[2001[:]db8[:][:]1]:8080/x"
        );
        assert_eq!(defang("::ffff:192.0.2.1"), "[:][:]ffff[:]192[.]0[.]2[.]1");
        assert_eq!(defang("12:30"), "12:30");
    }

    #[test]
    fn already_defanged_text_stays_as_it_is() {
        for s in [
            "https://192.0.2.1/sh",
            "2001:db8::1",
            "http://[2001:db8::1]/x.sh",
            "ftp://example.org",
            "plain text. with a dot",
            "",
            "übergröße.example.org",
        ] {
            let once = defang(s);
            assert_eq!(defang(&once), once, "{s}");
        }
        assert_eq!(defang("hxxps://a[.]b/c"), "hxxps://a[.]b/c");
    }

    #[test]
    fn nothing_linkable_is_left() {
        for s in [
            "https://192.0.2.1/sh",
            "HtTpS://example.org",
            "xhttp://example.org",
            "see http://a.example.org and https://b.example.org.",
        ] {
            let out = defang(s).to_ascii_lowercase();
            assert!(!out.contains("http:") && !out.contains("https:"), "{out}");
            assert!(
                !out.replace("[.]", "").contains('.') || s.ends_with('.'),
                "{out}"
            );
        }
    }
}
