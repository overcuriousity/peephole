//! Host names: what the admin may type into the Lookup box.
use std::net::IpAddr;

/// A host name in its canonical form (lower case, no trailing dot), or
/// None when the text is not one: it needs a dot, labels of letters,
/// digits and hyphens up to 63 characters (not starting or ending with a
/// hyphen), at most 253 characters in all, and it is not an IP address and
/// carries no scheme. Names with non-ASCII labels are not accepted yet.
pub fn valid_name(input: &str) -> Option<String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || !name.contains('.') || name.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    let ok = name.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    ok.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_are_canonical_and_the_rest_is_refused() {
        assert_eq!(valid_name("Example.COM."), Some("example.com".into()));
        assert_eq!(
            valid_name("a-b.example.org"),
            Some("a-b.example.org".into())
        );
        for bad in [
            "localhost",
            "203.0.113.9",
            "2001:db8::1",
            "https://example.com",
            "not a host",
            "-a.example.com",
            "a..com",
            "bücher.de",
            "",
        ] {
            assert_eq!(valid_name(bad), None, "{bad}");
        }
        assert_eq!(valid_name(&format!("{}.com", "a".repeat(64))), None);
    }
}
