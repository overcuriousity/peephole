//! The JA4H fingerprint of an HTTP/1 request head (FoxIO,
//! <https://github.com/FoxIO-LLC/ja4>): how the client builds its requests
//! (method, version, header names in order, cookie names), not what it asks.

use sha2::Digest;

/// The JA4H of a stored request head; `None` when it is not an HTTP/1.0 or
/// HTTP/1.1 request head.
///
/// As FoxIO's Rust implementation computes it (sorted cookies), with one
/// difference: a method it does not know (`PROPFIND`, …) gives its first two
/// letters, as their Python implementation does, instead of no fingerprint.
pub fn ja4h(raw_head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(raw_head);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let mut request = lines.next()?.split(' ');
    let method = request.next().filter(|m| !m.is_empty())?;
    let version = match request.nth(1)? {
        "HTTP/1.0" => "10",
        "HTTP/1.1" => "11",
        _ => return None,
    };
    let method: String = method.to_lowercase().chars().take(2).collect();

    let (mut cookie, mut referer) = (None, false);
    let mut language = None;
    let mut names = Vec::new();
    for line in lines.take_while(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.trim();
        if name.eq_ignore_ascii_case("cookie") {
            cookie.get_or_insert(value);
        } else if name.eq_ignore_ascii_case("referer") {
            referer = true;
        } else {
            if name.eq_ignore_ascii_case("accept-language") {
                language.get_or_insert(value);
            }
            names.push(name);
        }
    }

    let mut pairs: Vec<(&str, Option<&str>)> = cookie
        .into_iter()
        .flat_map(|c| c.split("; "))
        .filter(|c| !c.is_empty())
        .map(|c| match c.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (c, None),
        })
        .collect();
    pairs.sort_unstable();
    let cookie_names: Vec<&str> = pairs.iter().map(|(n, _)| *n).collect();
    let cookie_pairs: Vec<String> = pairs
        .iter()
        .map(|(n, v)| match v {
            Some(v) => format!("{n}={v}"),
            None => n.to_string(),
        })
        .collect();

    let lang: String = language
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .replace('-', "")
        .to_lowercase()
        .chars()
        .chain(std::iter::repeat('0'))
        .take(4)
        .collect();
    Some(format!(
        "{method}{version}{}{}{:02}{lang}_{}_{}_{}",
        if cookie.is_some() { 'c' } else { 'n' },
        if referer { 'r' } else { 'n' },
        names.len().min(99),
        hash12(&names.join(",")),
        hash12(&cookie_names.join(",")),
        hash12(&cookie_pairs.join(",")),
    ))
}

/// The first 12 hex digits of the SHA-256; all zeros for nothing.
fn hash12(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".into();
    }
    data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(s.as_bytes()))[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn sha12(s: &str) -> String {
        data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(s.as_bytes()))[..12].to_string()
    }

    /// The request in FoxIO's own JA4H test, against the value it expects.
    #[test]
    fn matches_the_reference_vector() {
        let head = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.cnn.com\r\n",
            "Cookie: FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726\r\n",
            "Sec-Ch-Ua: \r\n",
            "Sec-Ch-Ua-Mobile: ?0\r\n",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36\r\n",
            "Sec-Ch-Ua-Platform: \"\"\r\n",
            "Accept: */*\r\n",
            "Sec-Fetch-Site: same-origin\r\n",
            "Sec-Fetch-Mode: cors\r\n",
            "Sec-Fetch-Dest: empty\r\n",
            "Sec-Fetch-Mode: cors\r\n",
            "Sec-Fetch-Dest: empty\r\n",
            "Referer: https://www.cnn.com/\r\n",
            "Accept-Encoding: gzip, deflate\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
            "\r\n",
        );
        assert_eq!(
            ja4h(head.as_bytes()).as_deref(),
            Some("ge11cr13enus_88d2d584d47f_0f2659b474bf_161698816dab")
        );
    }

    #[test]
    fn a_bare_scanner_request() {
        let head = b"GET /.env HTTP/1.0\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n";
        let b = sha12("Host,User-Agent");
        assert_eq!(
            ja4h(head).unwrap(),
            format!("ge10nn020000_{b}_000000000000_000000000000")
        );
    }

    #[test]
    fn header_names_keep_their_case_and_order() {
        let a = ja4h(b"GET / HTTP/1.1\r\nhost: x\r\naccept: */*\r\n\r\n").unwrap();
        let b = ja4h(b"GET / HTTP/1.1\r\naccept: */*\r\nhost: x\r\n\r\n").unwrap();
        let c = ja4h(b"GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.contains(&sha12("host,accept")), "{a}");
    }

    #[test]
    fn cookies_are_named_and_sorted() {
        let head = b"POST /x HTTP/1.1\r\nHost: x\r\nCOOKIE: b=2; a=1; flag\r\nreferer: y\r\n\r\n";
        let b = sha12("Host");
        let c = sha12("a,b,flag");
        let d = sha12("a=1,b=2,flag");
        assert_eq!(ja4h(head).unwrap(), format!("po11cr010000_{b}_{c}_{d}"));
    }

    #[test]
    fn the_language_is_the_first_one_cut_to_four() {
        let lang = |v: &str| {
            let head = format!("GET / HTTP/1.1\r\nAccept-Language: {v}\r\n\r\n");
            ja4h(head.as_bytes()).unwrap()[8..12].to_string()
        };
        assert_eq!(lang("da, en-GB;q=0.8"), "da00");
        assert_eq!(lang("zh-Hant-TW"), "zhha");
        assert_eq!(lang("*"), "*000");
    }

    #[test]
    fn any_method_gives_its_first_two_letters() {
        let fp = ja4h(b"PROPFIND / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(fp.starts_with("pr11nn01"), "{fp}");
    }

    #[test]
    fn the_header_count_stops_at_99() {
        let mut head = String::from("GET / HTTP/1.1\r\n");
        for i in 0..120 {
            head.push_str(&format!("X-{i}: v\r\n"));
        }
        head.push_str("\r\n");
        assert_eq!(&ja4h(head.as_bytes()).unwrap()[..8], "ge11nn99");
    }

    #[test]
    fn not_an_http1_head_has_none() {
        assert_eq!(ja4h(b""), None);
        assert_eq!(ja4h(b"PRI * HTTP/2.0\r\n\r\n"), None);
        assert_eq!(ja4h(b"\x16\x03\x01garbage\r\n\r\n"), None);
        assert_eq!(ja4h(b"GET /\r\n\r\n"), None);
    }
}
