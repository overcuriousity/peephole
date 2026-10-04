//! Tokens: the credential-shaped strings of a request, where they were
//! found, hashed like canaries so the two can be joined.
use crate::canary::hash;
use std::collections::BTreeSet;

/// Version of these rules (`requests.canary_parsed`). A change bumps it,
/// and the backfill parses every row again.
pub const TOKENS_V: i64 = 1;
pub const MIN: usize = 16;
pub const MAX: usize = 128;
/// Most tokens kept per request.
pub const CAP: usize = 256;

fn is_tok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn is_sep(b: u8) -> bool {
    matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

#[derive(Default)]
struct Out {
    seen: BTreeSet<(String, i64)>,
    order: Vec<(String, i64)>,
}

impl Out {
    fn take(&mut self, place: &str, t: &[u8]) {
        if self.order.len() >= CAP || !(MIN..=MAX).contains(&t.len()) {
            return;
        }
        let Ok(s) = std::str::from_utf8(t) else {
            return;
        };
        let key = (place.to_string(), hash(s));
        if self.seen.insert(key.clone()) {
            self.order.push(key);
        }
    }

    /// Runs and their pieces, of the text as is and percent-decoded; a run
    /// that is base64 of printable text is decoded once and scanned too.
    fn scan(&mut self, place: &str, text: &[u8], depth: u8) {
        let decoded = crate::classify::percent_decode_once(text);
        let variants: &[&[u8]] = if decoded == text {
            &[text]
        } else {
            &[text, &decoded]
        };
        for v in variants {
            for run in v.split(|b| !is_tok(*b)).filter(|r| !r.is_empty()) {
                self.take(place, run);
                for piece in run.split(|b| is_sep(*b)) {
                    self.take(place, piece);
                }
                // `key=value` inside one run: the value as a whole (a
                // base64 value would otherwise only yield its pieces).
                for (i, _) in run
                    .iter()
                    .enumerate()
                    .filter(|(i, b)| **b == b'=' && run.get(i + 1).is_some_and(|n| *n != b'='))
                {
                    self.take(place, &run[i + 1..]);
                }
                if depth == 0
                    && run.len() >= MIN
                    && let Some(plain) = b64_text(run)
                {
                    self.scan(place, &plain, 1);
                }
            }
        }
    }
}

/// `run` decoded as base64 or base64url, when that gives printable text.
fn b64_text(run: &[u8]) -> Option<Vec<u8>> {
    let trimmed: Vec<u8> = run.iter().copied().filter(|b| *b != b'=').collect();
    let out = data_encoding::BASE64_NOPAD
        .decode(&trimmed)
        .or_else(|_| data_encoding::BASE64URL_NOPAD.decode(&trimmed))
        .ok()?;
    let printable = out.len() >= 4
        && std::str::from_utf8(&out).is_ok_and(|s| {
            s.chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n'))
        });
    printable.then_some(out)
}

fn place_of(name: &str) -> String {
    format!("header:{}", name.to_ascii_lowercase())
}

/// Every token of a stored request.
pub fn of_request(
    headers: &[(String, String)],
    raw_head: Option<&[u8]>,
    path: &str,
    query: Option<&str>,
    body: &[u8],
) -> Vec<(String, i64)> {
    let mut out = Out::default();
    for (k, v) in headers {
        let place = place_of(k);
        out.scan(&place, k.as_bytes(), 0);
        out.scan(&place, v.as_bytes(), 0);
    }
    if let Some(raw) = raw_head {
        let mut lines = raw.split(|b| *b == b'\n');
        if let Some(first) = lines.next() {
            out.scan("path", first, 0);
        }
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                break;
            }
            let name = line.split(|b| *b == b':').next().unwrap_or_default();
            let place = place_of(&String::from_utf8_lossy(name));
            out.scan(&place, line, 0);
        }
    }
    out.scan("path", path.as_bytes(), 0);
    if let Some(q) = query {
        out.scan("query", q.as_bytes(), 0);
    }
    if !body.is_empty() {
        let b = crate::classify::decoded_body(headers, body);
        out.scan("body", &b, 0);
    }
    out.order
}

/// The tokens where a login carries its credential: `Authorization`,
/// `Proxy-Authorization`, `Cookie` and, when given, the body.
pub fn of_credentials(headers: &[(String, String)], body: Option<&[u8]>) -> Vec<(String, i64)> {
    let mut out = Out::default();
    for (k, v) in headers {
        if ["authorization", "proxy-authorization", "cookie"]
            .iter()
            .any(|n| k.eq_ignore_ascii_case(n))
        {
            out.scan(&place_of(k), v.as_bytes(), 0);
        }
    }
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        let b = crate::classify::decoded_body(headers, b);
        out.scan("body", &b, 0);
    }
    out.order
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::hash;

    type Case = (
        Vec<(String, String)>,
        Option<&'static [u8]>,
        String,
        Option<String>,
        Vec<u8>,
        &'static str,
    );

    const SECRET: &str = "Zx8kQ2mPvR4tW6yB1nC3"; // 20 chars, like a v1 password

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn found(t: &[(String, i64)], place: &str, value: &str) -> bool {
        t.iter().any(|(p, x)| p == place && *x == hash(value))
    }

    #[test]
    fn credentials_are_found_wherever_they_travel() {
        let b64 = |s: &str| data_encoding::BASE64.encode(s.as_bytes());
        let cases: Vec<Case> = vec![
            (
                h(&[(
                    "authorization",
                    &format!("Basic {}", b64(&format!("admin:{SECRET}"))),
                )]),
                None,
                "/".into(),
                None,
                vec![],
                "header:authorization",
            ),
            (
                h(&[(
                    "proxy-authorization",
                    &format!("Basic {}", b64(&format!("u:{SECRET}"))),
                )]),
                None,
                "/".into(),
                None,
                vec![],
                "header:proxy-authorization",
            ),
            (
                h(&[("authorization", &format!("Bearer {SECRET}"))]),
                None,
                "/".into(),
                None,
                vec![],
                "header:authorization",
            ),
            (
                h(&[(
                    "authorization",
                    "AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/20261004/eu-central-1/s3/aws4_request, SignedHeaders=host, Signature=00",
                )]),
                None,
                "/".into(),
                None,
                vec![],
                "header:authorization",
            ),
            (
                h(&[(
                    "cookie",
                    &format!("a=1; wordpress_logged_in_x=admin%7C1791172800%7C{SECRET}%7Cabc"),
                )]),
                None,
                "/".into(),
                None,
                vec![],
                "header:cookie",
            ),
            (
                h(&[("x-auth", &b64(&format!("deploy:{SECRET}")))]),
                None,
                "/".into(),
                None,
                vec![],
                "header:x-auth",
            ),
            (
                h(&[(
                    "referer",
                    &format!("http://deploy:{SECRET}@203.0.113.7/git/shop.git"),
                )]),
                None,
                "/".into(),
                None,
                vec![],
                "header:referer",
            ),
            (
                h(&[]),
                None,
                "/".into(),
                Some(format!("key={SECRET}")),
                vec![],
                "query",
            ),
            (
                h(&[]),
                None,
                format!("/api/{SECRET}/x"),
                None,
                vec![],
                "path",
            ),
            (
                h(&[("content-type", "application/x-www-form-urlencoded")]),
                None,
                "/wp-login.php".into(),
                None,
                format!("log=admin&pwd={SECRET}").into_bytes(),
                "body",
            ),
            (
                h(&[("content-type", "application/json")]),
                None,
                "/".into(),
                None,
                format!("{{\"password\":\"{SECRET}\"}}").into_bytes(),
                "body",
            ),
            (
                h(&[("content-type", "multipart/form-data; boundary=x")]),
                None,
                "/".into(),
                None,
                format!(
                    "--x\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n{SECRET}\r\n--x--"
                )
                .into_bytes(),
                "body",
            ),
        ];
        for (headers, raw, path, query, body, place) in cases {
            let t = of_request(&headers, raw, &path, query.as_deref(), &body);
            assert!(
                found(&t, place, SECRET) || found(&t, place, "AKIAABCDEFGHIJKLMNOP"),
                "{place}: {t:?}"
            );
        }
    }

    #[test]
    fn raw_head_finds_what_the_parser_dropped() {
        let raw = format!("GET / HTTP/1.1\r\nHost: a\r\nX-Token: one\r\nX-Token: {SECRET}\r\n\r\n");
        let t = of_request(
            &h(&[("x-token", "one")]),
            Some(raw.as_bytes()),
            "/",
            None,
            b"",
        );
        assert!(found(&t, "header:x-token", SECRET), "{t:?}");
    }

    #[test]
    fn literal_plus_in_a_form_body_and_percent_encoding_both_match() {
        let v = "abc+def/ghi=jklmnopq"; // base64-ish, 20 chars
        let enc = "abc%2Bdef%2Fghi%3Djklmnopq";
        for body in [format!("x={v}"), format!("x={enc}")] {
            let t = of_request(
                &h(&[("content-type", "application/x-www-form-urlencoded")]),
                None,
                "/",
                None,
                body.as_bytes(),
            );
            assert!(found(&t, "body", v), "{body}: {t:?}");
        }
    }

    #[test]
    fn version_zero_values_are_one_token() {
        let t = of_request(
            &h(&[("authorization", "Bearer canary-0f8e7d6c5b4a")]),
            None,
            "/",
            None,
            b"",
        );
        assert!(found(&t, "header:authorization", "canary-0f8e7d6c5b4a"));
    }

    #[test]
    fn short_values_and_plain_requests_yield_nothing_to_match() {
        let t = of_request(
            &h(&[("user-agent", "curl/8.0"), ("host", "203.0.113.7")]),
            None,
            "/.env",
            None,
            b"",
        );
        assert!(!t.iter().any(|(_, x)| *x == hash(SECRET)));
        assert!(t.iter().all(|(p, _)| p != "body"));
    }

    #[test]
    fn binary_and_huge_inputs_are_safe() {
        let mut body = vec![0xffu8, 0x00, 0xfe];
        for i in 0..5000 {
            body.extend_from_slice(format!(" token{i:011}abcdef ").as_bytes());
        }
        let t = of_request(
            &h(&[("x", "\u{fffd}\u{0}")]),
            Some(&[0xff, 0xfe, b'\n']),
            "/",
            None,
            &body,
        );
        assert!(t.len() <= CAP);
        assert_eq!(
            t,
            of_request(
                &h(&[("x", "\u{fffd}\u{0}")]),
                Some(&[0xff, 0xfe, b'\n']),
                "/",
                None,
                &body
            ),
            "deterministic"
        );
    }

    #[test]
    fn credentials_only_looks_at_credential_places() {
        let hs = h(&[
            ("authorization", &format!("Bearer {SECRET}")),
            ("x-other", SECRET),
        ]);
        let t = of_credentials(&hs, Some(format!("pwd={SECRET}").as_bytes()));
        assert!(found(&t, "header:authorization", SECRET));
        assert!(found(&t, "body", SECRET));
        assert!(!t.iter().any(|(p, _)| p == "header:x-other"));
    }
}
