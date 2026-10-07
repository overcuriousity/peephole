//! What a web port serves: status, a few headers, the page title, cookie
//! names and body hashes, the shape of a 404, the favicon hash (Shodan's
//! MurmurHash3 form) and the redirect chain. Every hop of the chain is
//! resolved first and shown to the guard, so a redirect can never point the
//! probe at protected address space.

use super::{
    MAX_FAVICON, MAX_REDIRECTS, MAX_RESPONSE, connection_deadline, jarm, printable, sha256_hex, tls,
};
use anyhow::{Result, anyhow};
use reqwest::Url;
use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

/// A current desktop Chrome.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

/// Longest title kept, in characters.
const MAX_TITLE: usize = 200;
/// How far into a body the title (and the favicon link) is looked for.
const TITLE_WINDOW: usize = 64 * 1024;
/// Cookie names kept.
const MAX_COOKIES: usize = 20;
/// Bytes of a body that `body_sha256` covers.
const HASH_WINDOW: usize = 4 * 1024;
/// Longest a host-name lookup may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest header value kept, in bytes.
const MAX_HEADER: usize = 256;

/// The guard: `Some(why)` refuses an address.
pub type Guard<'a> = &'a (dyn Fn(&IpAddr) -> Option<String> + Sync);

/// One response as read.
#[derive(Debug, Clone)]
pub struct HttpSeen {
    pub status: u16,
    pub headers: HeaderMap,
    /// At most the `max` given to [`fetch`].
    pub body: Vec<u8>,
    /// The body went on past `max` (or past the deadline).
    pub truncated: bool,
}

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .connect_timeout(super::CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
}

/// A client that follows no redirect, accepts any certificate and gives up
/// at `probe_end` at the latest.
pub fn client(probe_end: Instant) -> reqwest::Client {
    let left = probe_end.saturating_duration_since(Instant::now());
    builder()
        .timeout(left.max(Duration::from_millis(1)))
        .build()
        .unwrap_or_default()
}

/// GET `url` and read at most `max` bytes of the body, stopping at
/// `deadline`.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    max: usize,
    deadline: Instant,
) -> Result<HttpSeen> {
    let mut resp = timeout_at(deadline, client.get(url).send())
        .await
        .map_err(|_| anyhow!("http deadline reached"))??;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let mut body = Vec::new();
    let mut truncated = false;
    loop {
        match timeout_at(deadline, resp.chunk()).await {
            Err(_) => {
                truncated = true;
                break;
            }
            Ok(Err(e)) if body.is_empty() => return Err(e.into()),
            Ok(Err(_)) | Ok(Ok(None)) => break,
            Ok(Ok(Some(c))) => {
                let room = max - body.len();
                if c.len() > room {
                    body.extend_from_slice(&c[..room]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&c);
            }
        }
    }
    Ok(HttpSeen {
        status,
        headers,
        body,
        truncated,
    })
}

/// Byte offset of `needle` (ASCII, lowercase) in `hay`, ignoring case.
fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// The `<title>` in the first 64 KiB, whitespace collapsed, at most 200
/// characters.
pub fn title_of(body: &[u8]) -> Option<String> {
    let head = &body[..body.len().min(TITLE_WINDOW)];
    let open = find_ci(head, b"<title")?;
    let rest = &head[open + 6..];
    let gt = rest.iter().position(|&b| b == b'>')?;
    let rest = &rest[gt + 1..];
    let end = find_ci(rest, b"</title").unwrap_or(rest.len());
    let text = String::from_utf8_lossy(&rest[..end]);
    let title: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TITLE)
        .collect();
    (!title.is_empty()).then_some(title)
}

/// The names of the cookies set, at most 20, each once.
pub fn cookie_names(headers: &HeaderMap) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in headers.get_all(SET_COOKIE) {
        let v = v.as_bytes();
        let name = v.split(|&b| b == b'=').next().unwrap_or_default();
        let name = printable(name).trim().to_string();
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
            if out.len() == MAX_COOKIES {
                break;
            }
        }
    }
    out
}

/// MurmurHash3 x86_32, as Python's `mmh3.hash` (signed).
pub fn mmh3_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let (blocks, tail) = data.as_chunks::<4>();
    for b in blocks {
        let mut k = u32::from_le_bytes(*b);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, &b) in tail.iter().enumerate() {
            k |= (b as u32) << (8 * i);
        }
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as i32
}

/// Shodan's favicon hash: MurmurHash3 of the base64 text with a newline
/// after every 76 characters (Python's `base64.encodebytes`).
pub fn favicon_mmh3(bytes: &[u8]) -> String {
    let b64 = data_encoding::BASE64.encode(bytes);
    let mut text = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for line in b64.as_bytes().chunks(76) {
        text.push_str(std::str::from_utf8(line).unwrap_or_default());
        text.push('\n');
    }
    mmh3_32(text.as_bytes(), 0).to_string()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    let v = headers.get(name)?.as_bytes();
    Some(printable(&v[..v.len().min(MAX_HEADER)]))
}

/// What every page (root, random path, redirect hop) is reduced to.
fn page_json(seen: &HttpSeen) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("status".into(), json!(seen.status));
    m.insert("server".into(), json!(header(&seen.headers, "server")));
    m.insert(
        "powered_by".into(),
        json!(header(&seen.headers, "x-powered-by")),
    );
    m.insert("title".into(), json!(title_of(&seen.body)));
    let window = &seen.body[..seen.body.len().min(HASH_WINDOW)];
    m.insert("body_sha256".into(), json!(sha256_hex(window)));
    m.insert("body_len".into(), json!(seen.body.len()));
    m
}

/// `scheme://host[:port]` of a URL.
fn origin_of(url: &Url) -> String {
    let mut o = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(p) = url.port() {
        o.push_str(&format!(":{p}"));
    }
    o
}

enum Host {
    Ip(IpAddr),
    Name(String),
}

/// A URL's host as an address or a name.
fn host_of(url: &Url) -> Option<Host> {
    let h = url.host_str()?;
    let bare = h.trim_start_matches('[').trim_end_matches(']');
    Some(match bare.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Name(h.to_string()),
    })
}

/// Where a URL points: its address (a name resolved once with the system
/// resolver) and port. `None` when it cannot be resolved.
async fn target_of(url: &Url, deadline: Instant) -> Option<(IpAddr, u16)> {
    let port = url.port_or_known_default()?;
    match host_of(url)? {
        Host::Ip(ip) => Some((ip, port)),
        Host::Name(name) => {
            let until = (Instant::now() + RESOLVE_TIMEOUT).min(deadline);
            let mut addrs = timeout_at(until, tokio::net::lookup_host((name.as_str(), port)))
                .await
                .ok()?
                .ok()?;
            addrs.next().map(|a| (a.ip(), port))
        }
    }
}

/// A client for one hop: a named host is pinned to the address the guard
/// saw, so the request cannot be resolved anywhere else.
fn hop_client(
    client: &reqwest::Client,
    url: &Url,
    ip: IpAddr,
    port: u16,
    probe_end: Instant,
) -> reqwest::Client {
    match host_of(url) {
        Some(Host::Name(name)) => {
            let left = probe_end.saturating_duration_since(Instant::now());
            builder()
                .timeout(left.max(Duration::from_millis(1)))
                .resolve(&name, SocketAddr::new(ip, port))
                .build()
                .unwrap_or_else(|_| client.clone())
        }
        _ => client.clone(),
    }
}

/// Follow `first_url`'s redirects, one GET per hop, at most
/// [`MAX_REDIRECTS`] hops. Each hop is resolved and shown to `guard` before
/// anything connects; a refused, repeated or unresolvable hop, or one past
/// the limit, ends the chain with a `skipped` marker.
pub async fn follow_redirects(
    client: &reqwest::Client,
    first_url: &str,
    guard: Guard<'_>,
    probe_end: Instant,
) -> Vec<Value> {
    let mut hops = Vec::new();
    let mut seen_urls = HashSet::new();
    let Ok(mut url) = Url::parse(first_url) else {
        hops.push(json!({"url": first_url, "skipped": "unresolved"}));
        return hops;
    };
    loop {
        let text = url.to_string();
        if hops.len() == MAX_REDIRECTS {
            hops.push(json!({"url": text, "skipped": "limit"}));
            break;
        }
        if !seen_urls.insert(text.clone()) {
            hops.push(json!({"url": text, "skipped": "loop"}));
            break;
        }
        let Some((ip, port)) = target_of(&url, connection_deadline(probe_end)).await else {
            hops.push(json!({"url": text, "skipped": "unresolved"}));
            break;
        };
        if let Some(why) = guard(&ip) {
            hops.push(json!({"url": text, "skipped": "protected", "why": why}));
            break;
        }
        let c = hop_client(client, &url, ip, port, probe_end);
        let seen = match fetch(&c, &text, MAX_RESPONSE, connection_deadline(probe_end)).await {
            Ok(s) => s,
            Err(e) => {
                hops.push(json!({"url": text, "error": e.to_string()}));
                break;
            }
        };
        let location = header(&seen.headers, LOCATION.as_str());
        let mut hop = Map::new();
        hop.insert("url".into(), json!(text));
        hop.extend(page_json(&seen));
        hop.insert("location".into(), json!(location));
        if url.scheme() == "https" {
            let t = tls::capture(ip, port, connection_deadline(probe_end)).await;
            hop.insert(
                "tls".into(),
                t.map(|t| tls::json(&t)).unwrap_or(Value::Null),
            );
            hop.insert(
                "jarm".into(),
                json!(jarm::fingerprint(ip, port, probe_end).await),
            );
        }
        hops.push(Value::Object(hop));
        let next = seen
            .headers
            .get(LOCATION)
            .filter(|_| (300..400).contains(&seen.status))
            .and_then(|l| l.to_str().ok())
            .and_then(|l| url.join(l).ok());
        match next {
            Some(n) => url = n,
            None => break,
        }
    }
    hops
}

/// The favicon URL: the page's `<link rel="icon">`, else `/favicon.ico`.
fn favicon_url(base: &Url, body: &[u8]) -> Option<Url> {
    let head = &body[..body.len().min(TITLE_WINDOW)];
    let mut at = 0;
    while let Some(i) = find_ci(&head[at..], b"<link") {
        let start = at + i;
        let end = head[start..]
            .iter()
            .position(|&b| b == b'>')
            .map_or(head.len(), |e| start + e);
        let tag = &head[start..end];
        let icon = attr(tag, b"rel").is_some_and(|r| {
            r.split(|b| b.is_ascii_whitespace())
                .any(|w| w.eq_ignore_ascii_case(b"icon"))
        });
        if icon
            && let Some(href) = attr(tag, b"href")
            && let Ok(u) = base.join(String::from_utf8_lossy(href).trim())
        {
            return Some(u);
        }
        at = end;
    }
    base.join("/favicon.ico").ok()
}

/// The value of attribute `name` (lowercase) in a tag, ignoring case.
fn attr<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut from = 0;
    while let Some(i) = find_ci(&tag[from..], name) {
        let p = from + i;
        from = p + name.len();
        let before_ok = p > 0 && tag[p - 1].is_ascii_whitespace();
        let rest = tag[from..].trim_ascii_start();
        if !before_ok || rest.first() != Some(&b'=') {
            continue;
        }
        let v = rest[1..].trim_ascii_start();
        return Some(match v.first() {
            Some(&q @ (b'"' | b'\'')) => {
                let v = &v[1..];
                &v[..v.iter().position(|&b| b == q).unwrap_or(v.len())]
            }
            _ => {
                &v[..v
                    .iter()
                    .position(|b| b.is_ascii_whitespace())
                    .unwrap_or(v.len())]
            }
        });
    }
    None
}

/// Read the web port `ip:port`: the root page, a random 404 path, the
/// favicon and (when the root redirects) the redirect chain.
pub async fn probe_http(
    ip: IpAddr,
    port: u16,
    https: bool,
    guard: Guard<'_>,
    probe_end: Instant,
) -> Value {
    let scheme = if https { "https" } else { "http" };
    let root = format!("{scheme}://{}/", SocketAddr::new(ip, port));
    let base = match Url::parse(&root) {
        Ok(u) => u,
        Err(e) => return json!({"error": e.to_string()}),
    };
    let client = client(probe_end);
    let seen = match fetch(&client, &root, MAX_RESPONSE, connection_deadline(probe_end)).await {
        Ok(s) => s,
        Err(e) => return json!({"error": e.to_string()}),
    };
    let mut out = page_json(&seen);
    out.insert("cookie_names".into(), json!(cookie_names(&seen.headers)));
    out.insert("truncated".into(), json!(seen.truncated));

    let random = format!("{}/{:016x}", origin_of(&base), rand::random::<u64>());
    out.insert(
        "not_found".into(),
        match fetch(
            &client,
            &random,
            MAX_RESPONSE,
            connection_deadline(probe_end),
        )
        .await
        {
            Ok(nf) => json!({
                "status": nf.status,
                "body_sha256": sha256_hex(&nf.body[..nf.body.len().min(HASH_WINDOW)]),
                "body_len": nf.body.len(),
            }),
            Err(_) => Value::Null,
        },
    );

    let (mut mmh3, mut sha) = (Value::Null, Value::Null);
    if let Some(fav) = favicon_url(&base, &seen.body) {
        let allowed = match target_of(&fav, connection_deadline(probe_end)).await {
            Some((fip, fport)) if guard(&fip).is_none() => {
                Some(hop_client(&client, &fav, fip, fport, probe_end))
            }
            _ => None,
        };
        if let Some(c) = allowed
            && let Ok(f) = fetch(
                &c,
                fav.as_str(),
                MAX_FAVICON,
                connection_deadline(probe_end),
            )
            .await
            && (200..300).contains(&f.status)
            && !f.truncated
            && !f.body.is_empty()
        {
            mmh3 = json!(favicon_mmh3(&f.body));
            sha = json!(sha256_hex(&f.body));
        }
    }
    out.insert("favicon_mmh3".into(), mmh3);
    out.insert("favicon_sha256".into(), sha);

    let redirects = if (300..400).contains(&seen.status) && seen.headers.contains_key(LOCATION) {
        follow_redirects(&client, &root, guard, probe_end).await
    } else {
        Vec::new()
    };
    out.insert("redirects".into(), Value::Array(redirects));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Redirect, Response};
    use axum::routing::get;

    fn not_global(ip: &IpAddr) -> Option<String> {
        // Loopback is where the test servers live; everything else that is
        // not globally routable is refused.
        let private = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        private.then(|| "not globally routable".to_string())
    }

    async fn serve(app: Router) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        addr
    }

    fn end() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn mmh3_matches_the_reference_vectors() {
        assert_eq!(mmh3_32(b"", 0), 0);
        assert_eq!(mmh3_32(b"hello", 0), 613153351);
        assert_eq!(
            mmh3_32(b"The quick brown fox jumps over the lazy dog", 0),
            776992547
        );
    }

    #[test]
    fn titles_and_cookie_names_are_read_and_bounded() {
        assert_eq!(
            title_of(b"<html><TITLE lang=en>\n  Hello\t  World </Title>").as_deref(),
            Some("Hello World")
        );
        assert_eq!(title_of(b"<html><body>no title</body>"), None);
        let long = format!("<title>{}</title>", "x".repeat(500));
        assert_eq!(title_of(long.as_bytes()).unwrap().chars().count(), 200);
        let late = format!("{}<title>late</title>", " ".repeat(70 * 1024));
        assert_eq!(title_of(late.as_bytes()), None);

        let mut h = HeaderMap::new();
        for i in 0..30 {
            h.append(SET_COOKIE, format!("c{i}=v; Path=/").parse().unwrap());
        }
        h.append(SET_COOKIE, "c0=again".parse().unwrap());
        let names = cookie_names(&h);
        assert_eq!(names.len(), 20);
        assert_eq!(names[0], "c0");
        assert_eq!(names[19], "c19");
    }

    #[tokio::test]
    async fn a_local_server_is_read_with_404_shape_favicon_and_redirects() {
        async fn root() -> Response {
            (
                [
                    (header::SERVER, "nginx/1.27.0"),
                    (header::HeaderName::from_static("x-powered-by"), "PHP/8.3"),
                    (header::SET_COOKIE, "PHPSESSID=abc; Path=/"),
                ],
                "<html><head><title>Admin Panel</title></head></html>",
            )
                .into_response()
        }
        let app = Router::new()
            .route("/", get(root))
            .route(
                "/favicon.ico",
                get(|| async { vec![0u8, 1, 2, 3, 4, 5, 6, 7] }),
            )
            .route(
                "/go",
                get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/landing")]) }),
            )
            .route("/landing", get(|| async { "<title>Landing</title>" }))
            .fallback(|| async { (StatusCode::NOT_FOUND, "nope") });
        let addr = serve(app).await;
        let v = probe_http(addr.ip(), addr.port(), false, &not_global, end()).await;
        assert_eq!(v["status"], 200);
        assert_eq!(v["server"], "nginx/1.27.0");
        assert_eq!(v["powered_by"], "PHP/8.3");
        assert_eq!(v["title"], "Admin Panel");
        assert_eq!(v["cookie_names"], json!(["PHPSESSID"]));
        assert_eq!(v["truncated"], false);
        assert_eq!(v["not_found"]["status"], 404);
        assert_eq!(v["not_found"]["body_len"], 4);
        assert_eq!(
            v["favicon_mmh3"],
            json!(favicon_mmh3(&[0, 1, 2, 3, 4, 5, 6, 7]))
        );
        assert_eq!(
            v["favicon_sha256"],
            json!(sha256_hex(&[0, 1, 2, 3, 4, 5, 6, 7]))
        );
        assert_eq!(v["redirects"], json!([]));

        let c = client(end());
        let hops = follow_redirects(&c, &format!("http://{addr}/go"), &not_global, end()).await;
        assert_eq!(hops.len(), 2, "{hops:?}");
        assert_eq!(hops[0]["status"], 302);
        assert_eq!(hops[0]["location"], "/landing");
        assert_eq!(hops[1]["url"], format!("http://{addr}/landing"));
        assert_eq!(hops[1]["status"], 200);
        assert_eq!(hops[1]["title"], "Landing");
    }

    #[tokio::test]
    async fn a_hop_to_protected_space_is_skipped() {
        let app = Router::new().route(
            "/",
            get(|| async { Redirect::temporary("http://10.0.0.1/admin") }),
        );
        let addr = serve(app).await;
        let v = probe_http(addr.ip(), addr.port(), false, &not_global, end()).await;
        let hops = v["redirects"].as_array().unwrap();
        assert_eq!(hops.len(), 2, "{hops:?}");
        assert_eq!(hops[0]["status"], 307);
        assert_eq!(hops[1]["url"], "http://10.0.0.1/admin");
        assert_eq!(hops[1]["skipped"], "protected");
        assert!(hops[1].get("status").is_none());
    }

    #[tokio::test]
    async fn a_chain_of_six_is_cut_at_five_hops() {
        let app = Router::new().route(
            "/{n}",
            get(
                |axum::extract::Path(n): axum::extract::Path<u32>| async move {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, format!("/{}", n + 1))],
                    )
                },
            ),
        );
        let addr = serve(app).await;
        let c = client(end());
        let hops = follow_redirects(&c, &format!("http://{addr}/1"), &not_global, end()).await;
        assert_eq!(hops.len(), 6, "{hops:?}");
        assert!(hops[..5].iter().all(|h| h["status"] == 302));
        assert_eq!(hops[5]["skipped"], "limit");
        assert_eq!(hops[5]["url"], format!("http://{addr}/6"));
    }
}
