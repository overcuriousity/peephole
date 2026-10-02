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
    let h = last_headers(&store).await;
    assert_eq!(header(&h, ":unrecorded"), Some("4"));
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
