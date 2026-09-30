use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::sync::Arc;

async fn spawn_trap() -> (String, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
trusted_proxies = ["127.0.0.1/32"]
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "peephole-test"
[maxmind]
account_id = "1"
license_key = "k"
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let state = Arc::new(TrapState::for_test(store.clone(), cfg));
    let app = trap::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // ConnectInfo extractors require into_make_service_with_connect_info.
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

#[tokio::test]
async fn probe_request_is_logged_and_serves_trap_page() {
    let (base, store, _dir) = spawn_trap().await;
    let resp = reqwest::get(format!("{base}/definitely-not-a-route"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("route which does not exist"));
    assert!(html.contains("classified as potentially malicious"));
    assert!(html.contains("I landed here by accident"));
    assert!(html.contains("this login form is for malicious bots"));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let level: i64 = sqlx::query_scalar("SELECT scan_level FROM requests LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(level, 1);
    // Level 1 → a scan job was queued.
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE status='queued'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(jobs, 1);
}

#[tokio::test]
async fn sqli_request_queues_level_4() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client
        .get(format!("{base}/login?u=admin'%20OR%20'1'='1"))
        .send()
        .await
        .unwrap();
    let level: i64 = sqlx::query_scalar("SELECT scan_level FROM requests LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(level, 4);
    let job_level: i64 = sqlx::query_scalar("SELECT level FROM scan_jobs LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(job_level, 4);
}

#[tokio::test]
async fn fp_claim_is_stored_and_scan_still_proceeds() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    // First a probe to create the IP + a scan job.
    let _ = client.get(format!("{base}/oops")).send().await.unwrap();
    let resp = client
        .post(format!("{base}/claim"))
        .header("user-agent", "Mozilla/5.0")
        .form(&[("email", "human@example.org")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let html = resp.text().await.unwrap();
    assert!(html.contains("admin was notified"));
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(claims, 1);
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(jobs >= 1, "scan must still be queued after fp claim");
}

#[tokio::test]
async fn bait_login_post_escalates() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{base}/login"))
        .form(&[("username", "admin"), ("password", "' OR '1'='1")])
        .send()
        .await
        .unwrap();
    let (level, labels): (i64, String) =
        sqlx::query_as("SELECT scan_level, labels_json FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(level, 4);
    assert!(labels.contains("form-interaction"));
}

#[tokio::test]
async fn collect_stores_fingerprint_and_correlates_ips() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    // Request 1 from "IP A" (simulated via X-Forwarded-For, 127.0.0.1 is trusted).
    let _ = client
        .get(format!("{base}/r1"))
        .header("x-forwarded-for", "203.0.113.50")
        .send()
        .await
        .unwrap();
    let token: String =
        sqlx::query_scalar("SELECT page_token FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    let payload = serde_json::json!({
        "token": token,
        "attrs": {"canvas":"abc","webgl_renderer":"Mesa","fonts_hash":"f1","audio":"0.4","screen":"1920x1080x24","timezone":"UTC","platform":"Linux","webdriver":false},
        "behavior": {"fill_seconds": null, "mouse_events": 5, "events": []}
    });
    let resp = client
        .post(format!("{base}/collect"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Same fingerprint from a second IP.
    let _ = client
        .get(format!("{base}/r2"))
        .header("x-forwarded-for", "198.51.100.60")
        .send()
        .await
        .unwrap();
    let token2: String =
        sqlx::query_scalar("SELECT page_token FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    let mut p2 = payload.clone();
    p2["token"] = serde_json::json!(token2);
    let _ = client
        .post(format!("{base}/collect"))
        .json(&p2)
        .send()
        .await
        .unwrap();

    let fps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fingerprints")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(fps, 2);
    let hash: String = sqlx::query_scalar("SELECT fp_hash FROM fingerprints LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let distinct: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT ip_id) FROM fingerprints WHERE fp_hash = ?")
            .bind(&hash)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(
        distinct, 2,
        "same operator across IPs — the core correlation"
    );

    // Panel endpoint returns human-readable, non-JSON HTML.
    let panel = client
        .get(format!("{base}/panel?token={token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(panel.contains("What we see about you"));
    assert!(panel.contains("Mesa"));
}

#[tokio::test]
async fn panel_is_structurally_randomized() {
    let (base, _store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client.get(format!("{base}/r1")).send().await.unwrap();
    let token: String = sqlx::query_scalar("SELECT page_token FROM requests LIMIT 1")
        .fetch_one(&_store.pool)
        .await
        .unwrap();
    let a = client
        .get(format!("{base}/panel?token={token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let b = client
        .get(format!("{base}/panel?token={token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(
        a, b,
        "panel markup must differ per request (bot-unfriendly)"
    );
}

use peephole::admin::{self, AdminState};

async fn spawn_admin_with(store: Store, dir: &std::path::Path) -> String {
    let cfg_path = dir.join("c.toml");
    let cfg = Config::load(&cfg_path).unwrap();
    let app = admin::router(std::sync::Arc::new(AdminState::public_only(store, cfg)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn dashboard_shows_aggregates_not_payloads() {
    let (trap_base, store, dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    // Generate traffic with a distinctive payload that must NOT leak to public pages.
    let _ = client
        .post(format!("{trap_base}/login"))
        .header("x-forwarded-for", "203.0.113.99")
        .form(&[("username", "SECRET-PAYLOAD-MARKER"), ("password", "x")])
        .send()
        .await
        .unwrap();
    let admin_base = spawn_admin_with(store.clone(), dir.path()).await;

    let html = reqwest::get(format!("{admin_base}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("peephole"));
    assert!(html.contains("203.0.113.99")); // IP is fine on the wall of shame
    assert!(!html.contains("SECRET-PAYLOAD-MARKER")); // payloads never public

    let stats: serde_json::Value = reqwest::get(format!("{admin_base}/api/stats"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(stats["total_requests"].as_i64().unwrap() >= 1);
    assert!(stats["unique_ips"].as_i64().unwrap() >= 1);
    assert!(!stats.to_string().contains("SECRET-PAYLOAD-MARKER"));
}

#[tokio::test]
async fn queue_sse_streams_job_updates() {
    let (trap_base, store, dir) = spawn_trap().await;
    let _ = reqwest::get(format!("{trap_base}/probe")).await.unwrap();
    let admin_base = spawn_admin_with(store, dir.path()).await;
    let resp = reqwest::get(format!("{admin_base}/api/queue"))
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    // SSE streams forever; read only the first chunks under a deadline.
    let body = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut resp = resp;
        let mut buf = String::new();
        while buf.len() < 16 {
            match resp.chunk().await.unwrap() {
                Some(c) => buf.push_str(&String::from_utf8_lossy(&c)),
                None => break,
            }
        }
        buf
    })
    .await
    .unwrap();
    assert!(body.contains("queued") || body.contains("running") || body.contains("done"));
}

#[tokio::test]
async fn authenticated_routes_redirect_without_session() {
    let (_trap_base, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let app = peephole::admin::router_with_auth(store, cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for path in ["/requests", "/ips/1", "/inbox", "/export", "/keys"] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 303, "{path} must redirect to login");
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }
    // Public routes stay public.
    let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("http://{addr}/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn webauthn_ceremony_with_soft_token() {
    // Full ceremony: enroll (with setup token) then login, using
    // webauthn-authenticator-rs's soft token.
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let (_trap_base, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let token = peephole::admin::auth::ensure_setup_token(&store, std::path::Path::new("/tmp"))
        .await
        .unwrap();
    let app = peephole::admin::router_with_auth(store.clone(), cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let mut soft = SoftPasskey::new(true);
    // Enrollment start: server returns PublicKeyCredentialCreationOptions JSON + challenge id cookie.
    let resp = client
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"setup_token": token.unwrap(), "label": "test-key"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cco: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let origin = Url::parse("https://localhost").unwrap();
    let cred = soft.perform_register(origin, options, 60_000).unwrap();
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&serde_json::json!({"credential": cred}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "enroll finish failed: {:?}",
        resp.text().await
    );
    assert_eq!(store.load_credentials().await.unwrap().len(), 1);

    // Login with the same soft token.
    let resp = client
        .post(format!("{base}/login/start"))
        .send()
        .await
        .unwrap();
    let cro: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialRequestOptions =
        serde_json::from_value(cro["publicKey"].clone()).unwrap();
    let assertion = soft
        .perform_auth(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    let resp = client
        .post(format!("{base}/login/finish"))
        .json(&serde_json::json!({"credential": assertion}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Login created a valid session (covered by the cookie set on /login/finish).
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(sessions >= 1);
}

/// Spins `router_with_auth` on an ephemeral port and runs the soft-passkey
/// enroll ceremony (fresh store per test, so the setup token is issuable).
async fn enrolled_admin_client(store: Store, cfg: Config) -> (reqwest::Client, String) {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let token = peephole::admin::auth::ensure_setup_token(&store, std::path::Path::new("/tmp"))
        .await
        .unwrap()
        .expect("setup token issuable on fresh store");
    let app = peephole::admin::router_with_auth(store, cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let mut soft = SoftPasskey::new(true);
    let resp = client
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"setup_token": token, "label": "test-key"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cco: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let cred = soft
        .perform_register(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&serde_json::json!({"credential": cred}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "enroll finish failed");
    (client, base)
}

#[tokio::test]
async fn detail_views_and_inbox_work_with_session() {
    let (trap_base, store, dir) = spawn_trap().await;
    let client_pub = reqwest::Client::new();
    // Seed: one probe, one fp claim with email, one sqli.
    let _ = client_pub
        .get(format!("{trap_base}/hello"))
        .header("x-forwarded-for", "203.0.113.77")
        .send()
        .await
        .unwrap();
    let _ = client_pub
        .post(format!("{trap_base}/claim"))
        .header("x-forwarded-for", "203.0.113.77")
        .form(&[("email", "lost@example.org")])
        .send()
        .await
        .unwrap();
    let _ = client_pub
        .get(format!("{trap_base}/login?u=' OR '1'='1"))
        .header("x-forwarded-for", "203.0.113.78")
        .send()
        .await
        .unwrap();

    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;

    // Request list with filter.
    let html = client
        .get(format!("{base}/requests?path=/hello"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("/hello"));
    assert!(!html.contains("/login"));

    // Per-request detail contains headers and body (authenticated only).
    let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/hello' LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let html = client
        .get(format!("{base}/requests/{rid}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("x-forwarded-for"));

    // Per-IP detail.
    let ip_id: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '203.0.113.77'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let html = client
        .get(format!("{base}/ips/{ip_id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.77"));
    assert!(html.contains("/hello"));

    // Inbox shows the fp claim with contact email.
    let html = client
        .get(format!("{base}/inbox"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("lost@example.org"));

    // Keys page lists enrolled key.
    let html = client
        .get(format!("{base}/keys"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("test-key") || html.contains("credential"));
}

#[tokio::test]
async fn export_download_requires_auth_and_filters() {
    let (trap_base, store, dir) = spawn_trap().await;
    let client_pub = reqwest::Client::new();
    let _ = client_pub
        .get(format!("{trap_base}/a"))
        .header("x-forwarded-for", "203.0.113.1")
        .send()
        .await
        .unwrap();
    let _ = client_pub
        .get(format!("{trap_base}/b"))
        .header("x-forwarded-for", "198.51.100.2")
        .send()
        .await
        .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;

    let resp = client
        .get(format!("{base}/export/download?format=csv&ip=203.0.113.1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("attachment")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("203.0.113.1"));
    assert!(!body.contains("198.51.100.2"));

    let resp = client
        .get(format!("{base}/export/download?format=jsonl"))
        .send()
        .await
        .unwrap();
    let first: serde_json::Value =
        serde_json::from_str(resp.text().await.unwrap().lines().next().unwrap()).unwrap();
    assert!(first.get("datetime").is_some());

    let resp = client
        .get(format!("{base}/export/download?format=parquet"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.unwrap().len() > 100);
}

#[tokio::test]
async fn full_stack_smoke() {
    // Start the real run() against a temp config with ephemeral ports.
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:18080"
admin_listen = "127.0.0.1:18443"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
trusted_proxies = ["127.0.0.1/32"]
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "peephole-test"
[maxmind]
account_id = "1"
license_key = "k"
[scan]
max_workers = 1
timeout_secs = 5
rescan_cooldown_hours = 24
max_scans_per_hour = 100
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, &cfg_text).unwrap();
    // Point the scan pool at the fake nmap so the smoke test needs no privileges.
    // SAFETY: test-only; PEEPHOLE_NMAP_PATH is read once by run() below and no
    // other test in this binary touches the environment.
    unsafe {
        std::env::set_var("PEEPHOLE_NMAP_PATH", fake_nmap(dir.path()));
    }
    let handle = tokio::spawn(peephole::run(cfg_path.clone()));
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:18080/bot-traffic")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = client
        .get("http://127.0.0.1:18443/api/stats")
        .send()
        .await
        .unwrap();
    let stats: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(stats["total_requests"], 1);
    // Fake nmap should have completed the queued scan.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let stats: serde_json::Value = client
            .get("http://127.0.0.1:18443/api/stats")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if stats["scans_done"].as_i64().unwrap() >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "scan did not complete"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    handle.abort();
}

fn fake_nmap(dir: &std::path::Path) -> String {
    let fake = dir.join("fake-nmap");
    std::fs::write(&fake, "#!/bin/sh\ncat \"$(dirname \"$0\")/nmap.xml\"\n").unwrap();
    std::fs::copy("tests/fixtures/nmap-basic.xml", dir.join("nmap.xml")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    fake.to_string_lossy().into_owned()
}

#[tokio::test]
async fn assets_and_security_headers() {
    let (_trap, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let resp = reqwest::get(format!("{base}/assets/app.css"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("max-age=31536000")
    );
    assert!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
    let css = resp.text().await.unwrap();
    assert!(css.contains("--color-accent"));
    assert!(css.contains("@font-face"));

    let resp = reqwest::get(format!("{base}/assets/fonts/inter-400.woff2"))
        .await
        .unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "font/woff2");

    let resp = reqwest::get(format!("{base}/")).await.unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );

    assert_eq!(
        reqwest::get(format!("{base}/assets/nope.css"))
            .await
            .unwrap()
            .status(),
        404
    );
}
