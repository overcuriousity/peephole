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
secure_cookies = false
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
    // Present a public source IP via XFF (127.0.0.1 is the trusted proxy);
    // loopback and other non-global addresses are never counter-scanned.
    let resp = reqwest::Client::new()
        .get(format!("{base}/definitely-not-a-route"))
        .header("x-forwarded-for", "203.0.113.1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("route which does not exist"));
    assert!(html.contains("classified as potentially malicious"));
    assert!(html.contains("I landed here by accident"));
    assert!(html.contains("decoy for automated tools"));
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
        .header("x-forwarded-for", "203.0.113.5")
        .send()
        .await
        .unwrap();
    let level: i64 = sqlx::query_scalar("SELECT scan_level FROM requests LIMIT 1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(level, 4);
    // One request is thin evidence (a link preview could cause it): the
    // job is capped at scan.single_request_max_level (2) ...
    let job_level = || async {
        sqlx::query_scalar::<_, i64>("SELECT MAX(level) FROM scan_jobs")
            .fetch_one(&store.pool)
            .await
            .unwrap()
    };
    assert_eq!(job_level().await, 2);
    // ... until the IP keeps at it.
    for _ in 0..2 {
        let _ = client
            .get(format!("{base}/login?u=admin'%20OR%20'1'='1"))
            .header("x-forwarded-for", "203.0.113.5")
            .send()
            .await
            .unwrap();
    }
    assert_eq!(job_level().await, 4);
}

#[tokio::test]
async fn fp_claim_is_stored_and_scan_still_proceeds() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    // First a probe to create the IP + a scan job (public IP via XFF).
    let _ = client
        .get(format!("{base}/oops"))
        .header("x-forwarded-for", "203.0.113.5")
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/claim"))
        .header("x-forwarded-for", "203.0.113.5")
        .header("user-agent", "Mozilla/5.0")
        .form(&[("email", "human@example.org")])
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let html = resp.text().await.unwrap();
    assert!(html.contains("administrator has been notified"));
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
async fn wall_shows_aggregates_not_payloads() {
    let (trap_base, store, dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{trap_base}/login"))
        .header("x-forwarded-for", "203.0.113.99")
        .form(&[("username", "SECRET-PAYLOAD-MARKER"), ("password", "x")])
        .send()
        .await
        .unwrap();
    let _ = client
        .get(format!("{trap_base}/wp-login.php"))
        .header("x-forwarded-for", "203.0.113.99")
        .header("x-secret-header", "HEADER-MARKER")
        .send()
        .await
        .unwrap();
    let admin_base = spawn_admin_with(store.clone(), dir.path()).await;
    let resp = reqwest::get(format!("{admin_base}/?range=7d"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    // The IP is named (wall of shame) but no request rows are shown: the
    // public wall has no "Recent activity" table, so request paths stay out.
    assert!(html.contains("203.0.113.99"));
    assert!(html.contains("href=\"/ip/203.0.113.99\""));
    assert!(
        !html.contains("/wp-login.php"),
        "public wall must not list request paths"
    );
    assert!(
        !html.contains("Recent activity"),
        "public wall has no recent-activity table"
    );
    assert!(html.contains("Last 7 days"));
    assert!(html.contains("data-range=\"7d\""));
    assert!(html.contains("id=\"map\""));
    assert!(html.contains("/assets/js/charts.js"));
    assert!(!html.contains("SECRET-PAYLOAD-MARKER"));
    assert!(!html.contains("HEADER-MARKER"));
    assert!(!html.contains("<script>"), "no inline scripts under CSP");
    assert!(!html.contains(" style=\""), "no inline styles under CSP");
    let ok = reqwest::get(format!("{admin_base}/healthz")).await.unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "ok");
    let svg = reqwest::get(format!("{admin_base}/assets/world.svg"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(svg.contains("id=\"DE\""));
}

async fn read_sse_until(resp: reqwest::Response, needle: &str, secs: u64) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(secs), async {
        let mut resp = resp;
        let mut buf = String::new();
        while !buf.contains(needle) {
            match resp.chunk().await.unwrap() {
                Some(c) => buf.push_str(&String::from_utf8_lossy(&c)),
                None => break,
            }
        }
        buf
    })
    .await
    .expect("sse deadline")
}

#[tokio::test]
async fn queue_sse_requires_session_and_streams_snapshot_then_jobs() {
    let (trap_base, store, dir) = spawn_trap().await;
    let _ = reqwest::Client::new()
        .get(format!("{trap_base}/probe"))
        .header("x-forwarded-for", "203.0.113.5")
        .send()
        .await
        .unwrap();
    // Unauthenticated → redirect to /login.
    let admin_base = spawn_admin_with(store.clone(), dir.path()).await;
    let resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!("{admin_base}/admin/api/queue"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get("location").unwrap(), "/login");

    // Authenticated: first event is a snapshot containing the queued probe job.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base, state) = enrolled_admin_client_with_state(store.clone(), cfg).await;
    let resp = client
        .get(format!("{base}/admin/api/queue"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let body = read_sse_until(resp, "event: snapshot", 5).await;
    assert!(body.contains("\"status\":\"queued\""));

    // A published job arrives as `event: job`.
    let resp = client
        .get(format!("{base}/admin/api/queue"))
        .send()
        .await
        .unwrap();
    let ip = store
        .upsert_ip("198.51.100.77".parse().unwrap())
        .await
        .unwrap();
    let id = match store.enqueue_scan(ip.id, 3, 24).await.unwrap() {
        peephole::store::scans::EnqueueOutcome::Queued(id) => id,
        o => panic!("{o:?}"),
    };
    state
        .notifier
        .publish(store.queue_job(id).await.unwrap().unwrap());
    let body = read_sse_until(resp, "event: job", 5).await;
    assert!(body.contains("198.51.100.77"));
}

#[tokio::test]
async fn admin_routes_redirect_without_session() {
    let (_trap_base, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for path in [
        "/admin",
        "/admin/queue",
        "/admin/requests/1",
        "/admin/scans",
        "/admin/scans/1",
        "/admin/scans/1/xml",
        "/admin/fingerprints",
        "/admin/inbox",
        "/admin/export",
        "/admin/export/download?format=csv",
        "/admin/keys",
        // Request rows identify individual clients, so request search is
        // admin-only.
        "/requests",
        "/requests?path=/x",
    ] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path}");
        assert_eq!(resp.headers().get("location").unwrap(), "/login", "{path}");
    }
    for path in [
        "/admin/requests/1/delete",
        "/admin/ips/203.0.113.1/delete",
        "/admin/scans/1/delete",
        "/admin/claims/1/delete",
        "/admin/keys/delete",
    ] {
        let resp = client.post(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path}");
    }
    // Public routes stay public.
    for path in ["/", "/login", "/ips"] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
    }
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

/// Spins the full router on an ephemeral port and runs the soft-passkey
/// enroll ceremony (fresh store per test, so the setup token is issuable).
/// Returns the shared state too, so tests can publish queue events.
async fn enrolled_admin_client_with_state(
    store: Store,
    cfg: Config,
) -> (reqwest::Client, String, Arc<AdminState>) {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let token = peephole::admin::auth::ensure_setup_token(&store, std::path::Path::new("/tmp"))
        .await
        .unwrap()
        .expect("setup token issuable on fresh store");
    let state = Arc::new(AdminState::public_only(store, cfg));
    let app = peephole::admin::full_router(state.clone());
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
    (client, base, state)
}

async fn enrolled_admin_client(store: Store, cfg: Config) -> (reqwest::Client, String) {
    let (c, b, _) = enrolled_admin_client_with_state(store, cfg).await;
    (c, b)
}

#[tokio::test]
async fn admin_pages_and_deletes_with_session() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let _ = c
        .get(format!("{trap_base}/hello"))
        .header("x-forwarded-for", "203.0.113.77")
        .header("x-marker", "HEADER-MARKER")
        .send()
        .await
        .unwrap();
    let _ = c
        .post(format!("{trap_base}/claim"))
        .header("x-forwarded-for", "203.0.113.77")
        .form(&[("email", "lost@example.org")])
        .send()
        .await
        .unwrap();
    let _ = c
        .post(format!("{trap_base}/login"))
        .header("x-forwarded-for", "203.0.113.78")
        .form(&[("username", "BODY-MARKER"), ("password", "x")])
        .send()
        .await
        .unwrap();
    let ip77 = store.ip_by_addr("203.0.113.77").await.unwrap().unwrap();
    let ip78 = store.ip_by_addr("203.0.113.78").await.unwrap().unwrap();
    store
        .insert_fingerprint(None, ip77.id, "CLUSTERHASH", None, "{}", "{}", b"[]")
        .await
        .unwrap();
    store
        .insert_fingerprint(None, ip78.id, "CLUSTERHASH", None, "{}", "{}", b"[]")
        .await
        .unwrap();
    // Finish every job the trap queued (78's bait POST is the interesting one).
    while let Some(job) = store.next_queued_job().await.unwrap() {
        store
            .finish_job(
                job.id,
                Some(&peephole::scan::nmap_xml::ScanResult {
                    os_guess: Some("Linux".into()),
                    raw_xml: b"<nmaprun>RAWXML</nmaprun>".to_vec(),
                    ports: vec![peephole::scan::nmap_xml::PortResult {
                        port: 22,
                        proto: "tcp".into(),
                        state: "open".into(),
                        service: Some("ssh".into()),
                        product: None,
                        version: None,
                    }],
                }),
                None,
            )
            .await
            .unwrap();
    }

    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;
    let get = |p: &str| client.get(format!("{base}{p}")).send();

    let html = get("/admin").await.unwrap().text().await.unwrap();
    assert!(
        html.contains("Scan queue")
            && html.contains("data-queue")
            && html.contains("/admin/api/queue")
    );
    assert!(html.contains("unread"));
    let html = get("/admin/queue").await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.78") && html.contains("done"));

    let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/login'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let html = get(&format!("/admin/requests/{rid}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("BODY-MARKER")
            && html.contains("x-forwarded-for")
            && html.contains("form-interaction")
    );
    assert!(
        html.contains("answered not-found (404)"),
        "how it was answered"
    );

    let html = get("/admin/scans").await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.78"));
    let sid: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?")
        .bind(ip78.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let html = get(&format!("/admin/scans/{sid}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("22/tcp") && html.contains("ssh"));
    let xml = get(&format!("/admin/scans/{sid}/xml")).await.unwrap();
    assert_eq!(
        xml.headers().get("content-type").unwrap(),
        "application/xml"
    );
    assert!(xml.text().await.unwrap().contains("RAWXML"));

    let html = get("/admin/fingerprints")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("CLUSTERHASH")
            && html.contains("203.0.113.77")
            && html.contains("203.0.113.78")
    );
    let html = get("/admin/inbox").await.unwrap().text().await.unwrap();
    assert!(html.contains("lost@example.org"));
    let html = get("/admin/keys").await.unwrap().text().await.unwrap();
    assert!(html.contains("test-key") && html.contains("/enroll"));
    let html = get("/admin/export").await.unwrap().text().await.unwrap();
    assert!(html.contains("/admin/export/download"));
    for html_path in [
        "/admin",
        "/admin/queue",
        &format!("/admin/requests/{rid}"),
        "/admin/keys",
    ] {
        let html = get(html_path).await.unwrap().text().await.unwrap();
        assert!(
            !html.contains("<script>") && !html.contains(" style=\""),
            "{html_path} inline code"
        );
    }

    // Deletes.
    let resp = client
        .post(format!("{base}/admin/scans/{sid}/delete"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200); // followed redirect
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans WHERE id = ?")
        .bind(sid)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let cid: i64 = sqlx::query_scalar("SELECT id FROM fp_claims")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    client
        .post(format!("{base}/admin/claims/{cid}/delete"))
        .send()
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    client
        .post(format!("{base}/admin/requests/{rid}/delete"))
        .send()
        .await
        .unwrap();
    assert!(store.request_by_id(rid).await.unwrap().is_none());
    let resp = client
        .post(format!("{base}/admin/ips/203.0.113.77/delete"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.url().path(), "/ips", "redirects to the directory");
    assert!(store.ip_by_addr("203.0.113.77").await.unwrap().is_none());
    assert!(store.ip_by_addr("203.0.113.78").await.unwrap().is_some());
    assert_eq!(
        client
            .post(format!("{base}/admin/ips/nope/delete"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn enroll_additional_key_with_session() {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let (_trap_base, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;
    // No setup token: the session alone authorises enrollment.
    let resp = client
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"label": "second"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cco: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let mut soft = SoftPasskey::new(true);
    let cred = soft
        .perform_register(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&serde_json::json!({"credential": cred}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(store.load_credentials().await.unwrap().len(), 2);
    let labels = store.list_credential_labels().await.unwrap();
    assert!(
        labels.iter().any(|(_, l, _)| l == "second"),
        "label stored: {labels:?}"
    );
    // Anonymous without token → 403.
    let anon = reqwest::Client::new();
    let resp = anon
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"label": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
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
        .get(format!(
            "{base}/admin/export/download?format=csv&ip=203.0.113.1"
        ))
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
        .get(format!("{base}/admin/export/download?format=jsonl"))
        .send()
        .await
        .unwrap();
    let first: serde_json::Value =
        serde_json::from_str(resp.text().await.unwrap().lines().next().unwrap()).unwrap();
    assert!(first.get("datetime").is_some());

    let resp = client
        .get(format!("{base}/admin/export/download?format=parquet"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.bytes().await.unwrap().len() > 100);

    // The export form submits every field, blank ones included.
    let body = client
        .get(format!(
            "{base}/admin/export/download?format=csv&from=&to=&ip=&label=&min_severity="
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body.lines().count(), 3, "header + both rows: {body}");

    // datetime-local bounds: today's minute range must include today's rows.
    let now = chrono::Utc::now();
    let from = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M");
    let to = now.format("%Y-%m-%dT%H:%M");
    let body = client
        .get(format!(
            "{base}/admin/export/download?format=csv&from={from}&to={to}&ip=&label="
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body.lines().count(), 3, "rows inside [from, to]: {body}");
}

#[tokio::test]
async fn full_stack_smoke() {
    // Start the real run() against a temp config with ephemeral ports.
    let dir = tempfile::tempdir().unwrap();
    let (trap, admin) = (free_port(), free_port());
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
trusted_proxies = ["127.0.0.1/32"]
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "peephole-test"
secure_cookies = false
[maxmind]
account_id = "1"
license_key = "k"
[scan]
max_workers = 1
timeout_secs = 60
rescan_cooldown_hours = 24
max_scans_per_hour = 100
# No Tor list and no DNS in tests.
tor_unknown = "scan"
verify_crawlers = false
# The fake nmap, so the smoke test needs no privileges.
nmap_path = "{nmap}"
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display(),
        nmap = fake_nmap(dir.path()),
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, &cfg_text).unwrap();
    let handle = tokio::spawn(peephole::run(cfg_path.clone()));

    let client = reqwest::Client::new();
    // Readiness: the trap starts before the web role, so once the admin
    // listener answers both are up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while client
        .get(format!("http://127.0.0.1:{admin}/healthz"))
        .send()
        .await
        .is_err()
    {
        assert!(!handle.is_finished(), "run() exited during startup");
        assert!(
            std::time::Instant::now() < deadline,
            "listeners never came up"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let resp = client
        .get(format!("http://127.0.0.1:{trap}/bot-traffic"))
        .header("x-forwarded-for", "203.0.113.7")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let resp = client
        .get(format!("http://127.0.0.1:{admin}/api/stats"))
        .send()
        .await
        .unwrap();
    let stats: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(stats["total_requests"], 1);
    // Fake nmap should have completed the queued scan. `/api/stats` is
    // cached for 15 s by design, so poll the database file directly.
    let probe = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let scans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
            .fetch_one(&probe.pool)
            .await
            .unwrap();
        if scans >= 1 {
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

/// A free localhost port (bound, then released for the code under test).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `web = false`: the trap serves, the admin listener is never bound.
#[tokio::test]
async fn run_without_web_role_binds_no_admin_listener() {
    let dir = tempfile::tempdir().unwrap();
    let (trap, admin) = (free_port(), free_port());
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{db}"
data_dir = "{d}"
rules_dir = "rules"
[roles]
scanner = false
web = false
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, &cfg_text).unwrap();
    let handle = tokio::spawn(peephole::run(cfg_path));
    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let resp = loop {
        match client
            .get(format!("http://127.0.0.1:{trap}/probe"))
            .send()
            .await
        {
            Ok(r) => break r,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            Err(e) => panic!("trap never came up: {e}"),
        }
    };
    assert_eq!(resp.status(), 404);
    assert!(
        client
            .get(format!("http://127.0.0.1:{admin}/"))
            .send()
            .await
            .is_err(),
        "admin listener must not be bound without the web role"
    );
    assert!(!handle.is_finished());
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

#[tokio::test]
async fn unknown_route_renders_styled_404() {
    let (_trap, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let resp = reqwest::get(format!("{base}/this/does/not/exist"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Not found"));
    assert!(html.contains("/assets/app.css"));
}

#[tokio::test]
async fn stats_and_map_json_by_range() {
    let (trap_base, store, dir) = spawn_trap().await;
    let _ = reqwest::Client::new()
        .get(format!("{trap_base}/x"))
        .header("x-forwarded-for", "203.0.113.9")
        .send()
        .await
        .unwrap();
    let base = spawn_admin_with(store, dir.path()).await;
    let s: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=7d"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["range"], "7d");
    assert_eq!(s["total_requests"], 1);
    assert!(s["timeline"].as_array().unwrap().len() == 1);
    let s2: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=7d"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(s["generated_at"], s2["generated_at"], "served from cache");
    let bad: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=1y"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bad["range"], "24h");
    let m: serde_json::Value = reqwest::get(format!("{base}/api/map"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(m["countries"].is_object());
    assert_eq!(m["max"], 0, "no geoip in tests");
}

#[tokio::test]
async fn public_ip_page_shows_aggregates_but_hides_requests_and_admin_data() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let _ = c
        .get(format!("{trap_base}/wp-login.php"))
        .header("x-forwarded-for", "203.0.113.42")
        .header("x-secret-header", "HEADER-MARKER")
        .send()
        .await
        .unwrap();
    let _ = c
        .post(format!("{trap_base}/claim"))
        .header("x-forwarded-for", "203.0.113.42")
        .form(&[("email", "claimant@example.org")])
        .send()
        .await
        .unwrap();
    let ip = store.ip_by_addr("203.0.113.42").await.unwrap().unwrap();
    store
        .insert_fingerprint(
            None,
            ip.id,
            "FPHASHMARKER",
            Some("VISITORMARKER"),
            "{}",
            "{}",
            b"[]",
        )
        .await
        .unwrap();
    // The trap already queued a scan for this IP; take and finish that job.
    let job = store.next_queued_job().await.unwrap().unwrap().id;
    store
        .finish_job(
            job,
            Some(&peephole::scan::nmap_xml::ScanResult {
                os_guess: Some("OSGUESSMARKER".into()),
                raw_xml: b"<nmaprun/>".to_vec(),
                ports: vec![peephole::scan::nmap_xml::PortResult {
                    port: 31337,
                    proto: "tcp".into(),
                    state: "open".into(),
                    service: Some("SERVICEMARKER".into()),
                    product: None,
                    version: None,
                }],
            }),
            None,
        )
        .await
        .unwrap();

    let base = spawn_admin_with(store.clone(), dir.path()).await;
    let html = reqwest::get(format!("{base}/ip/203.0.113.42"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.42"));
    assert!(html.contains("data-sparkline=\"["));
    for marker in [
        // Per-request rows (path included) are admin-only now.
        "/wp-login.php",
        "HEADER-MARKER",
        "claimant@example.org",
        "FPHASHMARKER",
        "VISITORMARKER",
        "OSGUESSMARKER",
        "SERVICEMARKER",
        "31337",
        "Counter-scans",
        "Jobs",
        "Delete",
    ] {
        assert!(!html.contains(marker), "public page leaked {marker}");
    }
    assert!(html.contains("Intelligence") && html.contains("MaxMind GeoLite2"));
    assert_eq!(
        reqwest::get(format!("{base}/ip/hello"))
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        reqwest::get(format!("{base}/ip/203.0.113.43"))
            .await
            .unwrap()
            .status(),
        404
    );
    store
        .upsert_ip("2001:db8::1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        reqwest::get(format!("{base}/ip/2001:db8::1"))
            .await
            .unwrap()
            .status(),
        200
    );

    // With a session the same page shows everything.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, abase) = enrolled_admin_client(store.clone(), cfg).await;
    let html = client
        .get(format!("{abase}/ip/203.0.113.42"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for marker in [
        "/wp-login.php",
        "claimant@example.org",
        "FPHASHMARKER",
        "OSGUESSMARKER",
        "SERVICEMARKER",
        "31337",
        "Counter-scans",
        "Jobs",
        "Intelligence",
        "Delete this IP",
    ] {
        assert!(html.contains(marker), "admin page missing {marker}");
    }
}

#[tokio::test]
async fn public_directory_is_public_but_request_search_is_admin() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    for (ip, path) in [
        ("203.0.113.1", "/a"),
        ("203.0.113.1", "/b"),
        ("203.0.113.200", "/c"),
        ("198.51.100.7", "/d"),
    ] {
        let _ = c
            .get(format!("{trap_base}{path}"))
            .header("x-forwarded-for", ip)
            .send()
            .await
            .unwrap();
    }
    let base = spawn_admin_with(store.clone(), dir.path()).await;
    // The IP directory stays public (named-and-shamed).
    let html = reqwest::get(format!("{base}/ips"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("href=\"/ip/203.0.113.1\""));
    assert!(html.contains("198.51.100.7"));
    let html = reqwest::get(format!("{base}/ips?q=203.0.113.0/24"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.1") && html.contains("203.0.113.200"));
    assert!(!html.contains("198.51.100.7"));
    let html = reqwest::get(format!("{base}/ips?q=garbage&page=-3"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("No IPs match"));
    // Request search is admin-only: anonymous is redirected to /login.
    let noredir = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = noredir
        .get(format!("{base}/requests?path=/c"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get("location").unwrap(), "/login");
    // With a session the search works and links to request detail.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, abase) = enrolled_admin_client(store, cfg).await;
    let html = client
        .get(format!("{abase}/requests?path=/c"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("/c") && !html.contains(">/a<"));
    assert!(html.contains("href=\"/admin/requests/"));
}

#[tokio::test]
async fn trap_page_is_a_realistic_notice_with_honest_footnote() {
    let (base, _store, _dir) = spawn_trap().await;
    let resp = reqwest::get(format!("{base}/anything")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Staff sign-in"));
    assert!(html.contains("decoy for automated tools"));
    assert!(html.contains("I landed here by accident"));
    assert!(html.contains("prefers-color-scheme: dark"));
    assert!(html.contains("noindex"));
    assert!(html.contains("window.PEEPHOLE_TOKEN"));
    assert!(!html.contains("href=\"/login\"") && !html.contains("/admin"));
    assert!(
        !html.contains("@font-face"),
        "trap uses the system font stack"
    );
    assert!(!html.contains("⚠"));
    let ok = reqwest::Client::new()
        .post(format!("{base}/claim"))
        .form(&[("email", "")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(ok.contains("Thank you") && ok.contains("prefers-color-scheme: dark"));
}

#[tokio::test]
async fn bulk_delete_checked_and_filtered() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let ip = store
        .upsert_ip("203.0.113.50".parse().unwrap())
        .await
        .unwrap();
    for _ in 0..120 {
        store
            .insert_request(&peephole::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/bulk".into(),
                query: None,
                headers_json: "[]".into(),
                body: None,
                labels_json: "[]".into(),
                severity: 0,
                scan_level: 0,
                is_fp_claim: false,
                page_token: None,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let _ = c
        .get(format!("{trap_base}/keep"))
        .header("x-forwarded-for", "203.0.113.50")
        .send()
        .await
        .unwrap();
    for lo in ["127.0.0.1", "127.0.0.2"] {
        let _ = c
            .get(format!("{trap_base}/lo"))
            .header("x-forwarded-for", lo)
            .send()
            .await
            .unwrap();
    }

    // Anonymous: gated.
    let base = spawn_admin_with(store.clone(), dir.path()).await;
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for p in ["/admin/requests/bulk-delete", "/admin/ips/bulk-delete"] {
        let resp = anon
            .post(format!("{base}{p}"))
            .form(&[("all", "1")])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 303, "{p}");
    }
    let resp = anon
        .get(format!("{base}/requests?path=/keep"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "request search is admin-only");

    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, abase) = enrolled_admin_client(store.clone(), cfg).await;
    let html = client
        .get(format!("{abase}/requests?path=/keep"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("name=\"ids\"") && html.contains("Delete all"));
    // "Delete selected" carries the filter so its redirect keeps it.
    let bulk_form = html.split("id=\"bulk-form\"").nth(1).unwrap();
    assert!(
        bulk_form.contains("name=\"path\" value=\"/keep\""),
        "bulk form keeps the filter"
    );

    // Checked rows.
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/bulk' LIMIT 2")
        .fetch_all(&store.pool)
        .await
        .unwrap();
    let noredir = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // Share the session cookie with the redirect-following client.
    let cookie = client.get(format!("{abase}/admin")).send().await.unwrap();
    assert_eq!(cookie.status(), 200);
    let resp = client
        .post(format!("{abase}/admin/requests/bulk-delete"))
        .form(&[("ids", ids[0].to_string()), ("ids", ids[1].to_string())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE path = '/bulk'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 118);

    // Everything matching the filter, across pages.
    let resp = client
        .post(format!("{abase}/admin/requests/bulk-delete"))
        .form(&[("all", "1"), ("path", "/bulk")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.url().query().unwrap_or("").contains("path=%2Fbulk"));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE path = '/bulk'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let keep: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE path = '/keep'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(keep, 1);
    drop(noredir);

    // IPs matching a CIDR.
    let resp = client
        .post(format!("{abase}/admin/ips/bulk-delete"))
        .form(&[("all", "1"), ("q", "127.0.0.0/8")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(store.ip_by_addr("127.0.0.1").await.unwrap().is_none());
    assert!(store.ip_by_addr("127.0.0.2").await.unwrap().is_none());
    assert!(store.ip_by_addr("203.0.113.50").await.unwrap().is_some());
    // Checked IPs by address.
    let resp = client
        .post(format!("{abase}/admin/ips/bulk-delete"))
        .form(&[("ids", "203.0.113.50")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(store.ip_by_addr("203.0.113.50").await.unwrap().is_none());
}

#[tokio::test]
async fn scan_pace_is_adjustable_from_the_queue_page() {
    let (trap_base, store, dir) = spawn_trap().await;
    // One queued job so the metrics have something to measure.
    let _ = reqwest::Client::new()
        .get(format!("{trap_base}/login?u=admin'%20OR%20'1'='1"))
        .header("x-forwarded-for", "203.0.113.90")
        .send()
        .await
        .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base, state) = enrolled_admin_client_with_state(store.clone(), cfg).await;

    let page = client
        .get(format!("{base}/admin/queue"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("Save pace"), "pace form on queue page");
    assert!(html.contains("Recommended:"));
    assert!(html.contains("Arrivals / h"));

    let resp = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[
            ("max_workers", "4"),
            ("max_scans_per_hour", "90"),
            ("timeout_minutes", "45"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "redirect followed back to the queue");
    let html = resp.text().await.unwrap();
    assert!(html.contains("Pace saved"));
    assert!(html.contains("name=\"timeout_minutes\"") && html.contains("value=\"45\""));
    let p = state.pace.get();
    assert_eq!(
        (p.max_workers, p.max_scans_per_hour, p.timeout_secs),
        (4, 90, 2700)
    );
    // Persisted: a fresh load (as on restart) sees the admin's values.
    let reloaded = peephole::scan::pace::SharedPace::load(&store, &state.cfg.scan)
        .await
        .unwrap()
        .get();
    assert_eq!(reloaded, p);

    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "999"), ("max_scans_per_hour", "90")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert!(bad.text().await.unwrap().contains("Pace not saved"));
    assert_eq!(state.pace.get(), p, "invalid input leaves the pace alone");
    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[
            ("max_workers", "2"),
            ("max_scans_per_hour", "90"),
            ("timeout_minutes", "0.5"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400, "timeout below the minimum");
    assert_eq!(state.pace.get(), p);

    // Retry: the failed job goes back in the queue.
    let job = store.next_queued_job().await.unwrap().unwrap();
    store
        .finish_job(job.id, None, Some("host reported down"))
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/admin/queue/retry-failed"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("1 failed job is back in the queue")
    );
    let status: String = sqlx::query_scalar("SELECT status FROM scan_jobs WHERE id = ?")
        .bind(job.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(status, "queued");

    // Without a session the endpoint is closed.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "1"), ("max_scans_per_hour", "1")])
        .send()
        .await
        .unwrap();
    assert!(anon.status().is_redirection() || anon.status() == 401);
    assert_eq!(state.pace.get(), p);
}

/// Regression: the page rendered a fresh token instead of the stored one, so
/// the browser's /collect never matched a request and /panel stayed on
/// "collecting browser characteristics…" forever.
#[tokio::test]
async fn trap_page_token_links_collect_to_panel() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let html = client
        .get(format!("{base}/some-page"))
        .header("x-forwarded-for", "203.0.113.51")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = html
        .split("window.PEEPHOLE_TOKEN = \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("token in page")
        .to_string();
    let stored: String =
        sqlx::query_scalar("SELECT page_token FROM requests ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(token, stored, "page shows the token that was stored");

    let pending = client
        .get(format!("{base}/panel?token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        pending.status(),
        202,
        "no fingerprint yet: tells the page to retry"
    );

    let payload = serde_json::json!({
        "token": token,
        "attrs": {"canvas":"abc","webgl_renderer":"Mesa","platform":"Linux","webdriver":false},
        "behavior": {"mouse_events": 5}
    });
    client
        .post(format!("{base}/collect"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let linked: Option<i64> =
        sqlx::query_scalar("SELECT request_id FROM fingerprints ORDER BY id DESC LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(linked.is_some(), "fingerprint linked to the page view");
    let panel = client
        .get(format!("{base}/panel?token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(panel.status(), 200);
    let panel = panel.text().await.unwrap();
    assert!(panel.contains("Mesa"));
    assert!(!panel.contains("collecting browser characteristics"));
}

/// A legitimate client that mistypes an API URL lands in the trap with its
/// credentials in the query string. Query strings are admin-only: never
/// shown publicly and never matched by public search (no probing oracle).
#[tokio::test]
async fn query_strings_are_admin_only() {
    let (trap_base, store, dir) = spawn_trap().await;
    const KEY: &str = "sk_live_51H8zzSECRETzz0123";
    let _ = reqwest::Client::new()
        .get(format!("{trap_base}/api/v1/usres?api_key={KEY}&page=2"))
        .header("x-forwarded-for", "203.0.113.200")
        .send()
        .await
        .unwrap();
    let base = spawn_admin_with(store.clone(), dir.path()).await;
    let get = |url: String| async move { reqwest::get(url).await.unwrap().text().await.unwrap() };
    // No public surface shows the query string — nor, now, request paths or
    // the per-request rows that carried them.
    for url in [
        format!("{base}/ip/203.0.113.200"),
        format!("{base}/ips"),
        format!("{base}/"),
        format!("{base}/api/stats?range=24h"),
    ] {
        let body = get(url.clone()).await;
        assert!(!body.contains("SECRET"), "{url} leaks the query string");
        assert!(
            !body.contains("/api/v1/usres"),
            "{url} leaks the request path"
        );
    }
    // Request search is admin-only, so there is no public oracle at all.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = anon
        .get(format!("{base}/requests?path=usres"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "request search is admin-only");

    // Admins see and search the query string.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, abase) = enrolled_admin_client(store.clone(), cfg).await;
    let body = admin
        .get(format!("{abase}/requests?path=SECRET"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains(KEY),
        "admin search and view include the query"
    );
}

#[tokio::test]
async fn cluster_page_explains_standalone_mode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("c.toml"),
        format!(
            r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{d}/t.db"
data_dir = "{d}"
rules_dir = "rules"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let (c, base) = enrolled_admin_client(store, cfg).await;
    let body = c
        .get(format!("{base}/admin/cluster"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("Standalone") && body.contains("[cluster]"),
        "{body}"
    );
    // Cluster actions need distributed mode.
    let r = c
        .post(format!("{base}/admin/cluster/invite"))
        .form(&[("ttl_hours", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}
