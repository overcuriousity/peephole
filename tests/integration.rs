use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::sync::Arc;

/// The trap's router, answering only once what the trap records (in the
/// background) is written, so a test can check the store as soon as it has
/// the answer.
fn settled_router(state: Arc<TrapState>) -> axum::Router {
    trap::router(state.clone()).layer(axum::middleware::map_response(
        move |r: axum::response::Response| {
            let state = state.clone();
            async move {
                state.guards.settled().await;
                r
            }
        },
    ))
}

async fn spawn_trap() -> (String, Store, tempfile::TempDir) {
    let (base, store, dir, _) = spawn_trap_with(settled_router).await;
    (base, store, dir)
}

/// A trap served by `router` (`trap::router` or [`settled_router`]).
async fn spawn_trap_with(
    router: fn(Arc<TrapState>) -> axum::Router,
) -> (String, Store, tempfile::TempDir, Arc<TrapState>) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
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
    let app = router(state.clone());
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
    (format!("http://{addr}"), store, dir, state)
}

/// The answer does not wait for the recording, and a request whose answer
/// went out is recorded even though its connection is gone.
#[tokio::test]
async fn request_is_recorded_after_it_is_answered() {
    let (base, store, _dir, state) = spawn_trap_with(trap::router).await;
    // Hold the write lock: recording cannot finish until it is released.
    let mut lock = store.pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/wp-login.php"))
        .header("x-forwarded-for", "203.0.113.9")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200); // the wp-login decoy
    drop(resp);
    drop(client);
    sqlx::query("COMMIT").execute(&mut *lock).await.unwrap();
    drop(lock);
    state.guards.settled().await;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE path = '/wp-login.php'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
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
async fn wrong_method_on_a_helper_path_is_the_trap() {
    let (base, store, _dir) = spawn_trap().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/claim"))
        .header("x-forwarded-for", "203.0.113.1")
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
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests WHERE path = '/claim'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
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
    // The probe carries the fingerprint of the rules that classified it;
    // the claim, which no rule classified, none.
    let rules: Vec<(bool, Option<String>)> =
        sqlx::query_as("SELECT is_fp_claim, rules FROM requests ORDER BY id")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    let ours = peephole::classify::Classifier::builtin()
        .fingerprint()
        .to_string();
    assert_eq!(rules, vec![(false, Some(ours)), (true, None)]);
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
    // The IP is named (public dashboard) and "Recent requests" lists paths,
    // but never bodies, headers or query strings.
    assert!(html.contains("203.0.113.99"));
    assert!(html.contains("<h1>Public dashboard</h1>"));
    assert!(html.contains(">Dashboard</a>"));
    assert!(!html.to_lowercase().contains("wall of shame"));
    assert!(html.contains("href=\"/ip/203.0.113.99\""));
    assert!(html.contains("Recent requests"));
    assert!(html.contains("/wp-login.php"));
    assert!(!html.contains("SECRET-PAYLOAD-MARKER"));
    assert!(!html.contains("HEADER-MARKER"));
    assert!(
        !html.contains("Recent activity"),
        "public dashboard has no live recent-activity card"
    );
    // The API page and error pages call the public page by its name too.
    let api = reqwest::get(format!("{admin_base}/api"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(api.contains("The public dashboard's numbers as JSON"));
    let missing = reqwest::get(format!("{admin_base}/ip/not-an-address"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(missing.contains("Back to the dashboard"));
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
    assert!(
        body.contains("\"active\":1"),
        "the snapshot carries the total: {body}"
    );

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
        "/admin/requests/1",
        "/admin/scans",
        "/admin/scans/1",
        "/admin/scans/1/xml",
        "/admin/links",
        "/admin/links/canaries",
        "/admin/links/canaries/served/1",
        "/admin/links/fp/x",
        "/admin/api/links/graph?focus=fp:x",
        "/admin/inbox",
        "/admin/system",
        "/admin/system/settings",
        "/admin/system/export",
        "/admin/export/download?format=csv",
        "/admin/system/keys",
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

    // A signed-in admin adding a key leaves a live setup token alone.
    let fresh = store.issue_setup_token().await.unwrap();
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
    let cred = SoftPasskey::new(true)
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
    assert!(store.setup_token_valid(&fresh).await.unwrap());
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
                    scrubbed: 0,
                    os_guess: Some("Linux".into()),
                    // Both IPs show the same host keys and certificate.
                    raw_xml: [
                        include_bytes!("fixtures/nmap-hostkeys.xml").as_slice(),
                        b"<!-- RAWXML -->\n",
                    ]
                    .concat(),
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

    // A failed scan is something to look at.
    let ipf = store
        .upsert_ip("203.0.113.79".parse().unwrap())
        .await
        .unwrap();
    if let peephole::store::scans::EnqueueOutcome::Queued(j) =
        store.enqueue_scan(ipf.id, 1, 24).await.unwrap()
    {
        store.next_queued_job().await.unwrap();
        store.finish_job(j, None, Some("host down")).await.unwrap();
    }
    let html = get("/admin").await.unwrap().text().await.unwrap();
    assert!(!html.contains("data-queue"), "no queue card on Overview");
    assert!(!html.contains("<h2>Intel</h2>"), "intel lives on System");
    assert!(html.contains("href=\"/admin/inbox\"") && html.contains("href=\"/admin/scans\""));
    assert!(html.contains("data-recent"), "recent activity stays");
    assert!(
        html.contains("Needs attention") && html.contains("failed in 24 h"),
        "{html}"
    );
    let html = get("/admin/scans?status=done")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.78") && html.contains("done"));
    let html = get("/admin/scans?status=nonsense&level=abc")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.78"), "unknown filters are ignored");
    assert!(!html.contains("nonsense"), "and not echoed");

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
    assert!(html.contains("not-found · 404"), "how it was answered");
    // This harness has no listener to keep the raw head (tests/capture.rs
    // covers that); the row is given a JA4H.
    let ja4h = "po11nn030000_aaaaaaaaaaaa_000000000000_000000000000";
    sqlx::query("UPDATE requests SET ja4h = ? WHERE id = ?")
        .bind(ja4h)
        .bind(rid)
        .execute(&store.pool)
        .await
        .unwrap();
    let html = get(&format!("/admin/requests/{rid}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains(ja4h), "JA4H on the request page");
    // A tarpit answer says how long it held the client.
    sqlx::query(
        "UPDATE requests SET answer = 'tarpit', status = 200, held_ms = 252000 WHERE id = ?",
    )
    .bind(rid)
    .execute(&store.pool)
    .await
    .unwrap();
    let html = get(&format!("/admin/requests/{rid}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("tarpit · 200 · held 4 min"), "time held");

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
    assert!(
        html.contains("Host keys and certificates")
            && html.contains("SHA256:LvbxsAtrLqDESt7sCPrXK6n7L9j4J9myhtEO50ocsdM")
            && html.contains("1 linked"),
        "host keys on the scan page"
    );
    let html = get("/ip/203.0.113.78").await.unwrap().text().await.unwrap();
    assert!(
        html.contains("shared with 1 other IP"),
        "host keys on the IP page"
    );
    let html = get("/admin/analytics?range=all")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("SSH servers (HASSH)") && html.contains("Certificate builders (JA4X)"));
    assert!(html.contains("HTTP fingerprints (JA4H)") && html.contains(ja4h));
    assert!(
        html.contains(&format!("href=\"/admin/links/ja4h/{ja4h}\"")),
        "JA4H → item page"
    );
    assert!(
        html.contains("href=\"/admin/links/hassh/") && html.contains("href=\"/admin/links/ja4x/")
    );
    assert!(html.contains("href=\"/admin/links/canaries?range=all\""));
    // Every Analytics row opens a filtered view.
    for want in [
        "href=\"/requests?ua=",
        "href=\"/requests?method=",
        "href=\"/requests?transport=",
        "href=\"/requests?answer=",
        "href=\"/ips?port=22%2Ftcp\"",
        "href=\"/ips?os=Linux\"",
        "href=\"/admin/scans?level=",
        "href=\"/admin/scans?status=",
        "href=\"/ips?nointel=abuseipdb\"",
    ] {
        assert!(html.contains(want), "analytics lacks {want}");
    }
    let ua_link = html
        .split("href=\"/requests?ua=")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .replace("&#38;", "&");
    let rows = get(&format!("/requests?ua={ua_link}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        rows.contains("/admin/requests/"),
        "the UA link finds requests"
    );
    let rows = get("/ips?port=22%2Ftcp")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(rows.contains("203.0.113.78"), "the port link finds IPs");
    // Applied filters show as chips; each × drops exactly that filter.
    assert!(
        rows.contains("class=\"chip\" href=\"/ips\"")
            && rows.contains("Open port: <span class=\"mono\">22/tcp</span>"),
        "port chip"
    );
    let rows = get("/requests?method=GET&path=%2Flogin&page=2")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        rows.contains("class=\"chip\" href=\"/requests?path=%2Flogin\""),
        "method chip keeps path, drops page"
    );
    assert!(rows.contains("class=\"chip\" href=\"/requests?method=GET\""));
    let rows = get("/requests").await.unwrap().text().await.unwrap();
    assert!(!rows.contains("class=\"chip\""), "no filter, no chips");
    // Quick filters are always there and apply in one click.
    assert!(rows.contains("class=\"chip shortcut\" href=\"/requests?answer=tarpit\""));
    let html = get("/admin/analytics?range=24h")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Askama writes `&` as `&#38;`.
    assert!(
        html.contains("&#38;from=") && !html.contains("ips?port=22%2Ftcp&#38;from"),
        "request links carry the range start, IP links don't"
    );
    let html = get(&format!("/admin/requests/{rid}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains(&format!("href=\"/admin/links/ja4h/{ja4h}\"")));
    let html = get("/ip/203.0.113.78").await.unwrap().text().await.unwrap();
    assert!(
        html.contains("href=\"/admin/links/fp/CLUSTERHASH\""),
        "fingerprint → item page"
    );
    assert!(
        html.contains("href=\"/admin/links/ip/203.0.113.78\""),
        "IP link graph"
    );
    assert!(
        html.contains("href=\"/admin/links/ssh/") && html.contains("href=\"/admin/links/hassh/"),
        "host keys → item pages"
    );
    assert!(!html.contains("/admin/fingerprints"));
    let html = get(&format!("/requests?ja4h={ja4h}"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains(&format!("/admin/requests/{rid}")),
        "JA4H search"
    );
    let xml = get(&format!("/admin/scans/{sid}/xml")).await.unwrap();
    assert_eq!(
        xml.headers().get("content-type").unwrap(),
        "application/xml"
    );
    assert!(xml.text().await.unwrap().contains("RAWXML"));

    let html = get("/admin/links").await.unwrap().text().await.unwrap();
    assert!(html.contains("CLUSTERHASH") && html.contains("/admin/links/fp/CLUSTERHASH"));
    let html = get("/admin/links?kind=ssh&q=ab&shared=0")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Kinds are a pill bar: the current one marked, the others keep every
    // filter but "starts with"; the software group is set apart.
    assert!(html.contains("<a href=\"/admin/links?kind=ssh&#38;shared=0\" title=\"Identity"));
    assert!(html.contains("<a href=\"/admin/links?kind=ja4&#38;shared=0\" class=\"group-start\""));
    assert!(html.contains(" aria-current=\"true\">SSH host key</a>"));
    assert!(!html.contains("<select name=\"kind\""));
    let html = get("/admin/links?kind=ssh")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let ssh: String =
        sqlx::query_scalar("SELECT fingerprint FROM host_keys WHERE kind = 'ssh-hostkey' LIMIT 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    let href = peephole::admin::views::link_href("ssh", &ssh);
    assert!(html.contains(&href), "ssh row links to {href}");
    // The encoded value round-trips through the path.
    let html = get(&href).await.unwrap().text().await.unwrap();
    assert!(
        html.contains("SSH host key") && html.contains(&ssh) && html.contains("203.0.113.78"),
        "{html}"
    );
    assert!(html.contains("data-link-graph") && html.contains("data-focus=\"ssh:"));
    let html = get("/admin/links/fp/CLUSTERHASH")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("203.0.113.77") && html.contains("203.0.113.78"));
    let html = get("/admin/links/fp/NEVERSEEN")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Not seen") && !html.contains("data-link-graph"));
    assert_eq!(get("/admin/links/bogus/x").await.unwrap().status(), 404);
    let html = get("/admin/links/ip/203.0.113.77")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("data-focus=\"ip:203.0.113.77\"")
            && html.contains("href=\"/ip/203.0.113.77\"")
    );
    // Old anchors.
    let r = get("/admin/links?anchor=CLUSTERHASH").await.unwrap();
    assert!(
        r.url().path().ends_with("/admin/links/fp/CLUSTERHASH"),
        "{}",
        r.url()
    );
    let a = peephole::store::hostkeys::anchor("ssh-hostkey", &ssh);
    let r = get(&format!("/admin/links?anchor={a}")).await.unwrap();
    assert!(
        r.url().path().starts_with("/admin/links/ssh/"),
        "{}",
        r.url()
    );
    let html = get("/admin/links?anchor=ssh-000000000000")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("no longer matches"));
    // The graph API.
    let j: serde_json::Value =
        get("/admin/api/links/graph?focus=fp:CLUSTERHASH&depth=9&types=fp,bogus")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let nodes = j["nodes"].as_array().unwrap();
    assert_eq!(nodes[0]["id"], "fp:CLUSTERHASH");
    assert!(nodes.iter().any(|n| n["id"] == "ip:203.0.113.78"));
    assert_eq!(j["truncated"], false);
    assert_eq!(
        get("/admin/api/links/graph?focus=bogus")
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(get("/admin/api/links/graph").await.unwrap().status(), 400);
    // An SSH fingerprint with `/` and `+` (base64) round-trips through its
    // item URL, an old anchor and the graph API.
    let odd = "SHA256:ab/cd+ef/gh+ij0123456789";
    sqlx::query(
        "INSERT INTO host_keys (scan_id, ip_id, port, kind, fingerprint, detail)
         SELECT s.id, s.ip_id, 2222, 'ssh-hostkey', ?, 'ssh-ed25519 256'
         FROM scans s JOIN ips i ON i.id = s.ip_id WHERE i.ip = '203.0.113.78' LIMIT 1",
    )
    .bind(odd)
    .execute(&store.pool)
    .await
    .unwrap();
    let href = peephole::admin::views::link_href("ssh", odd);
    assert!(href.contains("%2F") && href.contains("%2B"), "{href}");
    let r = get(&href).await.unwrap();
    assert_eq!(r.status(), 200, "{href}");
    let html = r.text().await.unwrap();
    assert!(
        html.contains(odd) && html.contains("203.0.113.78"),
        "{html}"
    );
    let a = peephole::store::hostkeys::anchor("ssh-hostkey", odd);
    let r = get(&format!("/admin/links?anchor={a}")).await.unwrap();
    assert_eq!(r.url().path(), href, "anchor {a}");
    let j: serde_json::Value = get(&format!(
        "/admin/api/links/graph?focus={}&depth=1",
        peephole::admin::views::link_href("ssh", odd).replacen("/admin/links/ssh/", "ssh:", 1)
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(j["nodes"][0]["id"], format!("ssh:{odd}"));
    let html = get("/admin/inbox").await.unwrap().text().await.unwrap();
    assert!(html.contains("lost@example.org"));
    let html = get("/admin/system/keys")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("test-key") && html.contains("/enroll"));
    let html = get("/admin/system/export")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("/admin/export/download"));
    for html_path in [
        "/admin",
        "/admin/scans",
        &format!("/admin/requests/{rid}"),
        &format!("/admin/scans/{sid}"),
        "/admin/links",
        "/admin/links/fp/CLUSTERHASH",
        "/admin/links/canaries",
        "/admin/analytics",
        "/ip/203.0.113.78",
        "/admin/system/keys",
        "/admin/system",
        "/admin/system/settings",
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
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_keys WHERE scan_id = ?")
        .bind(sid)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "a deleted scan's host keys go with it");
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

/// Start an enrollment with `body` and register a fresh soft passkey; the
/// finish request is left to the caller.
async fn start_enrollment(
    client: &reqwest::Client,
    base: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let resp = client
        .post(format!("{base}/enroll/start"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cco: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let cred = SoftPasskey::new(true)
        .perform_register(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    serde_json::json!({ "credential": cred })
}

async fn session_count(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_enrollment_ends_with_the_session_that_started_it() {
    let (_trap_base, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;
    let finish = start_enrollment(&client, &base, serde_json::json!({"label": "late"})).await;
    // The session ends (signed out elsewhere, expired) mid-ceremony.
    sqlx::query("DELETE FROM sessions")
        .execute(&store.pool)
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&finish)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(store.load_credentials().await.unwrap().len(), 1, "no key");
    assert_eq!(session_count(&store).await, 0, "and no new session");

    // Nor does another session finish what one started.
    let jar = Arc::new(reqwest::cookie::Jar::default());
    let url = reqwest::Url::parse(&base).unwrap();
    let signed_in = |token: String| jar.add_cookie_str(&format!("peephole_session={token}"), &url);
    signed_in(store.create_session().await.unwrap());
    let client = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .build()
        .unwrap();
    let finish = start_enrollment(&client, &base, serde_json::json!({"label": "x"})).await;
    let swapped = store.create_session().await.unwrap();
    signed_in(swapped.clone());
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&finish)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(store.load_credentials().await.unwrap().len(), 1);

    // A ceremony within its session still enrolls, without a new session.
    let finish = start_enrollment(&client, &base, serde_json::json!({"label": "ok"})).await;
    let before = session_count(&store).await;
    let resp = client
        .post(format!("{base}/enroll/finish"))
        .json(&finish)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .all(|c| !c.to_str().unwrap().starts_with("peephole_session=")),
        "no new session cookie"
    );
    assert_eq!(store.load_credentials().await.unwrap().len(), 2);
    assert_eq!(session_count(&store).await, before);
    assert!(store.validate_session(&swapped).await.unwrap());
}

#[tokio::test]
async fn a_setup_token_is_checked_again_when_the_enrollment_finishes() {
    let (_trap_base, store, dir) = spawn_trap().await;
    let token = store.issue_setup_token().await.unwrap();
    let base = spawn_admin_with(store.clone(), dir.path()).await;
    let client = || {
        reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap()
    };
    // Two ceremonies start with the same token: only one may use it.
    let (a, b) = (client(), client());
    let fin_a = start_enrollment(&a, &base, serde_json::json!({"setup_token": token})).await;
    let fin_b = start_enrollment(&b, &base, serde_json::json!({"setup_token": token})).await;
    let resp = a
        .post(format!("{base}/enroll/finish"))
        .json(&fin_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = b
        .post(format!("{base}/enroll/finish"))
        .json(&fin_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(store.load_credentials().await.unwrap().len(), 1);
    assert_eq!(session_count(&store).await, 1, "only the first signed in");

    // `peephole admin reset-token` invalidates a ceremony already started.
    let old = peephole::admin::cli::reset_token(&store).await.unwrap().0;
    let c = client();
    let fin = start_enrollment(&c, &base, serde_json::json!({"setup_token": old})).await;
    let new = peephole::admin::cli::reset_token(&store).await.unwrap().0;
    let resp = c
        .post(format!("{base}/enroll/finish"))
        .json(&fin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(store.load_credentials().await.unwrap().len(), 1);
    assert!(
        store.setup_token_valid(&new).await.unwrap(),
        "new one intact"
    );
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

    let resp = client
        .get(format!(
            "{base}/admin/export/download?format=csv&mode=redistributable"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!(
            "{base}/admin/export/download?format=csv&mode=everything"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let resp = client
        .get(format!("{base}/admin/export/intel"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "the separate enrichment export is gone");

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
trusted_proxies = ["127.0.0.1/32"]
[public]
delay_minutes = 0
jitter_minutes = 0
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "peephole-test"
secure_cookies = false
[maxmind]
account_id = "1"
license_key = "k"
[scan]
max_workers = 2
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
    // The trap records after it answers; `/api/stats` is cached for 15 s by
    // design, so wait for the row in the database file before asking.
    let probe = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM requests")
        .fetch_one(&probe.pool)
        .await
        .unwrap()
        == 0
    {
        assert!(std::time::Instant::now() < deadline, "request not recorded");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let resp = client
        .get(format!("http://127.0.0.1:{admin}/api/stats"))
        .send()
        .await
        .unwrap();
    let stats: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(stats["total_requests"], 1);
    // Fake nmap should have completed the queued scan (polled likewise).
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
    assert!(css.contains(".link-graph"), "the link graph's styles");
    let js = reqwest::get(format!("{base}/assets/js/linkgraph.js"))
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    assert!(js.text().await.unwrap().contains("data-link-graph"));

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
                scrubbed: 0,
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
    assert!(html.contains("data-week=\"["), "the activity chart's data");
    assert!(
        html.contains("data-calendar=\"["),
        "the activity calendar's data"
    );
    let ja4h = "ge11nn020000_bbbbbbbbbbbb_000000000000_000000000000";
    sqlx::query("UPDATE requests SET ja4h = ?")
        .bind(ja4h)
        .execute(&store.pool)
        .await
        .unwrap();
    for marker in [
        // Per-request rows (path included) are admin-only now.
        "/wp-login.php",
        // Fingerprints are never public.
        ja4h,
        "/admin/links",
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
    let v6 = store
        .upsert_ip("2001:db8::1".parse().unwrap())
        .await
        .unwrap();
    // An IP with no released request has no public page.
    assert_eq!(
        reqwest::get(format!("{base}/ip/2001:db8::1"))
            .await
            .unwrap()
            .status(),
        404
    );
    store
        .insert_request(&peephole::store::requests::NewRequest {
            ip_id: v6.id,
            method: "GET".into(),
            path: "/v6".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
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
    // The IP directory stays public.
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
    // Every filter field travels, so "Delete all N" deletes what N counted.
    let html = client
        .get(format!("{abase}/requests?path=/keep&session=s1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let bulk_form = html.split("id=\"bulk-form\"").nth(1).unwrap();
    assert!(
        bulk_form.contains("name=\"session\" value=\"s1\""),
        "bulk form keeps the session"
    );
    let all_form = html.split("id=\"dlg-bulk-all\"").nth(1).unwrap();
    assert!(all_form.contains("name=\"session\" value=\"s1\""));
    let html = client
        .get(format!("{abase}/ips?sort=requests&country=DE"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("name=\"sort\" value=\"requests\""));

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
async fn scan_pace_is_adjustable_from_the_scans_page() {
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
        .get(format!("{base}/admin/scans"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(
        html.contains("name=\"max_workers\""),
        "pace form on queue page"
    );
    assert!(!html.contains("Recommended"), "no pace recommendation");
    assert!(!html.contains("max_scans_per_hour") && !html.contains("timeout_minutes"));
    assert!(html.contains("Arrivals / h"));
    assert!(
        html.contains("data-queue") && html.contains("History"),
        "live card and history"
    );

    let resp = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "4")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "redirect followed back to the queue");
    let html = resp.text().await.unwrap();
    assert!(html.contains("Pace saved"));
    let p = state.pace.get();
    assert_eq!(p, peephole::scan::pace::Pace::new(4));
    // Persisted: a fresh load (as on restart) sees the admin's values.
    let reloaded = peephole::scan::pace::SharedPace::load(&store, state.cfg.scan.max_workers)
        .await
        .unwrap()
        .get();
    assert_eq!(reloaded, p);

    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "999")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert!(bad.text().await.unwrap().contains("Pace not saved"));
    assert_eq!(state.pace.get(), p, "invalid input leaves the pace alone");
    // 2^32 must not wrap to 0 workers (paused scanning).
    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "4294967296")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert_eq!(state.pace.get(), p);
    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    let html = bad.text().await.unwrap();
    assert!(
        html.contains("Pace not saved") && html.contains("data-queue") && html.contains("History"),
        "an error re-renders the whole Scans page"
    );

    // A failure is retried on its own: the scans page shows it, and the
    // manual retry is gone.
    let job = store.next_queued_job().await.unwrap().unwrap();
    store
        .finish_job(job.id, None, Some("host reported down"))
        .await
        .unwrap();
    let html = client
        .get(format!("{base}/admin/scans?status=failed"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("host reported down") && html.contains("retried"),
        "the failure and its retry"
    );
    assert!(!html.contains("Retry failed"));
    let gone = client
        .post(format!("{base}/admin/queue/retry-failed"))
        .send()
        .await
        .unwrap();
    assert!(gone.status().is_client_error(), "{}", gone.status());

    // Without a session the endpoint is closed.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "1")])
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
    // No public surface shows the query string. The wall's "Recent
    // requests" list the path alone (not in the JSON); the IP pages show
    // no request rows.
    for url in [
        format!("{base}/ip/203.0.113.200"),
        format!("{base}/ips"),
        format!("{base}/"),
        format!("{base}/api/stats?range=24h"),
    ] {
        let body = get(url.clone()).await;
        assert!(!body.contains("SECRET"), "{url} leaks the query string");
        assert!(!body.contains("api_key"), "{url} leaks the query string");
    }
    for url in [format!("{base}/ip/203.0.113.200"), format!("{base}/ips")] {
        assert!(
            !get(url.clone()).await.contains("/api/v1/usres"),
            "{url} leaks the request path"
        );
    }
    // The wall lists paths now, but its JSON keeps `recent` out.
    let stats = get(format!("{base}/api/stats?range=24h")).await;
    assert!(
        !stats.contains("/api/v1/usres"),
        "/api/stats leaks the request path"
    );
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

/// The canary a decoy served, read back from the store like a harvester
/// would read it from the body.
async fn served_value(store: &Store, path: &str, kind: peephole::canary::Kind) -> String {
    let tok: String = sqlx::query_scalar(
        "SELECT page_token FROM requests WHERE path = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(path)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    peephole::canary::value(&tok, kind)
}

async fn answer_of(store: &Store, path: &str) -> String {
    sqlx::query_scalar("SELECT answer FROM requests WHERE path = ? ORDER BY id DESC LIMIT 1")
        .bind(path)
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn harvested_credentials_open_the_decoy_logins() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let xff = ("x-forwarded-for", "203.0.113.20");
    let env = c
        .get(format!("{base}/.env"))
        .header(xff.0, xff.1)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let admin_pw = served_value(&store, "/.env", peephole::canary::Kind::AdminPassword).await;
    assert!(env.contains(&format!("ADMIN_PASSWORD={admin_pw}\n")));

    // Basic with the harvested password, from another address.
    let r = c
        .get(format!("{base}/admin/"))
        .basic_auth("admin", Some(&admin_pw))
        .header("x-forwarded-for", "203.0.113.21")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(answer_of(&store, "/admin/").await, "decoy:admin");

    // wp-login with it: a session cookie that opens wp-admin.
    let r = c
        .post(format!("{base}/wp-login.php"))
        .form(&[("log", "admin"), ("pwd", admin_pw.as_str())])
        .header(xff.0, xff.1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(
        answer_of(&store, "/wp-login.php").await,
        "decoy:wp-login-ok"
    );
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let r = c
        .get(format!("{base}/wp-admin/"))
        .header("cookie", &cookie)
        .header("x-forwarded-for", "203.0.113.22")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("Dashboard"));
    assert_eq!(answer_of(&store, "/wp-admin/").await, "decoy:wp-admin");

    // A wrong password stays a failed login.
    let r = c
        .post(format!("{base}/wp-login.php"))
        .form(&[("log", "admin"), ("pwd", "Wr0ngPassw0rdWr0ng12")])
        .header(xff.0, xff.1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        answer_of(&store, "/wp-login.php").await,
        "decoy:wp-login-failed"
    );
}

#[tokio::test]
async fn git_clone_with_the_harvested_token_reaches_the_refs() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let cfg = c
        .get(format!("{base}/.git/config"))
        .header("x-forwarded-for", "203.0.113.30")
        .header("host", "203.0.113.5")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    let url = cfg
        .lines()
        .find_map(|l| l.trim().strip_prefix("url = "))
        .unwrap()
        .to_string();
    assert!(
        url.starts_with(&format!("http://deploy:{token}@203.0.113.5/git/")),
        "{url}"
    );
    let repo_path = &url[url.find("/git/").unwrap()..];
    let refs = format!("{base}{repo_path}/info/refs?service=git-upload-pack");
    let r = c
        .get(&refs)
        .header("x-forwarded-for", "203.0.113.31")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));
    let r = c
        .get(&refs)
        .basic_auth("deploy", Some(&token))
        .header("x-forwarded-for", "203.0.113.31")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("refs/heads/main"));
}

#[tokio::test]
async fn canary_free_requests_answer_as_before() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    for (method, path, status) in [
        ("GET", "/admin/", 404),
        ("GET", "/wp-admin/", 404),
        ("HEAD", "/.env", 200),
        ("GET", "/.git/HEAD", 200),
        ("GET", "/nothing", 404),
    ] {
        let r = c
            .request(method.parse().unwrap(), format!("{base}{path}"))
            .basic_auth("admin", Some("NotACanaryNotACanary"))
            .header("x-forwarded-for", "203.0.113.40")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), status, "{method} {path}");
    }
    let v: Option<i64> =
        sqlx::query_scalar("SELECT decoy_v FROM requests WHERE path = '/.git/HEAD'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(v, Some(peephole::canary::DECOY_V));
    let v: Option<i64> = sqlx::query_scalar("SELECT decoy_v FROM requests WHERE path = '/nothing'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(v, None);
}

#[tokio::test]
async fn request_and_ip_pages_show_canary_reuse() {
    let (base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    c.get(format!("{base}/.git/config"))
        .header("x-forwarded-for", "203.0.113.60")
        .send()
        .await
        .unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    c.get(format!("{base}/x"))
        .basic_auth("deploy", Some(&token))
        .header("x-forwarded-for", "203.0.113.61")
        .send()
        .await
        .unwrap();
    c.get(format!("{base}/nothing"))
        .header("x-forwarded-for", "203.0.113.62")
        .send()
        .await
        .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, admin_base) = enrolled_admin_client(store.clone(), cfg).await;
    let id_of = |path: &'static str| {
        let pool = store.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT id FROM requests WHERE path = ?")
                .bind(path)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let (served, used, plain) = (
        id_of("/.git/config").await,
        id_of("/x").await,
        id_of("/nothing").await,
    );
    let page = admin
        .get(format!("{admin_base}/admin/requests/{served}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains("Canaries served") && page.contains(&token),
        "{page}"
    );
    assert!(page.contains("203.0.113.61"));
    let page = admin
        .get(format!("{admin_base}/admin/requests/{used}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains(&format!("/admin/requests/{served}"))
            && page.contains("header:authorization")
    );
    let ip = admin
        .get(format!("{admin_base}/ip/203.0.113.60"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(ip.contains("used by 1 other IP"), "{ip}");
    // Both request rows carry a mark that opens the decoy's canary page.
    let mark = format!("href=\"/admin/links/canaries/served/{served}\"");
    assert!(ip.contains(&mark), "served mark");
    let user_ip = admin
        .get(format!("{admin_base}/ip/203.0.113.61"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(user_ip.contains(&mark), "used mark");
    let decoy = admin
        .get(format!("{admin_base}/admin/links/canaries/served/{served}"))
        .send()
        .await
        .unwrap();
    assert_eq!(decoy.status(), 200);
    let decoy = decoy.text().await.unwrap();
    assert!(
        decoy.contains(&token)
            && decoy.contains("203.0.113.61")
            && decoy.contains(&format!("/admin/requests/{used}")),
        "{decoy}"
    );
    // Basic auth on /x got the admin decoy, which serves its own ETag
    // canary (version 3): a page of its own, no reuse on it.
    let own = admin
        .get(format!("{admin_base}/admin/links/canaries/served/{used}"))
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), 200);
    let own = own.text().await.unwrap();
    assert!(
        own.contains("<td>etag</td>")
            && !own.contains(&token)
            && own.contains("None of these canaries has come back."),
        "{own}"
    );
    let none = admin
        .get(format!("{admin_base}/admin/links/canaries/served/{plain}"))
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), 404, "served no canaries");
    // Nothing of it on the public IP page.
    let public = reqwest::get(format!("{admin_base}/ip/203.0.113.60"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!public.contains("Canar") && !public.contains(&token));
    assert!(!public.contains("canary-mark"));
}

#[tokio::test]
async fn canaries_page_lists_reuses_and_filters() {
    let (base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    c.get(format!("{base}/.git/config"))
        .header("x-forwarded-for", "203.0.113.70")
        .send()
        .await
        .unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    c.get(format!("{base}/x"))
        .basic_auth("deploy", Some(&token))
        .header("x-forwarded-for", "203.0.113.71")
        .send()
        .await
        .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, admin_base) = enrolled_admin_client(store.clone(), cfg).await;
    let page = admin
        .get(format!("{admin_base}/admin/links/canaries?range=all"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        page.contains("203.0.113.71") && page.contains("git-token"),
        "{page}"
    );
    assert!(
        page.contains("/admin/links/canary/"),
        "reuse rows link to the canary's graph"
    );
    let page = admin
        .get(format!(
            "{admin_base}/admin/links/canaries?range=all&source=same"
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("203.0.113.71"));
    // An IP the store does not know matches nothing, not everything.
    let page = admin
        .get(format!(
            "{admin_base}/admin/links/canaries?range=all&ip=198.51.100.250"
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("203.0.113.71"), "{page}");
    let nav = admin
        .get(format!("{admin_base}/admin"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(nav.contains("href=\"/admin/links\">Links<"), "links tab");
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    assert_ne!(
        anon.get(format!("{admin_base}/admin/links/canaries"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn a_served_decoy_renders_again_from_its_row() {
    let (base, store, _dir) = spawn_trap().await;
    let body = reqwest::Client::new()
        .get(format!("{base}/.env"))
        .header("x-forwarded-for", "203.0.113.50")
        .header("host", "shop.example.org")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let uid: String = sqlx::query_scalar("SELECT uid FROM requests WHERE path = '/.env'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let again = peephole::canary::cli::render_uid(&store, &uid)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(again.body, body);
}

/// A decoy served standalone renders the same after the node adopted its
/// history into a cluster (which sets the row's origin).
#[tokio::test]
async fn a_decoy_renders_the_same_after_adoption() {
    let (base, store, _dir) = spawn_trap().await;
    let body = reqwest::Client::new()
        .get(format!("{base}/.env"))
        .header("x-forwarded-for", "203.0.113.80")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    sqlx::query("UPDATE requests SET origin = ? WHERE path = '/.env'")
        .bind(vec![9u8; 32])
        .execute(&store.pool)
        .await
        .unwrap();
    let uid: String = sqlx::query_scalar("SELECT uid FROM requests WHERE path = '/.env'")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let again = peephole::canary::cli::render_uid(&store, &uid)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(again.body, body);
}

/// The admin subnav has seven tabs; Fingerprints and Canaries sit under
/// Links, intel status under System.
#[tokio::test]
async fn admin_nav_groups_pages_under_seven_tabs() {
    let (_trap, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    let get = |p: &str| {
        let (c, u) = (client.clone(), format!("{base}{p}"));
        async move {
            let r = c.get(u).send().await.unwrap();
            assert_eq!(r.status(), 200);
            r.text().await.unwrap()
        }
    };
    let nav = |html: &str| {
        html.split("aria-label=\"Admin sections\"")
            .nth(1)
            .expect("admin subnav")
            .split("</nav>")
            .next()
            .unwrap()
            .to_string()
    };
    let current = |html: &str| {
        nav(html)
            .split("aria-current=\"true\">")
            .nth(1)
            .map(|s| s.split('<').next().unwrap().to_string())
    };
    let home = get("/admin").await;
    let n = nav(&home);
    for want in [
        ">Overview<",
        ">Analytics<",
        ">Lookup<",
        ">Scans<",
        ">Links<",
        ">Inbox<",
        ">Cluster<",
        ">System<",
    ] {
        assert!(n.contains(want), "nav lacks {want}");
    }
    for gone in [
        ">Queue<",
        ">Fingerprints<",
        ">Canaries<",
        ">Export<",
        ">Keys<",
    ] {
        assert!(!n.contains(gone), "nav still has {gone}");
    }
    let fp = get("/admin/links").await;
    assert_eq!(current(&fp).as_deref(), Some("Links"));
    assert!(
        fp.contains("aria-label=\"Links pages\""),
        "named sub-tab nav"
    );
    let css = get("/assets/app.css").await;
    for rule in [".subtabs", ".topbar-search", "a.tile", ".attention-list"] {
        assert!(css.contains(rule), "app.css lacks {rule}");
    }
    let scans = get("/admin/scans").await;
    let live = scans
        .split("<table data-queue")
        .nth(1)
        .unwrap()
        .split("</thead>")
        .next()
        .unwrap();
    assert!(
        live.contains("<th>Started</th>") && !live.contains("<th>Error</th>"),
        "live queue columns: {live}"
    );
    assert!(
        fp.contains("href=\"/admin/links/canaries\""),
        "links sub-tabs"
    );
    assert_eq!(
        current(&get("/admin/links/canaries").await).as_deref(),
        Some("Links")
    );
    let sys = get("/admin/system").await;
    assert_eq!(current(&sys).as_deref(), Some("System"));
    assert!(sys.contains("Tor exit list") && sys.contains("MaxMind GeoLite2"));
    assert!(sys.contains("built in"), "this binary's rules");
}

/// Moved admin pages answer 308 to their new place, without a session
/// (the redirect reveals nothing).
#[tokio::test]
async fn moved_admin_pages_redirect_permanently() {
    let (_trap, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for (from, to) in [
        ("/admin/keys", "/admin/system/keys"),
        ("/admin/export", "/admin/system/export"),
        ("/admin/fingerprints", "/admin/links"),
        ("/admin/canaries", "/admin/links/canaries"),
        (
            "/admin/canaries?range=all&ip=203.0.113.9",
            "/admin/links/canaries?range=all&ip=203.0.113.9",
        ),
        ("/admin/queue", "/admin/scans"),
        (
            "/admin/queue?status=failed",
            "/admin/scans?status=failed#history",
        ),
        ("/admin/queue?status=queued", "/admin/scans"),
        (
            "/admin/queue?status=failed&level=3&page=2",
            "/admin/scans?status=failed&level=3&page=2#history",
        ),
    ] {
        let r = client.get(format!("{base}{from}")).send().await.unwrap();
        assert_eq!(r.status(), 308, "{from}");
        assert_eq!(r.headers()["location"], to, "{from}");
    }
}

/// The search box sends each kind of input to its page.
#[tokio::test]
async fn admin_search_sends_each_kind_of_input_to_its_page() {
    let (_trap, store, dir) = spawn_trap().await;
    let ip = store
        .upsert_ip("203.0.113.5".parse().unwrap())
        .await
        .unwrap();
    let rid = store
        .insert_request(&peephole::store::requests::NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ja4: Some("BOTHKINDS".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    for h in ["FPSEARCH", "BOTHKINDS"] {
        store
            .insert_fingerprint(None, ip.id, h, None, "{}", "{}", b"[]")
            .await
            .unwrap();
    }
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    let go = |q: &str| {
        let (c, u) = (
            client.clone(),
            format!(
                "{base}/admin/search?q={}",
                q.replace('#', "%23").replace('/', "%2F")
            ),
        );
        async move { c.get(u).send().await.unwrap() }
    };
    for (q, want) in [
        ("203.0.113.5", "/ip/203.0.113.5"),
        (" 198.51.100.99 ", "/admin/lookup?ip=198.51.100.99"),
        ("203.0.113.0/24", "/ips?q=203.0.113.0%2F24"),
        ("AS64500", "/ips?asn=64500"),
        ("as64500", "/ips?asn=64500"),
        (&format!("#{rid}"), &format!("/admin/requests/{rid}")),
        ("/wp-login.php", "/requests?path=%2Fwp-login.php"),
        ("FPSEARCH", "/admin/links/fp/FPSEARCH"),
    ] {
        let r = go(q).await;
        let got = format!(
            "{}{}",
            r.url().path(),
            r.url().query().map(|q| format!("?{q}")).unwrap_or_default()
        );
        assert_eq!(got, want, "{q}");
        assert_eq!(r.status(), 200, "{q}");
    }
    let html = go("BOTHKINDS").await.text().await.unwrap();
    assert!(
        html.contains("href=\"/admin/links/fp/BOTHKINDS\"")
            && html.contains("href=\"/admin/links/ja4/BOTHKINDS\""),
        "a value under two kinds lists both"
    );
    let html = go("zzz-nothing").await.text().await.unwrap();
    assert!(html.contains("Nothing found") && html.contains("zzz-nothing"));
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = anon
        .get(format!("{base}/admin/search?q=203.0.113.5"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "admin only");
}

/// Bulk lookup answers from stored data only: one row per stored address
/// or per stored address in a network, and the rest listed.
#[tokio::test]
async fn bulk_lookup_lists_stored_addresses() {
    let (_trap, store, dir) = spawn_trap().await;
    for a in ["203.0.113.5", "10.9.1.1", "10.9.2.2", "10.8.0.1"] {
        store.upsert_ip(a.parse().unwrap()).await.unwrap();
    }
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    let html = client
        .post(format!("{base}/admin/lookup/bulk"))
        .form(&[("ips", "203.0.113.5, 198.51.100.99\n10.9.0.0/16  bogus")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let rows = html.split("data-bulk").nth(1).expect("bulk table");
    for want in [
        "/ip/203.0.113.5",
        "/ip/10.9.1.1",
        "/ip/10.9.2.2",
        "/admin/links/ip/10.9.1.1",
    ] {
        assert!(rows.contains(want), "bulk lacks {want}");
    }
    assert!(!rows.contains("10.8.0.1"), "outside the network");
    assert!(rows.contains("198.51.100.99") && rows.contains("not stored"));
    assert!(html.contains("bogus"), "unreadable input is named");
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = anon
        .post(format!("{base}/admin/lookup/bulk"))
        .form(&[("ips", "203.0.113.5")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "admin only");
}

/// Every page's footer carries the version, the API specification, the
/// source and the disclaimer; /api and /about are public.
#[tokio::test]
async fn footer_links_api_specification_source_and_disclaimer() {
    let (_trap, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, base) = enrolled_admin_client(store, cfg).await;
    let anon = reqwest::Client::new();
    let footer = |html: &str| {
        html.split("<footer")
            .nth(1)
            .expect("footer")
            .split("</footer>")
            .next()
            .unwrap()
            .to_string()
    };
    for (who, client, path) in [
        ("public", &anon, "/"),
        ("public", &anon, "/ips"),
        ("admin", &admin, "/admin"),
    ] {
        let r = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(r.status(), 200, "{who} {path}");
        let f = footer(&r.text().await.unwrap());
        for want in [
            "href=\"/api\"",
            "href=\"/about\"",
            "href=\"https://github.com/overcuriousity/peephole\"",
            peephole::VERSION,
            "We claim the right to scan back.",
        ] {
            assert!(f.contains(want), "{who} {path} footer lacks {want}: {f}");
        }
    }
    let api = anon.get(format!("{base}/api")).send().await.unwrap();
    assert_eq!(api.status(), 200);
    let api = api.text().await.unwrap();
    for want in [
        "/api/blocklist",
        "/api/stats",
        "/api/map",
        "/api/countries",
        "/healthz",
        "min_severity",
        "networks=1",
        &format!("{}", peephole::admin::blocklist::MAX_HOURS),
        &format!("{}", peephole::admin::blocklist::MAX_ENTRIES),
    ] {
        assert!(api.contains(want), "/api lacks {want}");
    }
    let about = anon.get(format!("{base}/about")).send().await.unwrap();
    assert_eq!(about.status(), 200);
    let about = about.text().await.unwrap();
    assert!(about.contains("When you connect anything to the internet, you get scanned."));
    assert!(about.contains("GDPR"));
    for html in [&api, &about] {
        assert!(
            !html.contains("<script>") && !html.contains(" style=\""),
            "inline code"
        );
    }
}

/// Signed in, every page has the Lookup box; anonymous visitors don't.
#[tokio::test]
async fn lookup_box_only_for_admins() {
    let (_trap, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    for p in [
        "/admin",
        "/ips",
        "/admin/system/settings",
        "/admin/system/keys",
        "/admin/system/export",
    ] {
        let r = client.get(format!("{base}{p}")).send().await.unwrap();
        assert_eq!(r.status(), 200, "{p}");
        let html = r.text().await.unwrap();
        assert!(html.contains("action=\"/admin/search\""), "{p}");
    }
    let anon = reqwest::Client::new()
        .get(format!("{base}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!anon.contains("action=\"/admin/search\""));
}

/// A standalone node has no Access page and no node pages.
#[tokio::test]
async fn standalone_cluster_page_has_no_access() {
    let (_trap, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    let html = client
        .get(format!("{base}/admin/cluster"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Standalone") && !html.contains("/admin/cluster/access"));
    for p in [
        "/admin/cluster/access".to_string(),
        format!("/admin/cluster/node/{}", "00".repeat(32)),
    ] {
        let r = client.get(format!("{base}{p}")).send().await.unwrap();
        assert_eq!(r.status(), 404, "{p}");
    }
}

/// History pages link to the Scans page itself, also from the page a pace
/// error re-renders under the form's URL.
#[tokio::test]
async fn scans_history_pages_link_back_to_scans() {
    let (_trap, store, dir) = spawn_trap().await;
    let ip = store
        .upsert_ip("203.0.113.91".parse().unwrap())
        .await
        .unwrap();
    for _ in 0..101 {
        sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at, finished_at, error)
             VALUES (?, 1, 'failed', datetime('now'), datetime('now'), 'x')",
        )
        .bind(ip.id)
        .execute(&store.pool)
        .await
        .unwrap();
    }
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store, cfg).await;
    let bad = client
        .post(format!("{base}/admin/queue/pace"))
        .form(&[("max_workers", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    let html = bad.text().await.unwrap();
    assert!(
        html.contains("href=\"/admin/scans?page=2#history\""),
        "absolute next link"
    );
    let html = client
        .get(format!("{base}/admin/scans?status=failed&level=1"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let next = html
        .split("page=2#history")
        .next()
        .and_then(|h| h.rsplit("href=\"").next())
        .unwrap_or_default();
    assert!(
        html.contains("href=\"/admin/scans?status=failed&#38;level=1&#38;page=2#history\""),
        "filters carried: {next}"
    );
}
