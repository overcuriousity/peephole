use peephole::classify::Classifier;
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::sync::Arc;

async fn spawn_trap() -> (String, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(r#"
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
"#, db = dir.path().join("t.db").display(), d = dir.path().display());
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
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await.unwrap()
    });
    (format!("http://{addr}"), store, dir)
}

#[tokio::test]
async fn probe_request_is_logged_and_serves_trap_page() {
    let (base, store, _dir) = spawn_trap().await;
    let resp = reqwest::get(format!("{base}/definitely-not-a-route")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("route which does not exist"));
    assert!(html.contains("classified as potentially malicious"));
    assert!(html.contains("I landed here by accident"));
    assert!(html.contains("this login form is for malicious bots"));
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(n, 1);
    let level: i64 = sqlx::query_scalar("SELECT scan_level FROM requests LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(level, 1);
    // Level 1 → a scan job was queued.
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE status='queued'")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(jobs, 1);
}

#[tokio::test]
async fn sqli_request_queues_level_4() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client.get(format!("{base}/login?u=admin'%20OR%20'1'='1")).send().await.unwrap();
    let level: i64 = sqlx::query_scalar("SELECT scan_level FROM requests LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(level, 4);
    let job_level: i64 = sqlx::query_scalar("SELECT level FROM scan_jobs LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(job_level, 4);
}

#[tokio::test]
async fn fp_claim_is_stored_and_scan_still_proceeds() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    // First a probe to create the IP + a scan job.
    let _ = client.get(format!("{base}/oops")).send().await.unwrap();
    let resp = client.post(format!("{base}/claim"))
        .header("user-agent", "Mozilla/5.0")
        .form(&[("email", "human@example.org")])
        .send().await.unwrap();
    assert!(resp.status().is_success());
    let html = resp.text().await.unwrap();
    assert!(html.contains("admin was notified"));
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(claims, 1);
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs")
        .fetch_one(&store.pool).await.unwrap();
    assert!(jobs >= 1, "scan must still be queued after fp claim");
}

#[tokio::test]
async fn bait_login_post_escalates() {
    let (base, store, _dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client.post(format!("{base}/login"))
        .form(&[("username", "admin"), ("password", "' OR '1'='1")])
        .send().await.unwrap();
    let (level, labels): (i64, String) = sqlx::query_as("SELECT scan_level, labels_json FROM requests ORDER BY id DESC LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(level, 4);
    assert!(labels.contains("form-interaction"));
}
