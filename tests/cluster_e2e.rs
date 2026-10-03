//! Two real `peephole::run` instances from config files: a listener with
//! the web interface, and a headless scanner. A probe caught by the
//! listener is scanned by the scanner and both hold the whole dataset.
use peephole::cluster::identity::Identity;
use peephole::store::Store;
use std::time::Duration;

/// `(status, level, error, arbiter, scanner)` of a job, for diagnostics.
type JobDump = (
    String,
    i64,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn fake_nmap(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let xml = dir.join("nmap.xml");
    std::fs::copy("tests/fixtures/nmap-basic.xml", &xml).unwrap();
    let p = dir.join("fake-nmap");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'Nmap version 7.99 ( fake )'; exit 0; fi\ncat {}\n",
            xml.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

async fn count(db: &std::path::Path, sql: &str) -> i64 {
    let s = Store::connect(db).await.unwrap();
    let n = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&s.pool)
        .await
        .unwrap();
    s.pool.close().await;
    n
}

#[tokio::test]
async fn listener_and_headless_scanner_share_everything() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(b_dir.path());
    let a_key = Identity::load_or_create(&a_dir.path().join("node.key")).unwrap();
    let b_key = Identity::load_or_create(&b_dir.path().join("node.key")).unwrap();
    let (trap, admin, a_rpc, b_rpc) = (free_port(), free_port(), free_port(), free_port());
    let a_cfg = a_dir.path().join("config.toml");
    std::fs::write(
        &a_cfg,
        format!(
            r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{d}/a.db"
data_dir = "{d}"
trusted_proxies = ["127.0.0.1/32"]
[roles]
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
[cluster]
node_name = "listener-a"
listen = "127.0.0.1:{a_rpc}"
advertise = "127.0.0.1:{a_rpc}"
[[cluster.peers]]
name = "scanner-b"
address = "127.0.0.1:{b_rpc}"
public_key = "{b}"
"#,
            d = a_dir.path().display(),
            b = b_key.id
        ),
    )
    .unwrap();
    let b_cfg = b_dir.path().join("config.toml");
    std::fs::write(
        &b_cfg,
        format!(
            r#"
database_path = "{d}/b.db"
data_dir = "{d}"
[roles]
listener = false
web = false
[scan]
max_workers = 1
max_scans_per_hour = 600
# No Tor list and no DNS in tests.
tor_unknown = "scan"
verify_crawlers = false
nmap_path = "{nmap}"
[cluster]
node_name = "scanner-b"
listen = "127.0.0.1:{b_rpc}"
advertise = "127.0.0.1:{b_rpc}"
[[cluster.peers]]
name = "listener-a"
address = "127.0.0.1:{a_rpc}"
public_key = "{a}"
"#,
            d = b_dir.path().display(),
            a = a_key.id,
            nmap = nmap.display(),
        ),
    )
    .unwrap();
    let ha = tokio::spawn(peephole::run(a_cfg));
    let hb = tokio::spawn(peephole::run(b_cfg));

    let client = reqwest::Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        // An SQL injection probe: queued for a level-4 counter-scan.
        // From a public address: the scanner never scans cluster members
        // (127.0.0.1 here), so the probe arrives via the trusted proxy.
        let r = client
            .get(format!(
                "http://127.0.0.1:{trap}/item.php?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"
            ))
            .header("x-forwarded-for", "198.51.100.5")
            .send()
            .await;
        if r.is_ok() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "trap never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (a_db, b_db) = (a_dir.path().join("a.db"), b_dir.path().join("b.db"));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let done_a = count(
            &a_db,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'",
        )
        .await;
        let ports_a = count(&a_db, "SELECT COUNT(*) FROM ports").await;
        let reqs_b = count(&b_db, "SELECT COUNT(*) FROM requests").await;
        if done_a == 1 && ports_a == 3 && reqs_b == 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            for db in [&a_db, &b_db] {
                let s = Store::connect(db).await.unwrap();
                let rows: Vec<JobDump> =
                    sqlx::query_as("SELECT status, level, error, arbiter, scanner FROM scan_jobs")
                        .fetch_all(&s.pool)
                        .await
                        .unwrap();
                eprintln!("{}: {rows:?}", db.display());
            }
            panic!("not converged: done_a={done_a} ports_a={ports_a} reqs_b={reqs_b}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The scan ran on B for A's job.
    let scanner: Vec<u8> = {
        let s = Store::connect(&a_db).await.unwrap();
        sqlx::query_scalar("SELECT scanner FROM scan_jobs")
            .fetch_one(&s.pool)
            .await
            .unwrap()
    };
    assert_eq!(scanner, b_key.id.0.to_vec());
    // The public wall on A counts the request.
    let stats: serde_json::Value = client
        .get(format!("http://127.0.0.1:{admin}/api/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["total_requests"], 1);
    ha.abort();
    hb.abort();
}
