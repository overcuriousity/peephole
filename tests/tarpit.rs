//! The tarpit end to end: a source whose request reached severity 4 gets a
//! slow `200` next, recorded as `answer = tarpit` with the time held; with
//! the pool full it gets the normal answer.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A plain trap listener behind a trusted proxy at 127.0.0.1 (the client
/// is the `X-Forwarded-For` address), with the default hold, dripping
/// every second.
async fn spawn() -> (SocketAddr, Store, Arc<TrapState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
trusted_proxies = ["127.0.0.1/32"]
[roles]
web = false
[trap]
tarpit_pool = 1
tarpit_per_source = 1
tarpit_drip_every_secs = 1
"#,
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let trusted = Arc::new(cfg.trusted_proxies.clone());
    let state = Arc::new(TrapState {
        tarpit: Arc::new(trap::tarpit::Tarpit::of(&cfg)),
        ..TrapState::for_test(store.clone(), cfg)
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(stop);
    tokio::spawn(trap::listen::serve_trap(
        listener,
        trap::router(state.clone()),
        None,
        trusted,
        rx,
    ));
    (addr, store, state, dir)
}

const CLIENT: &str = "8.8.8.8";

async fn send(addr: SocketAddr, path: &str, extra: &str) -> tokio::net::TcpStream {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head =
        format!("GET {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {CLIENT}\r\n{extra}\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp
}

async fn read_all(mut tcp: tokio::net::TcpStream) -> String {
    let mut out = vec![];
    let _ = tcp.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Wait until `sql` counts at least `n`.
async fn until(store: &Store, sql: &str, n: i64) {
    let t0 = Instant::now();
    loop {
        let got: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_one(&store.pool)
            .await
            .unwrap();
        if got >= n {
            return;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "waiting for {sql}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Make the source severity 4 (Shellshock in a header) and wait for it.
async fn mark(addr: SocketAddr, store: &Store) {
    let answer = read_all(send(addr, "/", "User-Agent: () { :;}; /bin/bash -c id\r\n").await).await;
    assert!(
        answer.starts_with("HTTP/1.1 404"),
        "first contact: {answer}"
    );
    until(store, "SELECT COUNT(*) FROM requests WHERE severity = 4", 1).await;
}

/// No test waits out a hold (600 s): the tarpitted clients leave after the
/// first bytes, and the drip (every second) notices at its next writes.
/// Holding to the cap is `trap::tarpit`'s unit tests, on a paused clock.
#[tokio::test]
async fn a_severity_4_source_is_tarpitted_until_it_leaves() {
    let (addr, store, state, _d) = spawn().await;
    mark(addr, &store).await;
    let mut tcp = send(addr, "/index.php", "").await;
    let mut first = vec![0u8; 512];
    let n = tcp.read(&mut first).await.unwrap();
    let head = String::from_utf8_lossy(&first[..n]).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(state.tarpit.status().held, 1);
    drop(tcp);
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE answer = 'tarpit'",
        1,
    )
    .await;
    let (status, held): (i64, i64) =
        sqlx::query_as("SELECT status, held_ms FROM requests WHERE answer = 'tarpit'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(status, 200);
    assert!(held < 5_000, "counted until it left: {held}");
    assert_eq!(state.tarpit.status().held, 0, "given back");
}

#[tokio::test]
async fn with_the_pool_full_the_answer_is_the_normal_one() {
    let (addr, store, state, _d) = spawn().await;
    mark(addr, &store).await;
    let mut held = send(addr, "/a", "").await;
    let mut first = [0u8; 12];
    held.read_exact(&mut first).await.unwrap();
    assert_eq!(state.tarpit.status().held, 1);
    let answer = read_all(send(addr, "/b", "").await).await;
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    drop(held);
    until(&store, "SELECT COUNT(*) FROM requests", 3).await;
    let answers: Vec<(String, String)> =
        sqlx::query_as("SELECT path, answer FROM requests ORDER BY path")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    let answers: Vec<_> = answers
        .iter()
        .map(|(p, a)| (p.as_str(), a.as_str()))
        .collect();
    assert_eq!(
        answers,
        [("/", "not-found"), ("/a", "tarpit"), ("/b", "not-found")]
    );
}
