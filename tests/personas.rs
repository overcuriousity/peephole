//! Personas end to end: each answers `/` with its own page and every
//! response with its own banner, every decoy still answers under it, and
//! the rows render again as served.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::persona::{self, Persona};
use peephole::trap::{self, TrapState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn spawn() -> (SocketAddr, Store, tempfile::TempDir, Option<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        "trap_listen = \"127.0.0.1:0\"\ndatabase_path = \"{db}\"\ndata_dir = \"{d}\"\n\
         trusted_proxies = [\"127.0.0.1/32\"]\n[roles]\nweb = false\n[trap]\n",
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let trusted = Arc::new(cfg.trusted_proxies.clone());
    let state = Arc::new(TrapState::for_test(store.clone(), cfg));
    let node = state.recorder.node_id().map(|n| n.0.to_vec());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    std::mem::forget(stop);
    tokio::spawn(trap::listen::serve_trap(
        listener,
        trap::router(state),
        None,
        trusted,
        rx,
    ));
    (addr, store, dir, node)
}

/// One HTTP/1.1 exchange with `Host: host`; (status, headers lower-cased, body).
async fn http(
    addr: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    ct: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 8.8.8.8\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(ct) = ct {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str("\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp.write_all(body).await.unwrap();
    let mut out = vec![];
    tcp.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let (h, b) = text.split_once("\r\n\r\n").unwrap();
    let mut lines = h.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let hs = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    (status, hs, b.to_string())
}

fn header<'a>(hs: &'a [(String, String)], k: &str) -> Option<&'a str> {
    hs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

/// A public name this node presents `p` under.
fn host_for(node: Option<&[u8]>, p: &Persona) -> String {
    (0..1000)
        .map(|n| format!("h{n}.example.com"))
        .find(|h| persona::resolve(node, Some(h)) == p)
        .unwrap()
}

/// Method, path, content type, body, the answer recorded.
type Case<'a> = (&'a str, &'a str, Option<&'a str>, &'a [u8], &'a str);

#[tokio::test]
async fn every_persona_shows_its_banner_and_keeps_every_decoy() {
    let (addr, store, _dir, node) = spawn().await;
    let decoys: &[Case] = &[
        ("GET", "/.env", None, b"", "decoy:dotenv"),
        ("GET", "/.git/config", None, b"", "decoy:git-config"),
        ("GET", "/.git/HEAD", None, b"", "decoy:git-head"),
        ("GET", "/wp-login.php", None, b"", "decoy:wp-login"),
        ("GET", "/phpinfo.php", None, b"", "decoy:phpinfo"),
        (
            "GET",
            "/wp_filemanager.php",
            None,
            b"",
            "decoy:file-manager",
        ),
        (
            "POST",
            "/mcp",
            Some("application/json"),
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            "decoy:mcp:initialize",
        ),
        ("GET", "/api/tags", None, b"", "decoy:llm:tags"),
        ("GET", "/no/such/thing", None, b"", "not-found"),
        ("GET", "/", None, b"", "landing"),
    ];
    let mut want = 0;
    for p in &persona::ALL {
        let host = host_for(node.as_deref(), p);
        for (method, path, ct, body, answer) in decoys {
            let (status, hs, text) = http(addr, &host, method, path, *ct, body).await;
            let what = format!("{} {method} {path}", p.name);
            assert_eq!(
                status,
                if *answer == "not-found" { 404 } else { 200 },
                "{what}"
            );
            assert_eq!(header(&hs, "server"), p.server, "{what}");
            assert_eq!(
                header(&hs, "x-powered-by"),
                (p.name == "exchange-owa").then_some("ASP.NET"),
                "{what}"
            );
            match *answer {
                "landing" => {
                    assert!(text.contains("window.PEEPHOLE_TOKEN = \""), "{what}");
                    assert!(text.contains("/collect.js\" defer></script>"), "{what}");
                }
                "decoy:phpinfo" => assert!(text.contains(p.server_software()), "{what}"),
                _ => {}
            }
            want += 1;
        }
    }
    // Every row recorded under its persona, with what it was answered.
    let t0 = Instant::now();
    loop {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM requests")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        if n >= want {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "{n} of {want} rows");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let rows: Vec<(String, String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT uid, answer, persona, decoy_in FROM requests")
            .fetch_all(&store.pool)
            .await
            .unwrap();
    for p in &persona::ALL {
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.2.as_deref() == Some(p.name))
            .collect();
        assert_eq!(mine.len(), decoys.len(), "{}", p.name);
        for (_, _, _, _, answer) in decoys {
            assert!(mine.iter().any(|r| r.1 == *answer), "{} {answer}", p.name);
        }
        // The decoys that depend on the persona carry it, and render again
        // as served.
        for (uid, answer, _, din) in mine {
            if matches!(
                answer.as_str(),
                "decoy:phpinfo" | "decoy:mcp:initialize" | "decoy:llm:tags"
            ) {
                let din = din.as_deref().unwrap();
                assert!(din.contains(&format!(r#""p":"{}""#, p.name)), "{din}");
                let (d, _) = peephole::canary::cli::render_uid(&store, uid)
                    .await
                    .unwrap()
                    .unwrap();
                if answer == "decoy:phpinfo" {
                    assert!(d.body.contains(p.server_software()), "{}", p.name);
                }
            } else {
                assert_eq!(din, &None, "{} {answer}", p.name);
            }
        }
    }
}
