//! The AI decoys end to end: MCP over Streamable HTTP and the LLM gateway,
//! recorded with their decoy input, linked by canaries.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Spawned = (
    SocketAddr,
    Store,
    tempfile::TempDir,
    Arc<TrapState>,
    tokio::sync::watch::Sender<bool>,
);

async fn spawn_full(extra: &str, tarpit: bool) -> Spawned {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        "trap_listen = \"127.0.0.1:0\"\ndatabase_path = \"{db}\"\ndata_dir = \"{d}\"\n\
         trusted_proxies = [\"127.0.0.1/32\"]\n[roles]\nweb = false\n[trap]\n{extra}\n",
        db = dir.path().join("t.db").display(),
        d = dir.path().display()
    );
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let trusted = Arc::new(cfg.trusted_proxies.clone());
    let base = TrapState::for_test(store.clone(), cfg.clone());
    let state = Arc::new(if tarpit {
        TrapState {
            tarpit: Arc::new(trap::tarpit::Tarpit::of(&cfg)),
            ..base
        }
    } else {
        base
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(trap::listen::serve_trap(
        listener,
        trap::router(state.clone()),
        None,
        trusted,
        rx,
    ));
    (addr, store, dir, state, stop)
}

async fn spawn(extra: &str, tarpit: bool) -> (SocketAddr, Store, tempfile::TempDir) {
    let (addr, store, dir, _state, stop) = spawn_full(extra, tarpit).await;
    std::mem::forget(stop);
    (addr, store, dir)
}

/// One HTTP/1.1 exchange; returns (status, headers lower-cased, body).
async fn http(
    addr: SocketAddr,
    from: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: {from}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
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
    // Chunked bodies: good enough to search in.
    (status, hs, b.to_string())
}

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
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "timed out waiting for {sql}: {got}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const JSON_CT: (&str, &str) = ("Content-Type", "application/json");

#[tokio::test]
async fn an_mcp_session_is_recorded_and_its_canary_links_back() {
    let (addr, store, _d) = spawn("", false).await;
    let (st, hs, body) = http(addr, "8.8.8.8", "POST", "/mcp", &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#).await;
    assert_eq!(st, 200, "{body}");
    let sid = hs
        .iter()
        .find(|(k, _)| k == "mcp-session-id")
        .unwrap()
        .1
        .clone();
    assert!(body.contains("\"protocolVersion\":\"2025-03-26\""));
    let session = [JSON_CT, ("Mcp-Session-Id", sid.as_str())];
    let (st, _, _) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/mcp",
        &session,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(st, 202);
    let (_, _, body) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/mcp",
        &session,
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .await;
    assert!(body.contains("run_command"));
    let (_, _, body) = http(addr, "8.8.8.8", "POST", "/mcp", &session,
        br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/deploy/.aws/credentials"}}}"#).await;
    let key = body
        .split("aws_access_key_id = ")
        .nth(1)
        .unwrap()
        .split("\\n")
        .next()
        .unwrap()
        .to_string();
    assert!(key.starts_with("AKIA"), "{body}");
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE answer LIKE 'decoy:mcp:%' AND canary_parsed > 0",
        4,
    )
    .await;
    let din: String =
        sqlx::query_scalar("SELECT decoy_in FROM requests WHERE answer = 'decoy:mcp:tools/call'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert!(din.contains("\"cls\":\"aws-credentials\""), "{din}");
    // The session id names the initialize request; later calls carry it.
    let carriers: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT t.request_id) FROM canaries c JOIN request_tokens t ON t.value_hash = c.value_hash
         WHERE c.kind = 'mcp-session'").fetch_one(&store.pool).await.unwrap();
    assert_eq!(carriers, 3);
    // The AWS key, used from elsewhere, links back to the tools/call.
    let auth = format!("AWS4-HMAC-SHA256 Credential={key}/20261006/us-east-1/s3/aws4_request");
    http(
        addr,
        "9.9.9.9",
        "GET",
        "/",
        &[("Authorization", auth.as_str())],
        b"",
    )
    .await;
    until(&store, "SELECT COUNT(*) FROM requests r JOIN ips i ON i.id = r.ip_id WHERE i.ip = '9.9.9.9' AND r.canary_parsed > 0", 1).await;
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM canaries c JOIN request_tokens t ON t.value_hash = c.value_hash
         JOIN requests r ON r.id = c.request_id WHERE c.kind = 'aws-key' AND r.answer = 'decoy:mcp:tools/call'")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(linked, 1);
}

#[tokio::test]
async fn the_llm_gateway_answers_each_api_style() {
    let (addr, store, _d) = spawn("", false).await;
    let (st, _, b) = http(addr, "8.8.8.8", "GET", "/api/tags", &[], b"").await;
    assert!(st == 200 && b.contains("llama3.1:8b"));
    let (st, hs, b) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/v1/chat/completions",
        &[JSON_CT, ("Authorization", "Bearer sk-proj-abc")],
        br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
    )
    .await;
    assert_eq!(st, 200);
    assert!(
        hs.iter()
            .any(|(k, v)| k == "content-type" && v.starts_with("text/event-stream"))
    );
    assert!(b.contains("[DONE]"));
    let (st, _, b) = http(addr, "8.8.8.8", "POST", "/v1/messages", &[JSON_CT, ("x-api-key", "sk-ant-x"), ("anthropic-version", "2023-06-01")],
        br#"{"model":"claude-opus-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#).await;
    assert!(st == 200 && b.contains("end_turn"), "{b}");
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE answer LIKE 'decoy:llm:%'",
        3,
    )
    .await;
    let mut apis: Vec<String> = sqlx::query_scalar("SELECT json_extract(decoy_in, '$.api') FROM requests WHERE decoy_in IS NOT NULL ORDER BY id")
        .fetch_all(&store.pool).await.unwrap();
    // Rows are written apart from the answers, so their order is not fixed.
    apis.sort();
    assert_eq!(apis, ["anthropic", "ollama", "openai"]);
}

#[tokio::test]
async fn compressed_bodies_are_read_and_our_own_key_does_not_open_the_admin_page() {
    use std::io::Write;
    let (addr, store, _d) = spawn("", false).await;
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    gz.write_all(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .unwrap();
    let (st, _, b) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/mcp",
        &[JSON_CT, ("Content-Encoding", "gzip")],
        &gz.finish().unwrap(),
    )
    .await;
    assert!(st == 200 && b.contains("read_file"), "{b}");
    // Harvest an app-key canary from query_db, then present it as a Bearer key.
    let (_, _, b) = http(addr, "8.8.8.8", "POST", "/mcp", &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"sql":"select * from users"}}}"#).await;
    let key = b
        .split("| admin    | ")
        .nth(1)
        .unwrap()
        .split("\\n")
        .next()
        .unwrap()
        .trim()
        .to_string();
    until(
        &store,
        "SELECT COUNT(*) FROM canaries WHERE kind = 'app-key'",
        1,
    )
    .await;
    let bearer = format!("Bearer {key}");
    let (st, _, b) = http(
        addr,
        "7.7.7.7",
        "POST",
        "/v1/chat/completions",
        &[JSON_CT, ("Authorization", bearer.as_str())],
        br#"{"model":"gpt-4o"}"#,
    )
    .await;
    assert_eq!(st, 200);
    assert!(
        b.contains("chat.completion"),
        "LLM answer, not the admin page: {b}"
    );
}

#[tokio::test]
async fn a_tarpitted_source_still_gets_the_mcp_decoy() {
    let (addr, store, _d) = spawn(
        "tarpit_pool = 4\ntarpit_per_source = 4\ntarpit_hold_secs = 5\ntarpit_drip_every_secs = 1",
        true,
    )
    .await;
    // Severity 4 (mcp-abuse) marks the source for the tarpit…
    http(addr, "8.8.8.8", "POST", "/mcp", &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#).await;
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE severity = 4",
        1,
    )
    .await;
    // …but its next MCP call is still answered by the decoy, at once.
    let t0 = Instant::now();
    let (st, _, b) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/mcp",
        &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .await;
    assert!(st == 200 && b.contains("read_file"));
    assert!(t0.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_source_over_its_recording_rate_gets_the_decoy_and_a_renderable_light_row() {
    let (addr, store, _d, state, stop) = spawn_full(
        "record_rate = 0.001\nrecord_burst = 1\nsample_every = 1000000",
        false,
    )
    .await;
    for _ in 0..3 {
        let (st, _, b) = http(
            addr,
            "8.8.8.8",
            "POST",
            "/mcp",
            &[JSON_CT],
            br#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#,
        )
        .await;
        assert!(st == 200 && b.contains("\"id\":5"));
    }
    // Light rows are written when their batch flushes: stopping the flusher
    // writes everything buffered, as capture.rs does.
    let (fstop, frx) = tokio::sync::watch::channel(false);
    let flusher = tokio::spawn(trap::flush_skips(state.clone(), frx));
    fstop.send(true).unwrap();
    flusher.await.unwrap();
    drop(stop);
    until(
        &store,
        "SELECT COUNT(*) FROM skipped_requests WHERE decoy_in IS NOT NULL",
        1,
    )
    .await;
    let (b, row): (String, i64) = sqlx::query_as(
        "SELECT b.uid, (SELECT COUNT(*) FROM skipped_requests x WHERE x.batch_id = s.batch_id AND x.rowid <= s.rowid)
         FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id WHERE s.decoy_in IS NOT NULL LIMIT 1")
        .fetch_one(&store.pool).await.unwrap();
    let (d, _) = peephole::canary::cli::render_uid(&store, &format!("{b}#{row}"))
        .await
        .unwrap()
        .unwrap();
    assert!(d.body.contains("\"id\":5"), "{}", d.body);
}

#[tokio::test]
async fn legacy_sse_pushes_answers_down_the_stream() {
    let (addr, store, _d) = spawn("mcp_sse_hold_secs = 2", false).await;
    let mut sse = tokio::net::TcpStream::connect(addr).await.unwrap();
    sse.write_all(b"GET /sse HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 8.8.8.8\r\nAccept: text/event-stream\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut head = String::new();
    // Headers and the endpoint event may arrive in separate reads.
    while !head
        .split("data: ")
        .nth(1)
        .is_some_and(|r| r.contains('\n'))
    {
        let n = sse.read(&mut buf).await.unwrap();
        assert!(n > 0, "stream ended early: {head}");
        head.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let endpoint = head
        .split("data: ")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    assert!(endpoint.starts_with("/messages?sessionId="), "{head}");
    let (st, _, b) = http(
        addr,
        "8.8.8.8",
        "POST",
        &endpoint,
        &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":11,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!((st, b.as_str()), (202, "Accepted"));
    let mut got = String::new();
    while !got.contains("\"id\":11") {
        let n = sse.read(&mut buf).await.unwrap();
        assert!(n > 0, "stream ended early: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert!(got.contains("event: message") && got.contains("run_command"));
    // Unknown session: 404, recorded as no-session.
    let (st, _, _) = http(
        addr,
        "8.8.8.8",
        "POST",
        "/messages?sessionId=nope",
        &[JSON_CT],
        br#"{"jsonrpc":"2.0","id":12,"method":"ping"}"#,
    )
    .await;
    assert_eq!(st, 404);
    // The stream's own row arrives once it ends, with the time held.
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE answer = 'decoy:mcp:sse' AND held_ms >= 1000",
        1,
    )
    .await;
    until(
        &store,
        "SELECT COUNT(*) FROM requests WHERE answer = 'decoy:mcp:no-session'",
        1,
    )
    .await;
    // The POST carried the session id the GET was served: linked.
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT r.id) FROM canaries c JOIN request_tokens t ON t.value_hash = c.value_hash
         JOIN requests r ON r.id = t.request_id WHERE c.kind = 'mcp-session' AND r.answer = 'decoy:mcp:tools/list'")
        .fetch_one(&store.pool).await.unwrap();
    assert_eq!(linked, 1);
}
