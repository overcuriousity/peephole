//! The trap's upload sink (MIK-121): what each upload kind records and
//! answers, the body caps, and the per-source and flood bounds.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::sync::Arc;

const MIB: usize = 1 << 20;

/// The trap's router, answering once what it records is written.
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

/// A trap behind a trusted proxy at 127.0.0.1, with `extra` appended to
/// the config.
async fn spawn(extra: &str) -> (String, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_text = format!(
        r#"
trap_listen = "127.0.0.1:0"
database_path = "{db}"
data_dir = "{d}"
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
    let app = settled_router(Arc::new(TrapState::for_test(store.clone(), cfg)));
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

/// No flood gate: every request is recorded.
const UNGATED: &str = "[trap]\nrecord_rate = 0\n";

/// A multipart body with one file in `field`, and its content type.
fn multipart(field: &str, file: &str, data: &[u8]) -> (String, Vec<u8>) {
    let mut b =
        b"--b0undary\r\nContent-Disposition: form-data; name=\"_wpnonce\"\r\n\r\n1a2b\r\n".to_vec();
    b.extend_from_slice(
        format!(
            "--b0undary\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{file}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    b.extend_from_slice(data);
    b.extend_from_slice(b"\r\n--b0undary--\r\n");
    ("multipart/form-data; boundary=b0undary".into(), b)
}

async fn send(
    base: &str,
    method: &str,
    path: &str,
    ip: &str,
    ct: Option<&str>,
    body: Vec<u8>,
) -> reqwest::Response {
    let mut r = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .request(method.parse().unwrap(), format!("{base}{path}"))
        .header("x-forwarded-for", ip)
        .body(body);
    if let Some(ct) = ct {
        r = r.header("content-type", ct);
    }
    r.send().await.unwrap()
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    kind: String,
    filename: Option<String>,
    sniffed_type: String,
    size: i64,
    truncated: bool,
    answered_path: String,
    path_is_prefix: bool,
    content_state: String,
    ip: String,
    request_uid: String,
}

async fn uploads(store: &Store) -> Vec<Row> {
    sqlx::query_as(
        "SELECT u.kind, u.filename, u.sniffed_type, u.size, u.truncated, u.answered_path,
                u.path_is_prefix, u.content_state, i.ip, u.request_uid
         FROM uploads u JOIN ips i ON i.id = u.ip_id ORDER BY u.id",
    )
    .fetch_all(&store.pool)
    .await
    .unwrap()
}

async fn scalar(store: &Store, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn each_kind_records_its_path_and_answers() {
    let (base, store, _dir) = spawn(UNGATED).await;
    let ip = "203.0.113.40";

    let r = send(
        &base,
        "PUT",
        "/x/a.php",
        ip,
        None,
        b"<?php system($_GET['c']);".to_vec(),
    )
    .await;
    assert_eq!(r.status(), 201);
    assert_eq!(r.headers()["location"], "/x/a.php");
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");

    let (ct, b) = multipart("pluginzip", "wp-shell.zip", b"PK\x03\x04plugin");
    let r = send(
        &base,
        "POST",
        "/wp-admin/update.php?action=upload-plugin",
        ip,
        Some(&ct),
        b,
    )
    .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("Plugin installed successfully.")
    );

    let (ct, b) = multipart("themezip", "dark.zip", b"PK\x03\x04theme");
    let r = send(
        &base,
        "POST",
        "/wp-admin/update.php?action=upload-theme",
        ip,
        Some(&ct),
        b,
    )
    .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.text()
            .await
            .unwrap()
            .contains("Theme installed successfully.")
    );

    let (ct, b) = multipart("async-upload", "img.php", b"<?= `id` ?>");
    let r = send(
        &base,
        "POST",
        "/wp-admin/async-upload.php",
        ip,
        Some(&ct),
        b,
    )
    .await;
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["success"], true);
    let url = v["data"]["url"].as_str().unwrap().to_string();

    let (ct, b) = multipart("file", "../../x.sh", b"#!/bin/sh\nid\n");
    let r = send(
        &base,
        "POST",
        "/admin/elfinder/php/connector.php",
        ip,
        Some(&ct),
        b,
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "/uploads/x.sh\n");

    let rows = uploads(&store).await;
    let got: Vec<(&str, &str, bool, &str)> = rows
        .iter()
        .map(|r| {
            (
                r.kind.as_str(),
                r.answered_path.as_str(),
                r.path_is_prefix,
                r.sniffed_type.as_str(),
            )
        })
        .collect();
    let ym = chrono::Utc::now().format("%Y/%m");
    let media = format!("/wp-content/uploads/{ym}/img.php");
    assert_eq!(
        got,
        [
            ("put", "/x/a.php", false, "php"),
            ("wp_plugin", "/wp-content/plugins/wp-shell/", true, "zip"),
            ("wp_theme", "/wp-content/themes/dark/", true, "zip"),
            ("wp_media", media.as_str(), false, "php"),
            ("script", "/uploads/x.sh", false, "script"),
        ]
    );
    assert!(url.ends_with(&media), "{url}");
    assert_eq!(rows[4].filename.as_deref(), Some("../../x.sh"));
    for r in &rows {
        assert_eq!((r.content_state.as_str(), r.ip.as_str()), ("held", ip));
        // Linked to the request that carried it, answered as an upload.
        let answer: String = sqlx::query_scalar("SELECT answer FROM requests WHERE uid = ?")
            .bind(&r.request_uid)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(answer, format!("upload:{}", r.kind));
    }
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM upload_blobs").await, 5);
}

#[tokio::test]
async fn a_large_put_keeps_one_mib_and_its_full_size() {
    let (base, store, _dir) = spawn(UNGATED).await;
    let mut body = b"\x7fELF".to_vec();
    body.resize(MIB + MIB / 2, 7);
    let r = send(&base, "PUT", "/big.bin", "203.0.113.41", None, body).await;
    assert_eq!(r.status(), 201);
    let rows = uploads(&store).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].size, rows[0].truncated),
        ((MIB + MIB / 2) as i64, true)
    );
    assert_eq!(rows[0].sniffed_type, "elf");
    assert_eq!(
        scalar(&store, "SELECT size FROM upload_blobs").await,
        MIB as i64
    );
    // The request's own row keeps 64 KiB, as any other's.
    assert_eq!(
        scalar(&store, "SELECT length(body) FROM requests").await,
        64 * 1024
    );
}

#[tokio::test]
async fn a_post_that_is_no_upload_keeps_64_kib() {
    let (base, store, _dir) = spawn(UNGATED).await;
    // Multipart to a path that is no upload script, and to an upload
    // script without a file: neither is an upload.
    let (ct, b) = multipart("file", "a.php", &vec![b'a'; 200_000]);
    let r = send(&base, "POST", "/contact.php", "203.0.113.42", Some(&ct), b).await;
    assert_eq!(r.status(), 404);
    let form =
        "--b0undary\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b0undary--\r\n";
    let r = send(
        &base,
        "POST",
        "/upload.php",
        "203.0.113.42",
        Some(&ct),
        form.into(),
    )
    .await;
    assert_eq!(r.status(), 404);
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM uploads").await, 0);
    assert_eq!(
        scalar(&store, "SELECT MAX(length(body)) FROM requests").await,
        64 * 1024
    );
}

#[tokio::test]
async fn past_the_hourly_rate_a_source_is_recorded_by_hash_only() {
    let (base, store, _dir) = spawn(UNGATED).await;
    let mut replies = vec![];
    for i in 1..=7 {
        // Seven addresses in one /64, each file different.
        let ip = format!("2001:db8:1:2::{i}");
        let r = send(
            &base,
            "PUT",
            "/s.php",
            &ip,
            None,
            format!("<?php #{i}").into(),
        )
        .await;
        replies.push((
            r.status(),
            r.headers()["location"].clone(),
            r.text().await.unwrap(),
        ));
    }
    assert!(replies.iter().all(|r| *r == replies[0]), "{replies:?}");
    let states: Vec<String> = uploads(&store)
        .await
        .into_iter()
        .map(|r| r.content_state)
        .collect();
    assert!(states[..6].iter().all(|s| s == "held"), "{states:?}");
    assert_eq!(states[6], "dropped_rate");
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM upload_blobs").await, 6);
    // Another source still brings content.
    send(
        &base,
        "PUT",
        "/s.php",
        "2001:db8:1:3::1",
        None,
        b"<?php #8".to_vec(),
    )
    .await;
    assert_eq!(uploads(&store).await[7].content_state, "held");
}

#[tokio::test]
async fn a_request_the_flood_gate_skips_records_no_upload() {
    let (base, store, _dir) =
        spawn("[trap]\nrecord_rate = 0.001\nrecord_burst = 1\nsample_every = 0\n").await;
    let a = send(
        &base,
        "PUT",
        "/a.php",
        "203.0.113.43",
        None,
        b"<?php 1".to_vec(),
    )
    .await;
    let b = send(
        &base,
        "PUT",
        "/a.php",
        "203.0.113.43",
        None,
        b"<?php 2".to_vec(),
    )
    .await;
    // Answered alike, recorded once.
    assert_eq!((a.status().as_u16(), b.status().as_u16()), (201, 201));
    assert_eq!(a.headers()["location"], b.headers()["location"]);
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM uploads").await, 1);
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM upload_blobs").await, 1);
}

#[tokio::test]
async fn with_the_sink_off_an_upload_is_any_request() {
    let (base, store, _dir) = spawn(UNGATED).await;
    sqlx::query("INSERT INTO settings (key, value) VALUES ('uploads.enabled', 'false')")
        .execute(&store.pool)
        .await
        .unwrap();
    let r = send(
        &base,
        "PUT",
        "/x/a.php",
        "203.0.113.44",
        None,
        vec![b'a'; 200_000],
    )
    .await;
    assert_eq!(r.status(), 404);
    assert!(r.headers().get("location").is_none());
    let (ct, b) = multipart("pluginzip", "p.zip", b"PK\x03\x04");
    let r = send(
        &base,
        "POST",
        "/wp-admin/update.php?action=upload-plugin",
        "203.0.113.44",
        Some(&ct),
        b,
    )
    .await;
    assert_ne!(r.text().await.unwrap(), "");
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM uploads").await, 0);
    assert_eq!(scalar(&store, "SELECT COUNT(*) FROM upload_blobs").await, 0);
    assert_eq!(
        scalar(&store, "SELECT MAX(length(body)) FROM requests").await,
        64 * 1024
    );
}
