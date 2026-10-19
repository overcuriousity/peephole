//! `peephole decoy render <uid>`: the decoy a stored row was answered with,
//! rendered again from the row, byte for byte.
use crate::config::Config;
use crate::store::Store;
use crate::trap::decoy::ai::DecoyIn;
use crate::trap::decoy::{Decoy, Input, render};
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole decoy render UID [CONFIG]
       UID is a request's uid, or a light row's <batch uid>#<row> as the export writes it.
       Prints the status line, headers and body the trap sent.";

/// A light row's decoy inputs.
type LightRow = (
    i64,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);
/// A full row's decoy inputs.
type FullRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

/// The decoy of the row `uid` (None: no such row, or not a decoy), and for
/// a legacy-SSE POST the frame that went down the stream instead.
pub async fn render_uid(store: &Store, uid: &str) -> Result<Option<(Decoy, Option<String>)>> {
    if let Some((batch, row)) = uid.split_once('#') {
        // `row` is the position in the batch, from 1.
        let Some(offset) = row.parse::<i64>().ok().filter(|n| *n >= 1).map(|n| n - 1) else {
            return Ok(None);
        };
        let r: Option<LightRow> = sqlx::query_as(
            "SELECT s.ts_ms, s.method, s.path, s.page_token, s.host, s.answer, s.decoy_v, s.decoy_site, s.decoy_in
                 FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
                 WHERE b.uid = ? ORDER BY s.rowid LIMIT 1 OFFSET ?",
        )
        .bind(batch)
        .bind(offset)
        .fetch_optional(&store.read)
        .await?;
        let Some((ts_ms, method, path, Some(tok), host, Some(answer), v, site, decoy_in)) = r
        else {
            return Ok(None);
        };
        let Some(name) = answer.strip_prefix("decoy:") else {
            return Ok(None);
        };
        return Ok(with_pushed(
            &Input {
                v: v.unwrap_or(0),
                page_token: &tok,
                host: host.as_deref(),
                // Version 0 did not use the site; version 1 always stores it.
                word: site.as_deref().unwrap_or_default(),
                ts: ts_ms.div_euclid(1000),
                method: &method,
                path: &path,
                decoy_in: decoy_in.as_deref(),
            },
            name,
        ));
    }
    let r: Option<FullRow> = sqlx::query_as(
        "SELECT ts, method, path, headers_json, page_token, answer, decoy_v, decoy_site, decoy_in
             FROM requests WHERE uid = ?",
    )
    .bind(uid)
    .fetch_optional(&store.read)
    .await?;
    let Some((ts, method, path, headers_json, Some(tok), Some(answer), v, site, decoy_in)) = r
    else {
        return Ok(None);
    };
    let Some(name) = answer.strip_prefix("decoy:") else {
        return Ok(None);
    };
    let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
    let ts = chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S")
        .map(|t| t.and_utc().timestamp())
        .unwrap_or(0);
    Ok(with_pushed(
        &Input {
            v: v.unwrap_or(0),
            page_token: &tok,
            host: crate::canary::site::request_host(&headers),
            // Version 0 did not use the site; version 1 always stores it.
            word: site.as_deref().unwrap_or_default(),
            ts,
            method: &method,
            path: &path,
            decoy_in: decoy_in.as_deref(),
        },
        name,
    ))
}

/// The decoy of `name`, and for a legacy-SSE POST the frame that went down
/// the stream (the POST itself was answered `Accepted`).
fn with_pushed(input: &Input, name: &str) -> Option<(Decoy, Option<String>)> {
    let d = render(input, name)?;
    let din = DecoyIn::parse(input.decoy_in);
    let pushed = (din.via.as_deref() == Some("sse")
        && !matches!(name, "mcp:sse" | "mcp:no-session" | "mcp:busy"))
    .then(|| crate::trap::decoy::mcp::message(input, &din, name.trim_start_matches("mcp:")))
    .flatten()
    .map(|m| format!("event: message\ndata: {m}\n\n"));
    Some((d, pushed))
}

/// Run `decoy …`; `args` excludes `decoy` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let (Some("render"), Some(uid)) = (args.first().map(String::as_str), args.get(1)) else {
        bail!("{USAGE}");
    };
    let config = args.get(2).map(String::as_str).unwrap_or(default_config);
    let cfg = Config::load(Path::new(config))?;
    let store = Store::connect(&cfg.database_path).await?;
    let Some((d, pushed)) = render_uid(&store, uid).await? else {
        bail!("no decoy row with uid {uid}");
    };
    println!("{}", d.status);
    for (k, v) in &d.headers {
        println!("{k}: {v}");
    }
    println!();
    print!("{}", d.body);
    if let Some(frame) = pushed {
        println!("\n# pushed down the session's SSE stream:\n{frame}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    #[tokio::test]
    async fn a_light_row_renders_like_a_full_one() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        apply(
            &mut conn,
            Ctx {
                origin: None,
                hlc: 1,
            },
            &Record::SkipBatch(SkipBatchRec {
                uid: "b1".into(),
                ip: "198.51.100.3".into(),
                dropped: 0,
                rows: vec![SkipRow {
                    ts_ms: 1_791_000_000_000,
                    method: "GET".into(),
                    path: "/.env".into(),
                    page_token: Some("tok".into()),
                    host: Some("203.0.113.7".into()),
                    answer: Some("decoy:dotenv".into()),
                    decoy_v: Some(1),
                    decoy_site: Some("shop".into()),
                    held_ms: None,
                    decoy_in: None,
                }],
                build: String::new(),
            }),
        )
        .await
        .unwrap();
        drop(conn);
        let (d, _) = render_uid(&s, "b1#1").await.unwrap().unwrap();
        let want = crate::trap::decoy::render(
            &crate::trap::decoy::Input {
                v: 1,
                page_token: "tok",
                host: Some("203.0.113.7"),
                word: "shop",
                ts: 1_791_000_000,
                method: "GET",
                path: "/.env",
                decoy_in: None,
            },
            "dotenv",
        )
        .unwrap();
        assert_eq!(d, want);
        assert!(render_uid(&s, "nope").await.unwrap().is_none());
        for bad in ["b1#0", "b1#-1", "b1#x", "b1#2"] {
            assert!(render_uid(&s, bad).await.unwrap().is_none(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_version_5_ai_decoy_renders_with_the_identity_it_served() {
        use crate::trap::decoy::ai::{Ask, choose};
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = crate::cluster::identity::NodeId([5; 32]);
        let ident = crate::model::ai_id::derive(Some(&node.0));
        let word = crate::canary::site::word(Some(&node.0));
        let cases = [
            (
                "r1",
                "POST",
                "/mcp",
                &br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#[..],
            ),
            (
                "r2",
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            ),
            ("r3", "GET", "/api/tags", b""),
            ("r4", "GET", "/v1/models", b""),
        ];
        let mut conn = s.pool.acquire().await.unwrap();
        let mut want = vec![];
        for (n, (uid, method, path, body)) in cases.iter().enumerate() {
            let (name, d) = choose(
                &Ask {
                    method,
                    path,
                    query: None,
                    headers: &[],
                    body,
                },
                &ident,
            )
            .unwrap();
            let din = d.to_json();
            assert!(din.contains(&format!(r#""i":"{ident}""#)), "{din}");
            // As the trap rendered it when it answered.
            let served = crate::trap::decoy::render(
                &crate::trap::decoy::Input {
                    v: crate::canary::DECOY_V,
                    page_token: "tok",
                    host: None,
                    word,
                    ts: 1_791_108_000,
                    method,
                    path,
                    decoy_in: Some(&din),
                },
                &name,
            )
            .unwrap();
            apply(
                &mut conn,
                Ctx {
                    origin: Some(&node),
                    hlc: n as u64 + 1,
                },
                &Record::Request(Box::new(crate::cluster::record::RequestRec {
                    uid: (*uid).into(),
                    ts: "2026-10-04 10:00:00".into(),
                    ip: "198.51.100.4".into(),
                    method: (*method).into(),
                    path: (*path).into(),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    page_token: Some("tok".into()),
                    answer: Some(format!("decoy:{name}")),
                    decoy_v: Some(crate::canary::DECOY_V),
                    decoy_site: Some(word.into()),
                    decoy_in: Some(din.clone()),
                    ..Default::default()
                })),
            )
            .await
            .unwrap();
            want.push((*uid, served));
        }
        drop(conn);
        for (uid, served) in want {
            let (got, _) = render_uid(&s, uid).await.unwrap().unwrap();
            assert_eq!(got, served, "{uid}");
        }
    }

    #[tokio::test]
    async fn another_nodes_decoy_renders_with_the_site_it_served() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let node = crate::cluster::identity::NodeId([3; 32]);
        let word = crate::canary::site::word(Some(&node.0));
        apply(
            &mut conn,
            Ctx {
                origin: Some(&node),
                hlc: 1,
            },
            &Record::Request(Box::new(crate::cluster::record::RequestRec {
                uid: "r1".into(),
                ts: "2026-10-04 10:00:00".into(),
                ip: "198.51.100.4".into(),
                method: "GET".into(),
                path: "/.env".into(),
                headers_json: r#"[["host","203.0.113.7"]]"#.into(),
                labels_json: "[]".into(),
                page_token: Some("tok".into()),
                answer: Some("decoy:dotenv".into()),
                decoy_v: Some(1),
                decoy_site: Some(word.into()),
                ..Default::default()
            })),
        )
        .await
        .unwrap();
        drop(conn);
        let want = crate::trap::decoy::render(
            &crate::trap::decoy::Input {
                v: 1,
                page_token: "tok",
                host: Some("203.0.113.7"),
                word,
                ts: 1_791_108_000,
                method: "GET",
                path: "/.env",
                decoy_in: None,
            },
            "dotenv",
        )
        .unwrap();
        assert_eq!(render_uid(&s, "r1").await.unwrap().unwrap().0, want);
    }
}
