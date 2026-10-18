//! The wave loop: every [`WAVE_EVERY`] detect new exploit waves
//! (`store::waves`) and, with `[notify]` set, push the ones not pushed yet
//! to the operator's webhook or ntfy topic: one POST a pass, at most
//! [`PER_PUSH`] waves in it, [`MAX_ATTEMPTS`] tries a wave.
//!
//! Shape text is request content an attacker chose: it is cut to
//! [`SHAPE_MAX`] characters without control characters before it leaves,
//! never goes into a header, and nothing here logs it, the URL or the
//! token (a `reqwest::Error` names the URL, so only its class is logged).

use crate::config::{NotifyConfig, NotifyKind, WavesConfig};
use crate::store::Store;
use crate::store::waves::Wave;
use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use std::time::Duration;
use tracing::{info, warn};

/// How often the loop looks for waves; also the most one push an interval.
pub const WAVE_EVERY: Duration = Duration::from_secs(300);
/// Failed pushes after which a wave leaves the queue.
pub const MAX_ATTEMPTS: i64 = 3;
/// Waves in one push.
pub const PER_PUSH: i64 = 10;
/// Characters of shape text a push carries.
pub const SHAPE_MAX: usize = 120;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Where and how this node pushes; built once, only with `[notify]` set.
pub struct Pusher {
    client: reqwest::Client,
    cfg: NotifyConfig,
    node: String,
    /// `<webauthn.origin>/admin/paths`, on a node with the web role.
    page: Option<String>,
}

impl Pusher {
    pub fn new(cfg: NotifyConfig, node: String, admin_origin: Option<&str>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("peephole/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Self {
            client,
            cfg,
            node,
            page: admin_origin.map(|o| format!("{}/admin/paths", o.trim_end_matches('/'))),
        }
    }

    fn kind(&self) -> &'static str {
        match self.cfg.kind {
            NotifyKind::Webhook => "webhook",
            NotifyKind::Ntfy => "ntfy",
        }
    }

    /// One POST of these waves; `Err` is what may be logged: the HTTP
    /// status or the error class.
    async fn post(&self, waves: &[Wave], window_minutes: i64) -> Result<(), String> {
        let mut req = self.client.post(self.cfg.url.expose());
        if let Some(t) = &self.cfg.token
            && let Ok(mut v) = HeaderValue::from_str(&format!("Bearer {}", t.expose()))
        {
            v.set_sensitive(true);
            req = req.header(AUTHORIZATION, v);
        }
        req = match self.cfg.kind {
            NotifyKind::Webhook => req.json(&webhook_body(
                &self.node,
                waves,
                window_minutes,
                self.page.as_deref(),
            )),
            NotifyKind::Ntfy => {
                let title =
                    HeaderValue::from_bytes(format!("exploit wave on {}", self.node).as_bytes())
                        .unwrap_or_else(|_| HeaderValue::from_static("exploit wave"));
                req.header("Title", title)
                    .header("Priority", "4")
                    .header("Tags", "rotating_light")
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(ntfy_body(waves, window_minutes))
            }
        };
        match req.send().await {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => Err(format!("status {}", r.status().as_u16())),
            Err(e) => Err(error_class(&e).to_string()),
        }
    }

    /// Push the waves waiting, if any, and record the outcome.
    pub async fn push_pending(&self, store: &Store, window_minutes: i64, now: DateTime<Utc>) {
        let waves = match store.waves_to_notify(MAX_ATTEMPTS, PER_PUSH).await {
            Ok(w) if w.is_empty() => return,
            Ok(w) => w,
            Err(e) => return warn!(?e, "reading waves to push failed"),
        };
        let shapes: Vec<i64> = waves.iter().map(|w| w.shape).collect();
        let outcome = self.post(&waves, window_minutes).await;
        match &outcome {
            Ok(()) => info!(kind = self.kind(), waves = waves.len(), "waves pushed"),
            Err(why) => warn!(
                kind = self.kind(),
                waves = waves.len(),
                error = %why,
                "wave push failed"
            ),
        }
        let at = crate::store::shapes::ts_text(now.timestamp_millis());
        if let Err(e) = store.mark_notified(&shapes, outcome.is_ok(), &at).await {
            warn!(?e, "recording a wave push failed");
        }
    }
}

/// Shape text as a push carries it: no control characters, at most
/// [`SHAPE_MAX`] characters.
fn clean(text: &str) -> String {
    let mut s: String = text.chars().filter(|c| !c.is_control()).collect();
    if s.chars().count() > SHAPE_MAX {
        s = s.chars().take(SHAPE_MAX - 1).collect();
        s.push('…');
    }
    s
}

fn webhook_body(
    node: &str,
    waves: &[Wave],
    window_minutes: i64,
    page: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "exploit_wave",
        "node": node,
        "waves": waves.iter().map(|w| serde_json::json!({
            "shape": clean(&w.text),
            "ips": w.ips,
            "window_minutes": window_minutes,
            "window_start": w.window_start,
            "url": page,
        })).collect::<Vec<_>>(),
    })
}

fn ntfy_body(waves: &[Wave], window_minutes: i64) -> String {
    waves
        .iter()
        .map(|w| format!("{} IPs in {window_minutes} min: {}", w.ips, clean(&w.text)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn error_class(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_redirect() {
        "redirect"
    } else if e.is_builder() {
        "request"
    } else {
        "network"
    }
}

/// One pass: detect, then push when a pusher is set.
pub async fn pass(store: &Store, waves: WavesConfig, pusher: Option<&Pusher>, now: DateTime<Utc>) {
    match store
        .detect_waves(
            now,
            chrono::Duration::minutes(waves.window_minutes),
            waves.min_ips,
        )
        .await
    {
        Ok(w) if !w.is_empty() => info!(waves = w.len(), "exploit waves detected"),
        Ok(_) => {}
        Err(e) => warn!(?e, "detecting exploit waves failed"),
    }
    if let Some(p) = pusher {
        p.push_pending(store, waves.window_minutes, now).await;
    }
}

/// The loop, until shutdown: a pass at start, then every [`WAVE_EVERY`].
/// Without `[notify]` no client is built and nothing connects anywhere.
pub async fn run(
    store: Store,
    waves: WavesConfig,
    notify: Option<NotifyConfig>,
    node_name: String,
    admin_origin: Option<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let pusher = notify.map(|n| Pusher::new(n, node_name, admin_origin.as_deref()));
    loop {
        if *shutdown.borrow() {
            return;
        }
        pass(&store, waves, pusher.as_ref(), Utc::now()).await;
        tokio::select! {
            _ = tokio::time::sleep(WAVE_EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use axum::http::{HeaderMap, StatusCode, header::LOCATION};
    use std::sync::{Arc, Mutex};

    const SHAPE: &str = "/cgi-bin/luci/;stok=/locale-MARKER";

    type Got = Arc<Mutex<Vec<(HeaderMap, String)>>>;

    /// A loopback sink answering every POST to `/<path>` with `status`.
    async fn sink(path: &str, status: StatusCode) -> (String, Got) {
        let got: Got = Arc::default();
        let g = got.clone();
        let app = axum::Router::new().route(
            &format!("/{path}"),
            axum::routing::post(move |h: HeaderMap, body: String| {
                let g = g.clone();
                async move {
                    g.lock().unwrap().push((h, body));
                    (status, [(LOCATION, "http://127.0.0.1:9/elsewhere")])
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/{path}"), got)
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    /// A wave on a shape with this text, waiting to be pushed.
    async fn waiting(s: &Store, hash: i64, text: &str) {
        sqlx::query(
            "INSERT INTO shapes (hash, text, first_seen, last_seen, ips, rule_hits)
             VALUES (?, ?, '2026-10-04 12:30:00', '2026-10-04 12:30:00', 12, 0)",
        )
        .bind(hash)
        .bind(text)
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO waves (shape, detected_at, window_start, ips)
             VALUES (?, '2026-10-04 13:00:00', '2026-10-04 12:00:00', 12)",
        )
        .bind(hash)
        .execute(&s.pool)
        .await
        .unwrap();
    }

    async fn attempts(s: &Store, hash: i64) -> (i64, Option<String>) {
        sqlx::query_as("SELECT notify_attempts, notified_at FROM waves WHERE shape = ?")
            .bind(hash)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    fn pusher(kind: NotifyKind, url: &str, token: Option<&str>) -> Pusher {
        let cfg = NotifyConfig {
            url: Secret::from(url),
            kind,
            token: token.map(Secret::from),
        };
        Pusher::new(cfg, "node-a".into(), Some("https://admin.example/"))
    }

    fn now() -> DateTime<Utc> {
        "2026-10-04T13:05:00Z".parse().unwrap()
    }

    #[tokio::test]
    async fn notify_webhook_gets_the_json_and_the_token() {
        let (s, _dir) = store().await;
        waiting(&s, 1, SHAPE).await;
        let (url, got) = sink("hook", StatusCode::OK).await;
        let p = pusher(NotifyKind::Webhook, &url, Some("tk_1"));
        p.push_pending(&s, 60, now()).await;
        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        let (h, body) = &got[0];
        assert_eq!(h[AUTHORIZATION], "Bearer tk_1");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "kind": "exploit_wave",
                "node": "node-a",
                "waves": [{
                    "shape": SHAPE,
                    "ips": 12,
                    "window_minutes": 60,
                    "window_start": "2026-10-04 12:00:00",
                    "url": "https://admin.example/admin/paths",
                }],
            })
        );
        assert_eq!(
            attempts(&s, 1).await,
            (0, Some("2026-10-04 13:05:00".into()))
        );
        // Pushed waves are not pushed again.
        p.push_pending(&s, 60, now()).await;
        assert_eq!(attempts(&s, 1).await.0, 0);
    }

    #[tokio::test]
    async fn notify_ntfy_gets_text_and_a_fixed_title() {
        let (s, _dir) = store().await;
        let long = format!("/a\u{1b}[31m\r\n{}", "x".repeat(300));
        waiting(&s, 1, SHAPE).await;
        waiting(&s, 2, &long).await;
        let (url, got) = sink("topic", StatusCode::OK).await;
        pusher(NotifyKind::Ntfy, &url, None)
            .push_pending(&s, 60, now())
            .await;
        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "one push for both waves");
        let (h, body) = &got[0];
        assert_eq!(h["title"], "exploit wave on node-a");
        assert_eq!(h["priority"], "4");
        assert_eq!(h["tags"], "rotating_light");
        assert!(h.get(AUTHORIZATION).is_none());
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "{body}");
        assert_eq!(lines[0], format!("12 IPs in 60 min: {SHAPE}"));
        let cut = lines[1].strip_prefix("12 IPs in 60 min: ").unwrap();
        assert_eq!(cut.chars().count(), SHAPE_MAX);
        assert!(!cut.chars().any(char::is_control), "{cut:?}");
        assert!(cut.starts_with("/a[31m") && cut.ends_with('…'));
    }

    #[tokio::test]
    async fn notify_a_redirect_fails_and_three_failures_drop_the_wave() {
        let (s, _dir) = store().await;
        waiting(&s, 1, SHAPE).await;
        let (url, got) = sink("hook", StatusCode::FOUND).await;
        let p = pusher(NotifyKind::Webhook, &url, None);
        p.push_pending(&s, 60, now()).await;
        assert_eq!(attempts(&s, 1).await, (1, None));
        p.push_pending(&s, 60, now()).await;
        p.push_pending(&s, 60, now()).await;
        assert_eq!(attempts(&s, 1).await, (3, None));
        assert!(
            s.waves_to_notify(MAX_ATTEMPTS, PER_PUSH)
                .await
                .unwrap()
                .is_empty()
        );
        p.push_pending(&s, 60, now()).await;
        assert_eq!(
            got.lock().unwrap().len(),
            3,
            "no fourth try, redirect not followed"
        );
    }

    thread_local! {
        static CAPTURED: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
    }

    /// Writes into this thread's capture, if one is running.
    struct Capture;

    impl std::io::Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            CAPTURED.with(|c| c.borrow_mut().as_mut().map(|v| v.extend_from_slice(b)));
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The log lines a push writes, at every level and from every crate.
    /// A global subscriber (not `set_default`): with a scoped one, a test
    /// on another thread registering the same callsite can cache "never"
    /// for it (tracing-core `DefaultCallsite::register`), and the capture
    /// comes back empty. Needs a current-thread runtime.
    async fn logs_of(p: &Pusher, s: &Store) -> String {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let sub = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(|| Capture)
                .finish();
            tracing::subscriber::set_global_default(sub).expect("no other global subscriber");
        });
        CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
        p.push_pending(s, 60, now()).await;
        let out = CAPTURED.with(|c| c.borrow_mut().take()).unwrap_or_default();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn notify_failure_logs_name_no_url_token_or_shape() {
        let (s, _dir) = store().await;
        waiting(&s, 1, SHAPE).await;
        let (url, _got) = sink("secret-topic", StatusCode::INTERNAL_SERVER_ERROR).await;
        let status = logs_of(&pusher(NotifyKind::Ntfy, &url, Some("tk_secret")), &s).await;
        // A refused connection: reqwest's error names the URL.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://{}/secret-topic", closed.local_addr().unwrap());
        drop(closed);
        let refused = logs_of(&pusher(NotifyKind::Webhook, &dead, Some("tk_secret")), &s).await;
        for (logs, why) in [(&status, "status 500"), (&refused, "connect")] {
            assert!(logs.contains("wave push failed"), "{why}: {logs}");
            assert!(logs.contains(why), "{logs}");
            assert!(logs.contains("kind=") && logs.contains("waves=1"), "{logs}");
            for secret in ["secret-topic", "tk_secret", "MARKER", "luci"] {
                assert!(!logs.contains(secret), "{secret} in: {logs}");
            }
        }
    }

    #[tokio::test]
    async fn notify_run_without_a_section_detects_and_connects_nowhere() {
        let (s, _dir) = store().await;
        // Ten IPs on an unknown shape, just now.
        let ts = crate::store::shapes::ts_text(Utc::now().timestamp_millis() - 60_000);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        for i in 0..10 {
            crate::store::data::apply(
                &mut conn,
                crate::store::data::Ctx {
                    origin: None,
                    hlc: 1,
                },
                &crate::cluster::record::Record::Request(Box::new(
                    crate::cluster::record::RequestRec {
                        uid: format!("r{i}"),
                        ts: ts.clone(),
                        ip: format!("198.51.100.{}", i + 1),
                        method: "GET".into(),
                        path: "/new".into(),
                        headers_json: "[]".into(),
                        labels_json: r#"["probe"]"#.into(),
                        ..Default::default()
                    },
                )),
            )
            .await
            .unwrap();
        }
        drop(conn);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run(
            s.clone(),
            WavesConfig::default(),
            None,
            "node-a".into(),
            None,
            rx,
        ));
        let mut waves = 0;
        for _ in 0..100 {
            waves = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM waves")
                .fetch_one(&s.pool)
                .await
                .unwrap();
            if waves > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(waves, 1, "the pass detected the wave");
        tx.send(true).unwrap();
        task.await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "something connected");
    }
}
