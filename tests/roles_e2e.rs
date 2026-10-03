//! A real `peephole::run` whose trap role is switched off and on again
//! while it runs, by writing settings the way the CLI does.
use peephole::settings::{Changes, KEY_ROLE_LISTENER, Prereqs, Settings};
use peephole::store::Store;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn trap_answers(port: u16) -> bool {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/x"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .is_ok()
}

async fn eventually(what: &str, port: u16, want: bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while trap_answers(port).await != want {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn trap_role_switches_off_and_on_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (trap, admin) = (free_port(), free_port());
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{d}/p.db"
data_dir = "{d}"
rules_dir = "rules"
[roles]
scanner = false
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
    let cfg = peephole::config::Config::load(&cfg_path).unwrap();
    let node = tokio::spawn(peephole::run(cfg_path));
    eventually("trap up", trap, true).await;

    // What `peephole settings set roles.listener false` does.
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let cli = Settings::load(&store, &cfg, Prereqs::from_config(&cfg, false))
        .await
        .unwrap();
    cli.apply(
        &Changes {
            listener: Some(false),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .unwrap();
    eventually("trap down", trap, false).await;
    // The web role is untouched.
    let health = reqwest::get(format!("http://127.0.0.1:{admin}/healthz"))
        .await
        .unwrap();
    assert!(health.status().is_success());

    // `peephole settings reset roles.listener`: back to the config file.
    cli.reset(Some(KEY_ROLE_LISTENER)).await.unwrap().unwrap();
    eventually("trap up again", trap, true).await;
    node.abort();
}

/// A live queue page left open does not hold up switching the web role off,
/// nor any change after it.
#[tokio::test]
async fn an_open_queue_stream_does_not_block_role_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (trap, admin) = (free_port(), free_port());
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{d}/p.db"
data_dir = "{d}"
rules_dir = "rules"
[roles]
scanner = false
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
    let cfg = peephole::config::Config::load(&cfg_path).unwrap();
    let node = tokio::spawn(peephole::run(cfg_path));
    eventually("trap up", trap, true).await;
    // The admin listener binds after the trap's.
    eventually("admin up", admin, true).await;

    // An admin with the queue page open.
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let session = store.create_session().await.unwrap();
    let mut stream = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{admin}/admin/api/queue"))
        .header("cookie", format!("peephole_session={session}"))
        .send()
        .await
        .unwrap();
    assert!(stream.status().is_success());
    assert!(stream.chunk().await.unwrap().is_some(), "snapshot");

    let cli = Settings::load(&store, &cfg, Prereqs::from_config(&cfg, false))
        .await
        .unwrap();
    let set = |c: Changes| {
        let cli = cli.clone();
        async move { cli.apply(&c, None).await.unwrap().unwrap() }
    };
    set(Changes {
        web: Some(false),
        ..Default::default()
    })
    .await;
    // The stream ends instead of keeping the web role alive.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(_)) = stream.chunk().await {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the queue stream ends when the web role stops"
    );
    // The supervisor is free for the next change.
    set(Changes {
        listener: Some(false),
        web: Some(true),
        ..Default::default()
    })
    .await;
    eventually("trap down while the stream was open", trap, false).await;
    node.abort();
}
