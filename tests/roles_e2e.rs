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
