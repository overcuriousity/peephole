pub mod nmap_xml;

use crate::config::Config;
use crate::store::Store;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

/// nmap argv (after the binary name) for a level and target (spec §5).
pub fn nmap_argv(level: u8, target: &IpAddr, cfg: &Config) -> Vec<String> {
    let mut argv = cfg.default_level_argv(level);
    argv.push("-oX".into());
    argv.push("-".into());
    argv.push(target.to_string());
    argv
}

pub async fn run_workers(
    store: Store,
    cfg: Config,
    nmap_path: PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    notifier: crate::events::Notifier,
) {
    let mut joinset = tokio::task::JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        while joinset.len() < cfg.scan.max_workers {
            // Global rate cap (spec §5): don't start new scans past the hourly cap.
            match store.recent_scans_last_hour().await {
                Ok(n) if n >= cfg.scan.max_scans_per_hour => break,
                Err(e) => {
                    warn!(?e, "rate cap check failed");
                    break;
                }
                _ => {}
            }
            match store.next_queued_job().await {
                Ok(Some(job)) => {
                    let ip: String = sqlx::query_scalar("SELECT ip FROM ips WHERE id=?")
                        .bind(job.ip_id)
                        .fetch_one(&store.pool)
                        .await
                        .unwrap_or_default();
                    let Ok(target) = ip.parse::<IpAddr>() else {
                        continue;
                    };
                    if let Ok(Some(j)) = store.queue_job(job.id).await {
                        notifier.publish(j);
                    }
                    let argv = nmap_argv(job.level as u8, &target, &cfg);
                    let store2 = store.clone();
                    let notifier2 = notifier.clone();
                    let nmap = nmap_path.clone();
                    let timeout = Duration::from_secs(cfg.scan.timeout_secs);
                    joinset.spawn(async move {
                        let run = tokio::process::Command::new(nmap)
                            .args(&argv)
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::null())
                            .output();
                        match tokio::time::timeout(timeout, run).await {
                            Ok(Ok(out)) if out.status.success() => {
                                match nmap_xml::parse_nmap_xml(&out.stdout) {
                                    Ok(res) => {
                                        if let Err(e) =
                                            store2.finish_job(job.id, Some(&res), None).await
                                        {
                                            warn!(
                                                job = job.id,
                                                ?e,
                                                "could not record scan result (job deleted?)"
                                            );
                                        }
                                        info!(target = %target, level = job.level, "scan done");
                                    }
                                    Err(e) => {
                                        if let Err(e2) = store2
                                            .finish_job(job.id, None, Some(&e.to_string()))
                                            .await
                                        {
                                            warn!(
                                                job = job.id,
                                                ?e2,
                                                "could not record scan failure"
                                            );
                                        }
                                    }
                                }
                            }
                            Ok(Ok(out)) => {
                                if let Err(e) = store2
                                    .finish_job(
                                        job.id,
                                        None,
                                        Some(&format!("exit {:?}", out.status.code())),
                                    )
                                    .await
                                {
                                    warn!(job = job.id, ?e, "could not record scan failure");
                                }
                            }
                            Ok(Err(e)) => {
                                if let Err(e2) =
                                    store2.finish_job(job.id, None, Some(&e.to_string())).await
                                {
                                    warn!(job = job.id, ?e2, "could not record scan failure");
                                }
                            }
                            Err(_) => {
                                if let Err(e) =
                                    store2.finish_job(job.id, None, Some("timeout")).await
                                {
                                    warn!(job = job.id, ?e, "could not record scan timeout");
                                }
                            }
                        }
                        if let Ok(Some(j)) = store2.queue_job(job.id).await {
                            notifier2.publish(j);
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(?e, "queue poll failed");
                    break;
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = shutdown.changed() => {}
        }
    }
    while joinset.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::Store;
    use std::io::Write;
    use std::net::IpAddr;

    fn test_config(dir: &std::path::Path) -> Config {
        let toml = format!(
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "{db}"
data_dir = "{dir}"
rules_dir = "rules"
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
[maxmind]
account_id = "1"
license_key = "k"
"#,
            db = dir.join("t.db").display(),
            dir = dir.display()
        );
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        Config::load(&path).unwrap()
    }

    #[test]
    fn argv_contains_target_last_and_xml_flag() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let argv = nmap_argv(2, &ip, &cfg);
        assert_eq!(argv.last().unwrap(), "203.0.113.9");
        assert!(argv.windows(2).any(|w| w == ["-oX", "-"]));
        assert!(argv.contains(&"-sV".to_string()));
    }

    #[tokio::test]
    async fn cooldown_suppresses_rescan_but_allows_upgrade_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.1".parse().unwrap())
            .await
            .unwrap();
        // Pretend a level-1 scan finished just now.
        let job = match store.enqueue_scan(ip.id, 1, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(id) => id,
            other => panic!("expected queued, got {other:?}"),
        };
        store.finish_job(job, None, None).await.unwrap();
        // Same level within cooldown → suppressed.
        assert!(matches!(
            store.enqueue_scan(ip.id, 1, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Cooldown
        ));
        // Higher level → one upgrade allowed.
        assert!(matches!(
            store.enqueue_scan(ip.id, 3, 24).await.unwrap(),
            crate::store::scans::EnqueueOutcome::Queued(_)
        ));
    }

    #[tokio::test]
    async fn finish_job_on_deleted_ip_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        let job = match s.enqueue_scan(ip.id, 1, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        assert!(s.delete_ip(ip.id).await.unwrap());
        assert!(s.finish_job(job, None, Some("timeout")).await.is_err());
        assert!(s.queue_job(job).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn worker_runs_fake_nmap_and_stores_ports() {
        let dir = tempfile::tempdir().unwrap();
        // Fake nmap: copies the fixture to stdout, ignores argv.
        let fake = dir.path().join("fake-nmap");
        std::fs::write(&fake, "#!/bin/sh\ncat \"$(dirname \"$0\")/nmap.xml\"\n").unwrap();
        std::fs::copy("tests/fixtures/nmap-basic.xml", dir.path().join("nmap.xml")).unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();

        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.23".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(ip.id, 2, 24).await.unwrap();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let pool = tokio::spawn(run_workers(
            store.clone(),
            cfg,
            fake.clone(),
            rx,
            crate::events::Notifier::new(),
        ));
        // Wait until the job is done (poll DB, max 5s).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
                .fetch_one(&store.pool)
                .await
                .unwrap();
            if done == 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "worker did not finish"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tx.send(true).unwrap();
        pool.await.unwrap();
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(ports, 3);
        let mut f = std::fs::File::create("/dev/null").unwrap();
        f.write_all(b"").unwrap(); // keeps Write import used
    }
}
