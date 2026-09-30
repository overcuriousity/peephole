pub mod nmap_xml;
pub mod pace;

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
    pace: pace::SharedPace,
    nmap_path: PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    notifier: crate::events::Notifier,
) {
    match store.requeue_orphaned_jobs().await {
        Ok(0) => {}
        Ok(n) => info!(jobs = n, "requeued scans interrupted by the last shutdown"),
        Err(e) => warn!(?e, "could not requeue interrupted scans"),
    }
    let mut joinset = tokio::task::JoinSet::new();
    let mut last_start: Option<tokio::time::Instant> = None;
    loop {
        if *shutdown.borrow() {
            break;
        }
        // Reap finished scans: JoinSet::len() counts them until joined.
        while joinset.try_join_next().is_some() {}
        // Re-read every pass so admin changes apply without a restart.
        let p = pace.get();
        while joinset.len() < p.max_workers {
            // Cadence: space starts evenly instead of bursting up to the cap.
            let Some(interval) = p.interval() else { break };
            if last_start.is_some_and(|t| t.elapsed() < interval) {
                break;
            }
            // Global rate cap (spec §5), also across restarts.
            match store.jobs_started_last_hour().await {
                Ok(n) if n >= p.max_scans_per_hour => break,
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
                        let _ = store.finish_job(job.id, None, Some("invalid target")).await;
                        continue;
                    };
                    if let Ok(Some(j)) = store.queue_job(job.id).await {
                        notifier.publish(j);
                    }
                    last_start = Some(tokio::time::Instant::now());
                    let argv = nmap_argv(job.level as u8, &target, &cfg);
                    let store2 = store.clone();
                    let notifier2 = notifier.clone();
                    let nmap = nmap_path.clone();
                    let timeout = Duration::from_secs(p.timeout_secs);
                    joinset.spawn(async move {
                        // kill_on_drop: when the timeout drops this future, nmap
                        // must die with it, not linger behind a freed worker slot.
                        let run = tokio::process::Command::new(nmap)
                            .args(&argv)
                            .kill_on_drop(true)
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

    fn fake_nmap(dir: &std::path::Path) -> PathBuf {
        let fake = dir.join("fake-nmap");
        std::fs::write(&fake, "#!/bin/sh\ncat \"$(dirname \"$0\")/nmap.xml\"\n").unwrap();
        std::fs::copy("tests/fixtures/nmap-basic.xml", dir.join("nmap.xml")).unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();
        fake
    }

    async fn wait_for_scans(store: &Store, n: i64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let done: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
                .fetch_one(&store.pool)
                .await
                .unwrap();
            if done >= n {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {done} of {n} scans finished"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Regression: finished tasks were never reaped from the JoinSet, so the
    /// pool stalled for good after `max_workers` scans.
    #[tokio::test]
    async fn worker_keeps_draining_after_first_batch() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(dir.path());
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let jobs = cfg.scan.max_workers as i64 * 2 + 1;
        for i in 0..jobs {
            let ip = store
                .upsert_ip(format!("198.51.100.{}", 30 + i).parse().unwrap())
                .await
                .unwrap();
            store.enqueue_scan(ip.id, 2, 24).await.unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: cfg.scan.max_workers,
            max_scans_per_hour: 3600,
            timeout_secs: 60,
        });
        let pool = tokio::spawn(run_workers(
            store.clone(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
        ));
        wait_for_scans(&store, jobs).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
    }

    /// Regression: on timeout the output future was dropped but the nmap
    /// child kept running, so orphans piled up behind freed worker slots.
    #[tokio::test]
    async fn timed_out_nmap_is_killed_and_job_fails() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let fake = dir.path().join("slow-nmap");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
                pidfile.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&fake).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake, perms).unwrap();

        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("198.51.100.99".parse().unwrap())
            .await
            .unwrap();
        store.enqueue_scan(ip.id, 1, 24).await.unwrap();
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: 1,
            max_scans_per_hour: 3600,
            timeout_secs: 1,
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        let pool = tokio::spawn(run_workers(
            store.clone(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
        ));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let err = loop {
            let e: Option<String> =
                sqlx::query_scalar("SELECT error FROM scan_jobs WHERE status = 'failed'")
                    .fetch_optional(&store.pool)
                    .await
                    .unwrap()
                    .flatten();
            if let Some(e) = e {
                break e;
            }
            assert!(std::time::Instant::now() < deadline, "job never timed out");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        assert!(err.contains("timeout"), "{err}");
        tx.send(true).unwrap();
        pool.await.unwrap();
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));
        for _ in 0..20 {
            // A killed child may linger as a zombie until reaped; check state.
            let alive = std::fs::read_to_string(proc.join("stat"))
                .map(|s| s.split_whitespace().nth(2).is_none_or(|st| st != "Z"))
                .unwrap_or(false);
            if !alive {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("nmap child {} still running after timeout", pid.trim());
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
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let pool = tokio::spawn(run_workers(
            store.clone(),
            cfg,
            p,
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
