//! Reverse DNS of every source: the PTR names of each address that sent
//! requests, kept when they resolve back to it (forward-confirmed), looked
//! up when the source is first seen and again when it returns a day after
//! the last lookup. Each node looks up on its own and keeps the names
//! locally (`ip_names`, source `rdns`); a source's own DNS often names its
//! hoster or a research scanner.
use crate::scan::crawler::{Forward, confirmed_names, system_forward, system_resolver};
use crate::store::Store;
use futures::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Sources looked up per pass.
const BATCH: i64 = 50;
/// Lookups at a time.
const PARALLEL: usize = 4;
/// Between passes.
const EVERY: Duration = Duration::from_secs(60);
/// After a full batch: more are likely due (the backlog after an upgrade).
const AGAIN: Duration = Duration::from_secs(1);

/// Look up the sources that are due, `BATCH` at a time, until shutdown.
/// Off when `enabled` is false or no resolver is configured.
pub async fn run(store: Store, enabled: bool, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    if !enabled {
        return;
    }
    let Some(resolver) = system_resolver() else {
        tracing::info!("reverse DNS: no nameserver in /etc/resolv.conf, off");
        return;
    };
    let forward = system_forward();
    loop {
        let wait = match pass(&store, resolver, &forward).await {
            Ok(n) if n as i64 == BATCH => AGAIN,
            Ok(0) => EVERY,
            Ok(n) => {
                tracing::debug!(sources = n, "reverse DNS: looked up");
                EVERY
            }
            Err(e) => {
                tracing::warn!(error = %e, "reverse DNS: pass failed");
                EVERY
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            r = shutdown.changed() => if r.is_err() { return },
        }
        if *shutdown.borrow() {
            return;
        }
    }
}

/// One batch: every due source is marked looked up, whatever the
/// resolver answered (a broken resolver costs one try a day per source).
/// Returns how many sources were handled.
pub(crate) async fn pass(
    store: &Store,
    resolver: SocketAddr,
    forward: &Forward,
) -> anyhow::Result<usize> {
    let due = store.rdns_due(BATCH).await?;
    let n = due.len();
    let found: Vec<(i64, Vec<String>)> = futures::stream::iter(due)
        .map(|(id, ip)| async move {
            let names = match ip.parse::<IpAddr>() {
                Ok(addr) if crate::net::is_scannable_target(addr) => {
                    confirmed_names(resolver, forward, addr)
                        .await
                        .unwrap_or_else(|e| {
                            tracing::debug!(%ip, error = %e, "reverse DNS failed");
                            vec![]
                        })
                }
                _ => vec![],
            };
            (id, names)
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    // One source's failure does not lose the rest of the batch.
    for (id, names) in found {
        if let Err(e) = store.record_rdns(id, &names).await {
            tracing::warn!(ip_id = id, error = %e, "reverse DNS: not stored");
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::crawler::testing::fake_resolver;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn a_pass_stores_confirmed_names_and_marks_every_source() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut ids = vec![];
        for ip in ["198.51.100.7", "198.51.100.8"] {
            let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
            ids.push(row.id);
        }
        let resolver = fake_resolver(Arc::new(Mutex::new(Some("host-7.example.net".into())))).await;
        let forward: Forward = Arc::new(|name: String| {
            Box::pin(async move {
                if name.trim_end_matches('.') == "host-7.example.net" {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        });
        assert_eq!(pass(&s, resolver, &forward).await.unwrap(), 2);
        let n7 = s.names_for_ip(ids[0]).await.unwrap();
        assert_eq!(n7.len(), 1);
        assert_eq!(n7[0].source, "rdns");
        assert!(
            s.names_for_ip(ids[1]).await.unwrap().is_empty(),
            "the name points elsewhere"
        );
        assert_eq!(
            pass(&s, resolver, &forward).await.unwrap(),
            0,
            "both marked"
        );
    }
}
