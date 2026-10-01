//! Enrichment providers. A provider is something a node may or may not be
//! able to query: it needs a local database or an API key, and those stay on
//! the node. What a provider finds out about an IP is shared with the
//! cluster as an `ip_intel` record.
use super::SharedGeo;
use futures::future::BoxFuture;

/// What a provider says about one IP.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub ip: String,
    /// Version of the data the answer came from, if the provider has one.
    pub source_version: Option<String>,
    /// Provider-specific fields; an empty object when it knows nothing.
    pub data: serde_json::Value,
}

pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether this node can answer right now (database loaded, key set,
    /// quota left).
    fn ready(&self) -> bool;
    /// One finding per IP that was asked, also when nothing is known, so
    /// the IP is not asked again.
    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>>;
}

/// Seconds after an IP was first seen before the node at `rank` among the
/// able nodes looks it up: rank 0 at once, the others only if it is still
/// missing ten minutes per rank later.
pub fn step_in_secs(rank: usize) -> i64 {
    rank as i64 * 600
}

/// MaxMind GeoLite2: country and ASN from the node's own databases.
pub struct MaxMind(pub SharedGeo);

impl Provider for MaxMind {
    fn name(&self) -> &'static str {
        super::MAXMIND
    }

    fn ready(&self) -> bool {
        self.0.read().unwrap().is_some()
    }

    fn lookup<'a>(&'a self, ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
        Box::pin(async move {
            let guard = self.0.read().unwrap();
            let Some(g) = guard.as_ref() else {
                return vec![];
            };
            let version = g.build_date();
            ips.iter()
                .filter_map(|ip| {
                    let addr = ip.parse().ok()?;
                    let hit = g.lookup(&addr);
                    Some(Finding {
                        ip: ip.clone(),
                        source_version: version.clone(),
                        data: crate::store::recorder::Recorder::geo_data(
                            hit.country.as_deref(),
                            hit.asn,
                            hit.asn_org.as_deref(),
                        ),
                    })
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_ranks_step_in_ten_minutes_apart() {
        assert_eq!(step_in_secs(0), 0);
        assert_eq!(step_in_secs(1), 600);
        assert_eq!(step_in_secs(3), 1800);
    }

    #[tokio::test]
    async fn maxmind_answers_for_every_ip_asked_once_its_database_is_loaded() {
        let shared: SharedGeo = Default::default();
        let p = MaxMind(shared.clone());
        assert_eq!(p.name(), crate::intel::MAXMIND);
        assert!(!p.ready());
        assert!(p.lookup(&["2.125.160.216".into()]).await.is_empty());
        let dir = tempfile::tempdir().unwrap();
        for f in ["GeoLite2-City", "GeoLite2-ASN"] {
            std::fs::copy(
                format!("tests/fixtures/{f}-Test.mmdb"),
                dir.path().join(format!("{f}.mmdb")),
            )
            .unwrap();
        }
        *shared.write().unwrap() = Some(crate::intel::geo::GeoIp::load(dir.path()).unwrap());
        assert!(p.ready());
        let found = p
            .lookup(&["2.125.160.216".into(), "203.0.113.1".into(), "junk".into()])
            .await;
        assert_eq!(found.len(), 2, "one finding per valid IP, known or not");
        assert_eq!(found[0].data["country"], "GB");
        assert!(found[0].source_version.is_some());
        assert_eq!(found[1].data, serde_json::json!({}));
    }
}
