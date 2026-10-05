//! System: this node's intel feeds, settings, admin keys and export.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::store::stats::intel_stale;
use askama::Template;
use axum::{Router, extract::State, response::Html, routing::get};
use std::collections::HashMap;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin/system", get(status))
}

fn chrome() -> Chrome {
    Chrome::new(true, "admin")
}

/// The intel feeds as this node sees them.
pub struct IntelStatus {
    pub tor_fetch: String,
    pub maxmind_fetch: String,
    /// Tor or GeoIP data missing or older than 48 h.
    pub stale: bool,
    /// `(label, state)` per API provider.
    pub api: Vec<(&'static str, String)>,
}

pub(crate) async fn intel_status(st: &AdminState) -> AppResult<IntelStatus> {
    let intel: HashMap<String, String> =
        sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
            .fetch_all(&st.store.pool)
            .await?
            .into_iter()
            .collect();
    let fetched = |k: &str| intel.get(k).cloned().unwrap_or_else(|| "never".into());
    Ok(IntelStatus {
        stale: intel_stale(&intel),
        tor_fetch: fetched("tor_last_fetch"),
        maxmind_fetch: match (
            intel.get("maxmind_last_fetch"),
            intel.get(crate::intel::MAXMIND_CLUSTER_SEEN),
        ) {
            (None, Some(seen)) => format!("via a cluster member (seen {seen})"),
            _ => fetched("maxmind_last_fetch"),
        },
        api: api_provider_states(st).await?,
    })
}

/// Each API provider's state as this node sees it: its own budget and
/// pause, or whether a cluster member serves it; and how many lookups the
/// dataset holds.
async fn api_provider_states(st: &AdminState) -> anyhow::Result<Vec<(&'static str, String)>> {
    let counts: HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT provider, COUNT(*) FROM ip_intel_log GROUP BY provider",
    )
    .fetch_all(&st.store.read)
    .await?
    .into_iter()
    .collect();
    let served_elsewhere = |name: &str| {
        st.recorder.node().is_some_and(|node| {
            let me = node.id();
            node.live_members(std::time::Duration::from_secs(45))
                .into_iter()
                .any(|id| {
                    id != me
                        && node
                            .status
                            .known(&id)
                            .is_some_and(|k| k.hb.providers.iter().any(|n| n == name))
                })
        })
    };
    Ok(crate::intel::KNOWN_PROVIDERS
        .iter()
        .filter(|p| p.api)
        .map(|p| {
            let here = st.providers.iter().find(|x| x.name() == p.name);
            let mut state = match here {
                Some(x) => {
                    let s = x.status().unwrap_or_default();
                    if x.ready() {
                        format!("active · {s}")
                    } else {
                        format!("waiting · {s}")
                    }
                }
                None if served_elsewhere(p.name) => "via a cluster member".to_string(),
                None => "not configured".to_string(),
            };
            if let Some(n) = counts.get(p.name) {
                state.push_str(&format!(" · {n} lookups recorded"));
            }
            (p.label, state)
        })
        .collect())
}

#[derive(Template)]
#[template(path = "admin_system.html")]
struct StatusPage {
    chrome: Chrome,
    intel: IntelStatus,
    /// Shared intel files; None on a standalone node.
    shared: Option<Vec<crate::admin::cluster::IntelView>>,
    rules: &'static str,
    rules_short: String,
}

async fn status(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let shared = match st.recorder.node() {
        Some(node) => Some(crate::admin::cluster::intel(node).await?),
        None => None,
    };
    let rules = crate::admin::cluster::builtin_rules();
    render(&StatusPage {
        chrome: chrome(),
        intel: intel_status(&st).await?,
        shared,
        rules,
        rules_short: rules
            .chars()
            .take(crate::admin::cluster::SHORT_HASH)
            .collect(),
    })
}
