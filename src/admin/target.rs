//! Everything the dataset holds on one address. The IP page and the
//! lookup result both render this, from `templates/_target.html`: an
//! aggregation added here appears in both.
use crate::admin::AdminState;
use crate::admin::error::AppResult;
use crate::admin::public::{IntelCard, IpAdminData, ScanWithPorts, intel_cards};
use crate::store::browse::{Audience, IpOverview, Page, RequestListRow};
use crate::store::requests::IpRow;
use std::sync::Arc;

/// One address as the dataset knows it.
pub struct Target {
    pub ov: Arc<IpOverview>,
    /// `ov.week` and `ov.calendar` for the charts.
    pub week_json: String,
    pub calendar_json: String,
    /// Largest family count, for the bar widths.
    pub family_max: i64,
    pub page: Page<RequestListRow>,
    pub intel: Vec<IntelCard>,
    /// Admin-only sections; loaded only with a session.
    pub admin: Option<IpAdminData>,
    pub labels: bool,
    /// The requests list links to further pages (the IP page; the lookup
    /// result links to the IP page instead).
    pub paged: bool,
    /// Days of history this node keeps; 0: all of it.
    pub window_days: u32,
    /// The Actions card (admin only).
    pub actions: Option<crate::admin::probes::ActionsView>,
    /// Probe requests and results, newest first (admin only).
    pub probes: Vec<crate::admin::probes::GroupView>,
}

impl Target {
    /// `[group, node, state]` of every probe, for the live stream.
    pub fn probe_states(&self) -> String {
        crate::admin::probes::states_json(&self.probes)
    }

    /// A probe still waits for its result.
    pub fn probes_waiting(&self) -> bool {
        crate::admin::probes::any_waiting(&self.probes)
    }
}

/// Load `ip`'s view. None: the address is in the table but has no
/// overview (nothing recorded about it).
pub async fn load(
    state: &AdminState,
    ip: &IpRow,
    authed: bool,
    page: u32,
    paged: bool,
) -> AppResult<Option<Target>> {
    // Anonymous views go through the cache; an admin always reads fresh.
    let ov = if authed {
        state.store.ip_overview(ip.id).await?.map(Arc::new)
    } else {
        state.stats_cache.ip(&state.store, ip.id).await?
    };
    let Some(ov) = ov else {
        return Ok(None);
    };
    // Per-request rows are admin-only: not even queried for the public.
    let requests = if authed {
        state
            .store
            .requests_for_ip(ip.id, page, Audience::Admin)
            .await?
    } else {
        Page {
            items: vec![],
            page: 1,
            has_next: false,
        }
    };
    let admin = if authed {
        let found = state.store.scans_for_ip(ip.id).await?;
        let ids: Vec<i64> = found.iter().map(|s| s.id).collect();
        let mut ports = state.store.ports_for_scans(&ids).await?;
        let scans = found
            .into_iter()
            .map(|s| ScanWithPorts {
                ports: ports.remove(&s.id).unwrap_or_default(),
                s,
            })
            .collect();
        Some(IpAdminData {
            jobs: state.store.jobs_for_ip(ip.id, 20).await?,
            scans,
            fingerprints: state.store.fingerprints_for_ip(ip.id).await?,
            claims: state.store.claims_for_ip(ip.id).await?,
            skipped: state.store.skipped_for_ip(ip.id).await?,
            host_keys: state.store.host_keys_for_ip(ip.id).await?,
            canary_links: state.store.canary_links_for_ip(ip.id).await?,
            decoys: state.store.decoy_counts_for_ip(ip.id).await?,
        })
    } else {
        None
    };
    let (actions, probes) = match (authed, ip.ip.parse::<std::net::IpAddr>()) {
        (true, Ok(addr)) => (
            Some(crate::admin::probes::actions_for(state, &addr).await),
            crate::admin::probes::groups_for(state, ip.id).await,
        ),
        _ => (None, vec![]),
    };
    Ok(Some(Target {
        actions,
        probes,
        week_json: serde_json::to_string(&ov.week).unwrap_or_else(|_| "[]".into()),
        calendar_json: serde_json::to_string(&ov.calendar).unwrap_or_else(|_| "[]".into()),
        family_max: ov.families.iter().map(|f| f.count).max().unwrap_or(0),
        intel: intel_cards(state.store.intel_for_ip(&ip.ip).await?, authed),
        page: requests,
        admin,
        labels: crate::admin::public::labels_shown(state, authed),
        paged,
        window_days: state.recorder.node().map_or(0, |n| n.retention_days),
        ov,
    }))
}

/// What is near an address the dataset does not hold: the recorded
/// addresses in its network, and in its ASN once an answer names one.
pub struct Neighbourhood {
    pub net: String,
    pub rows: Vec<crate::store::browse::IpSummary>,
    pub asn: Option<i64>,
    /// Recorded addresses in that ASN, and the first of them.
    pub asn_count: i64,
    pub asn_rows: Vec<crate::store::browse::IpSummary>,
}

/// Addresses shown per part of the neighbourhood.
const NEAR_ROWS: usize = 20;

pub async fn neighbourhood(
    state: &AdminState,
    ip: std::net::IpAddr,
    asn: Option<i64>,
) -> AppResult<Neighbourhood> {
    let prefix = if ip.is_ipv4() { 24 } else { 48 };
    let net = ipnet::IpNet::new(ip, prefix)
        .map(|n| n.trunc())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = state
        .store
        .ips_matching(&[], &[net], NEAR_ROWS as i64)
        .await?;
    let (asn_count, asn_rows) = match asn {
        Some(a) => {
            let f = crate::store::browse::IpFilter {
                asn: Some(a),
                ..Default::default()
            };
            let mut page = state.store.list_ips(&f).await?.items;
            page.truncate(NEAR_ROWS);
            (state.store.count_ips(&f).await?, page)
        }
        None => (0, vec![]),
    };
    Ok(Neighbourhood {
        net: net.to_string(),
        rows,
        asn,
        asn_count,
        asn_rows,
    })
}

/// The ASN an answer names: MaxMind's number, or Shodan's "AS64500".
pub fn asn_named<'a>(data: impl IntoIterator<Item = &'a serde_json::Value>) -> Option<i64> {
    data.into_iter()
        .find_map(|d| match &d["asn"] {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s
                .trim()
                .trim_start_matches(['A', 'a'])
                .trim_start_matches(['S', 's'])
                .parse()
                .ok(),
            _ => None,
        })
        .filter(|a| *a > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_asn_is_read_from_either_provider() {
        assert_eq!(
            asn_named([&json!({"country": "DE", "asn": 3320})]),
            Some(3320)
        );
        assert_eq!(asn_named([&json!({"asn": "AS64500"})]), Some(64500));
        assert_eq!(
            asn_named([&json!({}), &json!({"asn": "as15169"})]),
            Some(15169)
        );
        assert_eq!(asn_named([&json!({"asn": "unknown"}), &json!({})]), None);
        assert_eq!(asn_named([&json!({"asn": 0})]), None);
    }
}
