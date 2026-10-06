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
    Ok(Some(Target {
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
/// addresses in its network.
pub struct Neighbourhood {
    pub net: String,
    pub rows: Vec<crate::store::browse::IpSummary>,
}

pub async fn neighbourhood(state: &AdminState, ip: std::net::IpAddr) -> AppResult<Neighbourhood> {
    let prefix = if ip.is_ipv4() { 24 } else { 48 };
    let net = ipnet::IpNet::new(ip, prefix)
        .map(|n| n.trunc())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = state.store.ips_matching(&[], &[net], 20).await?;
    Ok(Neighbourhood {
        net: net.to_string(),
        rows,
    })
}
