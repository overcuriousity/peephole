//! Overview: what needs a look, headline numbers, live recent activity.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::store::browse::Audience;
use crate::store::stats::Range;
use askama::Template;
use axum::{Router, extract::State, response::Html, routing::get};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new().route("/admin", get(home))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Warn,
}

/// One "needs attention" item: what, and where to deal with it.
#[derive(Debug, Clone)]
pub struct Attention {
    pub level: Level,
    pub text: String,
    pub href: String,
}

/// A cluster member as the strip needs it (active, not blocked, not us).
#[derive(Debug, Clone, Default)]
pub struct NodeState {
    pub name: String,
    pub key: String,
    pub live: bool,
    pub last_seen: String,
    pub issues: Vec<String>,
}

/// Everything the strip looks at, gathered on page load.
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub failed_24h: i64,
    /// Net queue growth per hour, when growing ("+4.0").
    pub growing: Option<String>,
    /// Share of scans hitting the timeout, when above the recommendation.
    pub timeouts: Option<String>,
    pub intel_stale: bool,
    pub nodes: Vec<NodeState>,
    /// Why this node is out of its cluster, in a sentence.
    pub detached: Option<&'static str>,
    /// Members whose older history no reachable peer can give.
    pub unserved: Option<String>,
}

/// The items to show, in a fixed order; empty when all is well.
pub fn attention(s: &Signals) -> Vec<Attention> {
    let warn = |text: String, href: &str| Attention {
        level: Level::Warn,
        text,
        href: href.to_string(),
    };
    let mut v = vec![];
    if let Some(d) = s.detached {
        v.push(warn(d.to_string(), "/admin/cluster"));
    }
    if let Some(u) = &s.unserved {
        v.push(warn(
            format!("History incomplete for {u}: waiting for a full member."),
            "/admin/cluster",
        ));
    }
    // Out of the cluster, every member looks offline: nothing to act on.
    let nodes = if s.detached.is_some() {
        &[][..]
    } else {
        &s.nodes[..]
    };
    for n in nodes {
        let href = format!("/admin/cluster/node/{}", n.key);
        if !n.live {
            let text = if n.last_seen == "never" {
                format!("{} has never been seen.", n.name)
            } else {
                format!(
                    "{} not seen for {}.",
                    n.name,
                    n.last_seen.trim_end_matches(" ago")
                )
            };
            v.push(warn(text, &href));
        }
        if !n.issues.is_empty() {
            v.push(warn(format!("{}: {}", n.name, n.issues.join(" · ")), &href));
        }
    }
    if s.failed_24h > 0 {
        v.push(warn(
            format!(
                "{} scan{} failed in 24 h",
                s.failed_24h,
                if s.failed_24h == 1 { "" } else { "s" }
            ),
            "/admin/scans?status=failed#history",
        ));
    }
    if let Some(n) = &s.growing {
        v.push(warn(
            format!("The scan queue grows by {n} jobs per hour."),
            "/admin/scans#pace",
        ));
    }
    if let Some(t) = &s.timeouts {
        v.push(warn(
            format!("{t} of scans hit the timeout."),
            "/admin/scans#pace",
        ));
    }
    if s.intel_stale {
        v.push(warn(
            "Tor exit list or GeoIP data missing or older than 48 h.".into(),
            "/admin/system",
        ));
    }
    v
}

async fn signals(st: &AdminState) -> AppResult<Signals> {
    let pace = crate::admin::scans::pace_view(st, None, None).await?;
    let mut s = Signals {
        failed_24h: pace.m.failed_24h,
        growing: pace.growing.then(|| pace.net.clone()),
        timeouts: pace.timeouts_high.then(|| pace.timeout_share.clone()),
        intel_stale: crate::admin::system::intel_status(st).await?.stale,
        ..Default::default()
    };
    if let Some(node) = st.recorder.node() {
        let check = crate::admin::cluster::rules_check(st, node).await?;
        let (_, members) = crate::admin::cluster::views(node, &check).await?;
        s.nodes = members
            .into_iter()
            .filter(|m| m.active && !m.blocked)
            .map(|m| NodeState {
                issues: m.issues(),
                name: m.name,
                key: m.key,
                live: m.live,
                last_seen: m.last_seen,
            })
            .collect();
        s.detached = node.detached().map(|d| d.label());
        s.unserved = crate::admin::cluster::unserved(node).await?;
    }
    Ok(s)
}

#[derive(Template)]
#[template(path = "admin_home.html")]
struct HomePage {
    chrome: Chrome,
    attention: Vec<Attention>,
    requests_24h: i64,
    new_ips_24h: i64,
    queued: i64,
    running: i64,
    done_24h: i64,
    inbox: i64,
    /// "Recent activity": the newest requests, then live over SSE.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// The newest request id shown (the live feed's cursor).
    recent_max_id: i64,
}

async fn home(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let stats = st.stats_cache.admin_stats(&st.store, Range::H24).await?;
    let q = st.store.queue_summary(&st.recorder).await?;
    let recent = st.store.recent_requests(50, Audience::Admin).await?;
    // Nothing in the last 24 h: follow from the newest row overall, so the
    // live feed does not backfill the table with old requests.
    let recent_max_id = match recent.iter().map(|r| r.id).max() {
        Some(id) => id,
        None => st.store.max_request_id().await?,
    };
    render(&HomePage {
        chrome: Chrome::new(true, "admin"),
        attention: attention(&signals(&st).await?),
        requests_24h: stats.total_requests,
        new_ips_24h: stats.new_ips,
        queued: q.queued,
        running: q.running,
        done_24h: q.done_24h,
        inbox: st.store.inbox_count().await?,
        recent,
        recent_max_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeState {
        NodeState {
            name: name.into(),
            key: format!("{name}-key"),
            live: true,
            last_seen: "3 s ago".into(),
            issues: vec![],
        }
    }

    #[test]
    fn nothing_to_say_when_all_is_well() {
        let s = Signals {
            nodes: vec![node("a")],
            ..Default::default()
        };
        assert!(attention(&s).is_empty());
    }

    #[test]
    fn each_signal_gives_one_item_with_its_link() {
        let mut down = node("b");
        down.live = false;
        down.last_seen = "2.0 h ago".into();
        let mut odd = node("c");
        odd.issues = vec!["clock +3.5 min".into(), "incompatible version".into()];
        let s = Signals {
            failed_24h: 3,
            growing: Some("+4.0".into()),
            timeouts: Some("25%".into()),
            intel_stale: true,
            nodes: vec![down, odd],
            detached: None,
            unserved: Some("writer".into()),
        };
        let items = attention(&s);
        let find = |href: &str, text: &str| {
            assert!(
                items
                    .iter()
                    .any(|a| a.href == href && a.text.contains(text)),
                "{href} {text}: {items:?}"
            )
        };
        find("/admin/scans?status=failed#history", "3 scans failed");
        find("/admin/scans#pace", "+4.0");
        find("/admin/scans#pace", "25%");
        find("/admin/system", "older than 48 h");
        find("/admin/cluster/node/b-key", "not seen for 2.0 h");
        find(
            "/admin/cluster/node/c-key",
            "clock +3.5 min · incompatible version",
        );
        find("/admin/cluster", "writer");
        assert_eq!(items.len(), 7);
        assert!(items.iter().all(|a| a.level == Level::Warn));
    }

    #[test]
    fn a_member_never_heard_from_says_so() {
        let mut n = node("d");
        n.live = false;
        n.last_seen = "never".into();
        let s = Signals {
            nodes: vec![n],
            ..Default::default()
        };
        assert_eq!(attention(&s)[0].text, "d has never been seen.");
    }

    #[test]
    fn a_node_out_of_its_cluster_lists_no_members() {
        let mut down = node("b");
        down.live = false;
        let s = Signals {
            detached: Some("This node left its cluster."),
            nodes: vec![down],
            ..Default::default()
        };
        let items = attention(&s);
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(items[0].text.contains("left its cluster"));
    }

    #[test]
    fn one_failed_scan_is_singular() {
        let s = Signals {
            failed_24h: 1,
            ..Default::default()
        };
        assert_eq!(attention(&s)[0].text, "1 scan failed in 24 h");
    }
}
