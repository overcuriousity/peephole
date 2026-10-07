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

/// How urgent an item is (one kind today; the strip styles by it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Warn,
}

impl Level {
    pub fn key(&self) -> &'static str {
        match self {
            Level::Warn => "warn",
        }
    }
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
    /// Members that showed two histories: `(name, key)`.
    pub forked: Vec<(String, String)>,
    /// Levels this node scans with its own arguments (`scan.level_argv`):
    /// those scans earn no scanner share.
    pub custom_argv: Vec<u8>,
    /// Credits of this node in the lot that expires today, when at least 1.
    pub expiring: Option<String>,
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
            // One item per offline member: what else is wrong rides along.
            let mut text = if n.last_seen == "never" {
                format!("{} has never been seen.", n.name)
            } else {
                format!(
                    "{} not seen for {}.",
                    n.name,
                    n.last_seen.trim_end_matches(" ago")
                )
            };
            if !n.issues.is_empty() {
                text.push_str(&format!(" Also: {}.", n.issues.join(" · ")));
            }
            v.push(warn(text, &href));
            continue;
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
            format!(
                "The scan queue grows by about {} jobs per hour.",
                n.trim_start_matches('+')
            ),
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
    for (name, key) in &s.forked {
        v.push(warn(
            format!("{name} showed two histories: its credits are void here."),
            &format!("/admin/cluster/node/{key}"),
        ));
    }
    if !s.custom_argv.is_empty() {
        let levels: Vec<String> = s.custom_argv.iter().map(u8::to_string).collect();
        v.push(warn(
            format!(
                "This node sets scan.level_argv for level {}: its scans there earn no scanner share.",
                levels.join(", ")
            ),
            "/admin/cluster/credits",
        ));
    }
    if let Some(c) = &s.expiring {
        v.push(warn(
            format!("{c} credits expire today."),
            "/admin/cluster/credits",
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
        intel_stale: crate::admin::system::intel_is_stale(st).await?,
        ..Default::default()
    };
    if let Some(node) = st.recorder.node() {
        s.detached = node.detached().map(|d| d.label());
        // The landing page must not fail with the cluster checks: without
        // them it lists what it can.
        match members(st, node).await {
            Ok(nodes) => s.nodes = nodes,
            Err(e) => tracing::warn!(error = ?e, "overview: member checks unavailable"),
        }
        match crate::admin::cluster::unserved(node).await {
            Ok(u) => s.unserved = u,
            Err(e) => tracing::warn!(error = ?e, "overview: unserved history unknown"),
        }
        if let Ok(forked) = crate::cluster::seal::forked(&node.store.pool).await {
            let members = node.members();
            s.forked = forked
                .iter()
                .map(|f| {
                    (
                        members
                            .get(&f.origin)
                            .map_or_else(|| f.origin.short(), |m| m.name.clone()),
                        f.origin.to_string(),
                    )
                })
                .collect();
        }
        if node.roles().scanner {
            let mut levels: Vec<u8> = st.cfg.scan.level_argv.keys().copied().collect();
            levels.sort();
            s.custom_argv = levels;
        }
        if let Ok(book) = crate::credits::book(node).await {
            let expiring = book.ledger.expiring_today(&node.id());
            s.expiring =
                (expiring >= crate::credits::CREDIT).then(|| crate::credits::show(expiring));
        }
    }
    Ok(s)
}

/// Active, unblocked members as the strip needs them. An offline member's
/// last error is left out: "not seen" says it already.
async fn members(st: &AdminState, node: &crate::cluster::Node) -> AppResult<Vec<NodeState>> {
    let check = crate::admin::cluster::rules_check(st, node).await?;
    let book = crate::credits::book(node).await?;
    let (_, members) = crate::admin::cluster::views(node, &check, Some(&book)).await?;
    Ok(members
        .into_iter()
        .filter(|m| m.active && !m.blocked)
        .map(|m| NodeState {
            issues: if m.live {
                m.issues()
            } else {
                crate::admin::cluster::MemberView {
                    error: None,
                    ..m.clone()
                }
                .issues()
            },
            name: m.name,
            key: m.key,
            live: m.live,
            last_seen: m.last_seen,
        })
        .collect())
}

/// The "Cluster" row: every figure from this node's view, each linked to
/// the page that breaks it down.
pub struct ClusterFigures {
    /// "11 of 12 members earn here".
    pub conformity: String,
    /// The lowest rules agreement among members ("disagree on 3% of 500").
    pub lowest_agreement: String,
    /// Different rules fingerprints the members' newest requests carry.
    pub rule_sets: usize,
    pub circulating: String,
    /// Per day, 7-day averages.
    pub earned: String,
    pub spent: String,
    pub expiring_today: String,
    /// Paid scans a day, low and high tier.
    pub paid_scans: (String, String),
    /// Scans a day the scanners can do, did, and the utilization in %.
    /// Scans a day: possible, done, idle; and the utilization in %.
    pub capacity: (String, String, String, String),
    /// Counted audits of 7 days: agrees, differs, inconclusive.
    pub audits: (u32, u32, u32),
    /// What a funded scan job costs here.
    pub scan: String,
    /// Lowest and highest announced price of a keyed provider.
    pub price_range: Option<(String, String)>,
    /// Paid lookups a day this node and live members offer, and lookups
    /// served today.
    pub lookups: (String, i64),
    pub forks: usize,
}

/// What lookups charged over the offers written since `from_ms`.
fn spending(offers: &[crate::credits::ledger::Offer], from_ms: u64) -> u64 {
    offers
        .iter()
        .filter(|o| crate::cluster::hlc::physical_ms(o.hlc) >= from_ms)
        .filter_map(|o| match o.state {
            crate::credits::ledger::OfferState::Charged { charged } => Some(charged),
            _ => None,
        })
        .sum()
}

async fn cluster_figures(
    st: &AdminState,
    node: &crate::cluster::Node,
) -> AppResult<ClusterFigures> {
    use crate::credits::audit::Outcome;
    use crate::credits::show;
    let book = crate::credits::book(node).await?;
    let check = crate::admin::cluster::rules_check(st, node).await?;
    let members = node.members();
    let active: Vec<_> = members.values().filter(|m| m.active).collect();
    let earning = active
        .iter()
        .filter(|m| book.standing(&m.id).earns_as_scanner())
        .count();
    let lowest = check
        .by_member
        .values()
        .filter(|a| a.sampled > 0)
        .max_by(|a, b| {
            (u64::from(a.differing) * u64::from(b.sampled))
                .cmp(&(u64::from(b.differing) * u64::from(a.sampled)))
        })
        .map(|a| a.summary())
        .unwrap_or_else(|| "no requests to compare".into());
    let rule_sets: std::collections::HashSet<&String> = check
        .carried
        .values()
        .filter_map(|c| c.newest.as_ref())
        .collect();
    let l = &book.ledger;
    let per_day = |total: u64| show(total / 7);
    let week = book.now_ms.saturating_sub(7 * crate::credits::DAY_MS);
    let in_week = |hlc: u64| crate::cluster::hlc::physical_ms(hlc) >= week;
    // The ledger walks 8 days of entries: count the last 7.
    let spent = spending(&l.offers, week);
    let (mut low, mut high) = (0u64, 0u64);
    for p in book.paid.iter().filter(|p| in_week(p.scan.hlc)) {
        if p.weight == 0 {
            continue;
        }
        if p.scan.level >= 3 {
            high += 1;
        } else {
            low += 1;
        }
    }
    let tenth = |n: u64| format!("{:.1}", n as f64 / 7.0);
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let mut audits = (0, 0, 0);
    for c in crate::credits::audit::counts(&node.store.pool, week << 16).await? {
        if !auditors.contains(&c.auditor) {
            continue;
        }
        match c.outcome {
            Outcome::Agrees => audits.0 += c.n,
            Outcome::Differs => audits.1 += c.n,
            Outcome::Inconclusive => audits.2 += c.n,
        }
    }
    let t = node.price_table();
    // What this node and live members ask for a keyed provider, and the
    // paid lookups a day they offer.
    let is_keyed =
        |p: &str, mc: u32| mc > 0 && crate::intel::provider_info(p).is_some_and(|i| i.api);
    let mut keyed: Vec<u32> = t
        .offers
        .iter()
        .filter(|o| is_keyed(&o.provider, o.price_mc))
        .map(|o| o.price_mc)
        .collect();
    let mut offered: u64 = t.offers.iter().map(|o| o.on_demand as u64).sum();
    let me = node.id();
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        if id == me {
            continue;
        }
        if let Some(k) = node.status.known(&id) {
            keyed.extend(
                k.hb.prices
                    .iter()
                    .filter(|(p, mc)| is_keyed(p, *mc))
                    .map(|(_, mc)| *mc),
            );
            offered += k.hb.on_demand.iter().map(|(_, n)| *n as u64).sum::<u64>();
        }
    }
    let served_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credit_entries
         WHERE kind = 'receipt' AND charged_mc > 0 AND hlc >= ?",
    )
    .bind(crate::cluster::hlc::to_db(
        (book.now_ms / crate::credits::DAY_MS * crate::credits::DAY_MS) << 16,
    ))
    .fetch_one(&st.store.read)
    .await?;
    Ok(ClusterFigures {
        conformity: format!("{earning} of {} members earn here", active.len()),
        lowest_agreement: lowest,
        rule_sets: rule_sets.len(),
        circulating: show(l.circulating()),
        earned: show(book.earned_per_day()),
        spent: per_day(spent),
        expiring_today: show(active.iter().map(|m| l.expiring_today(&m.id)).sum::<u64>()),
        paid_scans: (tenth(low), tenth(high)),
        capacity: (
            format!("{:.0}", t.capacity.per_day),
            format!("{:.0}", t.capacity.used_per_day),
            format!(
                "{:.0}",
                (t.capacity.per_day - t.capacity.used_per_day).max(0.0)
            ),
            format!("{:.0}", t.capacity.utilization * 100.0),
        ),
        audits,
        scan: show(t.scan_mc as u64),
        price_range: keyed
            .iter()
            .min()
            .zip(keyed.iter().max())
            .map(|(lo, hi)| (show(*lo as u64), show(*hi as u64))),
        lookups: (offered.to_string(), served_today),
        forks: crate::cluster::seal::forked(&node.store.pool).await?.len(),
    })
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
    /// 24 h ago (UTC), for the request search link.
    since_24h: String,
    /// "Recent activity": the newest requests, then live over SSE.
    recent: Vec<crate::store::stats::RecentRequest>,
    /// The newest request id shown (the live feed's cursor).
    recent_max_id: i64,
    cluster: Option<ClusterFigures>,
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
        since_24h: (chrono::Utc::now() - chrono::Duration::hours(24))
            .format("%Y-%m-%dT%H:%M")
            .to_string(),
        recent,
        recent_max_id,
        cluster: match st.recorder.node() {
            // The landing page must not fail with the cluster's figures.
            Some(node) => cluster_figures(&st, node)
                .await
                .inspect_err(
                    |e| tracing::warn!(error = ?e, "overview: cluster figures unavailable"),
                )
                .ok(),
            None => None,
        },
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
            ..Default::default()
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
        find("/admin/scans#pace", "by about 4.0 jobs");
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
    fn an_offline_member_is_one_item() {
        let mut n = node("e");
        n.live = false;
        n.last_seen = "5 min ago".into();
        n.issues = vec!["incompatible version".into()];
        let s = Signals {
            nodes: vec![n],
            ..Default::default()
        };
        let items = attention(&s);
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(
            items[0].text.contains("not seen for 5 min")
                && items[0].text.contains("incompatible version")
        );
    }

    #[test]
    fn one_failed_scan_is_singular() {
        let s = Signals {
            failed_24h: 1,
            ..Default::default()
        };
        assert_eq!(attention(&s)[0].text, "1 scan failed in 24 h");
    }

    #[test]
    fn spending_counts_the_last_seven_days_only() {
        use crate::credits::ledger::{Offer, OfferState};
        let id = crate::cluster::identity::NodeId([1; 32]);
        let offer = |day: u64, charged: u64| Offer {
            payer: id,
            seq: day,
            hlc: (day * crate::credits::DAY_MS) << 16,
            to: id,
            offered: charged,
            covered: charged,
            held: vec![],
            state: OfferState::Charged { charged },
            answered: vec![],
            job: None,
        };
        // Day 1 lies outside the week that starts on day 2.
        let offers = [offer(1, 1000), offer(2, 400), offer(8, 200)];
        assert_eq!(spending(&offers, 2 * crate::credits::DAY_MS), 600);
    }

    #[test]
    fn credit_matters_that_need_a_look() {
        let s = Signals {
            forked: vec![("node-x".into(), "key-x".into())],
            custom_argv: vec![2, 4],
            expiring: Some("3.25".into()),
            ..Default::default()
        };
        let v = attention(&s);
        let texts: Vec<&str> = v.iter().map(|a| a.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "node-x showed two histories: its credits are void here.",
                "This node sets scan.level_argv for level 2, 4: its scans there earn no scanner share.",
                "3.25 credits expire today.",
            ]
        );
        assert_eq!(v[0].href, "/admin/cluster/node/key-x");
        assert_eq!(v[2].href, "/admin/cluster/credits");
    }
}
