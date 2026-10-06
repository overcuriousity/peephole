//! Who earns here. Each node decides for itself, from what it holds:
//! a member's requests must classify the same under this build's rules,
//! its scans must stand up to audits, and a member that is blocked here or
//! showed two histories earns nothing at all. The gates are evaluated at
//! each recomputation, not stored: a member that agrees again (after an
//! upgrade, typically) earns again.
use super::earn::Gates;
use crate::classify::stored::{Agreement, agreement};
use crate::cluster::identity::NodeId;
use crate::cluster::{Node, members};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// Characters of a rules fingerprint shown.
pub const SHORT_HASH: usize = 12;

/// The rules fingerprints a member's newest classified requests carry
/// (`requests.rules`): what the recording binary says it classified with.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Carried {
    /// The newest request's.
    pub newest: Option<String>,
    /// Other fingerprints among the sample (a node upgraded meanwhile).
    pub others: usize,
}

impl Carried {
    /// What the page shows, and whether the newest is `ours`.
    pub(crate) fn view(&self, ours: &str) -> (String, Option<bool>) {
        let Some(h) = &self.newest else {
            return ("none recorded".into(), None);
        };
        let mut s: String = h.chars().take(SHORT_HASH).collect();
        match self.others {
            0 => {}
            1 => s.push_str(" +1 other"),
            n => s.push_str(&format!(" +{n} others")),
        }
        (s, Some(h == ours))
    }
}

/// The fingerprints the newest `sample` classified requests of `origin`
/// carry (None: this standalone node's own rows).
pub async fn carried(
    pool: &sqlx::SqlitePool,
    origin: Option<&[u8]>,
    sample: i64,
) -> anyhow::Result<Carried> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT rules FROM requests
         WHERE origin IS ? AND is_fp_claim = 0 AND rules IS NOT NULL
         ORDER BY id DESC LIMIT ?",
    )
    .bind(origin)
    .bind(sample)
    .fetch_all(pool)
    .await?;
    let distinct: std::collections::HashSet<&String> = rows.iter().collect();
    Ok(Carried {
        newest: rows.first().cloned(),
        others: distinct.len().saturating_sub(1),
    })
}

/// Members' recent requests classified again with this node's (built-in)
/// rules, and the rules fingerprints they carry, by member
/// ([`crate::classify::stored::agreement`], [`carried`]).
pub struct RulesCheck {
    pub by_member: std::collections::HashMap<NodeId, Agreement>,
    pub carried: std::collections::HashMap<NodeId, Carried>,
}

/// How long a comparison is shown before it is made again.
const RULES_CHECK_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Newest requests of each member compared.
pub const RULES_SAMPLE: i64 = 500;

async fn compare_rules(store: &crate::store::Store) -> anyhow::Result<RulesCheck> {
    let mut check = RulesCheck {
        by_member: Default::default(),
        carried: Default::default(),
    };
    let c = crate::classify::Classifier::builtin();
    for m in members::all(store).await? {
        let origin = Some(&m.id.0[..]);
        let a = agreement(&store.pool, c, origin, RULES_SAMPLE).await?;
        check.by_member.insert(m.id, a);
        let k = carried(&store.pool, origin, RULES_SAMPLE).await?;
        check.carried.insert(m.id, k);
    }
    Ok(check)
}

/// The comparison, made at most every [`RULES_CHECK_TTL`] (an older one is
/// used while it is made again), shared by the ledger and the pages.
pub async fn rules_check(node: &Node) -> Result<Arc<RulesCheck>> {
    let store = node.store.clone();
    node.rules_check
        .get((), RULES_CHECK_TTL, move || {
            let store = store.clone();
            Box::pin(async move { compare_rules(&store).await })
        })
        .await
}

/// A member is judged by its rules only when at least this many of its
/// newest requests could be compared.
pub const RULES_MIN_SAMPLE: u32 = 20;

/// Whether a member fails the rules gate: at least 20 requests compared
/// and more than 2 % of them classified differently here.
pub fn rules_fail(a: &Agreement) -> bool {
    a.sampled >= RULES_MIN_SAMPLE && u64::from(a.differing) * 50 > u64::from(a.sampled)
}

/// What stands between a member and its earnings on this node.
/// How a member that showed two histories is named, here and in issues.
pub const FORKED: &str = "showed two histories";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Standing {
    pub blocked: bool,
    /// It showed two histories, noticed at this position of its log.
    pub forked: Option<u64>,
    /// Its rules agreement, when that fails the gate.
    pub rules: Option<Agreement>,
    /// Counted audits of the last 7 days as `(conclusive, differing)`,
    /// when they fail the gate (`credits::audit`).
    pub audits: Option<(u32, u32)>,
}

impl Standing {
    /// Its shares count here (as trap; as scanner see `earns_as_scanner`).
    pub fn earns(&self) -> bool {
        !self.left_out() && self.rules.is_none()
    }

    pub fn earns_as_scanner(&self) -> bool {
        self.earns() && self.audits.is_none()
    }

    /// Out of the ledger altogether: no balance, and its payments move
    /// nothing.
    pub fn left_out(&self) -> bool {
        self.blocked || self.forked.is_some()
    }

    /// Every reason that applies, in words.
    pub fn reasons(&self) -> Vec<String> {
        let mut v = vec![];
        if self.blocked {
            v.push("blocked on this node".to_string());
        }
        if let Some(seq) = self.forked {
            v.push(format!("{FORKED} (at entry {seq} of its log)"));
        }
        if let Some(a) = &self.rules {
            v.push(format!("rules: {}", a.summary()));
        }
        if let Some((conclusive, differing)) = self.audits {
            v.push(format!("audits: {differing} of {conclusive} differ"));
        }
        v
    }
}

/// The members that do not earn in full here; everyone else does.
pub type Standings = HashMap<NodeId, Standing>;

/// Evaluate the gates now.
pub async fn standings(node: &Node) -> Result<Standings> {
    let mut out = Standings::new();
    for id in crate::cluster::block::list(&node.store).await? {
        out.entry(id).or_default().blocked = true;
    }
    for f in crate::cluster::seal::forked(&node.store.pool).await? {
        out.entry(f.origin).or_default().forked = Some(f.seq);
    }
    let check = rules_check(node).await?;
    for (id, a) in &check.by_member {
        // This node's own requests are what its rules made of them.
        if *id != node.id() && rules_fail(a) {
            out.entry(*id).or_default().rules = Some(*a);
        }
    }
    // Audits this node made itself, and those of its own fleet.
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let week = crate::cluster::hlc::wall_ms().saturating_sub(7 * super::DAY_MS) << 16;
    let counts = super::audit::counts(&node.store.pool, week).await?;
    for (scanner, (conclusive, differing)) in super::audit::counted(&counts, &auditors) {
        if super::audit::audits_fail(conclusive, differing) {
            out.entry(scanner).or_default().audits = Some((conclusive, differing));
        }
    }
    Ok(out)
}

/// The gates as the paying walk takes them.
pub fn to_gates(s: &Standings) -> Gates {
    let mut g = Gates::default();
    for (id, st) in s {
        if !st.earns() {
            g.no_shares.insert(*id, st.reasons().join("; "));
        } else if !st.earns_as_scanner() {
            g.no_scanner_share.insert(*id, st.reasons().join("; "));
        }
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(sampled: u32, differing: u32) -> Agreement {
        Agreement { sampled, differing }
    }

    #[test]
    fn the_rules_gate_needs_twenty_requests_and_more_than_two_percent() {
        assert!(!rules_fail(&a(19, 19)), "too few to judge");
        assert!(rules_fail(&a(20, 1)), "5 %");
        assert!(!rules_fail(&a(500, 10)), "2 % passes");
        assert!(rules_fail(&a(500, 11)));
        assert!(!rules_fail(&a(500, 0)));
        assert!(!rules_fail(&a(0, 0)));
    }

    #[test]
    fn standing_says_who_earns_and_why_not() {
        let fine = Standing::default();
        assert!(fine.earns() && fine.earns_as_scanner() && !fine.left_out());
        assert!(fine.reasons().is_empty());
        let rules = Standing {
            rules: Some(a(500, 60)),
            ..Default::default()
        };
        assert!(!rules.earns() && !rules.left_out());
        assert_eq!(rules.reasons(), ["rules: disagree on 12% of 500"]);
        let audits = Standing {
            audits: Some((5, 3)),
            ..Default::default()
        };
        assert!(audits.earns() && !audits.earns_as_scanner());
        assert_eq!(audits.reasons(), ["audits: 3 of 5 differ"]);
        let gone = Standing {
            blocked: true,
            forked: Some(7),
            ..Default::default()
        };
        assert!(gone.left_out() && !gone.earns());
        assert_eq!(
            gone.reasons(),
            [
                "blocked on this node",
                "showed two histories (at entry 7 of its log)"
            ]
        );

        let (x, y, z) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]));
        let all: Standings = [(x, rules), (y, audits), (z, fine)].into();
        let g = to_gates(&all);
        assert_eq!(
            g.no_shares.get(&x).map(String::as_str),
            Some("rules: disagree on 12% of 500")
        );
        assert_eq!(
            g.no_scanner_share.get(&y).map(String::as_str),
            Some("audits: 3 of 5 differ")
        );
        assert!(!g.no_shares.contains_key(&z) && !g.no_scanner_share.contains_key(&z));
    }
}
