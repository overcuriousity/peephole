//! Host names: what the admin may type into the Lookup box, and how a name
//! is resolved by several nodes at once. Each resolver's answer is kept in
//! an `ip_name` record; every node derives the per-address votes from those
//! answers itself (see `store::probes::apply_ip_name`), so a tally is never
//! taken on trust.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{IpNameRec, Record};
use crate::intel::SharedGeo;
use crate::store::recorder::Recorder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Most nodes asked to resolve one name (this node included).
pub const MAX_RESOLVERS: usize = 5;
/// Most agreed addresses of a name that are looked up in turn.
pub const MAX_FOLLOWED: usize = 16;
/// Most addresses kept of one resolver's answer.
pub const MAX_ADDRS: usize = 64;
/// How long this node's resolver may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest error text kept of one resolver.
const MAX_ERROR: usize = 200;

/// A host name in its canonical form (lower case, no trailing dot), or
/// None when the text is not one: it needs a dot, labels of letters,
/// digits and hyphens up to 63 characters (not starting or ending with a
/// hyphen), at most 253 characters in all, its last label is not all
/// digits (the resolver reads `1.2.3` as an IPv4 address), and it is not
/// an IP address and carries no scheme. A label with other letters is IDNA-encoded
/// (`xn--` and its punycode, RFC 3492).
pub fn valid_name(input: &str) -> Option<String> {
    let name = input.trim().trim_end_matches('.').to_lowercase();
    if name.is_empty() || !name.contains('.') || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Option<Vec<String>> = name
        .split('.')
        .map(|l| match l.is_ascii() {
            true => Some(l.to_string()),
            false if l.chars().any(|c| c.is_whitespace() || c.is_control()) => None,
            false => punycode(&l.chars().collect::<Vec<_>>()).map(|p| format!("xn--{p}")),
        })
        .collect();
    let name = labels?.join(".");
    let ok = name.len() <= 253
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    ok.then_some(name)
}

/// RFC 3492 §6.3: the punycode of one label (without the `xn--`). None on
/// overflow.
fn punycode(input: &[char]) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    let digit = |d: u32| match d {
        0..26 => (b'a' + d as u8) as char,
        _ => (b'0' + (d - 26) as u8) as char,
    };
    let adapt = |delta: u32, points: u32, first: bool| {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    };
    let mut out: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = out.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias) = (128u32, 0u32, 72u32);
    while (handled as usize) < input.len() {
        let m = input.iter().map(|&c| c as u32).filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for c in input.iter().map(|&c| c as u32) {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = match k {
                        k if k <= bias => TMIN,
                        k if k >= bias + TMAX => TMAX,
                        k => k - bias,
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// What one node asks another to resolve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveReq {
    pub name: String,
}

/// A node's answer: the global addresses its resolver returned, or why
/// there are none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResp {
    pub addrs: Vec<IpAddr>,
    #[serde(default)]
    pub error: Option<String>,
}

impl ResolveResp {
    pub fn refused(why: &str) -> ResolveResp {
        ResolveResp {
            addrs: vec![],
            error: Some(why.to_string()),
        }
    }
}

fn short(why: &str) -> String {
    why.chars().take(MAX_ERROR).collect()
}

/// This node's own answer: the system resolver, 5 s, global unicast only,
/// sorted, deduplicated.
pub async fn resolve_here(name: &str) -> Result<Vec<IpAddr>, String> {
    let name = valid_name(name).ok_or("not a host name")?;
    match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((name.as_str(), 0))).await {
        Err(_) => Err("timed out".into()),
        Ok(Err(e)) => Err(short(&e.to_string())),
        Ok(Ok(addrs)) => {
            let set: BTreeSet<IpAddr> = addrs
                .map(|a| crate::net::canonical(a.ip()))
                .filter(|ip| crate::net::is_scannable_target(*ip))
                .collect();
            Ok(set.into_iter().take(MAX_ADDRS).collect())
        }
    }
}

/// A node that may be asked to resolve a name.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolver {
    pub id: NodeId,
    pub name: String,
    /// Shares this node's owner (see `cluster::owner::fleet`).
    pub sibling: bool,
    /// Where its public address is, as this node's GeoLite2 places it.
    pub country: Option<String>,
}

/// A member's name and country, as this node knows them.
pub fn describe(node: &Node, geo: &SharedGeo, id: &NodeId) -> (String, Option<String>) {
    let (name, publics, dialled) = if *id == node.id() {
        ("this node".to_string(), node.public_addrs(), None)
    } else {
        (
            node.members()
                .get(id)
                .map(|m| m.name.clone())
                .unwrap_or_else(|| id.short()),
            node.status
                .known(id)
                .map(|k| k.hb.public_addrs.clone())
                .unwrap_or_default(),
            node.dial_address(id)
                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                .map(|a| a.ip()),
        )
    };
    let country = publics
        .first()
        .or(dialled.as_ref())
        .and_then(|ip| geo.read().ok()?.as_ref()?.lookup(ip).country);
    (name, country)
}

/// Up to [`MAX_RESOLVERS`]: this node, then random live members
/// preferring non-siblings and unseen countries.
pub fn choose(node: &Node, siblings: &HashSet<NodeId>, geo: &SharedGeo) -> Vec<Resolver> {
    use rand::seq::SliceRandom;
    let me = node.id();
    let resolver = |id: NodeId| {
        let (name, country) = describe(node, geo, &id);
        Resolver {
            id,
            name,
            sibling: siblings.contains(&id),
            country,
        }
    };
    let mut others: Vec<NodeId> = node
        .live_members(crate::intel::LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id != me && !node.is_blocked(id) && node.dial_address(id).is_some())
        .collect();
    others.shuffle(&mut rand::rng());
    let candidates: Vec<Resolver> = std::iter::once(me).chain(others).map(resolver).collect();
    pick(&candidates, MAX_RESOLVERS)
}

/// The first candidate (this node), then up to `n` in all: non-siblings
/// before siblings, and within each a new country before a seen one;
/// otherwise in the candidates' order.
pub fn pick(candidates: &[Resolver], n: usize) -> Vec<Resolver> {
    let Some((first, rest)) = candidates.split_first() else {
        return vec![];
    };
    let mut out = vec![first.clone()];
    let mut seen: HashSet<&str> = first.country.as_deref().into_iter().collect();
    for (sibling, fresh) in [(false, true), (false, false), (true, true), (true, false)] {
        for c in rest {
            if out.len() >= n {
                return out;
            }
            if c.sibling != sibling || out.iter().any(|o| o.id == c.id) {
                continue;
            }
            if fresh && !c.country.as_deref().is_some_and(|x| !seen.contains(x)) {
                continue;
            }
            if let Some(x) = c.country.as_deref() {
                seen.insert(x);
            }
            out.push(c.clone());
        }
    }
    out.truncate(n);
    out
}

/// One address and how many resolvers returned it.
#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub addr: IpAddr,
    pub votes: usize,
    /// More than half of the resolvers that answered returned it.
    pub agreed: bool,
}

/// The votes of one lookup.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tally {
    pub asked: usize,
    pub answered: usize,
    /// Most votes first.
    pub votes: Vec<Vote>,
    pub errors: Vec<(NodeId, String)>,
}

/// Per address: agreed when votes > answered / 2 (answered ≥ 1).
/// Non-global answers are dropped first; a node's second answer counts
/// for nothing.
pub fn tally(answers: &[(NodeId, Result<Vec<IpAddr>, String>)]) -> Tally {
    let mut t = Tally::default();
    let mut counted: HashSet<NodeId> = HashSet::new();
    let mut votes: BTreeMap<IpAddr, usize> = BTreeMap::new();
    for (id, answer) in answers {
        if !counted.insert(*id) {
            continue;
        }
        t.asked += 1;
        match answer {
            Ok(addrs) => {
                t.answered += 1;
                let set: BTreeSet<IpAddr> = addrs
                    .iter()
                    .map(|a| crate::net::canonical(*a))
                    .filter(|a| crate::net::is_scannable_target(*a))
                    .collect();
                for a in set {
                    *votes.entry(a).or_default() += 1;
                }
            }
            Err(e) => t.errors.push((*id, e.clone())),
        }
    }
    t.votes = votes
        .into_iter()
        .map(|(addr, votes)| Vote {
            addr,
            votes,
            agreed: t.answered >= 1 && votes * 2 > t.answered,
        })
        .collect();
    t.votes
        .sort_by(|a, b| b.votes.cmp(&a.votes).then(a.addr.cmp(&b.addr)));
    t
}

/// Ask the chosen resolvers (RPC `/rpc/v1/resolve`), build the record,
/// write it (cluster: replicated; standalone: local), return the tally.
/// Nothing is written when no resolver answered.
pub async fn lookup(
    rec: &Recorder,
    geo: &SharedGeo,
    name: &str,
) -> Result<(Tally, Option<IpNameRec>), String> {
    lookup_with(rec, geo, name, async |n: &str| resolve_here(n).await).await
}

/// [`lookup`], with `resolve` standing in for this node's resolver.
pub async fn lookup_with(
    rec: &Recorder,
    geo: &SharedGeo,
    name: &str,
    resolve: impl AsyncFn(&str) -> Result<Vec<IpAddr>, String>,
) -> Result<(Tally, Option<IpNameRec>), String> {
    let name = valid_name(name).ok_or("not a host name")?;
    let clip = |a: Result<Vec<IpAddr>, String>| match a {
        Ok(mut v) => {
            v.truncate(MAX_ADDRS);
            Ok(v)
        }
        Err(e) => Err(short(&e)),
    };
    let answers = match rec {
        Recorder::Local(_) => vec![(crate::scan::probe::gate::LOCAL, clip(resolve(&name).await))],
        Recorder::Cluster(node) => {
            let siblings: HashSet<NodeId> = crate::cluster::owner::fleet::siblings(&node.store)
                .await
                .inspect_err(|e| tracing::debug!(?e, "resolve: siblings not read"))
                .unwrap_or_default()
                .into_iter()
                .collect();
            let me = node.id();
            let remote = futures::future::join_all(
                choose(node, &siblings, geo)
                    .into_iter()
                    .filter(|r| r.id != me)
                    .map(|r| ask(node, r.id, &name)),
            );
            let (own, mut remote) = futures::join!(resolve(&name), remote);
            remote.insert(0, (me, own));
            remote.into_iter().map(|(id, a)| (id, clip(a))).collect()
        }
    };
    let t = tally(&answers);
    if t.answered == 0 {
        return Ok((t, None));
    }
    let r = IpNameRec {
        uid: rec.uid(),
        name,
        at: crate::store::data::now_ts(),
        answers,
        build: crate::COMMIT.into(),
    };
    rec.write(vec![Record::IpName(r.clone())])
        .await
        .map_err(|e| format!("not stored: {e:#}"))?;
    Ok((t, Some(r)))
}

/// One member's answer.
async fn ask(node: &Arc<Node>, id: NodeId, name: &str) -> (NodeId, Result<Vec<IpAddr>, String>) {
    let Some(addr) = node.dial_address(&id) else {
        return (id, Err("cannot be dialled from here".into()));
    };
    let req = ResolveReq {
        name: name.to_string(),
    };
    let call = node.call::<ResolveReq, ResolveResp>(id, &addr, "/rpc/v1/resolve", &req);
    let answer = match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT, call).await {
        Err(_) => Err("did not answer in time".into()),
        Ok(Err(e)) => Err(format!("could not be asked: {e:#}")),
        Ok(Ok(ResolveResp { error: Some(e), .. })) => Err(e),
        Ok(Ok(ResolveResp { addrs, .. })) => Ok(addrs),
    };
    (id, answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated_and_normalised() {
        assert_eq!(valid_name(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(
            valid_name("bücher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            valid_name("München.de").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
        assert_eq!(valid_name("例え.jp").as_deref(), Some("xn--r8jz45g.jp"));
        assert_eq!(
            valid_name("a-b.example.org").as_deref(),
            Some("a-b.example.org")
        );
        for bad in [
            "localhost",
            "-bad.example",
            "http://example.com",
            "203.0.113.1",
            "2001:db8::1",
            "not a host",
            "a..com",
            "1.2.3",
            "",
        ] {
            assert!(valid_name(bad).is_none(), "{bad}");
        }
        assert!(valid_name(&format!("{}.example", "a".repeat(64))).is_none());
        assert!(
            valid_name(&format!("{}example", "a.".repeat(125))).is_none(),
            "over 253"
        );
    }

    #[test]
    fn the_majority_is_per_address_over_those_that_answered() {
        let n = |i: u8| NodeId([i; 32]);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let t = tally(&[
            (n(1), Ok(vec![ip("203.0.113.1"), ip("203.0.113.2")])),
            (n(2), Ok(vec![ip("203.0.113.1")])),
            (n(3), Ok(vec![ip("203.0.113.1"), ip("10.0.0.1")])),
            (n(4), Err("timed out".into())),
            (n(5), Ok(vec![ip("198.51.100.9")])),
        ]);
        assert_eq!((t.asked, t.answered), (5, 4));
        let v = |a: &str| {
            t.votes
                .iter()
                .find(|v| v.addr == ip(a))
                .map(|v| (v.votes, v.agreed))
        };
        assert_eq!(v("203.0.113.1"), Some((3, true)));
        assert_eq!(v("203.0.113.2"), Some((1, false)));
        assert_eq!(
            v("198.51.100.9"),
            Some((1, false)),
            "the odd one out is kept, disputed"
        );
        assert_eq!(v("10.0.0.1"), None, "private answers are dropped");
        assert_eq!(t.errors.len(), 1);
        // Two responders: both must agree. One: unverified (agreed, answered == 1).
        let t2 = tally(&[
            (n(1), Ok(vec![ip("203.0.113.1")])),
            (n(2), Ok(vec![ip("203.0.113.3")])),
        ]);
        assert!(t2.votes.iter().all(|v| !v.agreed));
        let t1 = tally(&[(n(1), Ok(vec![ip("203.0.113.1")]))]);
        assert!(t1.votes[0].agreed && t1.answered == 1);
        // A node answering twice is counted once.
        let twice = tally(&[
            (n(1), Ok(vec![ip("203.0.113.1")])),
            (n(1), Ok(vec![ip("203.0.113.1")])),
            (n(2), Ok(vec![])),
        ]);
        assert_eq!(
            (twice.asked, twice.votes[0].votes, twice.votes[0].agreed),
            (2, 1, false)
        );
    }

    #[test]
    fn resolvers_prefer_non_siblings_and_new_countries() {
        let r = |i: u8, sibling: bool, country: Option<&str>| Resolver {
            id: NodeId([i; 32]),
            name: format!("n{i}"),
            sibling,
            country: country.map(str::to_string),
        };
        let all = [
            r(0, false, Some("DE")),
            r(1, true, Some("FR")),
            r(2, false, Some("DE")),
            r(3, false, Some("US")),
            r(4, false, None),
            r(5, true, Some("JP")),
            r(6, false, Some("US")),
            r(7, false, Some("BR")),
        ];
        let ids = |v: Vec<Resolver>| v.iter().map(|r| r.id.0[0]).collect::<Vec<_>>();
        // This node; new countries among non-siblings; then the other non-siblings.
        assert_eq!(ids(pick(&all, MAX_RESOLVERS)), [0, 3, 7, 2, 4]);
        // Siblings only when nothing else is left, a new country first.
        assert_eq!(ids(pick(&all, 8)), [0, 3, 7, 2, 4, 6, 1, 5]);
        assert_eq!(ids(pick(&all[..2], MAX_RESOLVERS)), [0, 1]);
        assert!(pick(&[], MAX_RESOLVERS).is_empty());
    }
}
