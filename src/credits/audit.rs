//! Audits: a second look at a scan. Signatures settle what nodes say to
//! each other and re-running settles computations over shared data;
//! whether a scan really ran is a statement about the outside world, and
//! only looking again can check it. The two results are compared
//! (`compare`).
//!
//! A share of the scans of paid jobs (granted by another arbiter and paid
//! for, `job_paid`) is designated for audit by a hash of the log the
//! scanner cannot steer (`designated`), and the scanner
//! buys each such audit from auditors ranked by the same hash
//! (`auditors`, `buy`); every node counts whether it did (`obligations`).
//! Each scanner also re-runs a share of others' fresh scans unpaid
//! (`Picker`). A node believes, for the differ gate, the audits it made
//! itself and those of its own fleet.
use crate::cluster::Node;
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::members::MemberRow;
use crate::cluster::msg::Msg;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

/// How an audit compares with the scan it checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Agrees,
    Differs,
    /// The audit found no open TCP port: a source that vanished cannot be
    /// told from one that was never scanned.
    Inconclusive,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Agrees => "agrees",
            Outcome::Differs => "differs",
            Outcome::Inconclusive => "inconclusive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "agrees" => Some(Outcome::Agrees),
            "differs" => Some(Outcome::Differs),
            "inconclusive" => Some(Outcome::Inconclusive),
            _ => None,
        }
    }
}

/// What a scan found, as far as audits compare it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Found {
    pub open_tcp: BTreeSet<u16>,
    /// `(port, kind, fingerprint)` of the SSH host keys and TLS
    /// certificates it saw.
    pub keys: BTreeSet<(u16, String, String)>,
}

/// Compare an audit with the scan it checks. A pure function of the two
/// stored results. They agree when at least half of the ports the audit
/// found open, and at least half of those the scan reported open, are open
/// in both: a scan that claims every port open contains whatever the
/// audit finds, but most of its claim is not there. The same host key or
/// certificate on a port open in both settles it, as long as the scan
/// claims at most twice as many open ports as the audit found.
pub fn compare(original: &Found, audit: &Found) -> Outcome {
    if audit.open_tcp.is_empty() {
        return Outcome::Inconclusive;
    }
    // A port open in both that carries the same host key or certificate.
    let same_key = audit.keys.iter().any(|k| {
        original.keys.contains(k)
            && original.open_tcp.contains(&k.0)
            && audit.open_tcp.contains(&k.0)
    });
    if same_key && original.open_tcp.len() <= 2 * audit.open_tcp.len() {
        return Outcome::Agrees;
    }
    let common = audit.open_tcp.intersection(&original.open_tcp).count();
    if common * 2 >= audit.open_tcp.len() && common * 2 >= original.open_tcp.len() {
        Outcome::Agrees
    } else {
        Outcome::Differs
    }
}

/// What the stored scan `scan_id` found.
pub async fn found(pool: &SqlitePool, scan_id: i64) -> Result<Found> {
    let ports: Vec<i64> = sqlx::query_scalar(
        "SELECT port FROM ports WHERE scan_id = ? AND proto = 'tcp' AND state = 'open'",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    let keys: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT port, kind, fingerprint FROM host_keys WHERE scan_id = ?")
            .bind(scan_id)
            .fetch_all(pool)
            .await?;
    let port = |p: i64| u16::try_from(p).ok();
    Ok(Found {
        open_tcp: ports.into_iter().filter_map(port).collect(),
        keys: keys
            .into_iter()
            .filter(|(_, kind, _)| crate::store::hostkeys::is_identity(kind))
            .filter_map(|(p, kind, fp)| Some((port(p)?, kind, fp)))
            .collect(),
    })
}

/// Audits compared per pass.
const SETTLE_BATCH: i64 = 200;

/// Compare the audits whose scan is held here and that have no result
/// yet, and keep the result with the audit. Returns how many.
pub async fn settle(pool: &SqlitePool) -> Result<usize> {
    let pairs: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT a.id, o.id FROM scans a JOIN scans o ON o.uid = a.audit_of
         WHERE a.audit_of IS NOT NULL AND a.audit_result IS NULL AND o.audit_of IS NULL
         ORDER BY a.id LIMIT ?",
    )
    .bind(SETTLE_BATCH)
    .fetch_all(pool)
    .await?;
    for (audit, original) in &pairs {
        let outcome = compare(&found(pool, *original).await?, &found(pool, *audit).await?);
        sqlx::query("UPDATE scans SET audit_result = ? WHERE id = ?")
            .bind(outcome.as_str())
            .bind(audit)
            .execute(pool)
            .await?;
    }
    Ok(pairs.len())
}

/// A scanner fails the audit gate when at least 5 counted audits of it
/// were conclusive and at least half of those differ.
pub fn audits_fail(conclusive: u32, differing: u32) -> bool {
    conclusive >= 5 && differing * 2 >= conclusive
}

/// How many audits of one scanner by one auditor came out one way.
#[derive(Debug, Clone, PartialEq)]
pub struct Count {
    pub scanner: NodeId,
    pub auditor: NodeId,
    pub outcome: Outcome,
    pub n: u32,
}

/// The compared audits dated `since_hlc` or later. A scanner's audits of
/// its own scans are left out: they say nothing.
pub async fn counts(pool: &SqlitePool, since_hlc: u64) -> Result<Vec<Count>> {
    let rows: Vec<(Vec<u8>, Vec<u8>, String, i64)> = sqlx::query_as(
        "SELECT o.origin, a.origin, a.audit_result, COUNT(*)
         FROM scans a JOIN scans o ON o.uid = a.audit_of
         WHERE a.audit_result IS NOT NULL AND a.hlc >= ?
           AND a.origin IS NOT NULL AND o.origin IS NOT NULL AND a.origin != o.origin
         GROUP BY o.origin, a.origin, a.audit_result",
    )
    .bind(hlc::to_db(since_hlc))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(scanner, auditor, result, n)| {
            Some(Count {
                scanner: NodeId::from_slice(&scanner).ok()?,
                auditor: NodeId::from_slice(&auditor).ok()?,
                outcome: Outcome::parse(&result)?,
                n: n.clamp(0, u32::MAX as i64) as u32,
            })
        })
        .collect())
}

/// Per audited scanner, the `(conclusive, differing)` audits made by
/// `auditors`: this node and its fleet. Audits by other operators are
/// shown but do not count, or a few throwaway nodes could strip an honest
/// scanner of its earnings.
pub fn counted(counts: &[Count], auditors: &[NodeId]) -> HashMap<NodeId, (u32, u32)> {
    let mut out: HashMap<NodeId, (u32, u32)> = HashMap::new();
    for c in counts {
        if !auditors.contains(&c.auditor) || c.outcome == Outcome::Inconclusive {
            continue;
        }
        let e = out.entry(c.scanner).or_default();
        e.0 += c.n;
        if c.outcome == Outcome::Differs {
            e.1 += c.n;
        }
    }
    out
}

/// An audit must start within this long after the audited scan ended: the
/// source may be gone later, and a late audit proves little.
pub const AUDIT_WINDOW_MS: u64 = 30 * 60 * 1000;
/// Audits waiting for a free worker.
const MAX_WAITING: usize = 1000;

/// A scan to run again: an unpaid pick (`offer` None) or a bought audit.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub scan_uid: String,
    pub job_uid: String,
    pub ip: String,
    pub level: u8,
    /// Wall-clock ms after which it is dropped.
    pub deadline_ms: u64,
    /// Who bought it, its offer and what it offered.
    pub offer: Option<(NodeId, u64, u32)>,
}

/// An offer that bought an audit: its payer and sequence number.
pub type OfferRef = (NodeId, u64);

/// Bought audits waiting for a free worker, handed out before unpaid
/// picks, and the offers of those running now.
#[derive(Default)]
pub struct Queue {
    waiting: VecDeque<Task>,
    running: std::collections::HashSet<OfferRef>,
}

impl Queue {
    /// Queue a bought audit; false when [`MAX_WAITING`] wait already.
    pub fn push(&mut self, t: Task) -> bool {
        if self.waiting.len() >= MAX_WAITING {
            return false;
        }
        self.waiting.push_back(t);
        true
    }

    /// Audits waiting.
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Whether the audit `offer` bought waits or runs here.
    pub fn holds(&self, offer: OfferRef) -> bool {
        self.running.contains(&offer)
            || self
                .waiting
                .iter()
                .any(|t| t.offer.is_some_and(|(p, q, _)| (p, q) == offer))
    }

    /// The next one still in time and not at a level in `exclude`; it
    /// counts as running until [`Queue::end`] or [`Queue::put_back`].
    pub fn take(&mut self, exclude: &[u8]) -> Option<Task> {
        let now = hlc::wall_ms();
        self.waiting.retain(|t| t.deadline_ms > now);
        let i = self
            .waiting
            .iter()
            .position(|t| !exclude.contains(&t.level))?;
        let t = self.waiting.remove(i)?;
        if let Some((p, q, _)) = t.offer {
            self.running.insert((p, q));
        }
        Some(t)
    }

    /// A taken audit that cannot start yet: first in line again.
    pub fn put_back(&mut self, t: Task) {
        if let Some((p, q, _)) = t.offer {
            self.running.remove(&(p, q));
        }
        self.waiting.push_front(t);
    }

    /// The audit `offer` bought ended, or was dropped.
    pub fn end(&mut self, offer: OfferRef) {
        self.running.remove(&offer);
    }
}

/// Chooses the scans this scanner audits: each fresh scan of another node
/// with probability `share`, from this node's own random source. Nobody
/// can predict or verify the choice, and nobody needs to.
pub struct Picker {
    share: f64,
    /// The newest scan row looked at; None before the first look.
    last_id: Option<i64>,
    queue: VecDeque<Task>,
}

fn chance(share: f64) -> bool {
    if share >= 1.0 {
        return true;
    }
    let mut b = [0u8; 4];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        return false;
    }
    (u32::from_le_bytes(b) as f64) < share * (u32::MAX as f64 + 1.0)
}

/// A row time (`YYYY-MM-DD HH:MM:SS`, UTC) as wall-clock milliseconds.
fn ms_of(ts: &str) -> Option<u64> {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc().timestamp_millis().max(0) as u64)
}

/// Scans read per look; a burst larger than this is read over several.
const POLL_BATCH: i64 = 500;

/// When the audit window of a scan starts: when it finished, but never
/// before it arrived here. `finished_at` is the scanner's own word: left
/// out, or dated back past the window, it would keep the scan from ever
/// being audited. A date in the future counts as now.
fn audit_from(finished: Option<u64>, arrived: Option<u64>, now: u64) -> Option<u64> {
    let from = match (finished, arrived) {
        (Some(f), Some(a)) => f.max(a),
        (f, a) => f.or(a)?,
    };
    Some(from.min(now))
}

impl Picker {
    pub fn new(share: f64) -> Self {
        Self {
            share,
            last_id: None,
            queue: VecDeque::new(),
        }
    }

    /// Look at the scans that arrived since the last look and pick some of
    /// those other nodes ran.
    pub async fn poll(&mut self, pool: &SqlitePool, me: &NodeId) -> Result<()> {
        if self.share <= 0.0 {
            return Ok(());
        }
        let Some(last) = self.last_id else {
            // What was there before this scanner started is not audited.
            let max: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM scans")
                .fetch_one(pool)
                .await?;
            self.last_id = Some(max.unwrap_or(0));
            return Ok(());
        };
        // The mark moves to `top` only once every row up to it was read:
        // rows of this node's own scans and of audits move it too, and
        // rows that arrive meanwhile lie above it.
        let top: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM scans")
            .fetch_one(pool)
            .await?;
        type Row = (
            i64,
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT s.id, s.uid, s.job_uid, i.ip, s.level, s.finished_at, l.received_at
             FROM scans s JOIN ips i ON i.id = s.ip_id
             LEFT JOIN repl_log l ON l.uid = s.uid AND l.origin = s.origin
             WHERE s.id > ? AND s.id <= ? AND s.audit_of IS NULL AND s.uid IS NOT NULL
               AND s.job_uid IS NOT NULL AND s.origin IS NOT NULL AND s.origin != ?
             ORDER BY s.id LIMIT ?",
        )
        .bind(last)
        .bind(top)
        .bind(&me.0[..])
        .bind(POLL_BATCH)
        .fetch_all(pool)
        .await?;
        let all_read = rows.len() < POLL_BATCH as usize;
        let now = hlc::wall_ms();
        for (id, scan_uid, job_uid, ip, level, finished_at, arrived) in rows {
            self.last_id = Some(id);
            let Some(ended) = audit_from(
                finished_at.as_deref().and_then(ms_of),
                arrived.as_deref().and_then(ms_of),
                now,
            ) else {
                continue;
            };
            let deadline_ms = ended + AUDIT_WINDOW_MS;
            if now >= deadline_ms || !(1..=5).contains(&level) || !chance(self.share) {
                continue;
            }
            if self.queue.len() < MAX_WAITING {
                self.queue.push_back(Task {
                    scan_uid,
                    job_uid,
                    ip,
                    level: level as u8,
                    deadline_ms,
                    offer: None,
                });
            }
        }
        if all_read {
            self.last_id = Some(top.max(last));
        }
        Ok(())
    }

    /// The next audit to start now: still in time, and not of a level in
    /// `exclude` (the scanner is at its share of that level).
    pub fn take(&mut self, exclude: &[u8]) -> Option<Task> {
        let now = hlc::wall_ms();
        self.queue.retain(|t| t.deadline_ms > now);
        let i = self
            .queue
            .iter()
            .position(|t| !exclude.contains(&t.level))?;
        self.queue.remove(i)
    }
}

/// The share of scans of paid jobs designated for a bought audit; a
/// protocol constant, so every node designates the same scans.
pub const AUDIT_RATE: f64 = 0.05;
/// Auditors that may sell the audit of one designated scan.
pub const AUDITORS: usize = 3;

/// What designates a scan and ranks its auditors: a hash of its job and
/// the HLC of the arbiter's done status, which the arbiter writes after
/// the result is published and the scanner charged ([`job_paid`]).
pub fn seed(job_uid: &str, done_hlc: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"peephole-audit\0");
    h.update(job_uid.as_bytes());
    h.update(done_hlc.to_be_bytes());
    h.finalize().into()
}

/// Whether the scan of `seed` is designated for a bought audit.
pub fn designated(seed: &[u8; 32]) -> bool {
    let x = u64::from_be_bytes(seed[..8].try_into().expect("8 bytes"));
    (x as f64) < AUDIT_RATE * (u64::MAX as f64 + 1.0)
}

/// The auditors of a designated scan at `level`, best first: the active
/// scanners of protocol 7 (of protocol 8 for level 5, which older ones do
/// not run) other than `scanner` admitted no later than the job's done
/// status `done_hlc`, ranked by `SHA-256(seed || key)`; the first
/// [`AUDITORS`]. A member admitted later cannot join the ranking of a
/// scan after the fact. Roles, protocol and standing are read from the
/// member records as held now.
pub fn auditors(
    seed: &[u8; 32],
    members: &[MemberRow],
    scanner: &NodeId,
    done_hlc: u64,
    level: u8,
) -> Vec<NodeId> {
    use crate::cluster::rpc::proto::{ECONOMY_PROTO, VULN_SCAN_PROTO};
    use sha2::{Digest, Sha256};
    let proto = if level >= 5 {
        VULN_SCAN_PROTO
    } else {
        ECONOMY_PROTO
    };
    let mut ranked: Vec<([u8; 32], NodeId)> = members
        .iter()
        .filter(|m| {
            m.active
                && m.id != *scanner
                && m.admitted_hlc <= done_hlc
                && m.proto_max >= proto
                && m.roles.iter().any(|r| r == "scanner")
        })
        .map(|m| {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(m.id.0);
            (h.finalize().into(), m.id)
        })
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .take(AUDITORS)
        .map(|(_, id)| id)
        .collect()
}

/// `(bought, designated)` when a scanner's designated scans lack a bought
/// audit four times or more and it bought fewer than 60 % of them. An
/// honest scanner misses one now and then (every auditor ranked for a scan
/// may be offline or decline it); one that skips its audits misses most.
pub fn owes(designated: u32, bought: u32) -> Option<(u32, u32)> {
    let missing = designated.saturating_sub(bought);
    (missing >= 4 && u64::from(bought) * 5 < u64::from(designated) * 3)
        .then_some((bought, designated))
}

/// The economy of the payments audits read, as stored.
fn economy() -> i64 {
    i64::from(crate::cluster::record::ECONOMY)
}

/// The SQL condition under which the receipt `r` is the one the ledger
/// counts for the offer `o` (`credits::ledger`): written by the node offered
/// to, dated after the offer and no later than its lifetime (the parameter
/// `ttl`, in ms) after it, and the first such. `economy` names the
/// parameter holding the economy.
fn counted_receipt(economy: &str, ttl: &str) -> String {
    format!(
        "r.kind = 'receipt' AND r.economy = {economy}
         AND r.origin = o.peer AND r.peer = o.origin AND r.offer_seq = o.seq
         AND r.hlc > o.hlc AND (r.hlc >> 16) <= (o.hlc >> 16) + {ttl}
         AND NOT EXISTS (SELECT 1 FROM credit_entries f
                         WHERE f.kind = 'receipt' AND f.economy = {economy}
                           AND f.origin = r.origin AND f.peer = r.peer
                           AND f.offer_seq = r.offer_seq
                           AND f.hlc > o.hlc AND (f.hlc >> 16) <= (o.hlc >> 16) + {ttl}
                           AND (f.hlc < r.hlc OR (f.hlc = r.hlc AND f.seq < r.seq)))"
    )
}

/// Whether the job `job_uid` that `arbiter` granted to `scanner` was paid
/// for: an offer of the arbiter funding it whose receipt the ledger counts
/// ([`counted_receipt`], within [`crate::credits::JOB_OFFER_TTL_MS`])
/// charged something, and is dated before the arbiter's done status
/// `done_hlc`. Only the scans of paid jobs are designated: a scanner paid
/// nothing for a job may hold nothing to buy its audit with. The scanner
/// charges before it reports the job done; a receipt written after the
/// done status (which designates) could be withheld for the scans it
/// designates, so it never makes a job paid.
pub async fn job_paid(
    pool: &SqlitePool,
    job_uid: &str,
    arbiter: &[u8],
    scanner: &[u8],
    done_hlc: u64,
) -> Result<bool> {
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT EXISTS (
           SELECT 1 FROM credit_entries o
           JOIN credit_entries r ON r.charged_mc > 0 AND r.hlc < ?6 AND {}
           WHERE o.kind = 'offer' AND o.economy = ?4 AND o.job_uid = ?1
             AND o.origin = ?2 AND o.peer = ?3)",
        counted_receipt("?4", "?5")
    )))
    .bind(job_uid)
    .bind(arbiter)
    .bind(scanner)
    .bind(economy())
    .bind(crate::credits::JOB_OFFER_TTL_MS as i64)
    .bind(hlc::to_db(done_hlc))
    .fetch_one(pool)
    .await?)
}

/// Per scanner: its scans of paid jobs ([`job_paid`]) designated over the
/// last 7 days (leaving out the newest
/// [`crate::credits::AUDIT_OFFER_TTL_MS`], whose audits may still run, and
/// those with no auditor to buy from), and how many of them it bought: an
/// audit by one of the scan's [`auditors`] (by `members` as held here),
/// with an audit offer from the scanner to that auditor naming the scan
/// that the receipt the ledger counts ([`counted_receipt`]) charged.
pub async fn obligations(
    pool: &SqlitePool,
    members: &[MemberRow],
    now_ms: u64,
) -> Result<HashMap<NodeId, (u32, u32)>> {
    let from = hlc::to_db(now_ms.saturating_sub(7 * crate::credits::DAY_MS) << 16);
    let to = hlc::to_db(now_ms.saturating_sub(crate::credits::AUDIT_OFFER_TTL_MS) << 16);
    // (scanner, scan uid, job uid, arbiter, done HLC, level)
    type Row = (Vec<u8>, String, String, Vec<u8>, i64, i64);
    let scans: Vec<Row> = sqlx::query_as(
        "SELECT s.origin, s.uid, j.uid, j.arbiter, j.status_hlc, s.level FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.audit_of IS NULL AND s.origin IS NOT NULL AND s.uid IS NOT NULL
           AND s.level BETWEEN 1 AND 5 AND j.status = 'done'
           AND j.arbiter IS NOT NULL AND j.arbiter != s.origin
           AND j.status_hlc >= ? AND j.status_hlc < ?",
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    // (scan uid, auditor) of every audit the scanner paid its auditor for.
    let paid: Vec<(String, Vec<u8>)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT o.audit_uid, o.peer FROM credit_entries o
         JOIN credit_entries r ON r.charged_mc > 0 AND {}
         JOIN scans a ON a.audit_of = o.audit_uid AND a.origin = o.peer
         WHERE o.kind = 'offer' AND o.economy = ?1 AND o.audit_uid IS NOT NULL",
        counted_receipt("?1", "?2")
    )))
    .bind(economy())
    .bind(crate::credits::AUDIT_OFFER_TTL_MS as i64)
    .fetch_all(pool)
    .await?;
    let paid: std::collections::HashSet<(String, Vec<u8>)> = paid.into_iter().collect();
    let mut out: HashMap<NodeId, (u32, u32)> = HashMap::new();
    for (scanner_key, scan_uid, job_uid, arbiter, done, level) in scans {
        let Ok(scanner) = NodeId::from_slice(&scanner_key) else {
            continue;
        };
        let done = hlc::from_db(done);
        let s = seed(&job_uid, done);
        if !designated(&s) {
            continue;
        }
        // A scan with nobody to buy its audit from is owed nothing.
        let ranked = auditors(&s, members, &scanner, done, level.clamp(1, 5) as u8);
        if ranked.is_empty() || !job_paid(pool, &job_uid, &arbiter, &scanner_key, done).await? {
            continue;
        }
        let e = out.entry(scanner).or_default();
        e.0 += 1;
        if ranked
            .iter()
            .any(|a| paid.contains(&(scan_uid.clone(), a.0.to_vec())))
        {
            e.1 += 1;
        }
    }
    Ok(out)
}

/// Whether this node's scan workers would run an audit of an address
/// (parsed, as stored) of a scan of a job (its uid) at a level now: None,
/// or why not. Registered by `scan::run_workers` in [`Node::audit_check`].
pub type Check = Arc<
    dyn Fn(
            std::net::IpAddr,
            String,
            String,
            u8,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>>
        + Send
        + Sync,
>;

/// Release the open audit offers made to this node that can no longer be
/// accepted ([`AUDIT_WINDOW_MS`] after they were written) and whose audit
/// neither waits nor runs here, so their payers have them back at once
/// rather than when they lapse. Returns how many.
pub async fn release_stale(node: &Arc<Node>) -> usize {
    use crate::credits::ledger::OfferState;
    let (me, now) = (node.id(), hlc::wall_ms());
    let stale = |book: &crate::credits::Book| -> Vec<OfferRef> {
        book.ledger
            .offers
            .iter()
            .filter(|o| {
                o.to == me
                    && o.audit.is_some()
                    && o.state == OfferState::Open
                    && now > hlc::physical_ms(o.hlc) + AUDIT_WINDOW_MS
            })
            .map(|o| (o.payer, o.seq))
            .collect()
    };
    // The cached book may predate the receipt of an audit that just
    // ended: what it shows open is looked at again in a fresh one.
    match crate::credits::book(node).await {
        Ok(b) if !stale(&b).is_empty() => {}
        _ => return 0,
    }
    let Ok(book) = crate::credits::book_fresh(node).await else {
        return 0;
    };
    let stale = stale(&book);
    let mut released = 0;
    for offer in stale {
        let busy = node.audit_queue.lock().unwrap().holds(offer)
            || node.serving_offers.lock().unwrap().contains(&offer);
        if !busy {
            crate::credits::pay::release(node, offer.0, offer.1).await;
            released += 1;
        }
    }
    released
}

/// `(scanner, job uid, ip, level, done HLC)` of the scan `scan_uid` held
/// here, once its job is done and paid for ([`job_paid`]); waits up to
/// `SERVE_WAIT` for them to arrive.
async fn scan_of(node: &Node, scan_uid: &str) -> Option<(NodeId, String, String, u8, u64)> {
    let until = tokio::time::Instant::now() + crate::credits::pay::SERVE_WAIT;
    loop {
        // (scanner, job uid, ip, level, done HLC, arbiter)
        type Row = (Vec<u8>, String, String, i64, i64, Vec<u8>);
        let row: Option<Row> = sqlx::query_as(
            "SELECT s.origin, j.uid, i.ip, s.level, j.status_hlc, j.arbiter FROM scans s
             JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
             JOIN ips i ON i.id = s.ip_id
             WHERE s.uid = ? AND s.audit_of IS NULL AND j.status = 'done'
               AND j.arbiter IS NOT NULL AND j.arbiter != s.origin",
        )
        .bind(scan_uid)
        .fetch_optional(&node.store.pool)
        .await
        .ok()
        .flatten();
        let paid = match &row {
            Some((s, job, _, _, done, arbiter)) => {
                job_paid(&node.store.pool, job, arbiter, s, hlc::from_db(*done))
                    .await
                    .unwrap_or(false)
            }
            None => false,
        };
        if let Some((s, job, ip, level, done, _)) = row.filter(|_| paid) {
            return Some((
                NodeId::from_slice(&s).ok()?,
                job,
                ip,
                u8::try_from(level).ok()?,
                hlc::from_db(done),
            ));
        }
        if tokio::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Answer bought audits: check the scan, the ranking and the offer, then
/// queue the audit.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::AuditReq {
                scan_uid,
                offer_seq,
            } = msg
            else {
                return None;
            };
            let node = weak.upgrade()?;
            Some(match sell(&node, from, &scan_uid, offer_seq).await {
                Ok(()) => Msg::AuditReply {
                    accepted: true,
                    why: None,
                    price_mc: None,
                },
                Err(Refused { why, price_mc }) => Msg::AuditReply {
                    accepted: false,
                    why: Some(why),
                    price_mc,
                },
            })
        })
    }));
}

/// Why an audit was not sold, and the price it costs here when the offer
/// was too low.
#[derive(Debug, PartialEq)]
struct Refused {
    why: String,
    price_mc: Option<u32>,
}

impl From<&str> for Refused {
    fn from(why: &str) -> Self {
        Self {
            why: why.to_string(),
            price_mc: None,
        }
    }
}

impl From<String> for Refused {
    fn from(why: String) -> Self {
        Self {
            why,
            price_mc: None,
        }
    }
}

async fn sell(node: &Arc<Node>, peer: NodeId, scan_uid: &str, seq: u64) -> Result<(), Refused> {
    use crate::credits::{JOB_OFFER_TTL_MS, entries, pay, price};
    // Asked again with an offer whose audit waits or runs here: turned
    // down before anything could release that offer.
    if node.audit_queue.lock().unwrap().holds((peer, seq)) {
        return Err("this audit is queued already".into());
    }
    let refuse = async |why: &str| {
        pay::release(node, peer, seq).await;
        Err(why.into())
    };
    if !node.roles().scanner || scan_uid.is_empty() || scan_uid.len() > 128 {
        return refuse("this node audits no such scan").await;
    }
    let Some((scanner, job_uid, ip, level, done)) = scan_of(node, scan_uid).await else {
        return refuse("the scan or its paid, done job is not held here").await;
    };
    let s = seed(&job_uid, done);
    let members = match crate::cluster::members::all(&node.store).await {
        Ok(m) => m,
        Err(e) => return refuse(&format!("this node could not read its members: {e:#}")).await,
    };
    if scanner != peer || !(1..=5).contains(&level) || !designated(&s) {
        return refuse("not a designated scan of the asker").await;
    }
    if !auditors(&s, &members, &scanner, done, level).contains(&node.id()) {
        return refuse("this node is not among the scan's auditors").await;
    }
    // What would keep a worker here from running it: declined now, so the
    // scanner asks its next auditor.
    let check = node.audit_check.lock().unwrap().clone();
    let Some(check) = check else {
        return refuse("this node runs no scan workers").await;
    };
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return refuse("the scan's address does not parse").await;
    };
    if let Some(why) = check(addr, ip.clone(), job_uid.clone(), level).await {
        return refuse(&format!("this node does not scan that address now: {why}")).await;
    }
    let least = price::min_take(node.price_table().price_of(price::SCAN).unwrap_or(0)) as u64;
    // Accepted until AUDIT_WINDOW_MS after the offer was written: an audit
    // started by then ends, with its receipt, within the offer's lifetime.
    let accepted = match pay::accept_offer(node, peer, seq, least, "audit", JOB_OFFER_TTL_MS).await
    {
        Ok(a) => a,
        Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => return Err(w.into()),
        Err(pay::Declined::TooLow { why, price_mc }) => {
            return Err(Refused {
                why,
                price_mc: Some(price_mc),
            });
        }
    };
    let named = entries::get(&node.store.pool, &peer, seq)
        .await
        .ok()
        .flatten();
    let Some(entries::Entry {
        kind: entries::Kind::Offer {
            audit: Some(of), ..
        },
        ..
    }) = named
    else {
        return refuse("the offer buys no audit").await;
    };
    if of != scan_uid {
        return refuse("the offer is for another scan").await;
    }
    let task = Task {
        scan_uid: scan_uid.to_string(),
        job_uid,
        ip,
        level,
        deadline_ms: hlc::physical_ms(accepted.hlc) + AUDIT_WINDOW_MS,
        offer: Some((peer, seq, accepted.offered.min(u32::MAX as u64) as u32)),
    };
    // Checked and queued at once, while the offer still counts as served:
    // asked twice with one offer, the first answer stands.
    let queued = {
        let mut q = node.audit_queue.lock().unwrap();
        if q.holds((peer, seq)) {
            Some(false)
        } else {
            q.push(task).then_some(true)
        }
    };
    drop(accepted);
    match queued {
        Some(true) => Ok(()),
        Some(false) => Err("this audit is queued already".into()),
        None => refuse("this scanner has too many audits waiting").await,
    }
}

/// Buy the audit of this node's designated scan `scan_uid` from its
/// auditors in rank order: the first that is live, announces a scan price
/// and accepts, at that price (at least 1 mc); one that declines naming a
/// higher price is offered that once ([`crate::credits::pay::retry_price`]).
/// Returns the auditor.
pub async fn buy(node: &Arc<Node>, scan_uid: &str) -> Result<NodeId, String> {
    let me = node.id();
    let Some((scanner, job_uid, _, level, done)) = scan_of(node, scan_uid).await else {
        return Err("the scan or its paid, done job is not held here".into());
    };
    if scanner != me {
        return Err("not this node's scan".into());
    }
    let s = seed(&job_uid, done);
    if !designated(&s) {
        return Err("not designated".into());
    }
    let members = crate::cluster::members::all(&node.store)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let mut last = "no auditor is reachable".to_string();
    for auditor in auditors(&s, &members, &me, done, level) {
        let live = node
            .live_members(crate::intel::LIVE_WINDOW)
            .contains(&auditor);
        let price = node.status.known(&auditor).and_then(|k| k.hb.scan_price_mc);
        let (true, Some(price)) = (live && node.can_call(&auditor), price) else {
            continue;
        };
        // At least 1 mc: only charged audit offers count as bought.
        let mut offer = price.max(1) as u64;
        let mut retried = false;
        loop {
            let named = match ask(node, auditor, scan_uid, offer).await {
                Ok(()) => return Ok(auditor),
                Err((why, named)) => {
                    last = why;
                    named
                }
            };
            match crate::credits::pay::retry_price(offer, named, true) {
                Some(p) if !retried => {
                    retried = true;
                    offer = p;
                }
                _ => break,
            }
        }
    }
    Err(last)
}

/// Offer `auditor` `mc` for the audit of `scan_uid` and ask it: why it
/// declined, and the price it named, if any.
async fn ask(
    node: &Arc<Node>,
    auditor: NodeId,
    scan_uid: &str,
    mc: u64,
) -> Result<(), (String, Option<u32>)> {
    use crate::cluster::rpc::proto::ECONOMY_PROTO;
    let offer_seq =
        crate::credits::pay::make_offer_for(node, auditor, mc, Some(scan_uid.to_string()))
            .await
            .map_err(|e| (e, None))?;
    let req = Msg::AuditReq {
        scan_uid: scan_uid.to_string(),
        offer_seq,
    };
    // Members below protocol 7 cannot decode the request: never through them.
    let avoid = crate::cluster::owner::cmd::old_relays(node, &auditor, ECONOMY_PROTO);
    match node
        .request_avoiding(auditor, req, std::time::Duration::from_secs(30), avoid)
        .await
    {
        Ok(Msg::AuditReply { accepted: true, .. }) => Ok(()),
        Ok(Msg::AuditReply { why, price_mc, .. }) => {
            Err((why.unwrap_or_else(|| "declined".into()), price_mc))
        }
        Ok(_) => Err(("unexpected answer".into(), None)),
        Err(e) => Err((format!("could not be asked: {e:#}"), None)),
    }
}

/// This node's scans of paid jobs whose done status arrived since
/// `since_ms` and that are designated, leaving out those with an audit
/// offer still open or charged (one released by its auditor does not
/// count: the audit is bought anew).
async fn due(pool: &SqlitePool, me: &NodeId, since_ms: u64) -> Result<Vec<String>> {
    let rows: Vec<(String, String, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT s.uid, j.uid, j.arbiter, j.status_hlc FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.origin = ?1 AND s.audit_of IS NULL AND s.uid IS NOT NULL
           AND s.level BETWEEN 1 AND 5 AND j.status = 'done'
           AND j.arbiter IS NOT NULL AND j.arbiter != ?1 AND j.status_hlc >= ?2
           AND NOT EXISTS (SELECT 1 FROM credit_entries o
                           WHERE o.origin = ?1 AND o.audit_uid = s.uid
                             AND o.kind = 'offer' AND o.economy = ?3
                             AND NOT EXISTS (SELECT 1 FROM credit_entries r
                                             WHERE r.kind = 'receipt' AND r.economy = ?3
                                               AND r.origin = o.peer AND r.peer = o.origin
                                               AND r.offer_seq = o.seq AND r.charged_mc = 0))",
    )
    .bind(&me.0[..])
    .bind(hlc::to_db(since_ms << 16))
    .bind(economy())
    .fetch_all(pool)
    .await?;
    let mut out = vec![];
    for (scan_uid, job_uid, arbiter, done) in rows {
        let done = hlc::from_db(done);
        if designated(&seed(&job_uid, done))
            && job_paid(pool, &job_uid, &arbiter, &me.0, done).await?
        {
            out.push(scan_uid);
        }
    }
    Ok(out)
}

/// Buy the audits of this node's designated scans whose done status
/// arrived within the audit window and that it is not buying already
/// ([`due`]). A purchase that fails is tried again on the next run while
/// the scan is in its window. Returns how many it bought.
pub async fn buy_due(node: &Arc<Node>) -> usize {
    let me = node.id();
    let since = hlc::wall_ms().saturating_sub(AUDIT_WINDOW_MS);
    let rows = due(&node.store.pool, &me, since).await.unwrap_or_default();
    let mut bought = 0;
    for scan_uid in rows {
        if !node.audits_tried.lock().unwrap().insert(scan_uid.clone()) {
            continue;
        }
        match buy(node, &scan_uid).await {
            Ok(by) => {
                tracing::info!(scan = %scan_uid, auditor = %by.short(), "audit bought");
                bought += 1;
            }
            Err(why) => {
                tracing::info!(scan = %scan_uid, %why, "designated scan not audited yet");
                node.audits_tried.lock().unwrap().remove(&scan_uid);
            }
        }
    }
    bought
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn found(ports: &[u16], keys: &[(u16, &str, &str)]) -> Found {
        Found {
            open_tcp: ports.iter().copied().collect(),
            keys: keys
                .iter()
                .map(|(p, k, f)| (*p, k.to_string(), f.to_string()))
                .collect(),
        }
    }

    #[test]
    fn comparing_an_audit_with_the_scan_it_checks() {
        use Outcome::*;
        let none = found(&[], &[]);
        let original = found(&[22, 80, 443], &[(22, "ssh-hostkey", "aa")]);
        // The audit found no open port: the source may be gone.
        assert_eq!(compare(&original, &none), Inconclusive);
        assert_eq!(compare(&none, &none), Inconclusive);
        // At least half of what each side found open is open in both:
        // agrees, with a port changed since.
        assert_eq!(compare(&original, &found(&[22, 80, 8080], &[])), Agrees);
        assert_eq!(compare(&original, &found(&[22, 80, 443], &[])), Agrees);
        assert_eq!(compare(&original, &found(&[22, 80], &[])), Agrees);
        // Less than half of the audit's: differs.
        assert_eq!(compare(&original, &found(&[22, 8080, 8443], &[])), Differs);
        // Less than half of the scan's: it reported more than is there.
        assert_eq!(compare(&original, &found(&[22], &[])), Differs);
        // Nothing reported, something found: a made-up result.
        assert_eq!(compare(&none, &found(&[22], &[])), Differs);
        // The same host key on a port open in both settles it, whatever
        // else changed.
        let moved = found(&[22, 1, 2, 3, 4], &[(22, "ssh-hostkey", "aa")]);
        assert_eq!(compare(&original, &moved), Agrees);
        // Another key on that port does not; the ports decide.
        let other = found(&[22, 1, 2, 3, 4], &[(22, "ssh-hostkey", "bb")]);
        assert_eq!(compare(&original, &other), Differs);
        // The same key reported for a port that is not open in both.
        let elsewhere = found(&[2222, 1, 2], &[(2222, "ssh-hostkey", "aa")]);
        assert_eq!(compare(&original, &elsewhere), Differs);
        // A made-up "everything open" always contains what the audit
        // finds; it does not agree.
        let all_open = found(&(1..=65535).collect::<Vec<_>>(), &[]);
        assert_eq!(compare(&all_open, &found(&[22, 80], &[])), Differs);
        let top_1000 = found(&(1..=1000).collect::<Vec<_>>(), &[]);
        assert_eq!(compare(&top_1000, &found(&[22, 80, 443], &[])), Differs);
        // Honest, with a little churn on a busy host: agrees.
        let busy = found(&[21, 22, 25, 80, 110, 143, 443, 993], &[]);
        let later = found(&[21, 22, 25, 80, 110, 143, 443, 8443], &[]);
        assert_eq!(compare(&busy, &later), Agrees);
        // The same key settles it while the scan claims at most twice as
        // many open ports as the audit found.
        let key = [(22, "ssh-hostkey", "aa")];
        let modest = found(&[22, 80, 443, 8080, 8443, 9000], &key);
        assert_eq!(compare(&modest, &found(&[22, 3000, 3001], &key)), Agrees);
        let huge = found(&(1..=1000).collect::<Vec<_>>(), &key);
        assert_eq!(compare(&huge, &found(&[22, 3000, 3001], &key)), Differs);
        for o in [Agrees, Differs, Inconclusive] {
            assert_eq!(Outcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(Outcome::parse("x"), None);
    }

    #[test]
    fn the_audit_gate_needs_five_conclusive_audits_and_half_of_them_differing() {
        assert!(!audits_fail(4, 4), "too few");
        assert!(audits_fail(5, 3));
        assert!(!audits_fail(5, 2));
        assert!(audits_fail(6, 3), "half");
        assert!(!audits_fail(0, 0));
    }

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn scanner_member(n: u8, proto: u32) -> crate::cluster::members::MemberRow {
        crate::cluster::members::MemberRow {
            id: id(n),
            name: format!("n{n}"),
            address: Some(format!("198.51.100.{n}:7443")),
            roles: vec!["scanner".into()],
            proto_min: 2,
            proto_max: proto,
            sponsor: id(n),
            active: true,
            standing: crate::cluster::members::Standing::Active,
            info_hlc: 0,
            last_entry_hlc: 0,
            admitted_hlc: 0,
            remote_config: false,
        }
    }

    #[test]
    fn about_one_scan_in_twenty_is_designated_and_nobody_chooses_which() {
        let n = (0..20_000u64)
            .filter(|h| designated(&seed("job-x", *h << 16)))
            .count();
        assert!((800..1200).contains(&n), "{n} of 20000");
        // The same job and done status: the same answer everywhere.
        assert_eq!(seed("job-x", 7), seed("job-x", 7));
        assert_ne!(seed("job-x", 7), seed("job-y", 7));
        assert_ne!(seed("job-x", 7), seed("job-x", 8));
    }

    #[test]
    fn the_auditors_are_ranked_by_the_seed_never_the_scanner() {
        let members = [
            scanner_member(1, 7),
            scanner_member(2, 7),
            scanner_member(3, 7),
            scanner_member(4, 7),
            scanner_member(5, 6), // too old to be paid
        ];
        let s = seed("job-x", 7);
        let got = auditors(&s, &members, &id(1), 7, 2);
        assert_eq!(got.len(), AUDITORS);
        assert!(!got.contains(&id(1)), "never the scanner itself");
        assert!(!got.contains(&id(5)));
        assert_eq!(got, auditors(&s, &members, &id(1), 7, 2), "deterministic");
        // Another seed, another order (for some seed among a few).
        assert!((8..40u64).any(|h| auditors(&seed("job-x", h), &members, &id(1), h, 2) != got));
        let mut listener = scanner_member(6, 7);
        listener.roles = vec!["listener".into()];
        assert!(
            !auditors(&s, &[listener], &id(1), 7, 2).contains(&id(6)),
            "not a scanner"
        );
    }

    /// Level 5 is known from protocol 8 on: older scanners would decline
    /// its audit, so they are not ranked for it.
    #[test]
    fn a_level_5_scan_is_audited_by_scanners_that_know_level_5() {
        let p = crate::cluster::rpc::proto::VULN_SCAN_PROTO;
        let members = [
            scanner_member(1, p),
            scanner_member(2, p - 1),
            scanner_member(3, p),
            scanner_member(4, p - 1),
        ];
        let s = seed("job-x", 7);
        assert_eq!(auditors(&s, &members, &id(1), 7, 5), [id(3)]);
        let low = auditors(&s, &members, &id(1), 7, 4);
        assert_eq!(low.len(), 3, "{low:?}");
    }

    #[test]
    fn a_member_admitted_after_the_scan_was_done_is_no_auditor_of_it() {
        let mut late = scanner_member(2, 7);
        late.admitted_hlc = 100;
        let members = [scanner_member(1, 7), late, scanner_member(3, 7)];
        let s = seed("job-x", 50);
        assert_eq!(auditors(&s, &members, &id(1), 50, 2), [id(3)]);
        let all = auditors(&s, &members, &id(1), 100, 2);
        assert!(all.contains(&id(2)) && all.contains(&id(3)), "{all:?}");
    }

    #[test]
    fn a_scanner_owes_when_four_designated_scans_lack_an_audit_and_it_bought_under_60_percent() {
        assert_eq!(owes(0, 0), None);
        assert_eq!(owes(3, 0), None, "three misses are forgiven");
        assert_eq!(owes(4, 0), Some((0, 4)));
        assert_eq!(owes(10, 6), None, "60 %");
        assert_eq!(owes(10, 5), Some((5, 10)));
        assert_eq!(owes(20, 13), None, "seven misses, but 65 %");
        assert_eq!(owes(12, 7), Some((7, 12)), "58 %");
    }

    #[test]
    fn bought_audits_are_handed_out_first_and_late_ones_dropped() {
        let now = hlc::wall_ms();
        let task = |uid: &str, level: u8, deadline_ms: u64| Task {
            scan_uid: uid.into(),
            job_uid: format!("job-{uid}"),
            ip: "203.0.113.5".into(),
            level,
            deadline_ms,
            offer: Some((id(1), 7, 3)),
        };
        let mut q = Queue::default();
        assert!(q.push(task("late", 2, now - 1)));
        assert!(q.push(task("four", 4, now + 60_000)));
        assert!(q.push(task("two", 2, now + 60_000)));
        assert_eq!(q.take(&[4]).map(|t| t.scan_uid), Some("two".into()));
        assert_eq!(q.take(&[4]), None, "level 4 excluded, the late one dropped");
        assert_eq!(q.take(&[]).map(|t| t.scan_uid), Some("four".into()));
        // Taken, it runs until it ends; put back, it is first in line.
        let offer = (id(1), 7);
        assert!(q.holds(offer) && q.is_empty());
        q.end(offer);
        assert!(!q.holds(offer));
        assert!(q.push(task("next", 2, now + 60_000)));
        let t = q.take(&[]).unwrap();
        q.put_back(t);
        assert!(q.push(task("last", 2, now + 60_000)));
        assert!(q.holds(offer), "waiting");
        assert_eq!(q.take(&[]).map(|t| t.scan_uid), Some("next".into()));
    }

    #[tokio::test]
    async fn the_obligation_counts_designated_scans_and_audits_bought_from_their_auditors() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let pool = &store.pool;
        let (s, arbiter, auditor, stranger) = (id(1), id(9), id(2), id(3));
        let members = [scanner_member(1, 7), scanner_member(2, 7)];
        sqlx::query(
            "INSERT INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')",
        )
        .execute(pool)
        .await
        .unwrap();
        let now = hlc::wall_ms();
        let day_ago = |extra: u64| ((now - 86_400_000 - extra) << 16) | 1;
        // Three done jobs of another arbiter whose done status designates them.
        let mut hlcs = vec![];
        let mut h = 0u64;
        while hlcs.len() < 3 {
            if designated(&seed(&format!("job-{}", hlcs.len()), day_ago(h))) {
                hlcs.push(day_ago(h));
            }
            h += 1;
        }
        for (n, done) in hlcs.iter().enumerate() {
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid, origin, arbiter, scanner, status_hlc)
                 VALUES (1, 2, 'done', datetime('now'), ?1, ?2, ?2, ?3, ?4)",
            )
            .bind(format!("job-{n}")).bind(&arbiter.0[..]).bind(&s.0[..]).bind(hlc::to_db(*done))
            .execute(pool).await.unwrap();
            pay_job(pool, arbiter, s, &format!("job-{n}"), 10 + n as i64, 5).await;
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, hlc, job_id)
                 VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4,
                         (SELECT id FROM scan_jobs WHERE uid = ?3))",
            )
            .bind(format!("scan-{n}")).bind(&s.0[..]).bind(format!("job-{n}")).bind(hlc::to_db(*done))
            .execute(pool).await.unwrap();
        }
        // scan-0: audited by its auditor, paid. scan-1: audited by a node
        // that is no auditor of it, paid. scan-2: not audited.
        for (n, by) in [(0i64, auditor), (1, stranger)] {
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, audit_of, hlc, job_id)
                 VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4, ?5,
                         (SELECT id FROM scan_jobs WHERE uid = ?3))",
            )
            .bind(format!("audit-{n}")).bind(&by.0[..]).bind(format!("job-{n}")).bind(format!("scan-{n}")).bind(hlc::to_db(day_ago(0)))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, audit_uid)
                 VALUES (?1, ?2, ?3, 'offer', ?4, '[]', 1, 2, ?5)",
            )
            .bind(&s.0[..]).bind(n + 1).bind(hlc::to_db(day_ago(0))).bind(&by.0[..]).bind(format!("scan-{n}"))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
                 VALUES (?1, 1, ?2, 'receipt', ?3, '[]', ?4, 4, '[\"audit\"]', 0, 2)",
            )
            .bind(&by.0[..]).bind(hlc::to_db(day_ago(0) + 2)).bind(&s.0[..]).bind(n + 1)
            .execute(pool).await.unwrap();
        }
        let got = obligations(pool, &members, now).await.unwrap();
        assert_eq!(got.get(&s), Some(&(3, 1)), "{got:?}");
        assert_eq!(owes(3, 1), None, "two misses: not owed yet");
        // A receipt of nothing for the same offer came first: the ledger
        // counts that one, so the audit was not bought.
        sqlx::query(
            "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
             VALUES (?1, 0, ?2, 'receipt', ?3, '[]', 1, 0, '[]', 0, 2)",
        )
        .bind(&auditor.0[..])
        .bind(hlc::to_db(day_ago(0) + 1))
        .bind(&s.0[..])
        .execute(pool)
        .await
        .unwrap();
        let got = obligations(pool, &members, now).await.unwrap();
        assert_eq!(got.get(&s), Some(&(3, 0)), "{got:?}");
        // Alone, the scanner has no auditor: nothing is owed.
        let alone = obligations(pool, &members[..1], now).await.unwrap();
        assert_eq!(alone.get(&s), None, "{alone:?}");
    }

    /// An audit receipt counts as bought only where the ledger counts it:
    /// dated after its offer and before the offer lapsed.
    #[tokio::test]
    async fn an_audit_receipt_the_ledger_ignores_buys_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let pool = &store.pool;
        let (s, arbiter, auditor) = (id(1), id(9), id(2));
        let members = [scanner_member(1, 7), scanner_member(2, 7)];
        let ttl = crate::credits::AUDIT_OFFER_TTL_MS;
        let day = 86_400_000;
        let offer_ms = hlc::wall_ms() - day;
        // (name, receipt dated this many ms after the offer, bought)
        let cases = [
            ("early", -1i64, false),
            ("late", ttl as i64 + 1, false),
            ("in-time", ttl as i64, true),
        ];
        for (n, (name, after, _)) in cases.iter().enumerate() {
            let scan = designated_job(pool, arbiter, s, name, day).await;
            pay_job(pool, arbiter, s, &format!("job-{name}"), 100 + n as i64, 5).await;
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, audit_of, hlc, job_id)
                 VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4, ?5,
                         (SELECT id FROM scan_jobs WHERE uid = ?3))",
            )
            .bind(format!("audit-{name}")).bind(&auditor.0[..]).bind(format!("job-{name}")).bind(&scan).bind(hlc::to_db(offer_ms << 16))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, audit_uid)
                 VALUES (?1, ?2, ?3, 'offer', ?4, '[]', 1, 2, ?5)",
            )
            .bind(&s.0[..]).bind(n as i64 + 1).bind(hlc::to_db(offer_ms << 16)).bind(&auditor.0[..]).bind(&scan)
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
                 VALUES (?1, ?2, ?3, 'receipt', ?4, '[]', ?2, 4, '[\"audit\"]', 0, 2)",
            )
            .bind(&auditor.0[..]).bind(n as i64 + 1)
            .bind(hlc::to_db(((offer_ms as i64 + after) as u64) << 16)).bind(&s.0[..])
            .execute(pool).await.unwrap();
        }
        let got = obligations(pool, &members, hlc::wall_ms()).await.unwrap();
        assert_eq!(
            got.get(&s),
            Some(&(3, 1)),
            "only the receipt in time: {got:?}"
        );
    }

    /// The arbiter's offer funding `job` of `scanner`, and the scanner's
    /// receipt charging `charged` mc.
    async fn pay_job(
        pool: &SqlitePool,
        arbiter: NodeId,
        scanner: NodeId,
        job: &str,
        seq: i64,
        charged: i64,
    ) {
        sqlx::query(
            "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, job_uid)
             VALUES (?1, ?2, 1, 'offer', ?3, '[]', 1, 2, ?4)",
        )
        .bind(&arbiter.0[..])
        .bind(seq)
        .bind(&scanner.0[..])
        .bind(job)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
             VALUES (?1, ?2, 2, 'receipt', ?3, '[]', ?2, ?4, '[\"scan\"]', 0, 2)",
        )
        .bind(&scanner.0[..])
        .bind(seq)
        .bind(&arbiter.0[..])
        .bind(charged)
        .execute(pool)
        .await
        .unwrap();
    }

    /// A done job of `arbiter` scanned by `scanner`, designated, done
    /// `ago_ms` ago; returns its scan uid.
    async fn designated_job(
        pool: &SqlitePool,
        arbiter: NodeId,
        scanner: NodeId,
        name: &str,
        ago_ms: u64,
    ) -> String {
        sqlx::query(
            "INSERT OR IGNORE INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')",
        )
        .execute(pool)
        .await
        .unwrap();
        let job = format!("job-{name}");
        let at = hlc::wall_ms() - ago_ms;
        let done = (0u64..)
            .map(|i| ((at - i) << 16) | 1)
            .find(|h| designated(&seed(&job, *h)))
            .unwrap();
        sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid, origin, arbiter, scanner, status_hlc)
             VALUES (1, 2, 'done', datetime('now'), ?1, ?2, ?2, ?3, ?4)",
        )
        .bind(&job).bind(&arbiter.0[..]).bind(&scanner.0[..]).bind(hlc::to_db(done))
        .execute(pool).await.unwrap();
        let scan = format!("scan-{name}");
        sqlx::query(
            "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, hlc, job_id)
             VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4,
                     (SELECT id FROM scan_jobs WHERE uid = ?3))",
        )
        .bind(&scan).bind(&scanner.0[..]).bind(&job).bind(hlc::to_db(done))
        .execute(pool).await.unwrap();
        scan
    }

    /// Only the scans of paid jobs are designated: a job granted at no
    /// price (no offer) or one whose receipt charged nothing owes no audit.
    #[tokio::test]
    async fn only_scans_of_paid_jobs_are_owed_an_audit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let pool = &store.pool;
        let (s, arbiter) = (id(1), id(9));
        let members = [scanner_member(1, 7), scanner_member(2, 7)];
        let day = 86_400_000;
        let now = hlc::wall_ms() << 16;
        designated_job(pool, arbiter, s, "free", day).await;
        designated_job(pool, arbiter, s, "zero", day).await;
        pay_job(pool, arbiter, s, "job-zero", 1, 0).await;
        let got = obligations(pool, &members, hlc::wall_ms()).await.unwrap();
        assert_eq!(got.get(&s), None, "{got:?}");
        assert!(
            !job_paid(pool, "job-zero", &arbiter.0, &s.0, now)
                .await
                .unwrap()
        );
        designated_job(pool, arbiter, s, "paid", day).await;
        pay_job(pool, arbiter, s, "job-paid", 2, 5).await;
        assert!(
            job_paid(pool, "job-paid", &arbiter.0, &s.0, now)
                .await
                .unwrap()
        );
        // Paid by another arbiter than the job's, or to another scanner:
        // not this job's payment.
        assert!(
            !job_paid(pool, "job-paid", &id(8).0, &s.0, now)
                .await
                .unwrap()
        );
        assert!(
            !job_paid(pool, "job-paid", &arbiter.0, &id(2).0, now)
                .await
                .unwrap()
        );
        let got = obligations(pool, &members, hlc::wall_ms()).await.unwrap();
        assert_eq!(got.get(&s), Some(&(1, 0)), "{got:?}");
        // Receipts the ledger ignores pay nothing: one dated before the
        // offer, one after it lapsed.
        let ttl = crate::credits::JOB_OFFER_TTL_MS;
        for (job, seq, receipt_ms) in [
            ("job-early", 3i64, 999_999u64),
            ("job-late", 4, 1_000_000 + ttl + 1),
            ("job-in-time", 5, 1_000_000 + ttl),
        ] {
            pay_job(pool, arbiter, s, job, seq, 5).await;
            for (origin, at) in [(arbiter, 1_000_000u64), (s, receipt_ms)] {
                sqlx::query("UPDATE credit_entries SET hlc = ? WHERE origin = ? AND seq = ?")
                    .bind(hlc::to_db(at << 16))
                    .bind(&origin.0[..])
                    .bind(seq)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
        assert!(
            !job_paid(pool, "job-early", &arbiter.0, &s.0, now)
                .await
                .unwrap()
        );
        assert!(
            !job_paid(pool, "job-late", &arbiter.0, &s.0, now)
                .await
                .unwrap()
        );
        assert!(
            job_paid(pool, "job-in-time", &arbiter.0, &s.0, now)
                .await
                .unwrap()
        );
        // A receipt written after the arbiter's done status does not count:
        // the scanner could see whether the scan was designated first.
        let receipt = (1_000_000 + ttl) << 16;
        for (done, paid) in [(receipt, false), (receipt + 1, true)] {
            let got = job_paid(pool, "job-in-time", &arbiter.0, &s.0, done);
            assert_eq!(got.await.unwrap(), paid, "done at {done}");
        }
    }

    /// A scan is due for a purchase while no audit offer for it is open or
    /// charged; one its auditor released is bought anew.
    #[tokio::test]
    async fn a_designated_scan_is_due_until_an_offer_for_it_stands() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let pool = &store.pool;
        let (me, arbiter, auditor) = (id(1), id(9), id(2));
        let since = hlc::wall_ms() - AUDIT_WINDOW_MS;
        let free = designated_job(pool, arbiter, me, "free", 60_000).await;
        let paid = designated_job(pool, arbiter, me, "paid", 60_000).await;
        pay_job(pool, arbiter, me, "job-paid", 1, 5).await;
        let old = designated_job(pool, arbiter, me, "old", AUDIT_WINDOW_MS + 60_000).await;
        pay_job(pool, arbiter, me, "job-old", 2, 5).await;
        assert_eq!(
            due(pool, &me, since).await.unwrap(),
            std::slice::from_ref(&paid)
        );
        assert!(!due(pool, &me, since).await.unwrap().contains(&free));
        assert!(!due(pool, &me, since).await.unwrap().contains(&old));
        // An open offer: being bought.
        sqlx::query(
            "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, audit_uid)
             VALUES (?1, 100, 1, 'offer', ?2, '[]', 1, 2, ?3)",
        )
        .bind(&me.0[..]).bind(&auditor.0[..]).bind(&paid)
        .execute(pool).await.unwrap();
        assert!(due(pool, &me, since).await.unwrap().is_empty());
        // Released by the auditor: due again.
        sqlx::query(
            "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
             VALUES (?1, 1, 2, 'receipt', ?2, '[]', 100, 0, '[]', 0, 2)",
        )
        .bind(&auditor.0[..]).bind(&me.0[..])
        .execute(pool).await.unwrap();
        assert_eq!(due(pool, &me, since).await.unwrap(), [paid]);
    }

    async fn test_node() -> (tempfile::TempDir, Arc<Node>) {
        use crate::cluster::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                relay_slots: 16,
                peers: vec![],
            },
            roles: Default::default(),
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 30,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        (dir, node)
    }

    /// A purchase that fails is tried again on the next run.
    #[tokio::test]
    async fn a_failed_purchase_is_tried_again() {
        let (_dir, node) = test_node().await;
        let pool = &node.store.pool;
        let (me, arbiter) = (node.id(), id(9));
        let scan = designated_job(pool, arbiter, me, "x", 60_000).await;
        pay_job(pool, arbiter, me, "job-x", 1, 5).await;
        // Nobody else scans: there is no auditor to buy from.
        assert_eq!(
            buy(&node, &scan).await,
            Err("no auditor is reachable".into())
        );
        assert_eq!(buy_due(&node).await, 0);
        assert!(
            !node.audits_tried.lock().unwrap().contains(&scan),
            "not marked tried"
        );
        assert_eq!(
            due(pool, &me, hlc::wall_ms() - AUDIT_WINDOW_MS)
                .await
                .unwrap(),
            [scan]
        );
    }

    #[tokio::test]
    async fn stale_audit_offers_to_this_node_are_released_unless_their_audit_waits_or_runs() {
        let (_dir, node) = test_node().await;
        let pool = &node.store.pool;
        let now = hlc::wall_ms();
        let payer = id(1);
        // (seq, minutes ago, audit uid)
        let offers = [
            (1i64, 60u64, Some("stale")),
            (2, 60, Some("queued")),
            (3, 10, Some("fresh")),
            (4, 60, None),
        ];
        for (seq, mins, audit) in offers {
            let at = (now - mins * 60_000) << 16;
            let parts = format!("[[{},10]]", crate::credits::day_of(at));
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, audit_uid)
                 VALUES (?1, ?2, ?3, 'offer', ?4, ?5, 1, 2, ?6)",
            )
            .bind(&payer.0[..])
            .bind(seq)
            .bind(hlc::to_db(at))
            .bind(&node.id().0[..])
            .bind(parts)
            .bind(audit)
            .execute(pool)
            .await
            .unwrap();
        }
        assert!(node.audit_queue.lock().unwrap().push(Task {
            scan_uid: "queued".into(),
            job_uid: "job".into(),
            ip: "203.0.113.5".into(),
            level: 2,
            deadline_ms: now + 60_000,
            offer: Some((payer, 2, 10)),
        }));
        assert_eq!(release_stale(&node).await, 1);
        let released: Vec<i64> = sqlx::query_scalar(
            "SELECT offer_seq FROM credit_entries WHERE kind = 'receipt' AND origin = ? AND peer = ?",
        )
        .bind(&node.id().0[..])
        .bind(&payer.0[..])
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(released, [1], "only the stale audit offer nothing holds");
    }

    /// A scan row with one open port per entry of `ports`.
    async fn scan(
        store: &Store,
        uid: &str,
        origin: u8,
        audit_of: Option<&str>,
        ports: &[u16],
    ) -> i64 {
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO scan_jobs (uid, ip_id, level, status, queued_at)
             VALUES ('job', ?, 1, 'done', datetime('now'))",
        )
        .bind(ip.id)
        .execute(&store.pool)
        .await
        .unwrap();
        let id: i64 = sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, audit_of)
             VALUES (?, ?, ?, (SELECT id FROM scan_jobs WHERE uid = 'job'), 'job', ?, 1,
                     datetime('now'), ?)",
        )
        .bind(uid)
        .bind(&self::id(origin).0[..])
        .bind((hlc::wall_ms() << 16) as i64)
        .bind(ip.id)
        .bind(audit_of)
        .execute(&store.pool)
        .await
        .unwrap()
        .last_insert_rowid();
        for p in ports {
            sqlx::query(
                "INSERT INTO ports (scan_id, port, proto, state) VALUES (?, ?, 'tcp', 'open')",
            )
            .bind(id)
            .bind(*p as i64)
            .execute(&store.pool)
            .await
            .unwrap();
        }
        id
    }

    #[tokio::test]
    async fn audits_are_compared_once_and_counted_per_auditor() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // Scanner 1 reported nothing; auditors 2 and 3 found a port.
        let orig = scan(&store, "o1", 1, None, &[]).await;
        scan(&store, "a1", 2, Some("o1"), &[22]).await;
        scan(&store, "a2", 3, Some("o1"), &[22]).await;
        // An honest scan of scanner 1, audited by 2: agrees. A closed, UDP
        // and filtered port do not count as open TCP.
        let honest = scan(&store, "o2", 1, None, &[22, 80]).await;
        sqlx::query(
            "INSERT INTO ports (scan_id, port, proto, state) VALUES
               (?1, 53, 'udp', 'open'), (?1, 81, 'tcp', 'closed'), (?1, 82, 'tcp', 'filtered')",
        )
        .bind(honest)
        .execute(&store.pool)
        .await
        .unwrap();
        scan(&store, "a3", 2, Some("o2"), &[22]).await;
        // The audit found nothing; and one whose scan is not held here.
        scan(&store, "a4", 2, Some("o2"), &[]).await;
        scan(&store, "a5", 2, Some("gone"), &[22]).await;
        assert_eq!(
            super::found(&store.pool, orig).await.unwrap(),
            Found::default()
        );
        assert_eq!(
            super::found(&store.pool, honest).await.unwrap().open_tcp,
            [22u16, 80].into_iter().collect()
        );

        assert_eq!(settle(&store.pool).await.unwrap(), 4);
        assert_eq!(settle(&store.pool).await.unwrap(), 0, "once");
        let pool = &store.pool;
        let result = |uid: &'static str| async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT audit_result FROM scans WHERE uid = ?")
                .bind(uid)
                .fetch_one(pool)
                .await
                .unwrap()
        };
        assert_eq!(result("a1").await.as_deref(), Some("differs"));
        assert_eq!(result("a3").await.as_deref(), Some("agrees"));
        assert_eq!(result("a4").await.as_deref(), Some("inconclusive"));
        assert_eq!(result("a5").await, None, "nothing to compare with");

        let all = counts(&store.pool, 0).await.unwrap();
        let n = |auditor: u8, o: Outcome| {
            all.iter()
                .find(|c| c.scanner == id(1) && c.auditor == id(auditor) && c.outcome == o)
                .map_or(0, |c| c.n)
        };
        assert_eq!((n(2, Outcome::Differs), n(2, Outcome::Agrees)), (1, 1));
        assert_eq!(n(2, Outcome::Inconclusive), 1);
        assert_eq!(n(3, Outcome::Differs), 1);
        // Only the auditors a node believes count; inconclusive ones never.
        assert_eq!(counted(&all, &[id(2)]).get(&id(1)), Some(&(2, 1)));
        assert_eq!(counted(&all, &[id(2), id(3)]).get(&id(1)), Some(&(3, 2)));
        assert_eq!(counted(&all, &[id(9)]).get(&id(1)), None);
        // A scanner's audit of its own scan counts for nothing.
        scan(&store, "a6", 1, Some("o1"), &[22]).await;
        settle(&store.pool).await.unwrap();
        let all = counts(&store.pool, 0).await.unwrap();
        assert_eq!(counted(&all, &[id(1), id(2)]).get(&id(1)), Some(&(2, 1)));
    }

    /// A scan row by `origin` that finished `mins_ago` minutes ago.
    async fn finished(store: &Store, uid: &str, origin: u8, mins_ago: i64, level: i64) {
        let id = scan(store, uid, origin, None, &[22]).await;
        sqlx::query("UPDATE scans SET level = ?, finished_at = datetime('now', ?) WHERE id = ?")
            .bind(level)
            .bind(format!("-{mins_ago} minutes"))
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_scans_of_other_nodes_are_picked_by_chance() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let me = id(9);
        finished(&store, "before", 1, 1, 1).await;
        let mut all = Picker::new(1.0);
        let mut none = Picker::new(0.0);
        // The first look only notes where the table stands.
        all.poll(&store.pool, &me).await.unwrap();
        none.poll(&store.pool, &me).await.unwrap();
        assert!(all.take(&[]).is_none());

        finished(&store, "fresh", 1, 1, 1).await;
        finished(&store, "mine", 9, 1, 1).await;
        finished(&store, "late", 1, 31, 1).await;
        finished(&store, "big", 1, 2, 4).await;
        scan(&store, "an-audit", 1, Some("fresh"), &[22]).await;
        all.poll(&store.pool, &me).await.unwrap();
        none.poll(&store.pool, &me).await.unwrap();
        assert!(none.take(&[]).is_none(), "share 0 audits nothing");

        // Level 4 is held back while this scanner is at its level-4 share.
        let t = all.take(&[4]).expect("the fresh scan of another node");
        assert_eq!(
            (t.scan_uid.as_str(), t.job_uid.as_str(), t.level),
            ("fresh", "job", 1)
        );
        assert_eq!(t.ip, "203.0.113.9");
        assert!(all.take(&[4]).is_none());
        assert_eq!(all.take(&[]).unwrap().scan_uid, "big");
        assert!(
            all.take(&[]).is_none(),
            "not its own, not an old one, not an audit"
        );
        // Seen once: the next look does not offer them again.
        all.poll(&store.pool, &me).await.unwrap();
        assert!(all.take(&[]).is_none());

        // An audit that was not started in time is dropped.
        finished(&store, "slow", 1, 29, 1).await;
        all.poll(&store.pool, &me).await.unwrap();
        all.queue[0].deadline_ms = hlc::wall_ms() - 1;
        assert!(all.take(&[]).is_none());
    }

    /// A burst larger than one look is read over several: the mark does
    /// not jump past the rows that were not read yet.
    #[tokio::test]
    async fn a_burst_of_scans_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let me = id(9);
        let mut p = Picker::new(1.0);
        p.poll(&store.pool, &me).await.unwrap();
        for i in 0..POLL_BATCH {
            finished(&store, &format!("late-{i}"), 1, 31, 1).await;
        }
        finished(&store, "fresh", 1, 1, 1).await;
        p.poll(&store.pool, &me).await.unwrap();
        assert!(p.take(&[]).is_none(), "the first look reads the late ones");
        p.poll(&store.pool, &me).await.unwrap();
        assert_eq!(p.take(&[]).unwrap().scan_uid, "fresh");
    }

    #[test]
    fn the_audit_window_starts_no_earlier_than_the_scan_arrived() {
        let (now, min) = (10_000_000u64, 60_000u64);
        assert_eq!(
            audit_from(Some(now - min), Some(now - 2 * min), now),
            Some(now - min)
        );
        // Without a finish date, or one dated back an hour: from its arrival.
        assert_eq!(audit_from(None, Some(now - min), now), Some(now - min));
        assert_eq!(audit_from(Some(now - 60 * min), Some(now), now), Some(now));
        assert_eq!(
            audit_from(Some(now + 60 * min), Some(now), now),
            Some(now),
            "future"
        );
        assert_eq!(audit_from(None, None, now), None);
    }
}
