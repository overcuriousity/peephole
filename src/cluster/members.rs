//! Cluster membership, materialized from member records.
//!
//! - `member_add` (by another member) admits a node; it fills in the
//!   node's description only until the node describes itself.
//! - `member_update` (by the node itself) sets its description, last write
//!   wins by HLC; it can never admit or re-admit.
//! - `member_revoke` is honoured only from the node it names: that is how
//!   a node leaves. Nobody can remove another node. A later add re-admits.
use super::Node;
use super::identity::NodeId;
use super::record::{MemberInfo, Record, WireEntry};
use anyhow::Result;
use sqlx::SqliteConnection;
use tracing::{info, warn};

/// A member without any sign of life for this long is pruned.
pub const PRUNE_AFTER_MS: u64 = 30 * 24 * 3600 * 1000;
/// A running node writes at least one entry this often, so it stays visible.
pub const KEEPALIVE_MS: u64 = 24 * 3600 * 1000;
/// New admissions one member may make per day (by the admissions' HLCs,
/// so every node reaches the same verdict). Keys are free: without a limit
/// one member could flood the cluster with members.
pub const ADMISSIONS_PER_DAY: i64 = 20;
const DAY_MS: u64 = 24 * 3600 * 1000;

/// A member's standing as this node computes it from its copy of the log.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub enum Standing {
    Active,
    /// It left by itself.
    Left,
    /// No sign of life for [`PRUNE_AFTER_MS`].
    Pruned,
    /// Known (e.g. it described itself) but never admitted.
    NotAdmitted,
}

impl Standing {
    pub fn label(&self) -> &'static str {
        match self {
            Standing::Active => "active",
            Standing::Left => "left",
            Standing::Pruned => "pruned",
            Standing::NotAdmitted => "not admitted",
        }
    }
}

/// Signs of life are the newest entry the member signed and its latest
/// admission. Entries are signed by their origin, so nobody can make another
/// node look stale, and evidence relayed by any member counts. An entry
/// counts at its HLC but no later than this node received it (plus the
/// allowed clock drift): a clock running ahead buys no extra life.
pub fn standing(
    admitted_hlc: u64,
    left_hlc: Option<u64>,
    last_entry_hlc: u64,
    last_entry_received_ms: u64,
    now_ms: u64,
) -> Standing {
    if admitted_hlc == 0 {
        return Standing::NotAdmitted;
    }
    if left_hlc.is_some_and(|l| l >= admitted_hlc) {
        return Standing::Left;
    }
    // Only the millisecond counts here, not the order within it.
    let entry = super::hlc::effective(last_entry_hlc, 0, last_entry_received_ms);
    let evidence = super::hlc::physical_ms(admitted_hlc.max(entry));
    if now_ms.saturating_sub(evidence) > PRUNE_AFTER_MS {
        Standing::Pruned
    } else {
        Standing::Active
    }
}

/// An admission time no later than now (`seq`: the entry's, see
/// [`super::hlc::cap`]). A sponsor's timestamp from the future must not
/// outrank what the admitted node decides later (leaving), nor count as a
/// sign of life that has not happened yet.
fn not_future(hlc: u64, seq: u64) -> u64 {
    super::hlc::cap(hlc, seq, (super::hlc::wall_ms() << 16) | 0xffff)
}

/// A member row as the UI and CLI show it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberRow {
    pub id: NodeId,
    pub name: String,
    pub address: Option<String>,
    pub roles: Vec<String>,
    pub proto_min: u32,
    pub proto_max: u32,
    pub sponsor: NodeId,
    /// `standing == Standing::Active`.
    pub active: bool,
    pub standing: Standing,
    /// HLC of the latest self-description (0: never described itself).
    pub info_hlc: u64,
    /// HLC of the newest log entry this member signed (0: none held).
    pub last_entry_hlc: u64,
    /// The member lets config key holders change its runtime settings.
    pub remote_config: bool,
}

type Row = (
    Vec<u8>,
    String,
    Option<String>,
    String,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    i64,
    Option<i64>,
    Option<i64>,
);

const SELECT: &str = "SELECT id, name, address, roles_json, proto_min, proto_max,
                             sponsor, info_hlc, admitted_hlc, revoked_hlc, remote_config,
                             (SELECT l.hlc FROM repl_log l
                              WHERE l.origin = members.id AND l.sig IS NOT NULL
                              ORDER BY l.seq DESC LIMIT 1),
                             (SELECT CAST(strftime('%s', l.received_at) AS INTEGER) * 1000
                              FROM repl_log l
                              WHERE l.origin = members.id AND l.sig IS NOT NULL
                              ORDER BY l.seq DESC LIMIT 1)
                      FROM members";

fn from_row(r: Row, now_ms: u64) -> Result<MemberRow> {
    let last_entry_hlc = super::hlc::from_db(r.11.unwrap_or(0));
    let received = super::hlc::from_db(r.12.unwrap_or(0));
    let standing = standing(
        super::hlc::from_db(r.8),
        r.9.map(super::hlc::from_db),
        last_entry_hlc,
        received,
        now_ms,
    );
    Ok(MemberRow {
        id: NodeId::from_slice(&r.0)?,
        name: r.1,
        address: r.2,
        roles: serde_json::from_str(&r.3).unwrap_or_default(),
        proto_min: r.4 as u32,
        proto_max: r.5 as u32,
        sponsor: NodeId::from_slice(&r.6)?,
        info_hlc: r.7 as u64,
        active: standing == Standing::Active,
        standing,
        last_entry_hlc,
        remote_config: r.10 != 0,
    })
}

/// Every member row with its standing as of now.
pub async fn all(store: &crate::store::Store) -> Result<Vec<MemberRow>> {
    all_at(store, super::hlc::wall_ms()).await
}

/// Like [`all`], judged at `now_ms` (tests).
pub async fn all_at(store: &crate::store::Store, now_ms: u64) -> Result<Vec<MemberRow>> {
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY name")))
        .fetch_all(&store.pool)
        .await?;
    rows.into_iter().map(|r| from_row(r, now_ms)).collect()
}

async fn get(conn: &mut SqliteConnection, id: &NodeId) -> Result<Option<MemberRow>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = ?")))
        .bind(&id.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    row.map(|r| from_row(r, super::hlc::wall_ms())).transpose()
}

async fn write_info(conn: &mut SqliteConnection, info: &MemberInfo, info_hlc: u64) -> Result<()> {
    sqlx::query(
        "UPDATE members SET name = ?, address = ?, roles_json = ?,
                proto_min = ?, proto_max = ?, remote_config = ?, info_hlc = ? WHERE id = ?",
    )
    .bind(&info.name)
    .bind(&info.address)
    .bind(serde_json::to_string(&info.roles)?)
    .bind(info.proto_min as i64)
    .bind(info.proto_max as i64)
    .bind(info.remote_config)
    .bind(info_hlc as i64)
    .bind(&info.id.0[..])
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn insert(
    conn: &mut SqliteConnection,
    info: &MemberInfo,
    sponsor: &NodeId,
    info_hlc: u64,
    admitted_hlc: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO members (id, name, address, roles_json, proto_min, proto_max,
                              remote_config, sponsor, info_hlc, admitted_hlc)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&info.id.0[..])
    .bind(&info.name)
    .bind(&info.address)
    .bind(serde_json::to_string(&info.roles)?)
    .bind(info.proto_min as i64)
    .bind(info.proto_max as i64)
    .bind(info.remote_config)
    .bind(&sponsor.0[..])
    .bind(info_hlc as i64)
    .bind(admitted_hlc as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// A member description as stored: a name of 1-64 printable characters
/// (otherwise one derived from the key), a dialable `host:port` or none,
/// and only role names this version knows. Every node cleans a description
/// the same way, so a member cannot make others dial or show junk.
pub fn sanitize(info: &MemberInfo) -> MemberInfo {
    let name = info.name.trim();
    let name = if valid_name(name) {
        name.to_string()
    } else {
        format!("node-{}", info.id.short())
    };
    let mut roles: Vec<String> = vec![];
    for r in &info.roles {
        if ["listener", "scanner", "web"].contains(&r.as_str()) && !roles.contains(r) {
            roles.push(r.clone());
        }
    }
    MemberInfo {
        id: info.id,
        name,
        address: info.address.clone().filter(|a| valid_address(a)),
        roles,
        proto_min: info.proto_min,
        proto_max: info.proto_max,
        remote_config: info.remote_config,
    }
}

/// 1-64 characters, none of them control characters.
pub fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=64).contains(&n) && !name.chars().any(char::is_control)
}

/// `host:port` with a DNS name or IP address and a non-zero port.
pub fn valid_address(addr: &str) -> bool {
    if addr.len() > 255 {
        return false;
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if !port.parse::<u16>().is_ok_and(|p| p > 0) {
        return false;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Whether the origin of `e` may admit `member` at `at`: it has not left,
/// was not pruned before writing this (no sign of life for the prune window
/// before it), and stays within [`ADMISSIONS_PER_DAY`]. Each sponsor's
/// admissions arrive in its own log order, so the verdict is the same on
/// every node.
async fn may_sponsor(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    member: &NodeId,
    at: u64,
) -> Result<bool> {
    let sponsor = e.origin;
    if sponsor != node.id() {
        let row: Option<(i64, Option<i64>)> =
            sqlx::query_as("SELECT admitted_hlc, revoked_hlc FROM members WHERE id = ?")
                .bind(&sponsor.0[..])
                .fetch_optional(&mut *conn)
                .await?;
        let Some((admitted, revoked)) = row else {
            return Ok(false);
        };
        let admitted = super::hlc::from_db(admitted);
        if revoked.is_some_and(|l| super::hlc::from_db(l) >= admitted) {
            warn!(sponsor = %sponsor.short(), member = %member.short(),
                  "ignored member_add by a node that left");
            return Ok(false);
        }
        // Its previous sign of life: the entry before this one, or its
        // admission.
        let prev: Option<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT hlc, CAST(strftime('%s', received_at) AS INTEGER) * 1000 FROM repl_log
             WHERE origin = ? AND seq < ? AND sig IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(&sponsor.0[..])
        .bind(e.seq.min(i64::MAX as u64) as i64)
        .fetch_optional(&mut *conn)
        .await?;
        let prev = prev.map_or(0, |(h, r)| {
            super::hlc::effective(
                super::hlc::from_db(h),
                0,
                super::hlc::from_db(r.unwrap_or(0)),
            )
        });
        // The entry before this one is not held (history below this node's
        // floor): silence cannot be judged across that gap.
        let gap = e.seq > 1 && {
            let n: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM repl_log WHERE origin = ? AND seq = ?")
                    .bind(&sponsor.0[..])
                    .bind((e.seq - 1).min(i64::MAX as u64) as i64)
                    .fetch_one(&mut *conn)
                    .await?;
            n == 0
        };
        let evidence = super::hlc::physical_ms(admitted.max(prev));
        if !gap && super::hlc::physical_ms(at).saturating_sub(evidence) > PRUNE_AFTER_MS {
            warn!(sponsor = %sponsor.short(), member = %member.short(),
                  "ignored member_add by a node that was pruned");
            return Ok(false);
        }
    }
    let known: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sponsorships WHERE sponsor = ? AND member = ?")
            .bind(&sponsor.0[..])
            .bind(&member.0[..])
            .fetch_one(&mut *conn)
            .await?;
    if known > 0 {
        return Ok(true);
    }
    let since = at.saturating_sub(DAY_MS << 16);
    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sponsorships WHERE sponsor = ? AND hlc > ? AND hlc <= ?",
    )
    .bind(&sponsor.0[..])
    .bind(super::hlc::to_db(since))
    .bind(super::hlc::to_db(at))
    .fetch_one(&mut *conn)
    .await?;
    if recent >= ADMISSIONS_PER_DAY {
        warn!(sponsor = %sponsor.short(), member = %member.short(),
              "ignored member_add over the sponsor's daily admission limit");
        return Ok(false);
    }
    Ok(true)
}

/// Whether this node may admit `member` now (checked before an invite is
/// used up: peers would ignore an admission over the daily limit).
pub async fn can_admit(node: &Node, member: &NodeId) -> Result<bool> {
    let mut conn = node.store.pool.acquire().await?;
    let probe = WireEntry {
        origin: node.id(),
        seq: u64::MAX,
        hlc: node.hlc.now(),
        kind: String::new(),
        uid: None,
        payload: None,
        sig: None,
        erased_by: None,
    };
    may_sponsor(
        node,
        &mut conn,
        &probe,
        member,
        not_future(probe.hlc, probe.seq),
    )
    .await
}

/// The nodes `root` admitted, the nodes those admitted, and so on (not
/// `root` itself nor `except`), for blocking a sponsor's whole subtree.
pub async fn subtree(
    store: &crate::store::Store,
    root: NodeId,
    except: NodeId,
) -> Result<Vec<NodeId>> {
    let mut seen = std::collections::HashSet::from([root, except]);
    let mut queue = std::collections::VecDeque::from([root]);
    let mut out = vec![];
    while let Some(s) = queue.pop_front() {
        let admitted: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT member FROM sponsorships WHERE sponsor = ? ORDER BY hlc")
                .bind(&s.0[..])
                .fetch_all(&store.pool)
                .await?;
        for m in admitted {
            let Ok(id) = NodeId::from_slice(&m) else {
                continue;
            };
            if seen.insert(id) {
                out.push(id);
                queue.push_back(id);
            }
        }
    }
    Ok(out)
}

/// Effects of a membership record; returns true if it was one. `at` is the
/// record's HLC as this node orders it (never later than its receipt).
pub async fn apply(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
    at: u64,
) -> Result<bool> {
    match r {
        Record::MemberAdd(info) => {
            if info.id == e.origin {
                warn!(origin = %e.origin.short(), "ignored self-sponsored member_add");
                return Ok(true);
            }
            let info = &sanitize(info);
            let at = not_future(at, e.seq);
            if !may_sponsor(node, conn, e, &info.id, at).await? {
                return Ok(true);
            }
            sqlx::query(
                "INSERT OR IGNORE INTO sponsorships (sponsor, member, hlc) VALUES (?, ?, ?)",
            )
            .bind(&e.origin.0[..])
            .bind(&info.id.0[..])
            .bind(super::hlc::to_db(at))
            .execute(&mut *conn)
            .await?;
            match get(conn, &info.id).await? {
                None => {
                    insert(conn, info, &e.origin, 0, at).await?;
                    info!(member = %info.name, id = %info.id.short(), by = %e.origin.short(), "member admitted");
                }
                Some(m) => {
                    sqlx::query(
                        "UPDATE members SET admitted_hlc = MAX(admitted_hlc, ?) WHERE id = ?",
                    )
                    .bind(super::hlc::to_db(at))
                    .bind(&info.id.0[..])
                    .execute(&mut *conn)
                    .await?;
                    if m.info_hlc == 0 {
                        write_info(conn, info, 0).await?;
                    }
                }
            }
        }
        Record::MemberUpdate(info) => {
            if info.id != e.origin {
                warn!(origin = %e.origin.short(), "ignored member_update for another node");
                return Ok(true);
            }
            let info = &sanitize(info);
            match get(conn, &info.id).await? {
                // Only this node's own first description lands here: any
                // other origin had to be admitted before its entries apply.
                None => {
                    let admitted = if info.id == node.id() { at } else { 0 };
                    insert(conn, info, &e.origin, at, admitted).await?;
                }
                Some(m) if at > m.info_hlc => write_info(conn, info, at).await?,
                Some(_) => {}
            }
        }
        Record::MemberRevoke { id } => {
            if *id != e.origin {
                warn!(
                    origin = %e.origin.short(),
                    target = %id.short(),
                    "ignored member_revoke for another node: a node can only remove itself"
                );
                return Ok(true);
            }
            sqlx::query(
                "UPDATE members SET revoked_hlc = MAX(COALESCE(revoked_hlc, 0), ?), revoked_by = ?
                 WHERE id = ?",
            )
            .bind(super::hlc::to_db(not_future(at, e.seq)))
            .bind(&e.origin.0[..])
            .bind(&id.0[..])
            .execute(&mut *conn)
            .await?;
            info!(id = %id.short(), "member left the cluster");
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600 * 1000;

    fn hlc(ms: u64) -> u64 {
        ms << 16
    }

    #[test]
    fn standing_follows_admission_leave_and_evidence() {
        let now = 1_000 * DAY;
        assert_eq!(standing(0, None, hlc(now), now, now), Standing::NotAdmitted);
        assert_eq!(standing(hlc(now), None, 0, 0, now), Standing::Active);
        // Left: the leave is newer than the admission; a later add re-admits.
        assert_eq!(
            standing(hlc(now - DAY), Some(hlc(now)), hlc(now), now, now),
            Standing::Left
        );
        assert_eq!(
            standing(hlc(now), Some(hlc(now - DAY)), 0, 0, now),
            Standing::Active
        );
        // 31 days without an entry: pruned. Either kind of evidence revives.
        let old = hlc(now - 31 * DAY);
        assert_eq!(standing(old, None, old, now, now), Standing::Pruned);
        assert_eq!(
            standing(old, None, hlc(now - DAY), now, now),
            Standing::Active
        );
        assert_eq!(
            standing(hlc(now - DAY), None, old, now, now),
            Standing::Active
        );
        // Exactly at the limit is still active.
        let edge = hlc(now - 30 * DAY);
        assert_eq!(standing(edge, None, edge, now, now), Standing::Active);
    }

    /// A clock running ahead buys no extra life: an entry counts no later
    /// than its receipt (plus the allowed drift). Before, a member whose
    /// entries were dated 400 days ahead never looked stale.
    #[test]
    fn a_clock_running_ahead_counts_from_receipt() {
        let now = 1_000 * DAY;
        let future = hlc(now + 400 * DAY);
        // Received just now: alive.
        assert_eq!(
            standing(hlc(now - 40 * DAY), None, future, now, now),
            Standing::Active
        );
        // Received 31 days ago and silent since: pruned, whatever it claimed.
        assert_eq!(
            standing(hlc(now - 40 * DAY), None, future, now - 31 * DAY, now),
            Standing::Pruned
        );
    }

    #[test]
    fn member_descriptions_are_cleaned() {
        let id = crate::cluster::identity::Identity::generate().unwrap().id;
        let info = |name: &str, addr: Option<&str>, roles: &[&str]| MemberInfo {
            id,
            name: name.into(),
            address: addr.map(str::to_string),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            proto_min: 2,
            proto_max: 2,
            remote_config: false,
        };
        let ok = sanitize(&info(
            " a ",
            Some("node.example:7443"),
            &["scanner", "scanner"],
        ));
        assert_eq!(ok.name, "a");
        assert_eq!(ok.address.as_deref(), Some("node.example:7443"));
        assert_eq!(ok.roles, vec!["scanner".to_string()]);
        assert_eq!(
            sanitize(&info("x", Some("[2001:db8::1]:7443"), &[]))
                .address
                .as_deref(),
            Some("[2001:db8::1]:7443")
        );
        let long = "x".repeat(65);
        let bad = sanitize(&info(&long, Some("evil host:99999"), &["root", "web"]));
        assert_eq!(bad.name, format!("node-{}", id.short()));
        assert_eq!(bad.address, None);
        assert_eq!(bad.roles, vec!["web".to_string()]);
        for a in ["nohost", ":7443", "h:0", "h:x", "a/b:1", "-h:1", "[::zz]:1"] {
            assert!(!valid_address(a), "{a}");
        }
        assert!(!valid_name("bell\u{7}"));
        assert!(!valid_name(""));
    }
}
