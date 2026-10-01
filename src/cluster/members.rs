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
/// node look stale, and evidence relayed by any member counts.
pub fn standing(
    admitted_hlc: u64,
    left_hlc: Option<u64>,
    last_entry_hlc: u64,
    now_ms: u64,
) -> Standing {
    if admitted_hlc == 0 {
        return Standing::NotAdmitted;
    }
    if left_hlc.is_some_and(|l| l >= admitted_hlc) {
        return Standing::Left;
    }
    let evidence = super::hlc::physical_ms(admitted_hlc.max(last_entry_hlc));
    if now_ms.saturating_sub(evidence) > PRUNE_AFTER_MS {
        Standing::Pruned
    } else {
        Standing::Active
    }
}

/// An admission time no later than now. A sponsor's timestamp from the
/// future must not outrank what the admitted node decides later (leaving),
/// nor count as a sign of life that has not happened yet.
fn not_future(hlc: u64) -> u64 {
    hlc.min((super::hlc::wall_ms() << 16) | 0xffff)
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
);

const SELECT: &str = "SELECT id, name, address, roles_json, proto_min, proto_max,
                             sponsor, info_hlc, admitted_hlc, revoked_hlc, remote_config,
                             (SELECT l.hlc FROM repl_log l
                              WHERE l.origin = members.id AND l.sig IS NOT NULL
                              ORDER BY l.seq DESC LIMIT 1)
                      FROM members";

fn from_row(r: Row, now_ms: u64) -> Result<MemberRow> {
    let last_entry_hlc = r.11.unwrap_or(0) as u64;
    let standing = standing(r.8 as u64, r.9.map(|v| v as u64), last_entry_hlc, now_ms);
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

/// Effects of a membership record; returns true if it was one.
pub async fn apply(
    node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<bool> {
    match r {
        Record::MemberAdd(info) => {
            if info.id == e.origin {
                warn!(origin = %e.origin.short(), "ignored self-sponsored member_add");
                return Ok(true);
            }
            let at = not_future(e.hlc);
            match get(conn, &info.id).await? {
                None => {
                    insert(conn, info, &e.origin, 0, at).await?;
                    info!(member = %info.name, id = %info.id.short(), by = %e.origin.short(), "member admitted");
                }
                Some(m) => {
                    sqlx::query(
                        "UPDATE members SET admitted_hlc = MAX(admitted_hlc, ?) WHERE id = ?",
                    )
                    .bind(at as i64)
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
            match get(conn, &info.id).await? {
                // Only this node's own first description lands here: any
                // other origin had to be admitted before its entries apply.
                None => {
                    let admitted = if info.id == node.id() { e.hlc } else { 0 };
                    insert(conn, info, &e.origin, e.hlc, admitted).await?;
                }
                Some(m) if e.hlc > m.info_hlc => write_info(conn, info, e.hlc).await?,
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
            .bind(e.hlc as i64)
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
        assert_eq!(standing(0, None, hlc(now), now), Standing::NotAdmitted);
        assert_eq!(standing(hlc(now), None, 0, now), Standing::Active);
        // Left: the leave is newer than the admission; a later add re-admits.
        assert_eq!(
            standing(hlc(now - DAY), Some(hlc(now)), hlc(now), now),
            Standing::Left
        );
        assert_eq!(
            standing(hlc(now), Some(hlc(now - DAY)), 0, now),
            Standing::Active
        );
        // 31 days without an entry: pruned. Either kind of evidence revives.
        let old = hlc(now - 31 * DAY);
        assert_eq!(standing(old, None, old, now), Standing::Pruned);
        assert_eq!(standing(old, None, hlc(now - DAY), now), Standing::Active);
        assert_eq!(standing(hlc(now - DAY), None, old, now), Standing::Active);
        // Exactly at the limit is still active.
        let edge = hlc(now - 30 * DAY);
        assert_eq!(standing(edge, None, edge, now), Standing::Active);
    }

    #[test]
    fn a_clock_running_ahead_never_looks_stale() {
        let now = 1_000 * DAY;
        let future = hlc(now + 400 * DAY);
        assert_eq!(standing(future, None, future, now), Standing::Active);
    }
}
