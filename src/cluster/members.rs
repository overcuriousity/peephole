//! Cluster membership, materialized from member records.
//!
//! - `member_add` (by another member) admits a node; it fills in the
//!   node's description only until the node describes itself.
//! - `member_update` (by the node itself) sets its description, last write
//!   wins by HLC; it can never admit or re-admit.
//! - `member_revoke` (by any member) revokes; a later add re-admits.
use super::Node;
use super::identity::NodeId;
use super::record::{MemberInfo, Record, WireEntry};
use anyhow::Result;
use sqlx::SqliteConnection;
use tracing::{info, warn};

/// A member row as the UI and CLI show it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberRow {
    pub id: NodeId,
    pub name: String,
    pub address: Option<String>,
    pub roles: Vec<String>,
    pub never_scan: Vec<String>,
    pub proto_min: u32,
    pub proto_max: u32,
    pub sponsor: NodeId,
    pub active: bool,
    /// HLC of the latest self-description (0: never described itself).
    pub info_hlc: u64,
}

type Row = (
    Vec<u8>,
    String,
    Option<String>,
    String,
    String,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
);

const SELECT: &str = "SELECT id, name, address, roles_json, never_scan_json, proto_min, proto_max,
                             sponsor, info_hlc, admitted_hlc, revoked_hlc FROM members";

fn from_row(r: Row) -> Result<MemberRow> {
    let admitted = r.9;
    Ok(MemberRow {
        id: NodeId::from_slice(&r.0)?,
        name: r.1,
        address: r.2,
        roles: serde_json::from_str(&r.3).unwrap_or_default(),
        never_scan: serde_json::from_str(&r.4).unwrap_or_default(),
        proto_min: r.5 as u32,
        proto_max: r.6 as u32,
        sponsor: NodeId::from_slice(&r.7)?,
        info_hlc: r.8 as u64,
        active: admitted > 0 && r.10.is_none_or(|rev| admitted > rev),
    })
}

/// Every member row, active or not.
pub async fn all(store: &crate::store::Store) -> Result<Vec<MemberRow>> {
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY name")))
        .fetch_all(&store.pool)
        .await?;
    rows.into_iter().map(from_row).collect()
}

async fn get(conn: &mut SqliteConnection, id: &NodeId) -> Result<Option<MemberRow>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = ?")))
        .bind(&id.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    row.map(from_row).transpose()
}

async fn write_info(conn: &mut SqliteConnection, info: &MemberInfo, info_hlc: u64) -> Result<()> {
    sqlx::query(
        "UPDATE members SET name = ?, address = ?, roles_json = ?, never_scan_json = ?,
                proto_min = ?, proto_max = ?, info_hlc = ? WHERE id = ?",
    )
    .bind(&info.name)
    .bind(&info.address)
    .bind(serde_json::to_string(&info.roles)?)
    .bind(serde_json::to_string(&info.never_scan)?)
    .bind(info.proto_min as i64)
    .bind(info.proto_max as i64)
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
        "INSERT INTO members (id, name, address, roles_json, never_scan_json, proto_min, proto_max,
                              sponsor, info_hlc, admitted_hlc)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&info.id.0[..])
    .bind(&info.name)
    .bind(&info.address)
    .bind(serde_json::to_string(&info.roles)?)
    .bind(serde_json::to_string(&info.never_scan)?)
    .bind(info.proto_min as i64)
    .bind(info.proto_max as i64)
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
            match get(conn, &info.id).await? {
                None => {
                    insert(conn, info, &e.origin, 0, e.hlc).await?;
                    info!(member = %info.name, id = %info.id.short(), by = %e.origin.short(), "member admitted");
                }
                Some(m) => {
                    sqlx::query(
                        "UPDATE members SET admitted_hlc = MAX(admitted_hlc, ?) WHERE id = ?",
                    )
                    .bind(e.hlc as i64)
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
            if get(conn, id).await?.is_none() {
                let placeholder = MemberInfo {
                    id: *id,
                    name: "(revoked)".into(),
                    address: None,
                    roles: vec![],
                    never_scan: vec![],
                    proto_min: 0,
                    proto_max: 0,
                };
                insert(conn, &placeholder, &e.origin, 0, 0).await?;
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
            info!(id = %id.short(), by = %e.origin.short(), "member revoked");
        }
        _ => return Ok(false),
    }
    Ok(true)
}
