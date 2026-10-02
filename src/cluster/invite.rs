//! Join invites.
//!
//! An invite token carries the inviter's addresses and key plus a 256-bit
//! secret; the inviter stores only the secret's hash. Redeeming it makes
//! the inviter vouch for the joiner (`member_add`), and the joiner vouch
//! for the inviter, so both sides pin each other's keys. An invite can be
//! redeemed any number of times until it expires, reaches its use limit or
//! is revoked, so one token can admit a whole peer group over time.
use super::Node;
use super::identity::NodeId;
use super::record::{MemberInfo, Record};
use super::repl;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest;

const PREFIX: &str = "peephole1:";

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub v: u8,
    pub addrs: Vec<String>,
    pub id: NodeId,
    #[serde(with = "serde_bytes")]
    pub secret: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinReq {
    #[serde(with = "serde_bytes")]
    pub secret: Vec<u8>,
    pub info: MemberInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinResp {
    pub info: MemberInfo,
}

fn hash(secret: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(secret))
}

pub fn parse(token: &str) -> Result<Token> {
    let b64 = token
        .trim()
        .strip_prefix(PREFIX)
        .context("not a peephole invite token")?;
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(b64.as_bytes())
        .context("invite token: invalid base64url")?;
    let t: Token = super::rpc::cbor::decode(&raw).context("invite token: malformed")?;
    if t.v != 1 || t.secret.len() != 32 || t.addrs.is_empty() {
        bail!("invite token: unsupported version or malformed");
    }
    Ok(t)
}

/// Default lifetime of an invite: a week.
pub const DEFAULT_TTL_HOURS: u64 = 7 * 24;
/// Default use limit of an invite.
pub const DEFAULT_MAX_USES: u32 = 10;

/// How an invite is limited. By default it expires after
/// [`DEFAULT_TTL_HOURS`] and admits at most [`DEFAULT_MAX_USES`] nodes;
/// `None` lifts a limit (explicitly: `--ttl 0`, `--uses 0`).
#[derive(Debug, Clone)]
pub struct InviteOpts {
    /// Shown in the invite list (who it was given to).
    pub label: String,
    pub ttl_hours: Option<u64>,
    pub max_uses: Option<u32>,
}

impl Default for InviteOpts {
    fn default() -> Self {
        Self {
            label: String::new(),
            ttl_hours: Some(DEFAULT_TTL_HOURS),
            max_uses: Some(DEFAULT_MAX_USES),
        }
    }
}

impl InviteOpts {
    /// Limits as typed by an operator: absent or empty means the default,
    /// `0` (or `never`/`none`) means no limit.
    pub fn parse_limits(
        ttl: Option<&str>,
        uses: Option<&str>,
    ) -> Result<(Option<u64>, Option<u32>)> {
        fn limit<T: std::str::FromStr + PartialEq + Default>(
            v: Option<&str>,
            default: T,
            what: &str,
        ) -> Result<Option<T>> {
            match v.map(str::trim) {
                None | Some("") => Ok(Some(default)),
                Some("never" | "none" | "unlimited") => Ok(None),
                Some(s) => {
                    let n: T = s
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{what} must be a number"))?;
                    Ok((n != T::default()).then_some(n))
                }
            }
        }
        Ok((
            limit(ttl, DEFAULT_TTL_HOURS, "the invite lifetime")?,
            limit(uses, DEFAULT_MAX_USES, "the invite use limit")?,
        ))
    }
}

/// Create an invite; returns the token (shown once).
pub async fn create(node: &Node, o: &InviteOpts) -> Result<String> {
    let Some(addr) = node.cfg.advertise.clone() else {
        bail!(
            "this node has no cluster.advertise address, so a joiner cannot reach it; \
             create the invite on a reachable node"
        );
    };
    if o.ttl_hours.is_some_and(|h| !(1..=24 * 365).contains(&h)) {
        bail!("invite lifetime must be between 1 hour and 1 year");
    }
    if o.max_uses.is_some_and(|n| !(1..=10_000).contains(&n)) {
        bail!("invite use limit must be between 1 and 10000");
    }
    let label = o.label.trim();
    if label.chars().count() > 64 {
        bail!("invite label must be at most 64 characters");
    }
    let mut secret = vec![0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).map_err(|_| anyhow::anyhow!("rng failure"))?;
    let expires = o.ttl_hours.map(|h| {
        (chrono::Utc::now() + chrono::Duration::hours(h as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    });
    sqlx::query(
        "INSERT INTO invites (secret_hash, label, created_at, expires_at, max_uses)
         VALUES (?, ?, datetime('now'), ?, ?)",
    )
    .bind(hash(&secret))
    .bind(label)
    .bind(expires)
    .bind(o.max_uses.map(i64::from))
    .execute(&node.store.pool)
    .await?;
    let token = Token {
        v: 1,
        addrs: vec![addr],
        id: node.id(),
        secret,
    };
    Ok(format!(
        "{PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&super::rpc::cbor::encode(&token)?)
    ))
}

/// Joiner side: redeem `token` at the inviter. Returns the inviter's info.
pub async fn join(node: &Node, token: &str) -> Result<MemberInfo> {
    let t = parse(token)?;
    if t.id == node.id() {
        bail!("this is our own invite");
    }
    let others = node
        .members()
        .values()
        .filter(|m| m.id != node.id())
        .count();
    // A node in a cluster may only rejoin that same cluster; a detached one
    // may join anywhere, like a standalone node.
    let known = super::members::all(&node.store)
        .await?
        .iter()
        .any(|m| m.id == t.id);
    if others > 0 && !known && node.detached().is_none() {
        bail!("this node already belongs to a cluster ({others} other member(s))");
    }
    let req = JoinReq {
        secret: t.secret.clone(),
        info: node.self_info(),
    };
    let mut last_err = None;
    for addr in &t.addrs {
        match node
            .call::<_, JoinResp>(t.id, addr, "/rpc/v1/join", &req)
            .await
        {
            Ok(resp) => {
                if resp.info.id != t.id {
                    bail!("inviter answered with a different identity");
                }
                let mut info = resp.info;
                if info.address.is_none() {
                    info.address = Some(addr.clone());
                }
                repl::append(node, &[Record::MemberAdd(info.clone())]).await?;
                super::set_detached(&node.store, None).await?;
                node.reload_members().await?;
                return Ok(info);
            }
            Err(e) => last_err = Some(e.context(format!("joining via {addr}"))),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no address in token")))
}

/// Inviter side: check and consume the invite, then vouch for the joiner.
/// `peer` is the key the joiner authenticated with in TLS.
pub async fn redeem(node: &Node, peer: NodeId, req: JoinReq) -> Result<JoinResp, (u16, String)> {
    if req.info.id != peer {
        return Err((400, "member info does not match the TLS key".into()));
    }
    if !super::members::valid_name(req.info.name.trim()) {
        return Err((400, "node name must be 1-64 printable characters".into()));
    }
    if req
        .info
        .address
        .as_deref()
        .is_some_and(|a| !super::members::valid_address(a))
    {
        return Err((400, "address must be host:port".into()));
    }
    let internal = |e: anyhow::Error| (500, format!("{e:#}"));
    // Peers ignore admissions over the daily limit; do not use up the
    // invite for one.
    if !super::members::can_admit(node, &peer)
        .await
        .map_err(internal)?
    {
        return Err((
            429,
            "this node admitted too many members today; try again tomorrow".into(),
        ));
    }
    // One statement, so concurrent joins cannot exceed the use limit.
    let invite: Option<i64> = sqlx::query_scalar(
        "UPDATE invites SET uses = uses + 1
         WHERE secret_hash = ? AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           AND (max_uses IS NULL OR uses < max_uses)
         RETURNING id",
    )
    .bind(hash(&req.secret))
    .fetch_optional(&node.store.pool)
    .await
    .map_err(|e| internal(e.into()))?;
    let Some(invite) = invite else {
        return Err((403, "invalid, revoked, exhausted or expired invite".into()));
    };
    sqlx::query(
        "INSERT INTO invite_uses (invite_id, node, used_at) VALUES (?, ?, datetime('now'))",
    )
    .bind(invite)
    .bind(&peer.0[..])
    .execute(&node.store.pool)
    .await
    .map_err(|e| internal(e.into()))?;
    repl::append(node, &[Record::MemberAdd(req.info)])
        .await
        .map_err(internal)?;
    Ok(JoinResp {
        info: node.self_info(),
    })
}

/// An invite as the UI and CLI list it.
#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: i64,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked: bool,
    /// Still redeemable right now.
    pub usable: bool,
    /// Nodes that joined with it.
    pub joined: Vec<NodeId>,
}

/// All invites created on this node, newest first.
pub async fn list(store: &crate::store::Store) -> Result<Vec<InviteRow>> {
    type Row = (
        i64,
        String,
        String,
        Option<String>,
        Option<i64>,
        i64,
        bool,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, label, created_at, expires_at, max_uses, uses, revoked_at IS NOT NULL,
                revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))
                  AND (max_uses IS NULL OR uses < max_uses)
         FROM invites ORDER BY id DESC",
    )
    .fetch_all(&store.pool)
    .await?;
    let mut out = vec![];
    for r in rows {
        let nodes: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT node FROM invite_uses WHERE invite_id = ? GROUP BY node ORDER BY MIN(used_at)",
        )
        .bind(r.0)
        .fetch_all(&store.pool)
        .await?;
        out.push(InviteRow {
            id: r.0,
            label: r.1,
            created_at: r.2,
            expires_at: r.3,
            max_uses: r.4,
            uses: r.5,
            revoked: r.6,
            usable: r.7,
            joined: nodes
                .iter()
                .filter_map(|n| NodeId::from_slice(n).ok())
                .collect(),
        });
    }
    Ok(out)
}

/// Stop an invite from admitting anyone else. Members that already joined
/// with it stay. Returns false if it was unknown or already revoked.
pub async fn revoke(store: &crate::store::Store, id: i64) -> Result<bool> {
    let n = sqlx::query(
        "UPDATE invites SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&store.pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invites_are_limited_unless_told_otherwise() {
        let d = InviteOpts::default();
        assert_eq!(
            (d.ttl_hours, d.max_uses),
            (Some(DEFAULT_TTL_HOURS), Some(DEFAULT_MAX_USES))
        );
        let p = InviteOpts::parse_limits;
        assert_eq!(
            p(None, None).unwrap(),
            (Some(DEFAULT_TTL_HOURS), Some(DEFAULT_MAX_USES))
        );
        assert_eq!(
            p(Some(""), Some(" ")).unwrap(),
            (Some(DEFAULT_TTL_HOURS), Some(DEFAULT_MAX_USES))
        );
        assert_eq!(p(Some("0"), Some("0")).unwrap(), (None, None));
        assert_eq!(p(Some("never"), Some("3")).unwrap(), (None, Some(3)));
        assert!(p(Some("soon"), None).is_err());
    }
}
