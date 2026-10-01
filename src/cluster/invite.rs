//! One-time join invites.
//!
//! An invite token carries the inviter's addresses and key plus a 256-bit
//! secret; the inviter stores only the secret's hash. Redeeming it makes
//! the inviter vouch for the joiner (`member_add`), and the joiner vouch
//! for the inviter, so both sides pin each other's keys.
use super::Node;
use super::identity::NodeId;
use super::record::{MemberInfo, Record};
use super::repl;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest;

const PREFIX: &str = "peephole1:";
pub const DEFAULT_TTL_HOURS: u64 = 24;

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

/// Create an invite valid for `ttl_hours`; returns the token (shown once).
pub async fn create(node: &Node, ttl_hours: u64) -> Result<String> {
    let Some(addr) = node.cfg.advertise.clone() else {
        bail!(
            "this node has no cluster.advertise address, so a joiner cannot reach it; \
             create the invite on a reachable node"
        );
    };
    if !(1..=24 * 30).contains(&ttl_hours) {
        bail!("invite lifetime must be between 1 hour and 30 days");
    }
    let mut secret = vec![0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).map_err(|_| anyhow::anyhow!("rng failure"))?;
    sqlx::query(
        "INSERT INTO invites (secret_hash, created_at, expires_at)
         VALUES (?, datetime('now'), datetime('now', ?))",
    )
    .bind(hash(&secret))
    .bind(format!("+{ttl_hours} hours"))
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
    if others > 0 {
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
    let name = req.info.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err((400, "node name must be 1-64 characters".into()));
    }
    let internal = |e: anyhow::Error| (500, format!("{e:#}"));
    let used = sqlx::query(
        "UPDATE invites SET used_at = datetime('now'), used_by = ?
         WHERE secret_hash = ? AND used_at IS NULL AND expires_at > datetime('now')",
    )
    .bind(&peer.0[..])
    .bind(hash(&req.secret))
    .execute(&node.store.pool)
    .await
    .map_err(|e| internal(e.into()))?
    .rows_affected();
    if used != 1 {
        return Err((403, "invalid, used or expired invite".into()));
    }
    repl::append(node, &[Record::MemberAdd(req.info)])
        .await
        .map_err(internal)?;
    Ok(JoinResp {
        info: node.self_info(),
    })
}
