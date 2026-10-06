//! Owner commands: what a managing node tells a sibling to do. A command
//! is signed with the ownership key over who sends it to whom, the
//! target's command counter and the command itself, so nobody without the
//! key can issue one and no relay can replay or redirect one.
use super::{OwnerId, OwnerKey};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::remote::{self, State};
use crate::cluster::rpc::proto::OWNER_PROTO;
use crate::settings::{Changes, Settings};
use crate::store::Store;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CMD_DOMAIN: &[u8] = b"peephole-owner-cmd-v1\0";
/// How long to wait for a node's answer.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Commands with a bad signature logged per sender and hour.
const BAD_SIGNATURES_LOGGED: u32 = 10;

/// What an owner may tell a node to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "c", rename_all = "snake_case")]
pub enum OwnerCmd {
    /// Report settings, counter, block list and invites. Changes nothing,
    /// so it is accepted with any counter and not logged.
    Status,
    /// Change runtime settings, like the node's own settings form.
    Settings {
        base_version: u64,
        changes: Changes,
    },
    /// Block a peer on the node (its local block list).
    Block {
        node: NodeId,
        subtree: bool,
    },
    Unblock {
        node: NodeId,
    },
    /// Delete a blocked peer's data on the node.
    Purge {
        node: NodeId,
    },
    /// Revoke one of the node's invites.
    InviteRevoke {
        id: i64,
    },
    /// The node leaves the cluster and keeps its data.
    Leave,
    /// Take another owner: its id and its certificate for the node.
    Reown {
        owner_id: serde_bytes::ByteBuf,
        cert: serde_bytes::ByteBuf,
    },
    /// The node drops its owner.
    Release,
}

impl OwnerCmd {
    /// One line for the log.
    pub fn describe(&self) -> String {
        match self {
            OwnerCmd::Status => "status".into(),
            OwnerCmd::Settings { changes, .. } => format!("settings: {}", changes.describe()),
            OwnerCmd::Block { node, subtree } => format!(
                "block {}{}",
                node.short(),
                if *subtree {
                    " with all it admitted"
                } else {
                    ""
                }
            ),
            OwnerCmd::Unblock { node } => format!("unblock {}", node.short()),
            OwnerCmd::Purge { node } => format!("purge {}", node.short()),
            OwnerCmd::InviteRevoke { id } => format!("revoke invite {id}"),
            OwnerCmd::Leave => "leave the cluster".into(),
            OwnerCmd::Reown { owner_id, .. } => match OwnerId::from_slice(owner_id) {
                Ok(id) => format!("take owner {}", id.short()),
                Err(_) => "take another owner".into(),
            },
            OwnerCmd::Release => "release (drop the owner)".into(),
        }
    }
}

/// An invite of the node, without its secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub id: i64,
    pub label: String,
    pub uses: i64,
    pub max_uses: Option<i64>,
    pub expires_at: Option<String>,
    pub usable: bool,
}

/// What a node tells its owner about itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// The counter the next command must name.
    pub counter: u64,
    pub state: State,
    pub build: String,
    pub blocked: Vec<NodeId>,
    pub invites: Vec<InviteInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "d", rename_all = "snake_case")]
pub enum OwnerData {
    Status(Box<Status>),
    /// The command was carried out; `note` says what happened.
    Done {
        note: String,
    },
}

fn signing_bytes(from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd) -> Vec<u8> {
    let mut m = CMD_DOMAIN.to_vec();
    m.extend_from_slice(&from.0);
    m.extend_from_slice(&to.0);
    m.extend_from_slice(&counter.to_be_bytes());
    // Encoding a plain enum into a Vec cannot fail.
    m.extend_from_slice(&crate::cluster::rpc::cbor::encode(cmd).unwrap_or_default());
    m
}

pub fn sign(key: &OwnerKey, from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd) -> Vec<u8> {
    key.sign(&signing_bytes(from, to, counter, cmd))
}

pub fn verify(
    owner: &OwnerId,
    from: &NodeId,
    to: &NodeId,
    counter: u64,
    cmd: &OwnerCmd,
    sig: &[u8],
) -> bool {
    owner.verify(&signing_bytes(from, to, counter, cmd), sig)
}

/// One received command, as the node's Ownership page lists it.
#[derive(Debug, Clone)]
pub struct LogRow {
    pub at: String,
    pub from: NodeId,
    pub command: String,
    pub result: String,
}

async fn log(store: &Store, from: &NodeId, command: &str, result: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO owner_log (at, from_node, command, result)
         VALUES (datetime('now'), ?, ?, ?)",
    )
    .bind(&from.0[..])
    .bind(command)
    .bind(result)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// The newest received commands, newest first.
pub async fn log_rows(store: &Store, limit: i64) -> Result<Vec<LogRow>> {
    let rows: Vec<(String, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT at, from_node, command, result FROM owner_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&store.pool)
    .await?;
    rows.into_iter()
        .map(|(at, from, command, result)| {
            Ok(LogRow {
                at,
                from: NodeId::from_slice(&from)?,
                command,
                result,
            })
        })
        .collect()
}

/// Bad signatures seen per sender in the current hour.
type Refusals = Arc<Mutex<HashMap<NodeId, (u64, u32)>>>;

fn may_log(seen: &Refusals, from: NodeId) -> bool {
    let hour = crate::cluster::hlc::wall_ms() / 3_600_000;
    let mut all = seen.lock().unwrap();
    all.retain(|_, (h, _)| *h == hour);
    let e = all.entry(from).or_insert((hour, 0));
    e.1 += 1;
    e.1 <= BAD_SIGNATURES_LOGGED
}

async fn status_of(node: &Node, settings: &Settings) -> Result<Status> {
    let invites = crate::cluster::invite::list(&node.store)
        .await?
        .into_iter()
        .map(|i| InviteInfo {
            id: i.id,
            label: i.label,
            uses: i.uses,
            max_uses: i.max_uses,
            expires_at: i.expires_at,
            usable: i.usable,
        })
        .collect();
    Ok(Status {
        counter: super::counter(&node.store).await?,
        state: remote::state(node, settings).await,
        build: crate::VERSION.to_string(),
        blocked: crate::cluster::block::list(&node.store).await?,
        invites,
    })
}

/// Carry out a verified command. Ok: what happened; Err: why not.
async fn execute(
    node: &Arc<Node>,
    settings: &Settings,
    from: NodeId,
    cmd: &OwnerCmd,
) -> Result<String, String> {
    let err = |e: anyhow::Error| format!("{e:#}");
    match cmd {
        OwnerCmd::Status => Ok(String::new()),
        OwnerCmd::Settings {
            base_version,
            changes,
        } => match settings.apply_at(*base_version, changes, Some(from)).await {
            Ok(Ok(v)) => {
                if !changes.is_empty() {
                    node.status.local.lock().unwrap().pace =
                        Some(remote::pace_info(settings.snapshot().pace));
                    node.publish_status();
                }
                Ok(format!("settings saved (version {v})"))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("{e:#}")),
        },
        OwnerCmd::Block {
            node: peer,
            subtree,
        } => {
            if *peer == from {
                return Err("a node is not told to block the node that manages it".into());
            }
            if *subtree {
                let (ids, n) = crate::cluster::block::block_subtree(node, *peer)
                    .await
                    .map_err(err)?;
                Ok(format!(
                    "blocked {} and the {} node(s) it admitted ({n} records out of view)",
                    peer.short(),
                    ids.len() - 1
                ))
            } else {
                let n = crate::cluster::block::block(node, *peer)
                    .await
                    .map_err(err)?;
                Ok(format!(
                    "blocked {} ({n} records out of view)",
                    peer.short()
                ))
            }
        }
        OwnerCmd::Unblock { node: peer } => {
            if crate::cluster::block::unblock(node, *peer)
                .await
                .map_err(err)?
            {
                Ok(format!("unblocked {}", peer.short()))
            } else {
                Err(format!("{} was not blocked", peer.short()))
            }
        }
        OwnerCmd::Purge { node: peer } => {
            let n = crate::cluster::block::purge(node, *peer)
                .await
                .map_err(err)?;
            Ok(format!("purged {} ({n} log entries deleted)", peer.short()))
        }
        OwnerCmd::InviteRevoke { id } => {
            if crate::cluster::invite::revoke(&node.store, *id)
                .await
                .map_err(err)?
            {
                Ok(format!("invite {id} revoked"))
            } else {
                Err(format!("no usable invite {id}"))
            }
        }
        OwnerCmd::Leave => {
            // After the answer is on its way: leaving stops the node's
            // contact with its peers.
            let node = node.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Err(e) = crate::cluster::leave(&node).await {
                    tracing::warn!(?e, "leaving on the owner's command failed");
                }
            });
            Ok("leaving the cluster".into())
        }
        OwnerCmd::Reown { owner_id, cert } => {
            let id = OwnerId::from_slice(owner_id).map_err(err)?;
            super::reown(&node.store, node.id(), id, cert)
                .await
                .map_err(err)?;
            Ok(format!("owner is now {}", id.short()))
        }
        OwnerCmd::Release => {
            super::release(&node.store).await.map_err(err)?;
            Ok("released: this node has no owner".into())
        }
    }
}

async fn handle(
    node: &Arc<Node>,
    settings: &Settings,
    seen: &Refusals,
    from: NodeId,
    counter: u64,
    cmd: OwnerCmd,
    sig: &[u8],
) -> Msg {
    let refuse = |counter: u64, e: String| Msg::OwnerReply {
        counter,
        error: Some(e),
        data: None,
    };
    let owned = match super::load(&node.store, node.id()).await {
        Ok(Some(o)) => o,
        Ok(None) => return refuse(0, "this node has no owner".into()),
        Err(e) => return refuse(0, format!("{e:#}")),
    };
    if !verify(&owned.id, &from, &node.id(), counter, &cmd, sig) {
        if may_log(seen, from) {
            tracing::warn!(by = %from.short(), "owner command with a wrong ownership key refused");
            let _ = log(
                &node.store,
                &from,
                &format!("(not verified) {}", cmd.describe()),
                "refused: the ownership key was not accepted",
            )
            .await;
        }
        return refuse(0, "the ownership key was not accepted".into());
    }
    let current = super::counter(&node.store).await.unwrap_or(0);
    if cmd == OwnerCmd::Status {
        return match status_of(node, settings).await {
            Ok(s) => Msg::OwnerReply {
                counter: current,
                error: None,
                data: Some(OwnerData::Status(Box::new(s))),
            },
            Err(e) => refuse(current, format!("{e:#}")),
        };
    }
    // Used up before the command runs: a copy of it never runs again.
    match super::take_counter(&node.store, counter).await {
        Ok(true) => {}
        Ok(false) => {
            let why = "the node changed meanwhile; reload and try again";
            let _ = log(
                &node.store,
                &from,
                &cmd.describe(),
                &format!("refused: {why}"),
            )
            .await;
            return refuse(current, why.into());
        }
        Err(e) => return refuse(current, format!("{e:#}")),
    }
    let result = execute(node, settings, from, &cmd).await;
    let text = match &result {
        Ok(note) => note.clone(),
        Err(e) => format!("refused: {e}"),
    };
    tracing::info!(by = %from.short(), command = %cmd.describe(), result = %text, "owner command");
    let _ = log(&node.store, &from, &cmd.describe(), &text).await;
    match result {
        Ok(note) => Msg::OwnerReply {
            counter: counter + 1,
            error: None,
            data: Some(OwnerData::Done { note }),
        },
        Err(e) => refuse(counter + 1, e),
    }
}

/// Carry out the owner's commands.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    let seen: Refusals = Default::default();
    node.on_message(Arc::new(move |from, msg| {
        let (settings, weak, seen) = (settings.clone(), weak.clone(), seen.clone());
        Box::pin(async move {
            let Msg::OwnerCmd { counter, cmd, sig } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            Some(handle(&node, &settings, &seen, from, counter, cmd, &sig).await)
        })
    }));
}

/// The ownership key this node keeps.
pub async fn kept_key(node: &Node) -> Result<OwnerKey> {
    match super::load(&node.store, node.id()).await? {
        Some(o) => match o.key {
            Some(k) => Ok(k),
            None => bail!("the ownership key is not kept on this node"),
        },
        None => bail!("this node has no owner"),
    }
}

fn speaks_owner(node: &Node, target: &NodeId) -> Result<()> {
    match node.members().get(target) {
        Some(m) if m.proto_max >= OWNER_PROTO => Ok(()),
        Some(m) => bail!("{} runs a version without ownership", m.name),
        None => bail!("{} is not a member", target.short()),
    }
}

/// Ask `target` for its status, signed with `key`.
pub async fn status(node: &Arc<Node>, key: &OwnerKey, target: NodeId) -> Result<Status> {
    speaks_owner(node, &target)?;
    let cmd = OwnerCmd::Status;
    let sig = sign(key, &node.id(), &target, 0, &cmd);
    let msg = Msg::OwnerCmd {
        counter: 0,
        cmd,
        sig: serde_bytes::ByteBuf::from(sig),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::OwnerReply {
            data: Some(OwnerData::Status(s)),
            ..
        } => Ok(*s),
        Msg::OwnerReply { error: Some(e), .. } => bail!("{e}"),
        other => bail!("unexpected answer {other:?}"),
    }
}

/// Send `cmd` to `target` for its counter `counter`, signed with `key`.
/// The inner error is the target's refusal.
pub async fn run(
    node: &Arc<Node>,
    key: &OwnerKey,
    target: NodeId,
    counter: u64,
    cmd: OwnerCmd,
) -> Result<Result<String, String>> {
    speaks_owner(node, &target)?;
    let leaves_fleet = matches!(cmd, OwnerCmd::Release | OwnerCmd::Reown { .. });
    let sig = sign(key, &node.id(), &target, counter, &cmd);
    let msg = Msg::OwnerCmd {
        counter,
        cmd,
        sig: serde_bytes::ByteBuf::from(sig),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::OwnerReply { error: Some(e), .. } => Ok(Err(e)),
        Msg::OwnerReply {
            data: Some(OwnerData::Done { note }),
            ..
        } => {
            if leaves_fleet {
                super::fleet::forget(&node.store, &target).await?;
            }
            Ok(Ok(note))
        }
        other => bail!("unexpected answer {other:?}"),
    }
}

/// What a key rotation did.
pub struct Rotation {
    /// The new key, to show once.
    pub key: OwnerKey,
    pub moved: Vec<NodeId>,
    /// Siblings still on the old key, and why.
    pub pending: Vec<(NodeId, String)>,
}

/// Tell `target` (still under `signer`) to take `new` as its owner.
async fn reown_one(
    node: &Arc<Node>,
    signer: &OwnerKey,
    new: &OwnerKey,
    target: NodeId,
) -> Result<(), String> {
    let st = status(node, signer, target)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let cmd = OwnerCmd::Reown {
        owner_id: serde_bytes::ByteBuf::from(new.id.0.to_vec()),
        cert: serde_bytes::ByteBuf::from(new.certify(&target)),
    };
    match run(node, signer, target, st.counter, cmd).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Siblings still on the previous key after a rotation.
pub async fn pending(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM reown_pending ORDER BY node")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// Replace the ownership key: every sibling that answers takes the new
/// one, then this node does. The old key stays here for the rest (see
/// [`retry`], [`discard`]).
pub async fn rotate(node: &Arc<Node>) -> Result<Rotation> {
    let old = kept_key(node).await?;
    let new = OwnerKey::generate()?;
    let (mut moved, mut pending) = (vec![], vec![]);
    for s in super::fleet::siblings(&node.store).await? {
        match reown_one(node, &old, &new, s).await {
            Ok(()) => moved.push(s),
            Err(e) => pending.push((s, e)),
        }
    }
    // Forgets the siblings and any earlier rotation.
    super::adopt(&node.store, node.id(), &new, true).await?;
    for m in &moved {
        super::fleet::remember(&node.store, m, &new.certify(m)).await?;
    }
    if !pending.is_empty() {
        node.store
            .setting_set(
                super::KEY_OLD_SEED,
                &data_encoding::BASE64URL_NOPAD.encode(&old.seed()),
            )
            .await?;
        for (p, _) in &pending {
            sqlx::query("INSERT OR IGNORE INTO reown_pending (node) VALUES (?)")
                .bind(&p.0[..])
                .execute(&node.store.pool)
                .await?;
        }
    }
    Ok(Rotation {
        key: new,
        moved,
        pending,
    })
}

/// Try again to move the siblings a rotation did not reach. When none is
/// left, the old key is deleted.
pub async fn retry(node: &Arc<Node>) -> Result<Vec<(NodeId, Result<(), String>)>> {
    let new = kept_key(node).await?;
    let Some(old) = node.store.setting_get(super::KEY_OLD_SEED).await? else {
        bail!("no rotation is waiting for siblings");
    };
    let seed: [u8; 32] = data_encoding::BASE64URL_NOPAD
        .decode(old.as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the stored previous key is unreadable"))?;
    let old = OwnerKey::from_seed(seed)?;
    let mut out = vec![];
    for p in pending(&node.store).await? {
        let r = reown_one(node, &old, &new, p).await;
        if r.is_ok() {
            sqlx::query("DELETE FROM reown_pending WHERE node = ?")
                .bind(&p.0[..])
                .execute(&node.store.pool)
                .await?;
            super::fleet::remember(&node.store, &p, &new.certify(&p)).await?;
        }
        out.push((p, r));
    }
    if pending(&node.store).await?.is_empty() {
        discard(&node.store).await?;
    }
    Ok(out)
}

/// Give up on the siblings still on the previous key: delete it.
pub async fn discard(store: &Store) -> Result<()> {
    for sql in [
        "DELETE FROM reown_pending",
        "DELETE FROM settings WHERE key = 'owner.old_seed'",
    ] {
        sqlx::query(sql).execute(&store.pool).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn the_signature_covers_sender_target_counter_and_command() {
        let (k, other) = (OwnerKey::generate().unwrap(), OwnerKey::generate().unwrap());
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let cmd = OwnerCmd::Settings {
            base_version: 4,
            changes: Changes {
                max_workers: Some(3),
                ..Default::default()
            },
        };
        let sig = sign(&k, &a, &b, 7, &cmd);
        assert!(verify(&k.id, &a, &b, 7, &cmd, &sig));
        assert!(!verify(&other.id, &a, &b, 7, &cmd, &sig), "another owner");
        assert!(!verify(&k.id, &b, &a, 7, &cmd, &sig), "direction");
        assert!(!verify(&k.id, &a, &b, 8, &cmd, &sig), "counter");
        assert!(
            !verify(&k.id, &a, &b, 7, &OwnerCmd::Status, &sig),
            "command"
        );
    }

    #[test]
    fn commands_describe_themselves_for_the_log() {
        assert_eq!(OwnerCmd::Status.describe(), "status");
        let c = OwnerCmd::Settings {
            base_version: 0,
            changes: Changes {
                max_workers: Some(2),
                scanner: Some(false),
                ..Default::default()
            },
        };
        assert_eq!(c.describe(), "settings: workers=2, scanner=off");
        let n = Identity::generate().unwrap().id;
        assert_eq!(
            OwnerCmd::Block {
                node: n,
                subtree: true
            }
            .describe(),
            format!("block {} with all it admitted", n.short())
        );
        assert_eq!(
            OwnerCmd::InviteRevoke { id: 4 }.describe(),
            "revoke invite 4"
        );
        assert_eq!(OwnerCmd::Leave.describe(), "leave the cluster");
        assert_eq!(OwnerCmd::Release.describe(), "release (drop the owner)");
    }

    #[tokio::test]
    async fn the_log_lists_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let from = Identity::generate().unwrap().id;
        log(&store, &from, "one", "done").await.unwrap();
        log(&store, &from, "two", "refused: x").await.unwrap();
        let rows = log_rows(&store, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].command.as_str(), rows[0].from), ("two", from));
        assert_eq!(rows[1].result, "done");
    }
}
