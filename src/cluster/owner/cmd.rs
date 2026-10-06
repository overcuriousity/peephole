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
    /// The node sends credits to a member (`credits::fleet`).
    SendCredits {
        to: NodeId,
        mc: u64,
    },
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
            OwnerCmd::SendCredits { to, mc } => {
                format!(
                    "send {} credits to {}",
                    crate::credits::show(*mc),
                    to.short()
                )
            }
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
    /// The node's credits as it counts them itself, in mc.
    #[serde(default)]
    pub balance_mc: u64,
    /// Where it forwards its credits (a node key), if anywhere.
    #[serde(default)]
    pub collect_to: Option<String>,
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

/// A command as it is signed and sent. The receiver checks the signature
/// over the bytes it received and only then reads them, so a field a later
/// version adds to a command does not break the signature here.
pub fn encode(cmd: &OwnerCmd) -> Result<Vec<u8>> {
    crate::cluster::rpc::cbor::encode(cmd)
}

/// None: a command this version does not know.
fn decode(cmd: &[u8]) -> Option<OwnerCmd> {
    crate::cluster::rpc::cbor::decode(cmd).ok()
}

fn signing_bytes(from: &NodeId, to: &NodeId, counter: u64, cmd: &[u8]) -> Vec<u8> {
    let mut m = CMD_DOMAIN.to_vec();
    m.extend_from_slice(&from.0);
    m.extend_from_slice(&to.0);
    m.extend_from_slice(&counter.to_be_bytes());
    m.extend_from_slice(cmd);
    m
}

/// `cmd`: the encoded command ([`encode`]).
pub fn sign(key: &OwnerKey, from: &NodeId, to: &NodeId, counter: u64, cmd: &[u8]) -> Vec<u8> {
    key.sign(&signing_bytes(from, to, counter, cmd))
}

pub fn verify(
    owner: &OwnerId,
    from: &NodeId,
    to: &NodeId,
    counter: u64,
    cmd: &[u8],
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

/// Rows kept in `owner_log`: commands signed with the owner's key, and
/// attempts that were not.
const KEEP_VERIFIED: i64 = 2000;
const KEEP_UNVERIFIED: i64 = 200;
/// The result of a command until it has one: what stays when the node
/// stopped while carrying it out.
const STARTED: &str = "started; no result recorded";

/// Write a row and return its id; the oldest rows of its kind go.
/// `verified`: the command was signed with this node's owner key.
async fn log(
    store: &Store,
    from: &NodeId,
    command: &str,
    result: &str,
    verified: bool,
) -> Result<i64> {
    let id = sqlx::query(
        "INSERT INTO owner_log (at, from_node, command, result, verified)
         VALUES (datetime('now'), ?, ?, ?, ?)",
    )
    .bind(&from.0[..])
    .bind(command)
    .bind(result)
    .bind(verified)
    .execute(&store.pool)
    .await?
    .last_insert_rowid();
    sqlx::query(
        "DELETE FROM owner_log WHERE verified = ?1 AND id <= (
           SELECT id FROM owner_log WHERE verified = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)",
    )
    .bind(verified)
    .bind(if verified {
        KEEP_VERIFIED
    } else {
        KEEP_UNVERIFIED
    })
    .execute(&store.pool)
    .await?;
    Ok(id)
}

async fn log_result(store: &Store, id: i64, result: &str) -> Result<()> {
    sqlx::query("UPDATE owner_log SET result = ? WHERE id = ?")
        .bind(result)
        .bind(id)
        .execute(&store.pool)
        .await?;
    Ok(())
}

async fn rows(store: &Store, verified: bool, limit: i64) -> Result<Vec<LogRow>> {
    let rows: Vec<(String, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT at, from_node, command, result FROM owner_log
         WHERE verified = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(verified)
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

/// The newest commands received from the owner, newest first.
pub async fn log_rows(store: &Store, limit: i64) -> Result<Vec<LogRow>> {
    rows(store, true, limit).await
}

/// The newest attempts that were not signed with the owner's key. Kept
/// apart: any member can cause them, and they must not push the owner's
/// commands off the page.
pub async fn refused_rows(store: &Store, limit: i64) -> Result<Vec<LogRow>> {
    rows(store, false, limit).await
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
        balance_mc: crate::credits::book(node)
            .await
            .map(|b| b.balance(&node.id()))
            .unwrap_or(0),
        collect_to: settings.snapshot().collect_to.map(|id| id.to_string()),
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
                // Looked up first: the block below would already cut this
                // node off from the one that manages it.
                let below = crate::cluster::members::subtree(&node.store, *peer, node.id())
                    .await
                    .map_err(err)?;
                if below.contains(&from) {
                    return Err(format!(
                        "{} admitted the node that manages it (directly or not), and a node is \
                         not told to block the node that manages it; block {} alone",
                        peer.short(),
                        peer.short()
                    ));
                }
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
        OwnerCmd::SendCredits { to, mc } => {
            let sent = crate::credits::fleet::send(node, *to, *mc)
                .await
                .map_err(err)?;
            Ok(format!(
                "sent {} credits to {}",
                crate::credits::show(sent),
                to.short()
            ))
        }
    }
}

async fn handle(
    node: &Arc<Node>,
    settings: &Settings,
    seen: &Refusals,
    from: NodeId,
    counter: u64,
    cmd: &[u8],
    sig: &[u8],
) -> Msg {
    let refuse = |counter: u64, e: String| Msg::OwnerReply {
        counter,
        error: Some(e),
        data: None,
    };
    // One command at a time from here to the counter, and to the end for a
    // command that changes the owner.
    let turn = node.owner_locks.commands.lock().await;
    let what = || decode(cmd).map_or_else(|| "unreadable command".into(), |c| c.describe());
    // Every command, accepted or refused, is listed; refusals that anyone
    // can cause (no signature checked yet) at most so often per sender.
    let refused = |why: String, verified: bool| {
        let what = what();
        async move {
            if verified || may_log(seen, from) {
                tracing::info!(by = %from.short(), command = %what, "owner command refused: {why}");
                let _ = log(
                    &node.store,
                    &from,
                    &what,
                    &format!("refused: {why}"),
                    verified,
                )
                .await;
            }
            why
        }
    };
    let owned = match super::load(&node.store, node.id()).await {
        Ok(Some(o)) => o,
        Ok(None) => return refuse(0, refused("this node has no owner".into(), false).await),
        Err(e) => {
            let why = format!("this node could not read its owner: {e:#}");
            return refuse(0, refused(why, false).await);
        }
    };
    if !verify(&owned.id, &from, &node.id(), counter, cmd, sig) {
        if may_log(seen, from) {
            tracing::warn!(by = %from.short(), "owner command with a wrong ownership key refused");
            let what = decode(cmd).map_or_else(|| "unreadable command".into(), |c| c.describe());
            let _ = log(
                &node.store,
                &from,
                &what,
                "refused: the ownership key was not accepted",
                false,
            )
            .await;
        }
        return refuse(0, "the ownership key was not accepted".into());
    }
    let current = match super::counter(&node.store).await {
        Ok(c) => c,
        Err(e) => return refuse(0, refused(format!("{e:#}"), true).await),
    };
    let Some(cmd) = decode(cmd) else {
        let why = "this node does not know that command (it runs an earlier version)";
        return refuse(current, refused(why.into(), true).await);
    };
    if cmd == OwnerCmd::Status {
        drop(turn);
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
    match super::take_counter(&node.store, counter, &owned.id).await {
        Ok(true) => {}
        Ok(false) => {
            let why = "the node changed meanwhile; reload and try again";
            tracing::info!(by = %from.short(), command = %cmd.describe(), "owner command refused: {why}");
            let _ = log(
                &node.store,
                &from,
                &cmd.describe(),
                &format!("refused: {why}"),
                true,
            )
            .await;
            return refuse(current, why.into());
        }
        Err(e) => return refuse(current, format!("{e:#}")),
    }
    // Anything else may take long (a block walks the peer's records) and
    // does not touch the owner: the next command need not wait for it.
    let turn = matches!(cmd, OwnerCmd::Reown { .. } | OwnerCmd::Release).then_some(turn);
    // Written before the command runs: the counter is used up, and the
    // list must say for what also when the node stops halfway.
    let row = log(&node.store, &from, &cmd.describe(), STARTED, true)
        .await
        .ok();
    let result = execute(node, settings, from, &cmd).await;
    drop(turn);
    let text = match &result {
        Ok(note) => note.clone(),
        Err(e) => format!("refused: {e}"),
    };
    tracing::info!(by = %from.short(), command = %cmd.describe(), result = %text, "owner command");
    if let Some(row) = row {
        let _ = log_result(&node.store, row, &text).await;
    }
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
            Some(handle(&node, &settings, &seen, from, counter, &cmd, &sig).await)
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

/// Sign `cmd` with `key` for `target`'s counter `counter` and wait for the
/// answer.
async fn send(
    node: &Arc<Node>,
    key: &OwnerKey,
    target: NodeId,
    counter: u64,
    cmd: &OwnerCmd,
) -> Result<Msg> {
    let bytes = encode(cmd)?;
    let sig = sign(key, &node.id(), &target, counter, &bytes);
    let msg = Msg::OwnerCmd {
        counter,
        cmd: serde_bytes::ByteBuf::from(bytes),
        sig: serde_bytes::ByteBuf::from(sig),
    };
    node.request_avoiding(target, msg, TIMEOUT, old_relays(node, &target))
        .await
}

/// Members that cannot pass an owner message on: a node cannot read, and
/// so cannot relay, a kind of message it does not know.
pub(crate) fn old_relays(node: &Node, target: &NodeId) -> Vec<NodeId> {
    node.members()
        .iter()
        .filter(|(id, m)| *id != target && m.proto_max < OWNER_PROTO)
        .map(|(id, _)| *id)
        .collect()
}

/// The outer error: no answer; the inner one: the target's refusal.
async fn ask_status(
    node: &Arc<Node>,
    key: &OwnerKey,
    target: NodeId,
) -> Result<Result<Status, String>> {
    if let Err(e) = speaks_owner(node, &target) {
        return Ok(Err(format!("{e:#}")));
    }
    match send(node, key, target, 0, &OwnerCmd::Status).await? {
        Msg::OwnerReply {
            data: Some(OwnerData::Status(s)),
            ..
        } => Ok(Ok(*s)),
        Msg::OwnerReply { error: Some(e), .. } => Ok(Err(e)),
        other => bail!("unexpected answer {other:?}"),
    }
}

/// Ask `target` for its status, signed with `key`.
pub async fn status(node: &Arc<Node>, key: &OwnerKey, target: NodeId) -> Result<Status> {
    match ask_status(node, key, target).await? {
        Ok(s) => Ok(s),
        Err(e) => bail!("{e}"),
    }
}

async fn command(
    node: &Arc<Node>,
    key: &OwnerKey,
    target: NodeId,
    counter: u64,
    cmd: &OwnerCmd,
) -> Result<Result<String, String>> {
    // Nothing is sent: a refusal, not a missing answer.
    if let Err(e) = speaks_owner(node, &target) {
        return Ok(Err(format!("{e:#}")));
    }
    match send(node, key, target, counter, cmd).await? {
        Msg::OwnerReply { error: Some(e), .. } => Ok(Err(e)),
        Msg::OwnerReply {
            data: Some(OwnerData::Done { note }),
            ..
        } => Ok(Ok(note)),
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
    let leaves_fleet = matches!(cmd, OwnerCmd::Release | OwnerCmd::Reown { .. });
    let answer = command(node, key, target, counter, &cmd).await?;
    if leaves_fleet && answer.is_ok() {
        super::fleet::forget(&node.store, &target).await?;
    }
    Ok(answer)
}

/// What a key rotation did.
pub struct Rotation {
    /// The new key, to show once.
    pub key: OwnerKey,
    pub moved: Vec<NodeId>,
    /// Siblings still on the old key, and why.
    pub pending: Vec<(NodeId, String)>,
}

/// Bring `target` from `old` to `new`. A node that no longer takes the old
/// key but answers under the new one has moved already: in an attempt
/// whose answer was lost, or one that was cut short.
async fn move_one(
    node: &Arc<Node>,
    old: &OwnerKey,
    new: &OwnerKey,
    target: NodeId,
) -> Result<(), String> {
    let text = |e: anyhow::Error| format!("{e:#}");
    let st = match ask_status(node, old, target).await.map_err(text)? {
        Ok(st) => st,
        Err(refusal) => {
            return match ask_status(node, new, target).await {
                Ok(Ok(_)) => Ok(()),
                _ => Err(refusal),
            };
        }
    };
    let cmd = OwnerCmd::Reown {
        owner_id: serde_bytes::ByteBuf::from(new.id.0.to_vec()),
        cert: serde_bytes::ByteBuf::from(new.certify(&target)),
    };
    match command(node, old, target, st.counter, &cmd).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(text(e)),
    }
}

/// Siblings still on the previous key after a rotation.
pub async fn pending(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM reown_pending ORDER BY node")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// The same, each with why it was not moved when last tried.
pub async fn pending_reasons(store: &Store) -> Result<Vec<(NodeId, String)>> {
    let rows: Vec<(Vec<u8>, String)> =
        sqlx::query_as("SELECT node, why FROM reown_pending ORDER BY node")
            .fetch_all(&store.pool)
            .await?;
    rows.into_iter()
        .map(|(n, why)| Ok((NodeId::from_slice(&n)?, why)))
        .collect()
}

/// Replace the ownership key: every sibling that answers takes the new
/// one, then this node does. The old key stays here for the rest (see
/// [`retry`], [`discard`]). Siblings in `leave_out` are not told: they stay
/// on the old key and are no siblings afterwards, which is how a node that
/// does not cooperate is put out of the fleet.
///
/// The new key is stored before the first sibling is told, so a rotation
/// that is cut short (the process stops, the caller goes away) is finished
/// by calling this again: with the same key.
pub async fn rotate(node: &Arc<Node>, leave_out: &[NodeId]) -> Result<Rotation> {
    let _one = node.owner_locks.rotation.lock().await;
    let old = kept_key(node).await?;
    if node.store.setting_get(super::KEY_OLD_SEED).await?.is_some()
        || !pending(&node.store).await?.is_empty()
    {
        bail!(
            "a rotation is still waiting for nodes on the previous key: retry or give up on \
             them first"
        );
    }
    let new = match super::stored_key(&node.store, super::KEY_NEXT_SEED).await? {
        Some(k) => k,
        None => {
            let k = OwnerKey::generate()?;
            super::store_next(&node.store, &k).await?;
            k
        }
    };
    // A sibling adopted minutes ago is known after one round.
    if let Err(e) = super::fleet::discover(node).await {
        tracing::debug!(?e, "sibling discovery before the rotation failed");
    }
    // All at once: a sibling that does not answer costs its timeouts
    // once, not once per sibling after it.
    let targets: Vec<NodeId> = super::fleet::siblings(&node.store)
        .await?
        .into_iter()
        .filter(|s| !leave_out.contains(s))
        .collect();
    let results =
        futures::future::join_all(targets.iter().map(|s| move_one(node, &old, &new, *s))).await;
    let (mut moved, mut pending) = (vec![], vec![]);
    for (s, r) in targets.into_iter().zip(results) {
        match r {
            Ok(()) => moved.push(s),
            Err(e) => pending.push((s, e)),
        }
    }
    super::switch_key(&node.store, node.id(), &new, &old, &moved, &pending).await?;
    tracing::info!(
        owner = %new.id.short(),
        moved = moved.len(),
        pending = pending.len(),
        "ownership key rotated"
    );
    Ok(Rotation {
        key: new,
        moved,
        pending,
    })
}

/// Try again to move the siblings a rotation did not reach. When none is
/// left, the old key is deleted.
pub async fn retry(node: &Arc<Node>) -> Result<Vec<(NodeId, Result<(), String>)>> {
    let _one = node.owner_locks.rotation.lock().await;
    let new = kept_key(node).await?;
    let Some(old) = super::stored_key(&node.store, super::KEY_OLD_SEED).await? else {
        bail!("no rotation is waiting for siblings");
    };
    let waiting = pending(&node.store).await?;
    let results =
        futures::future::join_all(waiting.iter().map(|p| move_one(node, &old, &new, *p))).await;
    let (mut moved, mut failed) = (vec![], vec![]);
    for (p, r) in waiting.iter().zip(&results) {
        match r {
            Ok(()) => moved.push(*p),
            Err(why) => failed.push((*p, why.clone())),
        }
    }
    super::settle_retry(&node.store, &new, &old, &moved, &failed).await?;
    Ok(waiting.into_iter().zip(results).collect())
}

/// Give up on the siblings still on the previous key: delete it.
pub async fn discard(store: &Store) -> Result<()> {
    for sql in [
        "DELETE FROM reown_pending",
        "DELETE FROM settings WHERE key = 'owner.old_seed'",
    ] {
        sqlx::query(sql).execute(&store.pool).await?;
    }
    super::scrub(store).await;
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
        let (c, bytes) = (Identity::generate().unwrap().id, encode(&cmd).unwrap());
        let sig = sign(&k, &a, &b, 7, &bytes);
        assert!(verify(&k.id, &a, &b, 7, &bytes, &sig));
        assert!(!verify(&other.id, &a, &b, 7, &bytes, &sig), "another owner");
        assert!(!verify(&k.id, &c, &b, 7, &bytes, &sig), "another sender");
        assert!(!verify(&k.id, &a, &c, 7, &bytes, &sig), "another target");
        assert!(!verify(&k.id, &b, &a, 7, &bytes, &sig), "direction");
        assert!(!verify(&k.id, &a, &b, 8, &bytes, &sig), "counter");
        let status = encode(&OwnerCmd::Status).unwrap();
        assert!(!verify(&k.id, &a, &b, 7, &status, &sig), "command");
    }

    /// A later version may add a field to a command. The signature is
    /// checked over the bytes as sent, so such a command still verifies
    /// here and is read without the field.
    #[test]
    fn a_command_with_a_field_of_a_later_version_still_verifies() {
        #[derive(Serialize)]
        struct LaterChanges {
            max_workers: Option<u32>,
            later_field: Option<String>,
        }
        #[derive(Serialize)]
        #[serde(tag = "c", rename_all = "snake_case")]
        enum Later {
            Settings {
                base_version: u64,
                changes: LaterChanges,
            },
            LaterCommand {
                mc: u32,
            },
        }
        let enc = |c: &Later| crate::cluster::rpc::cbor::encode(c).unwrap();
        let k = OwnerKey::generate().unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let bytes = enc(&Later::Settings {
            base_version: 4,
            changes: LaterChanges {
                max_workers: Some(3),
                later_field: Some("x".into()),
            },
        });
        let sig = sign(&k, &a, &b, 7, &bytes);
        assert!(verify(&k.id, &a, &b, 7, &bytes, &sig));
        let read = decode(&bytes).expect("read without the field");
        let known = OwnerCmd::Settings {
            base_version: 4,
            changes: Changes {
                max_workers: Some(3),
                ..Default::default()
            },
        };
        assert_eq!(read, known);
        // Encoding what was read gives other bytes: a check over those
        // would refuse the command as signed with a wrong key.
        assert_ne!(encode(&read).unwrap(), bytes);
        // A kind of command this version does not know is not read.
        assert!(decode(&enc(&Later::LaterCommand { mc: 1 })).is_none());
    }

    #[test]
    fn bad_signatures_are_logged_ten_times_an_hour_per_sender() {
        let seen: Refusals = Default::default();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        for _ in 0..BAD_SIGNATURES_LOGGED {
            assert!(may_log(&seen, a));
        }
        assert!(!may_log(&seen, a));
        assert!(may_log(&seen, b), "counted per sender");
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
        assert_eq!(
            OwnerCmd::SendCredits { to: n, mc: 1250 }.describe(),
            format!("send 1.25 credits to {}", n.short())
        );
    }

    #[tokio::test]
    async fn the_log_lists_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let from = Identity::generate().unwrap().id;
        log(&store, &from, "one", "done", true).await.unwrap();
        let two = log(&store, &from, "two", STARTED, true).await.unwrap();
        log(&store, &from, "forged", "refused: x", false)
            .await
            .unwrap();
        let rows = log_rows(&store, 10).await.unwrap();
        assert_eq!(rows.len(), 2, "attempts with a wrong key are listed apart");
        assert_eq!((rows[0].command.as_str(), rows[0].from), ("two", from));
        assert_eq!(
            rows[0].result, STARTED,
            "what stays if the node stops halfway"
        );
        assert_eq!(rows[1].result, "done");
        log_result(&store, two, "refused: y").await.unwrap();
        assert_eq!(log_rows(&store, 10).await.unwrap()[0].result, "refused: y");
        assert_eq!(refused_rows(&store, 10).await.unwrap()[0].command, "forged");
        // Any member can cause such rows: only the newest are kept, and
        // they never push out the owner's commands.
        for i in 0..KEEP_UNVERIFIED + 5 {
            log(&store, &from, &format!("forged {i}"), "refused", false)
                .await
                .unwrap();
        }
        let kept = refused_rows(&store, 10_000).await.unwrap();
        assert_eq!(kept.len() as i64, KEEP_UNVERIFIED);
        assert_eq!(kept[0].command, format!("forged {}", KEEP_UNVERIFIED + 4));
        assert_eq!(log_rows(&store, 10).await.unwrap().len(), 2);
    }
}
