//! `peephole cluster …` subcommands. They open the node's database
//! directly, so they work on headless nodes and while the daemon runs; the
//! daemon picks up their changes within a few seconds.
use super::identity::{Identity, NodeId};
use super::{Node, NodeParams, invite, members, repl};
use crate::config::Config;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::sync::Arc;

pub const USAGE: &str = "usage: peephole cluster id [CONFIG]
       peephole cluster invite [--label TEXT] [--ttl HOURS] [--uses N] [CONFIG]
       peephole cluster invites [CONFIG]
       peephole cluster invite-revoke ID [CONFIG]
       peephole cluster join TOKEN [CONFIG]
       peephole cluster members [CONFIG]
       peephole cluster status [CONFIG]
       peephole cluster config-key show|rotate [CONFIG]
       peephole cluster config-key add KEY [CONFIG]
       peephole cluster config-key forget NODE [CONFIG]
       peephole cluster block [--subtree] NODE [CONFIG]
                               (NODE: name, fingerprint or ed25519:… key; --subtree also
                                blocks every node it admitted, transitively)
       peephole cluster unblock NODE [CONFIG]
       peephole cluster purge NODE [CONFIG]     (delete a blocked node's data here)
       peephole cluster leave [CONFIG]";

/// `--name value` pairs.
type Flags = Vec<(String, String)>;

/// Flags that take no value.
const SWITCHES: &[&str] = &["subtree"];

/// Split `args` into flags (`--ttl 12`, `--subtree`) and positionals.
fn parse_args(args: &[String]) -> Result<(Flags, Vec<String>)> {
    let (mut flags, mut pos) = (vec![], vec![]);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if SWITCHES.contains(&name) {
                flags.push((name.to_string(), String::new()));
                continue;
            }
            let v = it
                .next()
                .with_context(|| format!("--{name} needs a value"))?;
            flags.push((name.to_string(), v.clone()));
        } else {
            pos.push(a.clone());
        }
    }
    Ok((flags, pos))
}

/// Reject flags a subcommand does not understand, so a typo like `--tll 12`
/// fails loudly instead of being silently ignored (and defaulting).
fn reject_unknown_flags(flags: &Flags, allowed: &[&str]) -> Result<()> {
    for (k, _) in flags {
        if !allowed.contains(&k.as_str()) {
            bail!("unknown option --{k}\n{USAGE}");
        }
    }
    Ok(())
}

async fn open(config: &str) -> Result<(Config, Arc<Node>)> {
    let cfg = Config::load(Path::new(config))?;
    if cfg.cluster.is_none() {
        bail!("{config} has no [cluster] section");
    }
    let store = Store::connect(&cfg.database_path).await?;
    let node = Node::open(NodeParams::from_config(&cfg, store)?).await?;
    // Make sure our own description exists before acting for the cluster.
    node.bootstrap().await?;
    Ok((cfg, node))
}

/// Find a member by name, short fingerprint or full key.
fn resolve(rows: &[members::MemberRow], who: &str) -> Result<NodeId> {
    if let Ok(id) = NodeId::parse(who) {
        return Ok(id);
    }
    let hits: Vec<_> = rows
        .iter()
        .filter(|m| m.name == who || m.id.short() == who)
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no member named `{who}`"),
        _ => bail!("`{who}` is ambiguous; use the full key"),
    }
}

/// Run a `cluster` subcommand; `args` excludes `cluster` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let (flags, pos) = parse_args(args)?;
    let cfg_at = |i: usize| pos.get(i).map(String::as_str).unwrap_or(default_config);
    match pos.first().map(String::as_str) {
        Some("id") => {
            reject_unknown_flags(&flags, &[])?;
            let cfg = Config::load(Path::new(cfg_at(1)))?;
            if cfg.cluster.is_none() {
                bail!("config has no [cluster] section");
            }
            let id = Identity::load_or_create(&cfg.node_key_path())?;
            println!("{}", id.id);
            eprintln!("fingerprint {}", id.id.short());
        }
        Some("invite") => {
            reject_unknown_flags(&flags, &["label", "ttl", "uses"])?;
            let flag = |name: &str| {
                flags
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
            };
            let opts = invite::InviteOpts {
                label: flag("label").unwrap_or_default().to_string(),
                ttl_hours: flag("ttl")
                    .map(|v| v.parse().context("--ttl: hours"))
                    .transpose()?,
                max_uses: flag("uses")
                    .map(|v| v.parse().context("--uses: a number"))
                    .transpose()?,
            };
            let (_, node) = open(cfg_at(1)).await?;
            let token = invite::create(&node, &opts).await?;
            println!("{token}");
            eprintln!(
                "reusable invite. Whoever holds it can join, and a member cannot be removed \
                 afterwards, only blocked node by node. Limit it with --uses or --ttl; \
                 revoke it with: peephole cluster invite-revoke <id> (see: peephole cluster invites)"
            );
        }
        Some("invites") => {
            reject_unknown_flags(&flags, &[])?;
            let cfg = Config::load(Path::new(cfg_at(1)))?;
            let store = Store::connect(&cfg.database_path).await?;
            for i in invite::list(&store).await? {
                println!(
                    "{:<4} {:<8} uses {}{}  expires {}  created {}  {}",
                    i.id,
                    if i.usable {
                        "usable"
                    } else if i.revoked {
                        "revoked"
                    } else {
                        "closed"
                    },
                    i.uses,
                    i.max_uses.map(|m| format!("/{m}")).unwrap_or_default(),
                    i.expires_at.as_deref().unwrap_or("never"),
                    i.created_at,
                    i.label
                );
                for n in i.joined {
                    println!("       joined: {}", n.short());
                }
            }
        }
        Some("invite-revoke") => {
            reject_unknown_flags(&flags, &[])?;
            let id: i64 = pos.get(1).context(USAGE)?.parse().context("invite id")?;
            let cfg = Config::load(Path::new(cfg_at(2)))?;
            let store = Store::connect(&cfg.database_path).await?;
            if invite::revoke(&store, id).await? {
                println!("invite {id} revoked; members that joined with it stay");
            } else {
                bail!("no usable invite {id}");
            }
        }
        Some("join") => {
            reject_unknown_flags(&flags, &[])?;
            let token = pos.get(1).context(USAGE)?;
            let (_, node) = open(cfg_at(2)).await?;
            let inviter = invite::join(&node, token).await?;
            println!(
                "joined via {} ({}); the cluster syncs once peephole runs",
                inviter.name,
                inviter.id.short()
            );
        }
        Some("members") | Some("status") => {
            reject_unknown_flags(&flags, &[])?;
            let status = pos[0] == "status";
            // Read-only: open the store directly instead of a full Node, so a
            // status check never writes (bootstrap would re-append this node's
            // MemberUpdate — repeatedly, if the clock is skewed).
            let cfg = Config::load(Path::new(cfg_at(1)))?;
            if cfg.cluster.is_none() {
                bail!("config has no [cluster] section");
            }
            let store = Store::connect(&cfg.database_path).await?;
            let my_id = Identity::load(&cfg.node_key_path()).ok().map(|i| i.id);
            let rows = members::all(&store).await?;
            let heads = repl::heads(&store).await?;
            let contact: Vec<(Vec<u8>, Option<String>, Option<String>)> =
                sqlx::query_as("SELECT id, last_ok, last_error FROM peer_contact")
                    .fetch_all(&store.pool)
                    .await?;
            let blocked = super::block::list(&store).await?;
            if let Some(d) = crate::cluster::Detached::read(&store).await? {
                println!("{}", d.label());
            }
            for m in rows {
                let me = if Some(m.id) == my_id {
                    " (this node)"
                } else {
                    ""
                };
                let state = m.standing.label();
                println!(
                    "{:<20} {}  {:<12} {:<28} roles={}{}{}",
                    m.name,
                    m.id.short(),
                    state,
                    m.address.as_deref().unwrap_or("(outbound-only)"),
                    m.roles.join(","),
                    if blocked.contains(&m.id) {
                        " blocked"
                    } else {
                        ""
                    },
                    me
                );
                if status {
                    println!("    key       {}", m.id);
                    println!("    log head  {}", repl::head_in(&heads, &m.id));
                    if let Some((_, ok, err)) = contact.iter().find(|c| c.0 == m.id.0) {
                        println!("    last ok   {}", ok.as_deref().unwrap_or("never"));
                        if let Some(e) = err {
                            println!("    error     {e}");
                        }
                    }
                }
            }
        }
        Some(cmd @ ("block" | "unblock")) => {
            reject_unknown_flags(&flags, if cmd == "block" { &["subtree"] } else { &[] })?;
            let who = pos.get(1).context(USAGE)?;
            let (_, node) = open(cfg_at(2)).await?;
            let id = resolve(&members::all(&node.store).await?, who)?;
            if cmd == "block" && flags.iter().any(|(k, _)| k == "subtree") {
                let (ids, n) = super::block::block_subtree(&node, id).await?;
                println!(
                    "blocked {} and the {} node(s) it admitted, directly or not ({n} records \
                     taken out of view). Other nodes are unaffected.",
                    id.short(),
                    ids.len() - 1
                );
                for i in &ids[1..] {
                    println!("  also blocked {}", i.short());
                }
            } else if cmd == "block" {
                let n = super::block::block(&node, id).await?;
                println!(
                    "blocked {}: this node no longer talks to it and shows none of its records \
                     ({n} taken out of view). Other nodes are unaffected.",
                    id.short()
                );
            } else if super::block::unblock(&node, id).await? {
                println!("unblocked {}; its records are back", id.short());
            } else {
                println!("{} was not blocked", id.short());
            }
        }
        Some("purge") => {
            reject_unknown_flags(&flags, &[])?;
            let who = pos.get(1).context(USAGE)?;
            let (_, node) = open(cfg_at(2)).await?;
            let id = resolve(&members::all(&node.store).await?, who)?;
            let n = super::block::purge(&node, id).await?;
            println!(
                "purged {}: {n} log entries deleted here; its entries are no longer accepted \
                 nor relayed. Unblocking fetches them again.",
                id.short()
            );
        }
        Some("config-key") => {
            reject_unknown_flags(&flags, &[])?;
            let sub = pos.get(1).map(String::as_str);
            let takes_arg = matches!(sub, Some("add" | "forget"));
            let cfg = Config::load(Path::new(cfg_at(if takes_arg { 3 } else { 2 })))?;
            let Some(c) = &cfg.cluster else {
                bail!("config has no [cluster] section");
            };
            let store = Store::connect(&cfg.database_path).await?;
            let me = Identity::load_or_create(&cfg.node_key_path())?.id;
            match sub {
                Some("show" | "rotate") => {
                    if !c.remote_config {
                        bail!(
                            "remote configuration is off (cluster.remote_config = false): \
                             this node has no usable config key"
                        );
                    }
                    let key = if sub == Some("rotate") {
                        super::confkey::rotate(&store, me).await?
                    } else {
                        super::confkey::ensure(&store, me).await?
                    };
                    println!("{}", key.encode());
                    eprintln!(
                        "whoever holds this key can change this node's scan pace, rescan \
                         cooldown and roles. `peephole cluster config-key rotate` withdraws it \
                         from everyone."
                    );
                }
                Some("add") => {
                    let id = super::confkey::add(&store, me, pos.get(2).context(USAGE)?).await?;
                    println!(
                        "config key for {} stored; configure it on Admin → Cluster",
                        id.short()
                    );
                }
                Some("forget") => {
                    let id = resolve(&members::all(&store).await?, pos.get(2).context(USAGE)?)?;
                    if super::confkey::forget(&store, &id).await? {
                        println!("config key for {} forgotten", id.short());
                    } else {
                        println!("no config key held for {}", id.short());
                    }
                }
                _ => bail!("{USAGE}"),
            }
        }
        Some("leave") => {
            reject_unknown_flags(&flags, &[])?;
            let (_, node) = open(cfg_at(1)).await?;
            let told = super::leave(&node).await?;
            println!(
                "left the cluster ({told} peer(s) told). This node keeps its data and no \
                 longer syncs; rejoin with: peephole cluster join <token>"
            );
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
