//! `peephole cluster …` subcommands. They open the node's database
//! directly, so they work on headless nodes and while the daemon runs; the
//! daemon picks up their changes within a few seconds.
use super::identity::Identity;
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
       peephole cluster leave [CONFIG]";

/// `--name value` pairs.
type Flags = Vec<(String, String)>;

/// Split `args` into flags (`--ttl 12`) and positionals.
fn parse_args(args: &[String]) -> Result<(Flags, Vec<String>)> {
    let (mut flags, mut pos) = (vec![], vec![]);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
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
                    "{:<20} {}  {:<12} {:<28} roles={}{}",
                    m.name,
                    m.id.short(),
                    state,
                    m.address.as_deref().unwrap_or("(outbound-only)"),
                    m.roles.join(","),
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
