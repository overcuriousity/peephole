//! `peephole owner …`: the ownership key on this node. Like `peephole
//! cluster`, it opens the node's database directly, so it works on
//! headless nodes and while the daemon runs.
use super::OwnerKey;
use crate::cluster::identity::Identity;
use crate::cluster::members;
use crate::config::Config;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole owner new [CONFIG]
       peephole owner adopt [--keep] [CONFIG]   (reads the key from standard input;
                                                 --keep: manage other nodes from here)
       peephole owner show [CONFIG]
       peephole owner forget-key [--force] [CONFIG]
                                                (the node stays owned; --force: also
                                                 while a key rotation is not finished)
       peephole owner release [CONFIG]          (the node has no owner afterwards)";

/// One line from standard input. Typed at a terminal, it is not shown
/// while it is typed (as far as `stty` can be asked to).
fn read_key() -> Result<String> {
    use std::io::IsTerminal;
    let stty = |arg: &str| {
        std::process::Command::new("stty")
            .arg(arg)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let typed = std::io::stdin().is_terminal();
    let hidden = typed && stty("-echo");
    if typed {
        eprint!(
            "ownership key{}: ",
            if hidden {
                ""
            } else {
                " (it will be visible; clear the screen afterwards)"
            }
        );
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if hidden {
        stty("echo");
        eprintln!();
    }
    read.context("reading the key from standard input")?;
    Ok(line)
}

pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let (mut keep, mut force) = (false, false);
    let mut pos: Vec<&str> = vec![];
    for a in args {
        match a.as_str() {
            "--keep" => keep = true,
            "--force" => force = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            f if f.starts_with("--") => bail!("unknown flag {f}\n\n{USAGE}"),
            p => pos.push(p),
        }
    }
    let sub = *pos.first().context(USAGE)?;
    if pos.len() > 2 {
        bail!("unexpected argument '{}'\n\n{USAGE}", pos[2]);
    }
    if keep && sub != "adopt" {
        bail!("--keep belongs to `adopt`\n\n{USAGE}");
    }
    if force && sub != "forget-key" {
        bail!("--force belongs to `forget-key`\n\n{USAGE}");
    }
    let cfg = Config::load(Path::new(pos.get(1).copied().unwrap_or(default_config)))?;
    if cfg.cluster.is_none() {
        bail!("config has no [cluster] section: ownership is for cluster nodes");
    }
    let store = Store::connect(&cfg.database_path).await?;
    let me = Identity::load_or_create(&cfg.node_key_path())?.id;
    match sub {
        "new" => {
            if let Some(o) = super::load(&store, me).await? {
                bail!(
                    "this node already has an owner ({}); release it first: peephole owner release",
                    o.id.short()
                );
            }
            let key = super::create(&store, me).await?;
            println!("{}", key.encode());
            eprintln!(
                "this is the ownership key, shown once. Whoever holds it controls every node \
                 it is entered on. Enter it on your other nodes with: peephole owner adopt"
            );
        }
        "adopt" => {
            let line = read_key()?;
            let key = OwnerKey::parse(&line)?;
            super::adopt(&store, me, &key, keep).await?;
            // As it is now: a key this node already kept stays kept.
            let kept = super::load(&store, me).await?.is_some_and(|o| o.managing());
            println!(
                "this node is now owned by {} ({})",
                key.id.short(),
                if kept {
                    "key kept here"
                } else {
                    "key not kept here"
                }
            );
        }
        "show" => match super::load(&store, me).await? {
            None => println!("no owner"),
            Some(o) => {
                println!(
                    "owner {} ({})",
                    o.id.short(),
                    if o.managing() {
                        "key kept here"
                    } else {
                        "key not kept here"
                    }
                );
                let names: std::collections::HashMap<_, _> = members::all(&store)
                    .await?
                    .into_iter()
                    .map(|m| (m.id, m.name))
                    .collect();
                let rows: Vec<Vec<u8>> =
                    sqlx::query_scalar("SELECT node FROM siblings ORDER BY node")
                        .fetch_all(&store.pool)
                        .await?;
                for r in rows {
                    let id = crate::cluster::identity::NodeId::from_slice(&r)?;
                    println!(
                        "  {} {}",
                        id.short(),
                        names.get(&id).map(String::as_str).unwrap_or("?")
                    );
                }
            }
        },
        "forget-key" => {
            let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reown_pending")
                .fetch_one(&store.pool)
                .await?;
            let unfinished = super::rotation_unfinished(&store).await?;
            // The keys kept for a rotation are the only way to the nodes it
            // has moved (when it was cut short) or not moved yet.
            let stranded = if unfinished {
                let siblings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM siblings")
                    .fetch_one(&store.pool)
                    .await?;
                format!(
                    "a key rotation was cut short here: up to {siblings} node(s) may already be \
                     on the new key"
                )
            } else {
                format!("a key rotation left {waiting} node(s) on the previous key")
            };
            if (unfinished || waiting > 0) && !force {
                bail!(
                    "{stranded}. Finish the rotation, or retry or give up on those nodes, on \
                     Cluster › Ownership first. To forget every key kept here anyway: \
                     peephole owner forget-key --force"
                );
            }
            if super::forget_key(&store).await? {
                println!("the ownership key is no longer kept on this node; it stays owned");
                if unfinished || waiting > 0 {
                    eprintln!(
                        "warning: {stranded}. The keys kept for the rotation are deleted too; \
                         give those nodes their owner again on the nodes themselves: \
                         peephole owner adopt"
                    );
                }
            } else {
                println!("no ownership key was kept on this node");
            }
        }
        "release" => {
            if super::release(&store).await? {
                println!("this node has no owner now");
            } else {
                println!("this node had no owner");
            }
        }
        other => bail!("unknown subcommand '{other}'\n\n{USAGE}"),
    }
    Ok(())
}
