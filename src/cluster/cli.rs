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
                               (default: expires after 168 h, 10 uses; 0 lifts a limit)
       peephole cluster invites [CONFIG]
       peephole cluster invite-revoke ID [CONFIG]
       peephole cluster join TOKEN [CONFIG]
       peephole cluster members [CONFIG]
       peephole cluster status [CONFIG]
       peephole cluster block [--subtree] NODE [CONFIG]
                               (NODE: name, fingerprint or ed25519:… key; --subtree also
                                blocks every node it admitted, transitively)
       peephole cluster unblock NODE [CONFIG]
       peephole cluster purge NODE [CONFIG]     (delete a blocked node's data here)
       peephole cluster agreement NODE [--sample N] [CONFIG]
                               (its newest N requests (default 500) classified again with
                                our rules, as the member pages do; lists those that differ)
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

/// Characters of a path shown by `agreement`.
const PATH_SHOWN: usize = 60;

/// What `cluster agreement` prints: the summary a member's page shows,
/// then every request our rules do not reproduce, with the verdicts under
/// both history bounds (see `classify::stored::History`).
fn agreement_report(
    id: NodeId,
    ours: &str,
    checks: &[crate::classify::stored::RowCheck],
) -> String {
    use crate::classify::stored::{Agreement, Reclassified};
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}: {} (our rules {})",
        id.short(),
        Agreement::of(checks).summary(),
        ours.chars().take(12).collect::<String>()
    );
    let verdict = |labels: &[String], severity: i64| {
        let labels = if labels.is_empty() {
            "-".to_string()
        } else {
            labels.join(",")
        };
        format!("{labels} severity {severity}")
    };
    for c in checks.iter().filter(|c| !c.agrees) {
        let r = &c.row;
        let mut path: String = r.path.chars().take(PATH_SHOWN).collect();
        if r.path.chars().count() > PATH_SHOWN {
            path.push('…');
        }
        let _ = writeln!(
            out,
            "#{} {} {} {}",
            r.id,
            r.ts,
            r.method,
            path.escape_debug()
        );
        let _ = writeln!(
            out,
            "    stored  {}",
            verdict(&r.stored_labels(), r.severity)
        );
        for x in [&c.seen, &c.own] {
            let Reclassified {
                scope,
                hist,
                verdict: v,
            } = x;
            let _ = writeln!(
                out,
                "    {:<7} {}  (history: {} requests, {} paths)",
                scope.name(),
                verdict(&v.labels, i64::from(v.severity)),
                hist.requests_1h,
                hist.distinct_paths_1h
            );
        }
    }
    out
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
            let (ttl_hours, max_uses) =
                invite::InviteOpts::parse_limits(flag("ttl"), flag("uses"))?;
            let opts = invite::InviteOpts {
                label: flag("label").unwrap_or_default().to_string(),
                ttl_hours,
                max_uses,
            };
            let (_, node) = open(cfg_at(1)).await?;
            let token = invite::create(&node, &opts).await?;
            println!("{token}");
            let limits = format!(
                "expires {}, {}",
                opts.ttl_hours
                    .map_or("never".to_string(), |h| format!("after {h} h")),
                opts.max_uses
                    .map_or("no use limit".to_string(), |n| format!("at most {n} uses"))
            );
            eprintln!(
                "reusable invite ({limits}). Whoever holds it can join, and a member cannot be \
                 removed afterwards, only blocked node by node. Change the limits with --uses \
                 or --ttl (0 lifts one); revoke it with: peephole cluster invite-revoke <id> \
                 (see: peephole cluster invites)"
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
            let floors = {
                let mut conn = store.pool.acquire().await?;
                super::history::floors(&mut conn).await?
            };
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
                    match floors.get(&m.id) {
                        Some(f) => println!(
                            "    log head  {} (held from seq {f})",
                            repl::head_in(&heads, &m.id)
                        ),
                        None => println!("    log head  {}", repl::head_in(&heads, &m.id)),
                    }
                    if Some(m.id) == my_id {
                        match cfg.retention_days {
                            0 => println!("    history   full"),
                            d => println!("    history   keeps {d} days"),
                        }
                    }
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
        Some("agreement") => {
            reject_unknown_flags(&flags, &["sample"])?;
            let who = pos.get(1).context(USAGE)?;
            let sample: i64 = match flags.iter().find(|(k, _)| k == "sample") {
                Some((_, v)) => v
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .context("--sample takes a positive number")?,
                None => crate::credits::gates::RULES_SAMPLE,
            };
            // Read-only, as `status`.
            let cfg = Config::load(Path::new(cfg_at(2)))?;
            if cfg.cluster.is_none() {
                bail!("config has no [cluster] section");
            }
            let store = Store::connect(&cfg.database_path).await?;
            let id = resolve(&members::all(&store).await?, who)?;
            let c = crate::classify::Classifier::builtin();
            let checks =
                crate::classify::stored::compare(&store.pool, c, Some(&id.0[..]), sample).await?;
            print!("{}", agreement_report(id, c.fingerprint(), &checks));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    /// The report lists the rows our rules do not reproduce, with both
    /// histories, and summarises as the member pages do.
    #[tokio::test]
    async fn agreement_lists_differing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = NodeId([7u8; 32]);
        for (path, labels, severity) in [("/fine", r#"["probe"]"#, 1), ("/odd", r#"["rce"]"#, 4)] {
            store
                .local()
                .insert_request_from(
                    "198.51.100.4",
                    &NewRequest {
                        method: "GET".into(),
                        path: path.into(),
                        headers_json: "[]".into(),
                        labels_json: labels.into(),
                        severity,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        sqlx::query("UPDATE requests SET origin = ?")
            .bind(&id.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        let c = crate::classify::Classifier::builtin();
        let checks = crate::classify::stored::compare(&store.pool, c, Some(&id.0[..]), 500)
            .await
            .unwrap();
        let out = agreement_report(id, c.fingerprint(), &checks);
        assert!(out.contains("disagree on 50% of 2"), "{out}");
        assert!(out.contains(" GET /odd\n"), "{out}");
        assert!(!out.contains("/fine"), "{out}");
        assert!(out.contains("    stored  rce severity 4\n"), "{out}");
        assert!(
            out.contains("    seen    probe severity 1  (history: 2 requests, 2 paths)\n"),
            "{out}"
        );
        assert!(
            out.contains("    own     probe severity 1  (history: 1 requests, 1 paths)\n"),
            "{out}"
        );
    }
}
