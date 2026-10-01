//! `peephole cluster …` subcommands.
use super::identity::Identity;
use crate::config::Config;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole cluster id [CONFIG]";

/// Run a `cluster` subcommand; `args` excludes `cluster` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let config = |i: usize| -> Result<Config> {
        Config::load(Path::new(
            args.get(i).map(String::as_str).unwrap_or(default_config),
        ))
    };
    match args.first().map(String::as_str) {
        Some("id") => {
            let cfg = config(1)?;
            if cfg.cluster.is_none() {
                bail!("config has no [cluster] section");
            }
            let id = Identity::load_or_create(&cfg.node_key_path())?;
            println!("{}", id.id);
            eprintln!("fingerprint {}", id.id.short());
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
