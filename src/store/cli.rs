//! `peephole db …`: database maintenance from the shell.
use crate::config::Config;
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole db vacuum [CONFIG]";

/// Run a `db` subcommand; `args` excludes `db` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let config = args.get(1).map(String::as_str).unwrap_or(default_config);
    match args.first().map(String::as_str) {
        Some("vacuum") => {
            let cfg = Config::load(Path::new(config))?;
            let store = Store::connect(&cfg.database_path).await?;
            println!(
                "rebuilding {} (stop the service first: this holds the database's \
                 write lock and needs free disk space of about its size) …",
                cfg.database_path.display()
            );
            let (before, after) = store.vacuum().await?;
            println!(
                "done: {} → {}; freed pages are now returned to the file system daily",
                mib(before),
                mib(after)
            );
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

fn mib(bytes: i64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}
