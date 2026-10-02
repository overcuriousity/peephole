//! `peephole admin …`: admin-area maintenance from the shell. Works on the
//! node's database; a running daemon sees the change at once.
use crate::config::Config;
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole admin reset-token [CONFIG]";

/// Run an `admin` subcommand; `args` excludes `admin` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("reset-token") => {
            if args.len() > 2 {
                bail!("{USAGE}");
            }
            let cfg = Config::load(Path::new(arg(1).unwrap_or(default_config)))?;
            if !cfg.roles.web || cfg.admin_listen.is_none() {
                bail!("this node has no web interface (roles.web and admin_listen)");
            }
            let store = Store::connect(&cfg.database_path).await?;
            let keys = store.load_credentials().await?.len();
            let token = super::auth::issue_setup_token(&store).await?;
            println!("{}", super::auth::setup_token_notice(&token));
            if keys > 0 {
                println!(
                    "{keys} admin key(s) are already enrolled; this token enrolls one more \
                     (for example to replace a lost key). Remove keys you no longer have \
                     under Admin → Keys."
                );
            }
            println!("Any earlier setup token no longer works.");
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
