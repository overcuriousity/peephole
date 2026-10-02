//! `peephole admin …`: admin-access tasks from the shell. Works on the
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
            let (token, keys) = reset_token(&store).await?;
            crate::admin::auth::print_setup_token(&token);
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

/// A fresh one-time setup token, replacing any earlier one (unused or
/// consumed), and the number of keys already enrolled. Used when the first
/// token was missed in the log, or every admin key is lost.
pub async fn reset_token(store: &Store) -> Result<(String, usize)> {
    let keys = store.load_credentials().await?.len();
    Ok((store.issue_setup_token().await?, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_new_token_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (first, _) = reset_token(&s).await.unwrap();
        let (second, keys) = reset_token(&s).await.unwrap();
        assert_eq!(keys, 0);
        assert!(!s.setup_token_valid(&first).await.unwrap(), "replaced");
        assert!(s.setup_token_valid(&second).await.unwrap());
        // With a key enrolled (a lost one, say) a token is still issued.
        s.save_credential(b"k", "{}", None).await.unwrap();
        let (third, keys) = reset_token(&s).await.unwrap();
        assert_eq!(keys, 1);
        assert!(s.setup_token_valid(&third).await.unwrap());
    }
}
