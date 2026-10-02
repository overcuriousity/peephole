//! `peephole admin …`: admin-access tasks from the shell.
use crate::config::Config;
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole admin setup-token [CONFIG]";

/// Run an `admin` subcommand; `args` excludes `admin` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let config = args.get(1).map(String::as_str).unwrap_or(default_config);
    match args.first().map(String::as_str) {
        Some("setup-token") => {
            let cfg = Config::load(Path::new(config))?;
            let store = Store::connect(&cfg.database_path).await?;
            let token = setup_token(&store).await?;
            crate::admin::auth::print_setup_token(&token);
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

/// A fresh first-run setup token (the previous one stops working). Only
/// while no key is enrolled: afterwards keys are added from Admin → Keys.
pub async fn setup_token(store: &Store) -> Result<String> {
    if !store.load_credentials().await?.is_empty() {
        bail!(
            "a FIDO2 key is already enrolled: sign in and add keys from Admin → Keys \
             (the setup token is only for the first key)"
        );
    }
    store.issue_setup_token().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issued_only_while_no_key_exists() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let first = setup_token(&s).await.unwrap();
        let second = setup_token(&s).await.unwrap();
        assert!(!s.setup_token_valid(&first).await.unwrap(), "replaced");
        assert!(s.setup_token_valid(&second).await.unwrap());
        s.save_credential(b"k", "{}", None).await.unwrap();
        let e = setup_token(&s).await.unwrap_err();
        assert!(e.to_string().contains("already enrolled"), "{e}");
    }
}
