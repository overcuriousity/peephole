//! `peephole admin …`: admin-access tasks from the shell. Works on the
//! node's database; a running daemon sees the change at once.
use crate::config::Config;
use crate::store::{Store, auth::LoginMethod};
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole admin reset-token [CONFIG]
       peephole admin password [--stdin] [CONFIG]
       peephole admin login-method passkey|password|both [CONFIG]";

/// Run an `admin` subcommand; `args` excludes `admin` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("reset-token") => {
            if args.len() > 2 {
                bail!("{USAGE}");
            }
            let store = open_store(arg(1).unwrap_or(default_config)).await?;
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
        Some("password") => {
            let stdin = arg(1) == Some("--stdin");
            let rest = &args[1 + usize::from(stdin)..];
            if rest.len() > 1 {
                bail!("{USAGE}");
            }
            let store = open_store(rest.first().map_or(default_config, String::as_str)).await?;
            let pw = if stdin {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                stdin_password(&line).to_string()
            } else {
                let pw = rpassword::prompt_password("New admin password: ")?;
                if rpassword::prompt_password("Repeat it: ")? != pw {
                    bail!("the two passwords differ");
                }
                pw
            };
            if let Err(why) = crate::admin::password::check_new(&pw) {
                bail!("the password needs {why}");
            }
            store
                .set_password_hash(&crate::admin::password::hash(&pw)?, None)
                .await?;
            println!(
                "Password set. Sign-in: {}.",
                store.login_method().await?.as_str()
            );
            Ok(())
        }
        Some("login-method") => {
            if args.len() < 2 || args.len() > 3 {
                bail!("{USAGE}");
            }
            let method: LoginMethod = args[1].parse()?;
            let store = open_store(arg(2).unwrap_or(default_config)).await?;
            store.set_login_method(method).await.map_err(|e| {
                if e.to_string() == "no password is set" {
                    anyhow::anyhow!("{e}: run peephole admin password first")
                } else {
                    e
                }
            })?;
            println!("Sign-in: {}.", method.as_str());
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

/// The node's store, for a node that serves the admin web interface.
async fn open_store(config: &str) -> Result<Store> {
    let cfg = Config::load(Path::new(config))?;
    if !cfg.roles.web || cfg.admin_listen.is_none() {
        bail!("this node has no web interface (roles.web and admin_listen)");
    }
    Store::connect(&cfg.database_path).await
}

/// The password from one line of stdin: only the line ending is removed.
fn stdin_password(input: &str) -> &str {
    let line = input.strip_suffix('\n').unwrap_or(input);
    line.strip_suffix('\r').unwrap_or(line)
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

    #[test]
    fn stdin_password_strips_only_the_line_ending() {
        assert_eq!(stdin_password("pw\n"), "pw");
        assert_eq!(stdin_password("pw\r\n"), "pw");
        assert_eq!(stdin_password(" spaced pw \n"), " spaced pw ");
    }

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
