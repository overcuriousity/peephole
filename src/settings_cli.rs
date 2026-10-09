//! `peephole settings …`: inspect and change runtime settings from the
//! shell. Works on the node's database; a running daemon picks the change
//! up within a few seconds.
use crate::config::Config;
use crate::settings::{Changes, KEYS, Prereqs, Settings};
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole settings show [CONFIG]
       peephole settings set KEY VALUE [CONFIG]
       peephole settings reset [KEY] [CONFIG]";

/// Run a `settings` subcommand; `args` excludes `settings` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    // A trailing argument that is not a settings key is the config path.
    let config = |i: usize| arg(i).unwrap_or(default_config);
    let open = |path: &str| {
        let path = path.to_string();
        async move {
            let cfg = Config::load(Path::new(&path))?;
            let store = Store::connect(&cfg.database_path).await?;
            let nmap_ok = tokio::process::Command::new(cfg.scan.nmap())
                .arg("--version")
                .output()
                .await
                .is_ok_and(|o| o.status.success());
            let s = Settings::load(&store, &cfg, Prereqs::from_config(&cfg, nmap_ok)).await?;
            anyhow::Ok((cfg, s))
        }
    };
    match arg(0) {
        Some("show") => {
            let (_, s) = open(config(1)).await?;
            let now = s.snapshot();
            let src = |changed: bool| if changed { "override" } else { "config file" };
            println!("version {}", now.version);
            let file = Changes::from(s.defaults()).pairs();
            for ((key, value), (_, from_file)) in Changes::from(now).pairs().into_iter().zip(file) {
                println!("{key:<28} {value:<8} ({})", src(value != from_file));
            }
        }
        Some("set") => {
            let (Some(key), Some(value)) = (arg(1), arg(2)) else {
                bail!("{USAGE}");
            };
            let changes = Changes::from_key_value(key, value).map_err(anyhow::Error::msg)?;
            let (_, s) = open(config(3)).await?;
            match s.apply(&changes, None).await? {
                Ok(v) => println!(
                    "{} (settings version {v}); a running node applies it within seconds",
                    changes.describe()
                ),
                Err(e) => bail!("{e}"),
            }
        }
        Some("reset") => {
            let (key, cfg_at) = match arg(1) {
                Some(k) if KEYS.contains(&k) => (Some(k), 2),
                _ => (None, 1),
            };
            let (_, s) = open(config(cfg_at)).await?;
            match s.reset(key).await? {
                Ok(v) => println!(
                    "{} back to the config file (settings version {v})",
                    key.unwrap_or("all runtime settings")
                ),
                Err(e) => bail!("{e}"),
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
