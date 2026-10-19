//! `peephole db …` (or `peephole store …`): database maintenance from the
//! shell.
use crate::config::Config;
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole db vacuum [CONFIG]
       peephole store recompute-campaigns [CONFIG]
       peephole store campaigns-eval CONFIG   (on a copy of the database)";

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
        Some("recompute-campaigns") => {
            let cfg = Config::load(Path::new(config))?;
            let store = Store::connect(&cfg.database_path).await?;
            println!("{}", store.recompute_campaigns(true).await?);
            crate::intel::hosting::install(&cfg.data_dir);
            print!("{}", store.recompute_evidence().await?);
            Ok(())
        }
        Some("campaigns-eval") if args.len() == 2 => {
            let cfg = Config::load(Path::new(config))?;
            let store = Store::connect(&cfg.database_path).await?;
            print!("{}", campaigns_eval(&store).await?);
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

/// Derive every path shape, then compare the campaign parameters on the
/// rows (see [`super::campaigns::evaluate`]). Derives into the database it
/// is given: run it on a copy.
async fn campaigns_eval(store: &Store) -> Result<String> {
    let started = std::time::Instant::now();
    while super::shapes::backfill(&store.pool).await? > 0 {}
    let mut conn = store.pool.acquire().await?;
    let input = super::campaigns::Input::read(&mut conn).await?;
    let read = started.elapsed().as_secs_f64();
    Ok(format!(
        "shapes derived and rows read in {read:.2} s\n{}",
        super::campaigns::evaluate(&input)
    ))
}

fn mib(bytes: i64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::campaigns::tests::section;

    #[tokio::test]
    async fn campaigns_eval_runs_on_an_empty_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let out = campaigns_eval(&store).await.unwrap();
        for title in ["V1", "guard only", "V2 default"] {
            assert!(
                section(&out, title).contains(&"campaigns 0, members 0"),
                "{out}"
            );
        }
        let rows = section(&out, "grid")
            .iter()
            .filter(|l| l.starts_with("| 0."))
            .count();
        assert_eq!(rows, 24, "{out}");
    }
}
