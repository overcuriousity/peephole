use std::path::{Path, PathBuf};

const DEFAULT_CONFIG: &str = "/etc/peephole/config.toml";

const USAGE: &str = "\
usage: peephole [CONFIG]                 run the daemon (default /etc/peephole/config.toml)
       peephole check-config [CONFIG]    validate config and nmap; show the built-in rules
       peephole cluster (id|invite|invites|invite-revoke|join|members|status|config-key|block|unblock|leave) …
       peephole settings (show|set|reset) …
       peephole export [OPTIONS] [CONFIG]  the dataset as Parquet, CSV or JSON Lines (--help)
       peephole admin reset-token [CONFIG]
       peephole db vacuum [CONFIG]
       peephole --version | -V
       peephole --help | -h | help

CONFIG must be a path: it contains a '/', ends in .toml, or names an existing file.";

/// What the command line asks for.
#[derive(Debug, PartialEq)]
enum Cmd {
    Help,
    Version,
    CheckConfig(PathBuf),
    Cluster,
    Settings,
    Export,
    Admin,
    Db,
    Run(PathBuf),
}

/// A word that may be taken as a config path: path-like or an existing file,
/// so a mistyped subcommand ("chek-config", "hepl") is not started as the
/// daemon with a config that does not exist.
fn config_path(arg: &str) -> Result<PathBuf, String> {
    if arg.starts_with('-') {
        return Err(format!("unknown option '{arg}'"));
    }
    if arg.contains('/') || arg.ends_with(".toml") || Path::new(arg).is_file() {
        Ok(PathBuf::from(arg))
    } else {
        Err(format!("unknown command '{arg}'"))
    }
}

fn parse(args: &[String]) -> Result<Cmd, String> {
    let extra = |from: usize| match args.get(from) {
        Some(a) => Err(format!("unexpected argument '{a}'")),
        None => Ok(()),
    };
    let config_at = |i: usize| -> Result<PathBuf, String> {
        let p = args
            .get(i)
            .map_or(Ok(PathBuf::from(DEFAULT_CONFIG)), |a| config_path(a))?;
        extra(i + 1)?;
        Ok(p)
    };
    match args.first().map(String::as_str) {
        Some("--help" | "-h" | "help") => Ok(Cmd::Help),
        Some("--version" | "-V") => extra(1).map(|_| Cmd::Version),
        Some("check-config") => config_at(1).map(Cmd::CheckConfig),
        // These parse their own arguments.
        Some("cluster") => Ok(Cmd::Cluster),
        Some("settings") => Ok(Cmd::Settings),
        Some("export") => Ok(Cmd::Export),
        Some("admin") => Ok(Cmd::Admin),
        Some("db") => Ok(Cmd::Db),
        _ => config_at(0).map(Cmd::Run),
    }
}

fn fail(e: anyhow::Error) -> ! {
    eprintln!("error: {e:#}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    match cmd {
        Cmd::Help => println!("{USAGE}"),
        // The first two words are what install.sh compares ("peephole <build>").
        Cmd::Version => println!(
            "peephole {} ({}, commit {})",
            peephole::VERSION,
            env!("CARGO_PKG_VERSION"),
            peephole::COMMIT
        ),
        Cmd::CheckConfig(path) => match peephole::check_config(&path).await {
            Ok((_, summary)) => println!("{summary}"),
            Err(e) => fail(e),
        },
        Cmd::Cluster => {
            if let Err(e) = peephole::cluster::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
        Cmd::Settings => {
            if let Err(e) = peephole::settings_cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
        Cmd::Export => {
            if args.get(1).is_some_and(|a| a == "--help" || a == "-h") {
                println!("{}", peephole::export::cli::USAGE);
            } else if let Err(e) = peephole::export::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
        Cmd::Admin => {
            if let Err(e) = peephole::admin::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
        Cmd::Db => {
            if let Err(e) = peephole::store::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
        Cmd::Run(config) => {
            tracing_subscriber::fmt()
                // RUST_LOG overrides; unset (as under the shipped systemd unit) means info,
                // otherwise every warning and the startup summary would be dropped.
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();
            return peephole::run(config).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cmd, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn subcommands_and_paths() {
        assert_eq!(p(&[]), Ok(Cmd::Run(DEFAULT_CONFIG.into())));
        assert_eq!(p(&["/etc/x.toml"]), Ok(Cmd::Run("/etc/x.toml".into())));
        assert_eq!(p(&["local.toml"]), Ok(Cmd::Run("local.toml".into())));
        assert_eq!(p(&["./conf"]), Ok(Cmd::Run("./conf".into())));
        for h in ["help", "-h", "--help"] {
            assert_eq!(p(&[h]), Ok(Cmd::Help));
        }
        assert_eq!(p(&["-V"]), Ok(Cmd::Version));
        assert_eq!(
            p(&["check-config"]),
            Ok(Cmd::CheckConfig(DEFAULT_CONFIG.into()))
        );
        assert_eq!(
            p(&["check-config", "c.toml"]),
            Ok(Cmd::CheckConfig("c.toml".into()))
        );
        assert_eq!(p(&["cluster", "anything", "goes"]), Ok(Cmd::Cluster));
        assert_eq!(p(&["settings"]), Ok(Cmd::Settings));
        assert_eq!(p(&["export", "--format", "csv"]), Ok(Cmd::Export));
    }

    #[test]
    fn typos_and_extra_arguments_are_refused() {
        assert!(p(&["chek-config"]).unwrap_err().contains("unknown command"));
        assert!(p(&["--verbose"]).unwrap_err().contains("unknown option"));
        assert!(p(&["a.toml", "b.toml"]).unwrap_err().contains("unexpected"));
        assert!(p(&["check-config", "a.toml", "x"]).is_err());
        assert!(p(&["check-config", "typo"]).is_err());
        assert!(p(&["--version", "x"]).is_err());
    }
}
