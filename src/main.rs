use std::path::PathBuf;

const DEFAULT_CONFIG: &str = "/etc/peephole/config.toml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("peephole {}", peephole::VERSION);
            return Ok(());
        }
        Some("check-config") => {
            let path = PathBuf::from(args.get(1).map(String::as_str).unwrap_or(DEFAULT_CONFIG));
            match peephole::check_config(&path).await {
                Ok((_, _, summary)) => {
                    println!("{summary}");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    std::process::exit(1);
                }
            }
        }
        Some("cluster") => {
            if let Err(e) = peephole::cluster::cli::run(&args[1..], DEFAULT_CONFIG).await {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("settings") => {
            if let Err(e) = peephole::settings_cli::run(&args[1..], DEFAULT_CONFIG).await {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("admin") => {
            if let Err(e) = peephole::admin::cli::run(&args[1..], DEFAULT_CONFIG).await {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("db") => {
            if let Err(e) = peephole::store::cli::run(&args[1..], DEFAULT_CONFIG).await {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--help") | Some("-h") => {
            println!(
                "usage: peephole [CONFIG]\n       peephole check-config [CONFIG]\n       peephole cluster (id|invite|invites|invite-revoke|join|members|status|config-key|block|unblock|leave) …\n       peephole settings (show|set|reset) …\n       peephole admin setup-token [CONFIG]\n       peephole db vacuum [CONFIG]\n       peephole --version"
            );
            return Ok(());
        }
        _ => {}
    }
    tracing_subscriber::fmt()
        // RUST_LOG overrides; unset (as under the shipped systemd unit) means info,
        // otherwise every warning and the startup summary would be dropped.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let config = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    peephole::run(config).await
}
