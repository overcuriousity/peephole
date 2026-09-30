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
        Some("--help") | Some("-h") => {
            println!(
                "usage: peephole [CONFIG]\n       peephole check-config [CONFIG]\n       peephole --version"
            );
            return Ok(());
        }
        _ => {}
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    peephole::run(config).await
}
