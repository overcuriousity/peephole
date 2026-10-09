//! `peephole export …`: the dataset export from the shell, for operators
//! without a web role (or a browser). Same rows, filters and formats as
//! Admin → Export; the file is streamed, so any size fits in memory.
use super::{ExportFilter, ExportOptions, Format, Mode};
use crate::config::Config;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use futures::StreamExt;
use std::collections::HashMap;
use std::path::Path;

pub const USAGE: &str = "usage: peephole export [OPTIONS] [CONFIG]
       --format parquet|csv|jsonl    file format (default parquet)
       --redistributable             leave out results whose terms forbid passing them on
                                     (GeoIP and API results); for sharing outside the cluster
       --from TIME, --to TIME        UTC bounds, YYYY-MM-DD or YYYY-MM-DDTHH:MM[:SS]
       --ip ADDRESS                  one IP only
       --label LABEL                 requests with this rule label only
       --min-severity N              requests of severity N or above (0-4)
       -o, --output FILE             write here (default: stdout)
       --dry-run                     print the filter and exit";

/// What the arguments ask for.
#[derive(Debug, Clone, PartialEq)]
pub struct Args {
    pub format: Format,
    pub mode: Mode,
    pub filter: ExportFilter,
    pub output: Option<String>,
    pub config: Option<String>,
    pub dry_run: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            format: Format::Parquet,
            mode: Mode::Full,
            filter: ExportFilter::default(),
            output: None,
            config: None,
            dry_run: false,
        }
    }
}

/// Parse `args` (excluding `export` itself).
pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut i = 0;
    let value = |i: &mut usize, flag: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--format" => {
                out.format = match value(&mut i, a)?.as_str() {
                    "parquet" => Format::Parquet,
                    "csv" => Format::Csv,
                    "jsonl" => Format::Jsonl,
                    other => return Err(format!("unknown format '{other}'")),
                }
            }
            "--redistributable" => out.mode = Mode::Redistributable,
            "--from" => {
                out.filter.from = Some(crate::store::browse::ts_bound(&value(&mut i, a)?, false));
            }
            "--to" => {
                out.filter.to = Some(crate::store::browse::ts_bound(&value(&mut i, a)?, true));
            }
            "--ip" => {
                out.filter.ip = Some(crate::store::browse::canonical_ip(&value(&mut i, a)?));
            }
            "--label" => out.filter.label = Some(value(&mut i, a)?),
            "--min-severity" => {
                let v = value(&mut i, a)?;
                out.filter.min_severity = Some(
                    v.parse::<i64>()
                        .ok()
                        .filter(|n| (0..=4).contains(n))
                        .ok_or_else(|| format!("--min-severity must be 0-4, not '{v}'"))?,
                );
            }
            "-o" | "--output" => out.output = Some(value(&mut i, a)?),
            "--dry-run" => out.dry_run = true,
            _ if a.starts_with('-') => return Err(format!("unknown option '{a}'")),
            _ if out.config.is_none() => out.config = Some(a.to_string()),
            _ => return Err(format!("unexpected argument '{a}'")),
        }
        i += 1;
    }
    Ok(out)
}

/// Run `peephole export`; `args` excludes `export` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => bail!("{e}\n\n{USAGE}"),
    };
    if a.dry_run {
        println!("{}", describe(&a));
        return Ok(());
    }
    let cfg = Config::load(Path::new(a.config.as_deref().unwrap_or(default_config)))?;
    let store = Store::connect(&cfg.database_path).await?;
    let names = member_names(&store).await;
    // This node's own addresses and names, kept out of the served XML.
    // Without a running node this is the configured and interface
    // addresses only: the address peers saw this node connect from lives
    // in the running node's memory, so a node behind NAT should set
    // `scan.own_addresses`. The admin download and export remove it too.
    let mut safety = crate::scan::safety::Safety::new(&cfg);
    safety.refresh(&cfg, None).await;
    let own = safety.own_identity();
    let mut out: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match &a.output {
        Some(p) => Box::new(
            tokio::fs::File::create(p)
                .await
                .with_context(|| format!("creating {p}"))?,
        ),
        None => Box::new(tokio::io::stdout()),
    };
    let (rows, bytes) = write(store, &a, names, own, &mut out).await?;
    if a.output.is_some() {
        eprintln!(
            "exported {rows} row{} ({} MiB) as {}",
            if rows == 1 { "" } else { "s" },
            bytes / (1024 * 1024),
            format_name(a.format)
        );
    }
    Ok(())
}

/// Stream the export to `out`; returns rows written and bytes.
pub async fn write(
    store: Store,
    a: &Args,
    names: HashMap<Vec<u8>, String>,
    own: crate::scan::scrub::Own,
    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
) -> Result<(u64, u64)> {
    use tokio::io::AsyncWriteExt;
    let counted = super::stream_requests_counted(
        store,
        a.filter.clone(),
        a.format,
        ExportOptions {
            mode: a.mode,
            names,
            own,
        },
    );
    let mut stream = std::pin::pin!(counted.0);
    let mut bytes = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("export failed")?;
        bytes += chunk.len() as u64;
        out.write_all(&chunk).await.context("writing export")?;
    }
    out.flush().await?;
    Ok((counted.1.load(std::sync::atomic::Ordering::Relaxed), bytes))
}

/// Node names for the `node` columns (empty when standalone).
async fn member_names(store: &Store) -> HashMap<Vec<u8>, String> {
    match crate::cluster::members::all(store).await {
        Ok(m) => m.into_iter().map(|m| (m.id.0.to_vec(), m.name)).collect(),
        Err(_) => HashMap::new(),
    }
}

fn format_name(f: Format) -> &'static str {
    match f {
        Format::Parquet => "Parquet",
        Format::Csv => "CSV",
        Format::Jsonl => "JSON Lines",
    }
}

/// One line per setting, for `--dry-run`.
pub fn describe(a: &Args) -> String {
    let f = &a.filter;
    let mut v = vec![
        format!("format: {}", format_name(a.format)),
        format!(
            "content: {}",
            match a.mode {
                Mode::Full => "everything",
                Mode::Redistributable => "redistributable only",
            }
        ),
    ];
    for (k, val) in [
        ("from", &f.from),
        ("to", &f.to),
        ("ip", &f.ip),
        ("label", &f.label),
    ] {
        if let Some(x) = val {
            v.push(format!("{k}: {x}"));
        }
    }
    if let Some(s) = f.min_severity {
        v.push(format!("min severity: {s}"));
    }
    v.push(format!(
        "output: {}",
        a.output.as_deref().unwrap_or("stdout")
    ));
    v.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Args, String> {
        parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn options_and_config_path() {
        let a = p(&[
            "--format",
            "csv",
            "--redistributable",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-31T12:00",
            "--ip",
            "2001:DB8::1",
            "--label",
            "sqli",
            "--min-severity",
            "3",
            "-o",
            "out.csv",
            "/etc/x.toml",
        ])
        .unwrap();
        assert_eq!(a.format, Format::Csv);
        assert_eq!(a.mode, Mode::Redistributable);
        assert_eq!(a.filter.from.as_deref(), Some("2026-01-01"));
        assert_eq!(a.filter.to.as_deref(), Some("2026-01-31 12:00:59"));
        assert_eq!(a.filter.ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(a.filter.label.as_deref(), Some("sqli"));
        assert_eq!(a.filter.min_severity, Some(3));
        assert_eq!(a.output.as_deref(), Some("out.csv"));
        assert_eq!(a.config.as_deref(), Some("/etc/x.toml"));
        assert_eq!(p(&[]).unwrap(), Args::default());
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(p(&["--format", "xlsx"]).unwrap_err().contains("format"));
        assert!(p(&["--min-severity", "9"]).unwrap_err().contains("0-4"));
        assert!(p(&["--from"]).unwrap_err().contains("needs a value"));
        assert!(p(&["--verbose"]).unwrap_err().contains("unknown option"));
        assert!(p(&["a.toml", "b.toml"]).unwrap_err().contains("unexpected"));
    }

    #[tokio::test]
    async fn writes_every_format_from_an_empty_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (format, head) in [
            (Format::Csv, b"kind,uid,node".as_slice()),
            (Format::Parquet, b"PAR1".as_slice()),
            (Format::Jsonl, b"".as_slice()),
        ] {
            let a = Args {
                format,
                ..Args::default()
            };
            let mut buf: Vec<u8> = vec![];
            let (rows, bytes) = write(
                store.clone(),
                &a,
                HashMap::new(),
                Default::default(),
                &mut buf,
            )
            .await
            .unwrap();
            assert_eq!(rows, 0);
            assert_eq!(bytes as usize, buf.len());
            assert!(
                buf.starts_with(head),
                "{format:?}: {:?}",
                &buf[..buf.len().min(8)]
            );
        }
    }
}
