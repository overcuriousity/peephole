//! Observational probes: what an admin may read from ports a counter-scan
//! already found open. Each reader speaks just enough of its protocol to see
//! what the service presents — a page, a certificate chain, a ServerHello, an
//! SSH banner, algorithm lists and host key — and then hangs up. Nothing is
//! logged into, nothing is authenticated, no secret is derived.
//!
//! Every reader takes an absolute deadline and gives up there; the caps
//! below bound what one probe may cost the probed host and this node.

pub mod http;
pub mod jarm;
pub mod ssh;
pub mod tls;

use crate::cluster::record::ProbePortRec;
use crate::store::data::now_ts;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

/// Open ports read per probe (the lowest-numbered ones).
pub const MAX_PORTS: usize = 16;
/// Longest any one connection (and the reading on it) may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a whole probe may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest response body kept.
pub const MAX_RESPONSE: usize = 256 * 1024;
/// Largest favicon read (a larger one is not hashed).
pub const MAX_FAVICON: usize = 100 * 1024;
/// HTTP redirect hops fetched, the first request included.
pub const MAX_REDIRECTS: usize = 5;
/// How long one node leaves an address alone after probing it.
pub const PROBE_COOLDOWN_HOURS: i64 = 24;

/// Largest banner kept.
const MAX_BANNER: usize = 1024;
/// Silence that ends a banner.
const BANNER_SILENCE: Duration = Duration::from_secs(5);

/// The deadline for one connection: [`CONNECT_TIMEOUT`] from now, never past
/// the end of the probe.
pub fn connection_deadline(probe_end: Instant) -> Instant {
    (Instant::now() + CONNECT_TIMEOUT).min(probe_end)
}

pub(crate) fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "probe deadline reached")
}

/// A TCP connection to `ip:port`, or `TimedOut` at `deadline`.
pub async fn connect(ip: IpAddr, port: u16, deadline: Instant) -> io::Result<TcpStream> {
    timeout_at(deadline, TcpStream::connect((ip, port)))
        .await
        .map_err(|_| timed_out())?
}

/// What a service says unprompted: up to [`MAX_BANNER`] bytes, ended by
/// [`BANNER_SILENCE`], the peer closing, or `deadline`. A port that stays
/// silent is `TimedOut`.
pub async fn banner(ip: IpAddr, port: u16, deadline: Instant) -> io::Result<String> {
    let mut s = connect(ip, port, deadline).await?;
    let mut out = Vec::new();
    let mut buf = [0u8; MAX_BANNER];
    while out.len() < MAX_BANNER {
        let until = (Instant::now() + BANNER_SILENCE).min(deadline);
        match timeout_at(until, s.read(&mut buf[..MAX_BANNER - out.len()])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(e)) if out.is_empty() => return Err(e),
            Ok(Err(_)) => break,
        }
    }
    if out.is_empty() {
        return Err(timed_out());
    }
    Ok(printable(&out))
}

/// `bytes` as text for people: printable ASCII, `\n` and `\t` as they are,
/// every other byte as `\xNN`.
pub fn printable(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\n' | b'\t' | 0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

/// What the latest counter-scan found open, as the runner takes it.
pub struct Target {
    pub ip: IpAddr,
    /// Port and nmap's service name, when it gave one.
    pub ports: Vec<(u16, Option<String>)>,
}

/// What one probe saw.
pub struct Outcome {
    pub started_at: String,
    pub finished_at: String,
    pub rtt_min_ms: Option<u32>,
    pub ports: Vec<ProbePortRec>,
}

/// How long a port nmap did not name gets to show a TLS handshake.
const TLS_TRY: Duration = Duration::from_secs(3);

/// Which reader a port gets: nmap's service name first, then the well-known
/// ports. `https`, `http`, `ssh`, `tls` or `banner`.
pub fn protocol_for(port: u16, service: Option<&str>) -> &'static str {
    let svc = service.unwrap_or("").to_ascii_lowercase();
    if svc == "ssh" || port == 22 {
        "ssh"
    } else if svc == "https" || svc.starts_with("ssl/http") || [443, 8443].contains(&port) {
        "https"
    } else if svc == "http" || [80, 8080, 8000, 8008, 8888].contains(&port) {
        "http"
    } else if svc.contains("ssl") || svc.contains("tls") {
        "tls"
    } else {
        "banner"
    }
}

/// The smallest of three TCP connect times to `ip:port` in milliseconds, or
/// `None` when none connected.
pub async fn rtt_min_ms(ip: IpAddr, port: u16, deadline: Instant) -> Option<u32> {
    let mut best: Option<u32> = None;
    for _ in 0..3 {
        let began = Instant::now();
        let until = (began + CONNECT_TIMEOUT).min(deadline);
        if connect(ip, port, until).await.is_ok() {
            let ms = began.elapsed().as_millis().min(u32::MAX as u128) as u32;
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
    }
    best
}

fn rec(port: u16, protocol: &str, outcome: &str, detail: Value) -> ProbePortRec {
    ProbePortRec {
        port,
        protocol: protocol.into(),
        outcome: outcome.into(),
        detail_json: detail.to_string(),
    }
}

fn kind_outcome(kind: Option<io::ErrorKind>) -> &'static str {
    match kind {
        Some(io::ErrorKind::ConnectionRefused) => "refused",
        Some(io::ErrorKind::TimedOut) => "timeout",
        _ => "error",
    }
}

fn failed(port: u16, protocol: &str, e: &anyhow::Error) -> ProbePortRec {
    let kind = e.downcast_ref::<io::Error>().map(|e| e.kind());
    rec(
        port,
        protocol,
        kind_outcome(kind),
        json!({"error": e.to_string()}),
    )
}

/// `tls` and `jarm` for a port whose handshake `capture` already succeeded on.
async fn tls_detail(ip: IpAddr, port: u16, seen: &tls::TlsSeen, probe_end: Instant) -> Value {
    json!({"tls": tls::json(seen), "jarm": jarm::fingerprint(ip, port, probe_end).await})
}

async fn probe_port(
    ip: IpAddr,
    port: u16,
    service: Option<&str>,
    guard: http::Guard<'_>,
    probe_end: Instant,
) -> ProbePortRec {
    let deadline = connection_deadline(probe_end);
    match protocol_for(port, service) {
        "ssh" => match ssh::capture(ip, port, deadline).await {
            Ok(seen) => rec(port, "ssh", "ok", json!({"ssh": ssh::json(&seen)})),
            Err(e) => failed(port, "ssh", &e),
        },
        "tls" => match tls::capture(ip, port, deadline).await {
            Ok(seen) => rec(
                port,
                "tls",
                "ok",
                tls_detail(ip, port, &seen, probe_end).await,
            ),
            Err(e) => failed(port, "tls", &e),
        },
        p @ ("http" | "https") => {
            let https = p == "https";
            let mut page = http::probe_http(ip, port, https, guard, probe_end).await;
            if let Some(err) = page.get("error").and_then(Value::as_str) {
                // probe_http reports failures as text only.
                let lower = err.to_ascii_lowercase();
                let outcome = if lower.contains("refused") {
                    "refused"
                } else if lower.contains("timed out") || lower.contains("deadline") {
                    "timeout"
                } else {
                    "error"
                };
                return rec(port, p, outcome, page);
            }
            if https
                && let Value::Object(m) = &mut page
                && let Ok(seen) = tls::capture(ip, port, connection_deadline(probe_end)).await
                && let Value::Object(t) = tls_detail(ip, port, &seen, probe_end).await
            {
                m.extend(t);
            }
            rec(port, p, "ok", page)
        }
        _ => {
            let tls_until = (Instant::now() + TLS_TRY).min(deadline);
            if let Ok(seen) = tls::capture(ip, port, tls_until).await {
                return rec(
                    port,
                    "tls",
                    "ok",
                    tls_detail(ip, port, &seen, probe_end).await,
                );
            }
            match banner(ip, port, connection_deadline(probe_end)).await {
                Ok(b) => rec(port, "banner", "ok", json!({"banner": b})),
                Err(e) => rec(
                    port,
                    "banner",
                    kind_outcome(Some(e.kind())),
                    json!({"error": e.to_string()}),
                ),
            }
        }
    }
}

/// Read the open ports of `t` (the lowest [`MAX_PORTS`]) one after another,
/// each by its protocol, and measure the round-trip time. A port reached
/// after [`PROBE_TIMEOUT`] is recorded `timeout` without connecting.
pub async fn run_probe(t: &Target, guard: &(dyn Fn(&IpAddr) -> Option<String> + Sync)) -> Outcome {
    let started_at = now_ts();
    let probe_end = Instant::now() + PROBE_TIMEOUT;
    let mut ports: Vec<&(u16, Option<String>)> = t.ports.iter().collect();
    ports.sort_by_key(|(p, _)| *p);
    ports.truncate(MAX_PORTS);

    let rtt = match ports.first() {
        Some((p, _)) => rtt_min_ms(t.ip, *p, probe_end).await,
        None => None,
    };
    let mut recs = Vec::with_capacity(ports.len());
    for (port, service) in ports {
        let protocol = protocol_for(*port, service.as_deref());
        if Instant::now() >= probe_end {
            recs.push(rec(
                *port,
                protocol,
                "timeout",
                json!({"error": "probe deadline reached"}),
            ));
            continue;
        }
        recs.push(probe_port(t.ip, *port, service.as_deref(), guard, probe_end).await);
    }
    Outcome {
        started_at,
        finished_at: now_ts(),
        rtt_min_ms: rtt,
        ports: recs,
    }
}

/// SHA-256 as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn banner_reads_what_a_service_sends_and_escapes_control_bytes() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"220 hi\x01\r\n").await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let b = banner(addr.ip(), addr.port(), deadline).await.unwrap();
        assert_eq!(b, "220 hi\\x01\\x0d\n");
    }

    async fn web() -> std::net::SocketAddr {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async { axum::response::Html("<title>t</title>") }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn a_probe_reads_each_open_port_by_protocol_and_measures_rtt() {
        let (tls_addr, _) = tls::tests::tls_server(&["h2"]).await;
        let http = web().await;
        let t = Target {
            ip: "127.0.0.1".parse().unwrap(),
            ports: vec![(http.port(), Some("http".into())), (tls_addr.port(), None)],
        };
        let mut t = t;
        t.ports.sort_by_key(|(p, _)| *p);
        let out = run_probe(&t, &|_| None).await;
        assert_eq!(out.ports.len(), 2);
        let by = |p: u16| out.ports.iter().find(|r| r.port == p).unwrap();
        let h = by(http.port());
        assert_eq!(h.protocol, "http");
        let d0: serde_json::Value = serde_json::from_str(&h.detail_json).unwrap();
        assert_eq!(d0["title"], "t");
        // A port nmap did not name that speaks TLS is recorded as tls, with a JARM.
        let s = by(tls_addr.port());
        assert_eq!(s.protocol, "tls");
        let d1: serde_json::Value = serde_json::from_str(&s.detail_json).unwrap();
        assert_eq!(d1["tls"]["chain_len"], 1);
        assert_eq!(d1["jarm"].as_str().unwrap().len(), 62);
        assert!(out.rtt_min_ms.is_some());
    }

    #[tokio::test]
    async fn a_slow_port_times_out_and_the_probe_continues() {
        // A listener that accepts and never writes.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = vec![];
            loop {
                let Ok((s, _)) = l.accept().await else { break };
                held.push(s);
            }
        });
        let http = web().await;
        let mut ports = vec![(slow, None), (http.port(), Some("http".to_string()))];
        ports.sort_by_key(|(p, _)| *p);
        let t = Target {
            ip: "127.0.0.1".parse().unwrap(),
            ports,
        };
        let started = std::time::Instant::now();
        let out = run_probe(&t, &|_| None).await;
        let by = |p: u16| out.ports.iter().find(|r| r.port == p).unwrap();
        assert_eq!(by(slow).outcome, "timeout");
        assert_eq!(by(http.port()).outcome, "ok");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "one slow port costs its own timeout, not the probe's"
        );
    }

    #[tokio::test]
    async fn a_refused_port_is_recorded_as_refused() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let t = Target {
            ip: "127.0.0.1".parse().unwrap(),
            ports: vec![(port, None)],
        };
        let out = run_probe(&t, &|_| None).await;
        assert_eq!(out.ports[0].outcome, "refused");
    }

    #[test]
    fn protocols_follow_nmap_names_then_well_known_ports() {
        assert_eq!(protocol_for(22, None), "ssh");
        assert_eq!(protocol_for(2222, Some("ssh")), "ssh");
        assert_eq!(protocol_for(443, None), "https");
        assert_eq!(protocol_for(8443, Some("ssl/http")), "https");
        assert_eq!(protocol_for(80, None), "http");
        assert_eq!(protocol_for(993, Some("ssl/imap")), "tls");
        assert_eq!(protocol_for(25, Some("smtp")), "banner");
    }
}
