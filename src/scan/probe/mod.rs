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
}
