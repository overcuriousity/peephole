//! What an SSH server presents before anyone logs in: its banner, its
//! KEXINIT algorithm lists (HASSH-server) and its host key. RFC 4253 version
//! exchange (§4.2), binary packets (§6) and KEXINIT (§7.1); when the server
//! offers curve25519-sha256 (RFC 8731), one ECDH init so the server sends its
//! host key in the reply. The connection is closed right there: no secret is
//! derived, the signature is not checked, nothing is authenticated.

use super::{MAX_RESPONSE, connect, printable, timed_out};
use anyhow::{Result, bail};
use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

/// Our identification string (RFC 4253 §4.2).
const CLIENT_BANNER: &str = "SSH-2.0-OpenSSH_10.0";
/// Lines a server may send before its identification string, and their
/// length (RFC 4253 §4.2: 255 bytes with CR LF).
const MAX_PRE_LINES: usize = 32;
const MAX_LINE: usize = 255;
/// Packets skipped (IGNORE, DEBUG, …) while waiting for an expected one.
const MAX_SKIPPED: usize = 8;

const MSG_DISCONNECT: u8 = 1;
const MSG_KEXINIT: u8 = 20;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;

const KEX: &str = "curve25519-sha256,curve25519-sha256@libssh.org";
const HOST_KEYS: &str = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
const CIPHERS: &str =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr";
const MACS: &str = "hmac-sha2-256-etm@openssh.com,hmac-sha2-256";
const COMPRESSION: &str = "none";

/// What the server showed. The lists are the server's KEXINIT name-lists
/// (server-to-client where the direction matters).
#[derive(Debug, Clone, PartialEq)]
pub struct SshSeen {
    pub banner: String,
    pub kex_algorithms: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub compression: Vec<String>,
    /// The host-key blob's leading name, e.g. `ssh-ed25519`.
    pub host_key_type: Option<String>,
    /// Base64 (no padding) SHA-256 of the host-key blob, as OpenSSH prints
    /// it after `SHA256:`.
    pub host_key_sha256: Option<String>,
}

/// An unencrypted binary packet (RFC 4253 §6) around `payload`: at least
/// four bytes of padding, the whole a multiple of eight.
pub fn packet(payload: &[u8]) -> Vec<u8> {
    let mut pad = 8 - (payload.len() + 5) % 8;
    if pad < 4 {
        pad += 8;
    }
    let mut out = Vec::with_capacity(payload.len() + 5 + pad);
    out.extend(((payload.len() + 1 + pad) as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend(payload);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// One unencrypted binary packet's payload.
pub async fn read_packet(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let len = s.read_u32().await? as usize;
    if !(5..=MAX_RESPONSE).contains(&len) {
        return Err(bad("ssh packet length out of range"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    let pad = buf[0] as usize;
    if pad + 1 > len {
        return Err(bad("ssh padding longer than the packet"));
    }
    buf.truncate(len - pad);
    buf.remove(0);
    Ok(buf)
}

/// RFC 4251 §5 string / name-list reader.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?) as usize;
        let s = self.0.get(4..4 + len)?;
        self.0 = &self.0[4 + len..];
        Some(s)
    }
    fn name_list(&mut self) -> Option<Vec<String>> {
        let s = self.string()?;
        if s.is_empty() {
            return Some(Vec::new());
        }
        Some(s.split(|&b| b == b',').map(printable).collect())
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s);
}

fn kexinit() -> Vec<u8> {
    let mut p = vec![MSG_KEXINIT];
    let mut cookie = [0u8; 16];
    rand::fill(&mut cookie[..]);
    p.extend(cookie);
    for list in [
        KEX,
        HOST_KEYS,
        CIPHERS,
        CIPHERS,
        MACS,
        MACS,
        COMPRESSION,
        COMPRESSION,
        "",
        "",
    ] {
        put_string(&mut p, list.as_bytes());
    }
    p.push(0); // first_kex_packet_follows
    p.extend(0u32.to_be_bytes());
    p
}

/// The next packet of type `want`, skipping IGNORE/DEBUG and the like.
async fn expect(s: &mut TcpStream, want: u8) -> Result<Vec<u8>> {
    for _ in 0..MAX_SKIPPED {
        let p = read_packet(s).await?;
        match p.first() {
            Some(&t) if t == want => return Ok(p),
            Some(&MSG_DISCONNECT) => bail!("ssh server disconnected"),
            Some(&t) if (2..=4).contains(&t) => continue,
            _ => bail!("unexpected ssh message instead of {want}"),
        }
    }
    bail!("no ssh message {want}")
}

/// The server's identification string, after any lines before it.
async fn read_banner(s: &mut TcpStream) -> Result<String> {
    for _ in 0..MAX_PRE_LINES {
        let mut line = Vec::new();
        loop {
            let b = s.read_u8().await?;
            if b == b'\n' {
                break;
            }
            if line.len() >= MAX_LINE {
                bail!("ssh line too long");
            }
            line.push(b);
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.starts_with(b"SSH-") {
            return Ok(printable(&line));
        }
    }
    bail!("no ssh identification string")
}

/// Banner and the server's KEXINIT.
async fn hello(s: &mut TcpStream) -> Result<SshSeen> {
    s.write_all(format!("{CLIENT_BANNER}\r\n").as_bytes())
        .await?;
    let banner = read_banner(s).await?;
    s.write_all(&packet(&kexinit())).await?;
    let p = expect(s, MSG_KEXINIT).await?;
    let mut r = Reader(p.get(17..).unwrap_or_default());
    let bad = || anyhow::anyhow!("malformed ssh KEXINIT");
    let kex_algorithms = r.name_list().ok_or_else(bad)?;
    let host_key_algorithms = r.name_list().ok_or_else(bad)?;
    let _ciphers_c2s = r.name_list().ok_or_else(bad)?;
    let ciphers = r.name_list().ok_or_else(bad)?;
    let _macs_c2s = r.name_list().ok_or_else(bad)?;
    let macs = r.name_list().ok_or_else(bad)?;
    let _compression_c2s = r.name_list().ok_or_else(bad)?;
    let compression = r.name_list().ok_or_else(bad)?;
    Ok(SshSeen {
        banner,
        kex_algorithms,
        host_key_algorithms,
        ciphers,
        macs,
        compression,
        host_key_type: None,
        host_key_sha256: None,
    })
}

/// ECDH init with a throwaway X25519 key; the reply's host-key blob.
async fn host_key(s: &mut TcpStream) -> Result<Vec<u8>> {
    use aws_lc_rs::agreement::{EphemeralPrivateKey, X25519};
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let key =
        EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| anyhow::anyhow!("x25519 key"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("x25519 public key"))?;
    let mut p = vec![MSG_KEX_ECDH_INIT];
    put_string(&mut p, public.as_ref());
    s.write_all(&packet(&p)).await?;
    let reply = expect(s, MSG_KEX_ECDH_REPLY).await?;
    let blob = Reader(&reply[1..])
        .string()
        .ok_or_else(|| anyhow::anyhow!("malformed ssh ECDH reply"))?;
    Ok(blob.to_vec())
}

/// Read banner, algorithm lists and (with curve25519) the host key of
/// `ip:port`. Once the KEXINIT is in, a failed key exchange still returns
/// what was seen, without a host key.
pub async fn capture(ip: IpAddr, port: u16, deadline: Instant) -> Result<SshSeen> {
    let mut s = connect(ip, port, deadline).await?;
    let mut seen = timeout_at(deadline, hello(&mut s))
        .await
        .map_err(|_| timed_out())??;
    let curve = seen
        .kex_algorithms
        .iter()
        .any(|k| k == "curve25519-sha256" || k == "curve25519-sha256@libssh.org");
    if curve && let Ok(Ok(blob)) = timeout_at(deadline, host_key(&mut s)).await {
        seen.host_key_type = Reader(&blob).string().map(printable);
        seen.host_key_sha256 = Some(data_encoding::BASE64_NOPAD.encode(&Sha256::digest(&blob)));
    }
    Ok(seen)
}

/// HASSH-server: MD5 of `kex;enc_s2c;mac_s2c;comp_s2c`.
pub fn hassh(seen: &SshSeen) -> String {
    let text = format!(
        "{};{};{};{}",
        seen.kex_algorithms.join(","),
        seen.ciphers.join(","),
        seen.macs.join(","),
        seen.compression.join(",")
    );
    data_encoding::HEXLOWER.encode(&Md5::digest(text.as_bytes()))
}

/// What was seen, plus `hassh`; the algorithm lists as comma-joined
/// strings, as they travel on the wire.
pub fn json(seen: &SshSeen) -> Value {
    json!({
        "banner": seen.banner,
        "kex_algorithms": seen.kex_algorithms.join(","),
        "host_key_algorithms": seen.host_key_algorithms.join(","),
        "ciphers": seen.ciphers.join(","),
        "macs": seen.macs.join(","),
        "compression": seen.compression.join(","),
        "host_key_type": seen.host_key_type,
        "host_key_sha256": seen.host_key_sha256,
        "hassh": hassh(seen),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// An OpenSSH-10-like server: banner, KEXINIT with `kex` and `hostkeys`,
    /// and an ECDH reply carrying an `ssh-ed25519` blob (junk signature).
    async fn fake_ssh(kex: &str, hostkeys: &str) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (kex, hostkeys) = (kex.to_string(), hostkeys.to_string());
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"SSH-2.0-OpenSSH_10.2 Debian\r\n")
                .await
                .unwrap();
            let mut p = vec![MSG_KEXINIT];
            p.extend([1u8; 16]);
            for list in [
                kex.as_str(),
                hostkeys.as_str(),
                "aes128-ctr",
                "chacha20-poly1305@openssh.com,aes128-ctr",
                "hmac-sha2-256",
                "umac-128-etm@openssh.com,hmac-sha2-256",
                "none",
                "none,zlib@openssh.com",
                "",
                "",
            ] {
                put_string(&mut p, list.as_bytes());
            }
            p.push(0);
            p.extend(0u32.to_be_bytes());
            s.write_all(&packet(&p)).await.unwrap();
            assert!(read_banner(&mut s).await.unwrap().starts_with("SSH-2.0-"));
            assert_eq!(read_packet(&mut s).await.unwrap()[0], MSG_KEXINIT);
            let Ok(init) = read_packet(&mut s).await else {
                return; // no shared kex: the client left
            };
            assert_eq!(init[0], MSG_KEX_ECDH_INIT);
            let mut blob = Vec::new();
            put_string(&mut blob, b"ssh-ed25519");
            put_string(&mut blob, &[5u8; 32]);
            let mut r = vec![MSG_KEX_ECDH_REPLY];
            put_string(&mut r, &blob);
            put_string(&mut r, &[6u8; 32]);
            put_string(&mut r, b"junk signature");
            s.write_all(&packet(&r)).await.unwrap();
            let _ = s.read_u8().await;
        });
        addr
    }

    #[tokio::test]
    async fn banner_hassh_and_host_key_are_read_from_an_openssh_10_style_server() {
        let kex = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org";
        let addr = fake_ssh(kex, "rsa-sha2-512,ssh-ed25519").await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = capture(addr.ip(), addr.port(), deadline).await.unwrap();
        assert_eq!(seen.banner, "SSH-2.0-OpenSSH_10.2 Debian");
        assert_eq!(seen.kex_algorithms, kex.split(',').collect::<Vec<_>>());
        assert_eq!(seen.host_key_type.as_deref(), Some("ssh-ed25519"));
        let fp = seen.host_key_sha256.as_deref().unwrap();
        assert_eq!(fp.len(), 43);
        assert!(!fp.ends_with('='));
        let j = json(&seen);
        let h = j["hassh"].as_str().unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn a_server_without_curve25519_still_gives_banner_and_hassh() {
        let addr = fake_ssh("diffie-hellman-group14-sha256", "rsa-sha2-512").await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = capture(addr.ip(), addr.port(), deadline).await.unwrap();
        assert_eq!(seen.banner, "SSH-2.0-OpenSSH_10.2 Debian");
        assert_eq!(seen.host_key_type, None);
        assert_eq!(json(&seen)["hassh"].as_str().unwrap().len(), 32);
    }
}
