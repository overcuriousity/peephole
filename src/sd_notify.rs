//! systemd readiness notification (`Type=notify`) without a library: one
//! datagram to the socket systemd names in `NOTIFY_SOCKET`.
use std::ffi::OsStr;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Tell systemd the service is up (`READY=1`). Does nothing when not started
/// by systemd with `Type=notify` (no `NOTIFY_SOCKET`); a failure is logged,
/// never fatal.
pub fn ready() {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(e) = notify(&socket, "READY=1")
    {
        tracing::warn!(error = %e, "sd_notify READY=1 failed");
    }
}

fn notify(socket: &OsStr, state: &str) -> std::io::Result<()> {
    let sock = UnixDatagram::unbound()?;
    // "@name" is a socket in the abstract namespace.
    if let Some(name) = socket.as_encoded_bytes().strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        sock.send_to_addr(state.as_bytes(), &SocketAddr::from_abstract_name(name)?)?;
    } else {
        sock.send_to(state.as_bytes(), socket)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recv(rx: &UnixDatagram) -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn sends_to_a_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let rx = UnixDatagram::bind(&path).unwrap();
        notify(path.as_os_str(), "READY=1").unwrap();
        assert_eq!(recv(&rx), b"READY=1");
    }

    #[test]
    fn sends_to_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("peephole-test-{}", std::process::id());
        let rx = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        notify(OsStr::new(&format!("@{name}")), "READY=1").unwrap();
        assert_eq!(recv(&rx), b"READY=1");
    }
}
