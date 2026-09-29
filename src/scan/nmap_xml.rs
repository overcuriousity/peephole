use anyhow::{bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Clone, PartialEq)]
pub struct PortResult {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug)]
pub struct ScanResult {
    pub os_guess: Option<String>,
    pub ports: Vec<PortResult>,
    pub raw_xml: Vec<u8>,
}

pub fn parse_nmap_xml(xml: &[u8]) -> Result<ScanResult> {
    let mut reader = Reader::from_reader(xml);
    let mut ports: Vec<PortResult> = Vec::new();
    let mut os_guess: Option<String> = None;
    let mut cur: Option<PortResult> = None;
    let mut saw_host = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf).context("parsing nmap xml")? {
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name();
                match name.as_ref() {
                    b"host" => saw_host = true,
                    b"port" => {
                        let mut port = 0u16;
                        let mut proto = String::from("tcp");
                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                b"portid" => port = String::from_utf8_lossy(&a.value).parse().unwrap_or(0),
                                b"protocol" => proto = String::from_utf8_lossy(&a.value).into_owned(),
                                _ => {}
                            }
                        }
                        cur = Some(PortResult {
                            port, proto, state: "unknown".into(),
                            service: None, product: None, version: None,
                        });
                    }
                    b"state" => {
                        if let Some(p) = cur.as_mut() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"state" {
                                    p.state = String::from_utf8_lossy(&a.value).into_owned();
                                }
                            }
                        }
                    }
                    b"service" => {
                        if let Some(p) = cur.as_mut() {
                            for a in e.attributes().flatten() {
                                match a.key.as_ref() {
                                    b"name" => p.service = Some(String::from_utf8_lossy(&a.value).into_owned()),
                                    b"product" => p.product = Some(String::from_utf8_lossy(&a.value).into_owned()),
                                    b"version" => p.version = Some(String::from_utf8_lossy(&a.value).into_owned()),
                                    _ => {}
                                }
                            }
                        }
                    }
                    b"osmatch" => {
                        if os_guess.is_none() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == b"name" {
                                    os_guess = Some(String::from_utf8_lossy(&a.value).into_owned());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::End(e) if e.name().as_ref() == b"port" => {
                if let Some(p) = cur.take() {
                    if p.port > 0 { ports.push(p); }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !saw_host && ports.is_empty() {
        bail!("nmap xml contained no host data");
    }
    Ok(ScanResult { os_guess, ports, raw_xml: xml.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports_os_and_states() {
        let xml = include_bytes!("../../tests/fixtures/nmap-basic.xml");
        let r = parse_nmap_xml(xml).unwrap();
        assert_eq!(r.os_guess.as_deref(), Some("Linux 5.X"));
        assert_eq!(r.ports.len(), 3);
        let ssh = r.ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        let https = r.ports.iter().find(|p| p.port == 443).unwrap();
        assert_eq!(https.state, "filtered");
        assert!(https.service.is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_nmap_xml(b"not xml at all").is_err());
    }
}
