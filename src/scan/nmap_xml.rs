use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;

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
    let mut host_timed_out = false;
    let mut buf = Vec::new();

    loop {
        match reader
            .read_event_into(&mut buf)
            .context("parsing nmap xml")?
        {
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name();
                match name.as_ref() {
                    "host" => {
                        saw_host = true;
                        host_timed_out |= e
                            .attributes()
                            .flatten()
                            .any(|a| a.key.as_ref() == "timedout" && a.value.as_ref() == "true");
                    }
                    "port" => {
                        let mut port = 0u16;
                        let mut proto = String::from("tcp");
                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                "portid" => port = a.value.parse().unwrap_or(0),
                                "protocol" => proto = a.value.clone().into_owned(),
                                _ => {}
                            }
                        }
                        cur = Some(PortResult {
                            port,
                            proto,
                            state: "unknown".into(),
                            service: None,
                            product: None,
                            version: None,
                        });
                    }
                    "state" => {
                        if let Some(p) = cur.as_mut() {
                            for a in e.attributes().flatten() {
                                if a.key.as_ref() == "state" {
                                    p.state = a.value.clone().into_owned();
                                }
                            }
                        }
                    }
                    "service" => {
                        if let Some(p) = cur.as_mut() {
                            for a in e.attributes().flatten() {
                                match a.key.as_ref() {
                                    "name" => p.service = Some(a.value.clone().into_owned()),
                                    "product" => p.product = Some(a.value.clone().into_owned()),
                                    "version" => p.version = Some(a.value.clone().into_owned()),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "osmatch" if os_guess.is_none() => {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == "name" {
                                os_guess = Some(a.value.clone().into_owned());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::End(e) if e.name().as_ref() == "port" => {
                if let Some(p) = cur.take()
                    && p.port > 0
                {
                    ports.push(p);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    // nmap's --host-timeout discards the host's results (7.9x): not a scan.
    if host_timed_out {
        bail!("timeout (nmap host-timeout)");
    }
    if !saw_host && ports.is_empty() {
        bail!("host reported down: no reply to nmap's discovery probes (use -Pn)");
    }
    Ok(ScanResult {
        os_guess,
        ports,
        raw_xml: xml.to_vec(),
    })
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

    #[test]
    fn down_and_timed_out_hosts_are_named() {
        let down = br#"<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>"#;
        let e = parse_nmap_xml(down).unwrap_err().to_string();
        assert!(e.contains("host reported down"), "{e}");
        let timed_out = br#"<nmaprun><host timedout="true"><status state="up"/>
            <address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>"#;
        let e = parse_nmap_xml(timed_out).unwrap_err().to_string();
        assert!(e.starts_with("timeout"), "{e}");
    }
}
