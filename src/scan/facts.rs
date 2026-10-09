//! What a scan says a source serves and what it calls itself, read only
//! from the places nmap writes as structure: the attributes of `<service>`
//! and its `<cpe>` children, and the `<elem>`s of a few scripts at fixed
//! keys. Never from a script's prose `output`, and never from an `<elem>`
//! whose key is data (`http-grep`, `fcrdns`). Derived from the stored XML
//! on every node (`store::facts`), like host keys, so nothing is
//! replicated and older scans can be read after the fact.
use super::hostkeys::{Node, elem, key_attr, table, walk_scripts};
use quick_xml::Reader;
use quick_xml::events::Event;

/// Version of what `extract` reads (`scans.facts_parsed`). A change bumps
/// it, and the backfill reads every stored scan again.
pub const FACTS_V: i64 = 1;
/// Longest fact value kept, in bytes (cut at a character boundary).
pub const MAX_VALUE: usize = 512;
/// Most facts kept of one scan, in document order.
pub const MAX_FACTS: usize = 64;

pub const HTTP_TITLE: &str = "http.title";
pub const HTTP_REDIRECT: &str = "http.redirect";
pub const HTTP_SERVER: &str = "http.server";
pub const HTTP_AUTH: &str = "http.auth";
pub const NTLM_NETBIOS_COMPUTER: &str = "ntlm.netbios_computer";
pub const NTLM_NETBIOS_DOMAIN: &str = "ntlm.netbios_domain";
pub const NTLM_DNS_COMPUTER: &str = "ntlm.dns_computer";
pub const NTLM_DNS_DOMAIN: &str = "ntlm.dns_domain";
pub const NTLM_DNS_TREE: &str = "ntlm.dns_tree";
pub const NTLM_PRODUCT_VERSION: &str = "ntlm.product_version";
pub const SOCKS_METHOD: &str = "socks.method";
pub const DNS_NSID: &str = "dns.nsid";
pub const SMB_SERVER: &str = "smb.server";
pub const SMB_DOMAIN: &str = "smb.domain";
pub const SMB_FQDN: &str = "smb.fqdn";
pub const SMB_DOMAIN_DNS: &str = "smb.domain_dns";
pub const SMB_FOREST_DNS: &str = "smb.forest_dns";
pub const SMB_WORKGROUP: &str = "smb.workgroup";
pub const SMB_OS: &str = "smb.os";
pub const SMB_LANMANAGER: &str = "smb.lanmanager";

/// Every kind, for the label test and the docs.
pub const KINDS: [&str; 20] = [
    HTTP_TITLE,
    HTTP_REDIRECT,
    HTTP_SERVER,
    HTTP_AUTH,
    NTLM_NETBIOS_COMPUTER,
    NTLM_NETBIOS_DOMAIN,
    NTLM_DNS_COMPUTER,
    NTLM_DNS_DOMAIN,
    NTLM_DNS_TREE,
    NTLM_PRODUCT_VERSION,
    SOCKS_METHOD,
    DNS_NSID,
    SMB_SERVER,
    SMB_DOMAIN,
    SMB_FQDN,
    SMB_DOMAIN_DNS,
    SMB_FOREST_DNS,
    SMB_WORKGROUP,
    SMB_OS,
    SMB_LANMANAGER,
];

/// The `<elem>` keys read per script, and the kind each becomes. One
/// table: a script or key not here is not read, however interesting.
const KEYS: &[(&str, &str, &str)] = &[
    ("http-title", "title", HTTP_TITLE),
    ("http-title", "redirect_url", HTTP_REDIRECT),
    (
        "rdp-ntlm-info",
        "NetBIOS_Computer_Name",
        NTLM_NETBIOS_COMPUTER,
    ),
    ("rdp-ntlm-info", "NetBIOS_Domain_Name", NTLM_NETBIOS_DOMAIN),
    ("rdp-ntlm-info", "DNS_Computer_Name", NTLM_DNS_COMPUTER),
    ("rdp-ntlm-info", "DNS_Domain_Name", NTLM_DNS_DOMAIN),
    ("rdp-ntlm-info", "DNS_Tree_Name", NTLM_DNS_TREE),
    ("rdp-ntlm-info", "Product_Version", NTLM_PRODUCT_VERSION),
    ("dns-nsid", "bind.version", DNS_NSID),
    ("dns-nsid", "id.server", DNS_NSID),
    ("smb-os-discovery", "server", SMB_SERVER),
    ("smb-os-discovery", "domain", SMB_DOMAIN),
    ("smb-os-discovery", "fqdn", SMB_FQDN),
    ("smb-os-discovery", "domain_dns", SMB_DOMAIN_DNS),
    ("smb-os-discovery", "forest_dns", SMB_FOREST_DNS),
    ("smb-os-discovery", "workgroup", SMB_WORKGROUP),
    ("smb-os-discovery", "os", SMB_OS),
    ("smb-os-discovery", "lanmanager", SMB_LANMANAGER),
];

/// The scripts walked: the keyed ones above, and three with their own
/// shape (`http-server-header`: unnamed elems; `http-auth` and
/// `socks-auth-info`: one table per entry).
const SCRIPTS: [&str; 7] = [
    "http-title",
    "http-server-header",
    "http-auth",
    "rdp-ntlm-info",
    "socks-auth-info",
    "dns-nsid",
    "smb-os-discovery",
];

/// What nmap's `-sV` wrote about one port beyond name, product and version.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PortDetail {
    pub port: u16,
    pub proto: String,
    pub extrainfo: Option<String>,
    pub ostype: Option<String>,
    pub devicetype: Option<String>,
    pub hostname: Option<String>,
    pub cpe: Vec<String>,
}

impl PortDetail {
    fn any(&self) -> bool {
        self.extrainfo.is_some()
            || self.ostype.is_some()
            || self.devicetype.is_some()
            || self.hostname.is_some()
            || !self.cpe.is_empty()
    }
}

/// One fact from a script, on a port or (None) about the host.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub port: Option<(u16, String)>,
    pub kind: &'static str,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct Facts {
    pub ports: Vec<PortDetail>,
    pub facts: Vec<Fact>,
}

/// `s` trimmed and cut to `MAX_VALUE` bytes at a character boundary;
/// None when nothing is left.
fn value(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut end = s.len().min(MAX_VALUE);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_string())
}

/// An SMB string as nmap writes it, without the NUL terminator nmap
/// encodes as the four characters `\x00`.
fn smb_value(s: &str) -> Option<String> {
    value(s.strip_suffix("\\x00").unwrap_or(s))
}

/// Everything in an nmap XML report that section 4 of the spec names.
/// Unparsable input yields what was found before the error.
pub fn extract(xml: &[u8]) -> Facts {
    let (details, protos) = port_details(xml);
    let mut out = Facts {
        ports: details,
        facts: vec![],
    };
    walk_scripts(xml, &SCRIPTS, &mut |port, id, _output, root| {
        let at = (port > 0).then(|| {
            let proto = protos
                .iter()
                .find(|(p, _)| *p == port)
                .map(|(_, pr)| pr.clone())
                .unwrap_or_else(|| "tcp".into());
            (port, proto)
        });
        let mut push = |kind: &'static str, v: Option<String>| {
            if let Some(value) = v {
                out.facts.push(Fact {
                    port: at.clone(),
                    kind,
                    value,
                });
            }
        };
        match id {
            "http-server-header" => {
                for n in root {
                    if let Node::Elem { key: None, text } = n {
                        push(HTTP_SERVER, value(text));
                    }
                }
            }
            "http-auth" => {
                for n in root {
                    let Node::Table { children, .. } = n else {
                        continue;
                    };
                    let Some(scheme) = elem(children, "scheme").and_then(value) else {
                        continue;
                    };
                    let realm = table(children, "params")
                        .and_then(|p| elem(p, "realm"))
                        .and_then(value);
                    push(
                        HTTP_AUTH,
                        value(&match realm {
                            Some(r) => format!("{scheme} realm=\"{r}\""),
                            None => scheme,
                        }),
                    );
                }
            }
            "socks-auth-info" => {
                for n in root {
                    if let Node::Table { children, .. } = n {
                        push(SOCKS_METHOD, elem(children, "name").and_then(value));
                    }
                }
            }
            _ => {
                for (script, key, kind) in KEYS {
                    if *script != id {
                        continue;
                    }
                    let v = elem(root, key);
                    let v = if id == "smb-os-discovery" {
                        v.and_then(smb_value)
                    } else {
                        v.and_then(value)
                    };
                    push(kind, v);
                }
            }
        }
    });
    out.facts.truncate(MAX_FACTS);
    out
}

/// The `<service>` attributes and `<cpe>` texts of every port that has
/// any, and the protocol of every port.
fn port_details(xml: &[u8]) -> (Vec<PortDetail>, Vec<(u16, String)>) {
    let mut out = vec![];
    let mut protos = vec![];
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut cur: Option<PortDetail> = None;
    let mut cpe: Option<String> = None;
    while let Ok(ev) = reader.read_event_into(&mut buf) {
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) if e.name().as_ref() == "port" => {
                let port = key_attr(e, "portid")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                let proto = key_attr(e, "protocol").unwrap_or_else(|| "tcp".into());
                if port > 0 {
                    protos.push((port, proto.clone()));
                }
                cur = Some(PortDetail {
                    port,
                    proto,
                    ..Default::default()
                });
            }
            Event::Start(ref e) | Event::Empty(ref e) if e.name().as_ref() == "service" => {
                if let Some(p) = cur.as_mut() {
                    for a in e.attributes().flatten() {
                        let v = a
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| a.value.to_string());
                        match a.key.as_ref() {
                            "extrainfo" => p.extrainfo = value(&v),
                            "ostype" => p.ostype = value(&v),
                            "devicetype" => p.devicetype = value(&v),
                            "hostname" => p.hostname = value(&v),
                            _ => {}
                        }
                    }
                }
            }
            Event::Start(ref e) if e.name().as_ref() == "cpe" && cur.is_some() => {
                cpe = Some(String::new())
            }
            Event::Text(t) => {
                if let Some(s) = cpe.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::End(ref e) => match e.name().as_ref() {
                "cpe" => {
                    if let (Some(s), Some(p)) = (cpe.take(), cur.as_mut())
                        && let Some(v) = value(&s)
                    {
                        p.cpe.push(v);
                    }
                }
                "port" => {
                    if let Some(p) = cur.take()
                        && p.port > 0
                        && p.any()
                    {
                        out.push(p);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    (out, protos)
}

/// The label a page shows before a value of `kind`.
pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        HTTP_TITLE => "Title",
        HTTP_REDIRECT => "Redirects to",
        HTTP_SERVER => "Server",
        HTTP_AUTH => "Login",
        NTLM_NETBIOS_COMPUTER | SMB_SERVER => "Computer",
        NTLM_NETBIOS_DOMAIN | SMB_DOMAIN => "Domain",
        NTLM_DNS_COMPUTER => "DNS name",
        NTLM_DNS_DOMAIN | SMB_DOMAIN_DNS => "DNS domain",
        NTLM_DNS_TREE | SMB_FOREST_DNS => "Forest",
        NTLM_PRODUCT_VERSION => "Windows build",
        SOCKS_METHOD => "SOCKS",
        DNS_NSID => "DNS server",
        SMB_FQDN => "FQDN",
        SMB_WORKGROUP => "Workgroup",
        SMB_OS => "OS",
        SMB_LANMANAGER => "LAN Manager",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/nmap-facts.xml");

    fn values<'a>(f: &'a Facts, kind: &str) -> Vec<(Option<u16>, &'a str)> {
        f.facts
            .iter()
            .filter(|x| x.kind == kind)
            .map(|x| (x.port.as_ref().map(|p| p.0), x.value.as_str()))
            .collect()
    }

    #[test]
    fn every_service_detail_is_read() {
        let f = extract(FIXTURE);
        assert_eq!(f.ports.len(), 1, "only port 22 has details: {:?}", f.ports);
        let p = &f.ports[0];
        assert_eq!((p.port, p.proto.as_str()), (22, "tcp"));
        assert_eq!(p.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));
        assert_eq!(p.ostype.as_deref(), Some("Linux"));
        assert_eq!(p.devicetype.as_deref(), Some("general purpose"));
        assert_eq!(p.hostname.as_deref(), Some("host-7.example.net"));
        assert_eq!(
            p.cpe,
            vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
        );
    }

    #[test]
    fn every_script_fact_is_read_from_its_fixed_key() {
        let f = extract(FIXTURE);
        assert_eq!(
            values(&f, HTTP_TITLE),
            vec![
                (Some(80), "PentAGI & friends"),
                (Some(8443), "MinIO Console")
            ]
        );
        assert_eq!(
            values(&f, HTTP_REDIRECT),
            vec![(Some(80), "http://192.0.2.7/login")]
        );
        assert_eq!(values(&f, HTTP_SERVER), vec![(Some(80), "nginx/1.18.0")]);
        assert_eq!(
            values(&f, HTTP_AUTH),
            vec![(Some(80), "Basic realm=\"bifrost\"")]
        );
        assert_eq!(
            values(&f, NTLM_NETBIOS_COMPUTER),
            vec![(Some(3389), "WIN-344VU98D3RU")]
        );
        assert_eq!(
            values(&f, NTLM_NETBIOS_DOMAIN),
            vec![(Some(3389), "WORKGROUP")]
        );
        assert_eq!(
            values(&f, NTLM_DNS_COMPUTER),
            vec![(Some(3389), "WIN-344VU98D3RU")]
        );
        assert_eq!(
            values(&f, NTLM_DNS_DOMAIN),
            vec![(Some(3389), "WIN-344VU98D3RU")]
        );
        assert_eq!(
            values(&f, NTLM_DNS_TREE),
            vec![(Some(3389), "corp.example")]
        );
        assert_eq!(
            values(&f, NTLM_PRODUCT_VERSION),
            vec![(Some(3389), "10.0.17763")]
        );
        assert_eq!(
            values(&f, SOCKS_METHOD),
            vec![
                (Some(1080), "No authentication"),
                (Some(1080), "Username and password")
            ]
        );
        assert_eq!(
            values(&f, DNS_NSID),
            vec![(Some(53), "9.18.1"), (Some(53), "ns1")]
        );
        assert_eq!(values(&f, SMB_SERVER), vec![(None, "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, SMB_DOMAIN), vec![(None, "WORKGROUP")]);
        assert_eq!(values(&f, SMB_WORKGROUP), vec![(None, "WORKGROUP")]);
        assert_eq!(values(&f, SMB_FQDN), vec![(None, "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, SMB_DOMAIN_DNS), vec![(None, "corp.example")]);
        assert_eq!(values(&f, SMB_FOREST_DNS), vec![(None, "corp.example")]);
        assert_eq!(
            values(&f, SMB_OS),
            vec![(None, "Windows Server 2019 Standard 17763")]
        );
        assert_eq!(
            values(&f, SMB_LANMANAGER),
            vec![(None, "Windows Server 2019 Standard 6.3")]
        );
        // Keys the table does not list, and prose or data-keyed scripts.
        let all: Vec<&str> = f.facts.iter().map(|x| x.value.as_str()).collect();
        for absent in [
            "2026-10-06T10:00:00+00:00",
            "2026-10-06T10:00:00",
            "WordPress 6.4",
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
            "192.0.2.7",
            "fail",
            "0",
            "2",
        ] {
            assert!(!all.contains(&absent), "{absent} in {all:?}");
        }
        assert!(f.facts.iter().all(|x| x.kind != "Target_Name"));
        // 2 titles, 1 redirect, 1 server, 1 login, 6 NTLM, 2 SOCKS, 2 NSID, 8 SMB.
        assert_eq!(f.facts.len(), 23, "{:?}", f.facts);
    }

    #[test]
    fn prose_only_and_data_keyed_scripts_yield_nothing() {
        let xml = br#"<nmaprun><host><ports>
<port protocol="tcp" portid="25"><service name="smtp"/><script id="smtp-commands" output="mail.example.net Hello scanner [203.0.113.5]"/><script id="banner" output="220 mail"/></port>
<port protocol="tcp" portid="80"><service name="http"/><script id="http-generator" output="Drupal 7"/><script id="http-grep" output="x"><table key="http://h/"><elem key="ip">1.2.3.4</elem></table></script></port>
</ports><hostscript><script id="fcrdns" output="FAIL"><table key="203.0.113.9"><elem key="status">fail</elem></table></script></hostscript></host></nmaprun>"#;
        let f = extract(xml);
        assert!(f.facts.is_empty(), "{:?}", f.facts);
        assert!(f.ports.is_empty(), "{:?}", f.ports);
    }

    #[test]
    fn values_are_cut_at_a_character_boundary() {
        let long = "ü".repeat(300); // 600 bytes
        let xml = format!(
            r#"<nmaprun><host><ports><port protocol="tcp" portid="80"><service name="http" extrainfo="{long}"/><script id="http-title" output="t"><elem key="title">{long}</elem><elem key="redirect_url">   </elem></script></port></ports></host></nmaprun>"#
        );
        let f = extract(xml.as_bytes());
        let title = &values(&f, HTTP_TITLE)[0].1;
        assert_eq!(title.len(), 512);
        assert_eq!(title.chars().count(), 256);
        assert_eq!(f.ports[0].extrainfo.as_deref().map(str::len), Some(512));
        assert!(
            values(&f, HTTP_REDIRECT).is_empty(),
            "blank values are skipped"
        );
        // An odd cut lands on the boundary before the character.
        let odd = format!("{}ü", "a".repeat(511));
        let xml = format!(
            r#"<nmaprun><host><ports><port protocol="tcp" portid="80"><script id="http-title" output="t"><elem key="title">{odd}</elem></script></port></ports></host></nmaprun>"#
        );
        assert_eq!(values(&extract(xml.as_bytes()), HTTP_TITLE)[0].1.len(), 511);
    }

    #[test]
    fn the_per_scan_cap_holds() {
        let mut ports = String::new();
        for p in 1..=70u16 {
            ports.push_str(&format!(
                r#"<port protocol="tcp" portid="{p}"><script id="http-title" output="t"><elem key="title">T{p}</elem></script></port>"#
            ));
        }
        let xml = format!("<nmaprun><host><ports>{ports}</ports></host></nmaprun>");
        let f = extract(xml.as_bytes());
        assert_eq!(f.facts.len(), MAX_FACTS);
        assert_eq!(
            f.facts.last().unwrap().value,
            "T64",
            "document order, first ones kept"
        );
    }

    #[test]
    fn unparsable_input_yields_what_came_before() {
        let cut = &FIXTURE[..FIXTURE.len() / 2];
        let f = extract(cut);
        assert!(!f.ports.is_empty() || !f.facts.is_empty());
        assert!(extract(b"not xml").facts.is_empty());
    }

    #[test]
    fn every_kind_has_a_label() {
        for k in KINDS {
            assert_ne!(kind_label(k), "Other", "{k}");
        }
        assert_eq!(kind_label("nope"), "Other");
    }
}
