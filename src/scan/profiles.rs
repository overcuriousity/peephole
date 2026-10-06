//! The nmap arguments of each scan level as this build runs them, and how
//! to recognize them in a finished scan. A scan earns its scanner share
//! (see `credits::earn`) only when the command line in its XML is one of
//! the built-in lists, apart from what legitimately differs per node and
//! target.
use quick_xml::Reader;
use quick_xml::events::Event;

/// One NSE argument; it contains spaces, so lists are built element by
/// element. `discovery` and `safe` also hold scripts that would leak the
/// target to third parties (`external`: whois, ASN and geolocation
/// lookups), broadcast on the scanner's own network (`broadcast`
/// prerules), or flood (`dos`); those categories are excluded.
pub const SCRIPTS: &str = "(discovery or safe) and not (intrusive or broadcast or external or dos)";
/// Level 2 names its scripts: the source's own identifiers (SSH host keys
/// and algorithm lists, the TLS certificate), each one handshake with a
/// port nmap already found open, all in `safe`.
pub const IDENTITY_SCRIPTS: &str = "ssh-hostkey,ssh2-enum-algos,ssl-cert";

/// The built-in arguments of a level, without the target. `udp`: level 4
/// also scans the top UDP ports (`scan.level4_udp`). None for a level
/// outside 1..=4.
pub fn builtin(level: u8, udp: bool) -> Option<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<String>>();
    Some(match level {
        1 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "--version-light",
            "-T3",
            "--top-ports",
            "100",
        ]),
        2 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--script",
            IDENTITY_SCRIPTS,
        ]),
        3 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            SCRIPTS,
        ]),
        4 => {
            let mut v = s(&["-Pn", "-sS"]);
            if udp {
                v.push("-sU".into());
                v.push("-p".into());
                v.push(format!("T:1-65535,U:{}", crate::config::UDP_TOP50));
            } else {
                v.push("-p-".into());
            }
            v.extend(s(&[
                "-sV",
                "-O",
                "-T3",
                "--max-retries",
                "1",
                "--traceroute",
                "--script",
                SCRIPTS,
            ]));
            v
        }
        _ => return None,
    })
}

/// Built-in lists of earlier releases that still earn, normalized, with
/// their level. A release that changes a list appends the old one here
/// and removes it two releases later, so a rolling upgrade costs nobody
/// their earnings.
pub const ACCEPTED: &[(u8, &[&str])] = &[];

/// A command line as words: split at whitespace, quotes dropped (nmap
/// versions differ in whether they quote an argument with spaces; the
/// words are the same either way).
fn words(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|w| w.replace(['"', '\''], ""))
        .filter(|w| !w.is_empty())
        .collect()
}

/// `tokens` (an nmap command line as words, without the program) with
/// everything removed that legitimately differs per node or target: the
/// target, `-oX -`, `-6`, the two timeouts, the rate floor and, at level
/// 4, the choice between all TCP ports and TCP plus the top UDP ports.
pub fn normalize(tokens: &[String], level: u8) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        let next = tokens.get(i + 1).map(String::as_str);
        match t {
            "-6" => i += 1,
            "-oX" | "--host-timeout" | "--script-timeout" | "--min-rate" => i += 2,
            "-sU" | "-p-" if level == 4 => i += 1,
            "-p" if level == 4 && next.is_some_and(|n| n.starts_with("T:1-65535,U:")) => i += 2,
            _ => {
                out.push(tokens[i].clone());
                i += 1;
            }
        }
    }
    // The target is the last argument.
    if out
        .last()
        .is_some_and(|t| t.parse::<std::net::IpAddr>().is_ok())
    {
        out.pop();
    }
    out
}

fn args_ok_among(command_line: &str, level: u8, accepted: &[(u8, &[&str])]) -> bool {
    let all = words(command_line);
    // The first word is the program as it was called.
    let Some((_, args)) = all.split_first() else {
        return false;
    };
    let got = normalize(args, level);
    if got.is_empty() {
        return false;
    }
    let built_in = builtin(level, false).map(|b| normalize(&words(&b.join(" ")), level));
    built_in.is_some_and(|b| b == got)
        || accepted
            .iter()
            .any(|(l, list)| *l == level && list.iter().copied().eq(got.iter().map(String::as_str)))
}

/// Whether `command_line` (the `args` nmap wrote into its XML) is a
/// built-in argument list of `level`: this build's, or an accepted
/// earlier one.
pub fn args_ok(command_line: &str, level: u8) -> bool {
    args_ok_among(command_line, level, ACCEPTED)
}

/// The command line nmap recorded in its XML output (`<nmaprun args=…>`).
pub fn xml_args(xml: &[u8]) -> Option<String> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) | Event::Empty(e) => {
                if e.name().as_ref() != "nmaprun" {
                    return None;
                }
                return e.attributes().flatten().find_map(|a| {
                    (a.key.as_ref() == "args").then(|| {
                        #[allow(deprecated)]
                        a.unescape_value()
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| a.value.clone().into_owned())
                    })
                });
            }
            Event::Eof => return None,
            _ => {}
        }
        buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg(scan: &str) -> Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n[scan]\n{scan}"
        ))
        .unwrap()
    }

    /// What nmap writes into `args`: its argv joined by spaces.
    fn command_line(cfg: &Config, level: u8, target: &str) -> String {
        let argv = crate::scan::nmap_argv(level, &target.parse().unwrap(), cfg, 900).unwrap();
        format!("/usr/bin/nmap {}", argv.join(" "))
    }

    #[test]
    fn every_built_in_level_is_recognized_with_every_tunable_set() {
        let plain = cfg("");
        let tuned = cfg("min_rate = 1000\nlevel4_udp = true");
        for level in 1..=4u8 {
            for (c, target) in [
                (&plain, "203.0.113.7"),
                (&tuned, "203.0.113.7"),
                (&plain, "2001:db8::7"),
                (&tuned, "2001:db8::7"),
            ] {
                let line = command_line(c, level, target);
                assert!(args_ok(&line, level), "level {level}: {line}");
            }
        }
        // A list of one level is not that of another.
        let l1 = command_line(&plain, 1, "203.0.113.7");
        assert!(!args_ok(&l1, 2) && !args_ok(&l1, 4));
        assert!(!args_ok(&command_line(&plain, 3, "203.0.113.7"), 2));
        assert!(!args_ok("", 1) && !args_ok("nmap", 1));
        assert!(!args_ok(&l1, 0) && !args_ok(&l1, 9));
    }

    #[test]
    fn an_operators_own_list_is_not_a_built_in_one() {
        let custom =
            cfg("[scan.level_argv]\n2 = [\"-Pn\", \"-sS\", \"-T4\", \"--top-ports\", \"10\"]");
        assert!(!args_ok(&command_line(&custom, 2, "203.0.113.7"), 2));
        // One argument more or less, or another value, is another list.
        let line = command_line(&cfg(""), 2, "203.0.113.7");
        assert!(!args_ok(&line.replace("-T3", "-T5"), 2));
        assert!(!args_ok(&line.replace(" -O", ""), 2));
        assert!(!args_ok(&format!("{line} --script vuln"), 2));
        // What may differ: timeouts, the rate floor, the target.
        let ip = "203.0.113.7".parse().unwrap();
        let short = crate::scan::nmap_argv(2, &ip, &cfg(""), 60)
            .unwrap()
            .join(" ");
        assert!(!line.ends_with(&short), "another timeout");
        assert!(args_ok(&format!("nmap {short}"), 2));
        // nmap versions that quote an argument with spaces still match.
        let l3 = command_line(&cfg(""), 3, "203.0.113.7");
        let quoted = l3.replace(SCRIPTS, &format!("\"{SCRIPTS}\""));
        assert_ne!(quoted, l3);
        assert!(args_ok(&quoted, 3));
    }

    #[test]
    fn an_earlier_built_in_list_stays_accepted() {
        let old: &[&str] = &["-Pn", "-sS", "--top-ports", "50"];
        let line = "nmap -Pn -sS --top-ports 50 --host-timeout 60s -oX - 203.0.113.7";
        assert!(!args_ok(line, 1));
        assert!(args_ok_among(line, 1, &[(1, old)]));
        assert!(
            !args_ok_among(line, 2, &[(1, old)]),
            "accepted for its level only"
        );
    }

    #[test]
    fn the_command_line_is_read_from_the_xml() {
        let xml = br#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn --script &quot;a or b&quot; -oX - 203.0.113.7" start="1">
<host/></nmaprun>"#;
        assert_eq!(
            xml_args(xml).as_deref(),
            Some("nmap -Pn --script \"a or b\" -oX - 203.0.113.7")
        );
        assert_eq!(xml_args(b"<nmaprun start=\"1\"/>"), None);
        assert_eq!(xml_args(b"not xml"), None);
        let fixture = std::fs::read("tests/fixtures/nmap-basic.xml").unwrap();
        assert_eq!(
            xml_args(&fixture).as_deref(),
            Some("nmap -sS -sV -oX - 198.51.100.23")
        );
    }
}
