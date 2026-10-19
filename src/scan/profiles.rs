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
/// prerules), or flood (`dos`); those categories are excluded. So is one
/// script by name: `http-comments-displayer` spiders up to 20 pages per
/// HTTP port and copies every comment it finds, binary files it misreads
/// included, unbounded text of no use for analysis (198 KB of one 266 KB
/// scan in the 2026-10-06 export).
pub const SCRIPTS: &str = "(discovery or safe) and not (intrusive or broadcast or external or dos or http-comments-displayer)";
/// Level 2 names its scripts: the source's own identifiers (SSH host keys
/// and algorithm lists, the TLS certificate, the HTTP headers with their
/// ETag), each one handshake or request to a port nmap already found
/// open, all in `safe`.
pub const IDENTITY_SCRIPTS: &str = "ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers";
/// Level 5 runs the `vuln` category — checks that probe a service for a
/// known vulnerability — but not the ones that ask third parties
/// (`external`: whois, ASN and CVE-API lookups). Unlike every other level
/// it is deliberately intrusive; only an admin's bought scan reaches it,
/// never the automatic queue.
pub const VULN_SCRIPTS: &str = "vuln and not external";

/// nmap's `--top-ports 100` (TCP), as nmap 7.95 recorded it in
/// `<scaninfo services=…>` of a level-1 scan on the hermes node
/// (2026-10-19, MIK-586).
pub const NMAP_TOP_100: &str = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157";
/// nmap's `--top-ports 1000` (TCP), recorded the same way from a level-2
/// scan.
pub const NMAP_TOP_1000: &str = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3006,3011,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5985-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389";
/// Ports levels 1 to 3 scan beyond nmap's top lists, so the device and
/// proxy evidence (`store::evidence`) does not need a level-4 scan. Ranks
/// in nmap-services (nmap commit 542eda7c, 2026-08-07, TCP by open
/// frequency) and membership in the recorded top lists above: proxies and
/// relays 1080 (socks, rank 166, top 1000), 4145 (socks4, 6435), 8118
/// (privoxy, 1301), 9050 (tor-socks, 300, top 1000); consumer devices 7547
/// (TR-069 cwmp, 7519), 8291 (MikroTik WinBox, 367, top 1000), 8089
/// (FRITZ!Box TR-069, 271, top 1000), 5555 (Android ADB, 180, top 1000),
/// 37777 (Dahua, 2870). 2000 (MikroTik btest), 3128, 8080 and 9999 are
/// in the top 100 already.
pub const RELAY_PORTS: &[u16] = &[1080, 4145, 8118, 9050];
pub const DEVICE_PORTS: &[u16] = &[7547, 8291, 8089, 5555, 37777];

/// `base` (an nmap port list) with `extra` added, as sorted ranges.
fn with_ports(base: &str, extra: &[&[u16]]) -> String {
    let mut ports: std::collections::BTreeSet<u16> = base
        .split(',')
        .flat_map(|r| {
            let (a, b) = r.split_once('-').unwrap_or((r, r));
            a.parse::<u16>().unwrap()..=b.parse::<u16>().unwrap()
        })
        .collect();
    ports.extend(extra.iter().flat_map(|e| e.iter().copied()));
    let mut out: Vec<String> = vec![];
    let mut it = ports.into_iter().peekable();
    while let Some(start) = it.next() {
        let mut end = start;
        while it.peek() == Some(&(end + 1)) {
            end = it.next().unwrap();
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    out.join(",")
}

/// The TCP ports of levels 1 and 2/3: nmap's top 100 and top 1000 with
/// [`RELAY_PORTS`] and [`DEVICE_PORTS`].
pub fn level_ports(level: u8) -> Option<String> {
    let base = match level {
        1 => NMAP_TOP_100,
        2 | 3 => NMAP_TOP_1000,
        _ => return None,
    };
    Some(with_ports(base, &[RELAY_PORTS, DEVICE_PORTS]))
}

/// The built-in arguments of a level, without the target. `udp`: level 4
/// also scans the top UDP ports (`scan.level4_udp`). None for a level
/// outside 1..=5.
pub fn builtin(level: u8, udp: bool) -> Option<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<String>>();
    Some(match level {
        1 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "--version-light",
            "-T3",
            "-p",
            &level_ports(1)?,
        ]),
        2 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "-p",
            &level_ports(2)?,
            "--script",
            IDENTITY_SCRIPTS,
        ]),
        3 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "-p",
            &level_ports(3)?,
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
        5 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            VULN_SCRIPTS,
        ]),
        _ => return None,
    })
}

/// Built-in lists of earlier releases that still earn, normalized, with
/// their level. A release that changes a list appends the old one here
/// and removes it two releases later, so a rolling upgrade costs nobody
/// their earnings.
pub const ACCEPTED: &[(u8, &[&str])] = &[
    // Levels 1 to 3 on nmap's top lists alone (0.20.0 and earlier).
    (
        1,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "--version-light",
            "-T3",
            "--top-ports",
            "100",
        ],
    ),
    (
        2,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--script",
            IDENTITY_SCRIPTS,
        ],
    ),
    (
        3,
        &[
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
        ],
    ),
    // Level 2 before `http-headers` (0.9.0 and earlier).
    (
        2,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--script",
            "ssh-hostkey,ssh2-enum-algos,ssl-cert",
        ],
    ),
    // Levels 3 and 4 with `http-comments-displayer` (0.9.0 and earlier).
    (
        3,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            OLD_SCRIPTS,
        ],
    ),
    (
        4,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--max-retries",
            "1",
            "--traceroute",
            "--script",
            OLD_SCRIPTS,
        ],
    ),
];

/// The level 3 and 4 script list of 0.9.0 and earlier.
const OLD_SCRIPTS: &str = "(discovery or safe) and not (intrusive or broadcast or external or dos)";

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
            .filter(|(l, _)| *l == level)
            .any(|(_, list)| normalize(&words(&list.join(" ")), level) == got)
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
                        a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
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
    fn level_5_runs_the_vuln_category_without_external_lookups() {
        let argv = builtin(5, false).unwrap();
        assert_eq!(builtin(5, true).unwrap(), argv, "no UDP variant at level 5");
        let i = argv.iter().position(|a| a == "--script").unwrap();
        assert_eq!(argv[i + 1], "vuln and not external");
        assert!(argv.contains(&"--top-ports".to_string()));
        assert!(!argv.iter().any(|a| a == "-p-"), "the level-3 port set");
        let plain = cfg("");
        let line = command_line(&plain, 5, "203.0.113.7");
        assert!(args_ok(&line, 5), "{line}");
        assert!(!args_ok(&line, 4), "level 5's list is not level 4's");
    }

    #[test]
    fn every_built_in_level_is_recognized_with_every_tunable_set() {
        let plain = cfg("");
        let tuned = cfg("min_rate = 1000\nlevel4_udp = true");
        for level in 1..=5u8 {
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
    fn level_2_reads_http_headers_and_the_previous_list_still_earns() {
        let l2 = builtin(2, false).unwrap();
        assert!(l2.last().unwrap().ends_with(",http-headers"), "{l2:?}");
        let old = "nmap -Pn -sS -sV -O -T3 --top-ports 1000 --script \
                   ssh-hostkey,ssh2-enum-algos,ssl-cert --host-timeout 900s \
                   --script-timeout 570s -oX - 203.0.113.7";
        assert!(args_ok(old, 2));
        assert!(!args_ok(old, 3), "accepted for level 2 only");
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

    #[test]
    fn levels_3_and_4_leave_out_http_comments_displayer_and_the_previous_lists_still_earn() {
        assert!(
            SCRIPTS.ends_with("or http-comments-displayer)"),
            "{SCRIPTS}"
        );
        let plain = cfg("");
        for level in [3u8, 4] {
            let line = command_line(&plain, level, "203.0.113.7");
            assert!(args_ok(&line, level), "{line}");
            // The list of 0.9.0 and earlier, as nmap recorded it (level 3
            // then scanned nmap's top 1000 alone).
            let mut old = line.replace(" or http-comments-displayer)", ")");
            if level == 3 {
                old = old.replace(
                    &format!("-p {}", level_ports(3).unwrap()),
                    "--top-ports 1000",
                );
            }
            assert_ne!(old, line);
            assert!(args_ok(&old, level), "previous list, level {level}: {old}");
            let other = if level == 3 { 4 } else { 3 };
            assert!(!args_ok(&old, other), "accepted for its level only");
            // Put back by hand: another list.
            let by_hand = line.replace(
                "or http-comments-displayer)",
                "or http-comments-displayer) or http-comments-displayer",
            );
            assert!(!args_ok(&by_hand, level));
        }
        let udp = cfg("level4_udp = true");
        let old_udp =
            command_line(&udp, 4, "203.0.113.7").replace(" or http-comments-displayer)", ")");
        assert!(args_ok(&old_udp, 4), "{old_udp}");
    }

    /// Levels 1 to 3 scan nmap's top lists plus the relay/proxy and
    /// consumer-device ports the evidence rows read; level 4 scans every
    /// port; the lists of 0.20.0 (top lists alone) still earn (MIK-586).
    #[test]
    fn levels_1_to_3_add_the_relay_and_device_ports() {
        let ports = |level: u8| -> std::collections::BTreeSet<u16> {
            let argv = builtin(level, false).unwrap();
            let i = argv.iter().position(|a| a == "-p").unwrap();
            argv[i + 1]
                .split(',')
                .flat_map(|r| {
                    let (a, b) = r.split_once('-').unwrap_or((r, r));
                    a.parse::<u16>().unwrap()..=b.parse::<u16>().unwrap()
                })
                .collect()
        };
        let top = |list: &str| with_ports(list, &[]).split(',').count();
        assert_eq!(
            with_ports(NMAP_TOP_100, &[]),
            NMAP_TOP_100,
            "already ranges"
        );
        assert!(top(NMAP_TOP_1000) > 100);
        for (level, n) in [(1u8, 100), (2, 1000), (3, 1000)] {
            let p = ports(level);
            for want in [
                1080, 4145, 8118, 9050, 7547, 8291, 8089, 5555, 37777, 2000, 3128, 8080, 9999,
            ] {
                assert!(p.contains(&want), "level {level} lacks {want}");
            }
            assert!(p.contains(&22) && p.contains(&443), "level {level}");
            // nmap's list, plus the ports it did not have.
            let missing = if level == 1 { 9 } else { 4 };
            assert_eq!(p.len(), n + missing, "level {level}");
        }
        assert_eq!(ports(2), ports(3));
        assert!(builtin(4, false).unwrap().contains(&"-p-".to_string()));
        let plain = cfg("");
        for level in 1..=3u8 {
            let line = command_line(&plain, level, "203.0.113.7");
            assert!(args_ok(&line, level), "{line}");
            let top = if level == 1 { "100" } else { "1000" };
            let old = line.replace(
                &format!("-p {}", level_ports(level).unwrap()),
                &format!("--top-ports {top}"),
            );
            assert_ne!(old, line);
            assert!(args_ok(&old, level), "0.20.0 list, level {level}: {old}");
            assert!(!args_ok(&old, if level == 1 { 2 } else { 1 }));
        }
    }
}
