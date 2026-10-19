//! Evidence rows and the verdict over them (docs/detection.md, "Device
//! evidence"): typed observations about one address, each pointing at the
//! row that produced it (a scan, a name, a host key, a canary reuse), and a
//! first-match verdict that names what was observed, never a score.
//!
//! Derived on each node from rows it already holds, with the bundled
//! catalogues (`rules/evidence/*.toml`); recomputed with the hourly
//! campaign pass, never replicated, never exported, never in the blocklist:
//! a dynamic address can be personal data, and a device banner is
//! forgeable by the party with the most to gain from it.
use super::Store;
use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

/// Version of the derivation and the catalogues; recorded on every row.
pub const EVIDENCE_V: i64 = 1;
/// Evidence older than the address's `last_seen` by more than this is not
/// used: on a dynamic line the next subscriber may hold the address.
pub const STALE_SECS: i64 = 24 * 3600;
/// `fleet.key`: an instance key on this address and on at least this many
/// others …
pub const FLEET_KEY_MIN_OTHERS: usize = 2;
/// … and at most this many (more is shared infrastructure, as in the
/// campaign cap).
pub const FLEET_KEY_MAX_OTHERS: usize = super::campaigns::HARD_FANOUT_MAX;
/// `fleet.dense`: sources in the address's /24 (IPv4) or /48 (IPv6).
pub const DENSE_MIN: usize = 16;
/// The AS-type list's file name among the catalogues. Absent: no `net.*`
/// row exists, so rules 3 to 5 and the `fleet.dense` and `name.scanner`
/// branches of rule 2 cannot fire.
pub const AS_TYPES: &str = "as-types.toml";
/// Unmatched OS guesses and device types the report lists.
const REPORT_UNMATCHED: usize = 25;

/// The catalogues built into the binary (`rules/evidence/*.toml` at build
/// time, by name), from `build.rs`.
pub const BUILTIN: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/builtin_evidence.rs"));

static CATALOGUE: LazyLock<Catalogue> =
    LazyLock::new(|| Catalogue::parse(BUILTIN).expect("built-in evidence catalogues"));

/// The kinds of evidence row.
pub const KINDS: &[&str] = &[
    "device.cpe",
    "device.proxy",
    "name.consumer",
    "name.scanner",
    "fleet.key",
    "fleet.canary",
    "fleet.dense",
    "net.hosting",
    "net.eyeball",
];

// ---- Catalogues -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Cpe,
    Proxy,
}

impl DeviceKind {
    pub fn row_kind(self) -> &'static str {
        match self {
            DeviceKind::Cpe => "device.cpe",
            DeviceKind::Proxy => "device.proxy",
        }
    }
}

/// What a scan saw, as a catalogue entry reads it.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub port: Option<i64>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub os_guess: Option<String>,
    pub fact: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEntry {
    id: String,
    kind: DeviceKind,
    label: String,
    #[serde(default)]
    ports: Vec<i64>,
    product: Option<String>,
    service: Option<String>,
    os_guess: Option<String>,
    fact: Option<String>,
    sample: Vec<Sample>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicesFile {
    device: Vec<DeviceEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NameEntry {
    id: String,
    pattern: String,
    sample: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamesFile {
    #[serde(default)]
    consumer: Vec<NameEntry>,
    #[serde(default)]
    scanner: Vec<NameEntry>,
}

/// An AS type in the bundled list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AsType {
    Hosting,
    Cloud,
    Scanner,
    Fixed,
    Mobile,
}

impl AsType {
    /// The `net.*` row it gives, and its value.
    fn row(self) -> (&'static str, &'static str) {
        match self {
            AsType::Hosting => ("net.hosting", "hosting"),
            AsType::Cloud => ("net.hosting", "cloud"),
            AsType::Scanner => ("net.hosting", "scanner"),
            AsType::Fixed => ("net.eyeball", "fixed"),
            AsType::Mobile => ("net.eyeball", "mobile"),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AsEntry {
    asn: i64,
    #[serde(rename = "type")]
    kind: AsType,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AsTypesFile {
    #[serde(rename = "as")]
    entries: Vec<AsEntry>,
}

/// One device or proxy signature, compiled.
pub struct Device {
    pub id: String,
    pub kind: DeviceKind,
    pub label: String,
    ports: Vec<i64>,
    product: Option<Regex>,
    service: Option<Regex>,
    os_guess: Option<Regex>,
    fact: Option<String>,
    pub samples: Vec<Sample>,
}

/// Where a device entry matched.
#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    /// An open port: number, nmap's product (if any).
    Port(i64, Option<String>),
    /// The scan's OS guess.
    Os(String),
    /// A scan fact of this kind on a port.
    Fact(Option<i64>, String),
}

/// A device entry that matched a scan.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub kind: DeviceKind,
    pub id: String,
    pub label: String,
    pub seen: Seen,
}

impl Device {
    /// Whether this entry reads a port (not the OS guess or a fact).
    fn on_port(&self) -> bool {
        self.os_guess.is_none() && self.fact.is_none()
    }

    fn port_ok(&self, port: Option<i64>) -> bool {
        self.ports.is_empty() || port.is_some_and(|p| self.ports.contains(&p))
    }

    /// Whether the entry matches one open port.
    pub fn matches_port(&self, port: i64, service: Option<&str>, product: Option<&str>) -> bool {
        let re = |r: &Option<Regex>, v: Option<&str>| {
            r.as_ref().is_none_or(|r| v.is_some_and(|v| r.is_match(v)))
        };
        self.on_port()
            && self.port_ok(Some(port))
            && re(&self.product, product)
            && re(&self.service, service)
    }

    pub fn matches_os(&self, os_guess: &str) -> bool {
        self.os_guess.as_ref().is_some_and(|r| r.is_match(os_guess))
    }

    pub fn matches_fact(&self, port: Option<i64>, kind: &str) -> bool {
        self.fact.as_deref() == Some(kind) && self.port_ok(port)
    }

    /// Whether the entry matches a sample (as a scan would show it).
    pub fn matches(&self, s: &Sample) -> bool {
        if let Some(os) = &s.os_guess
            && self.matches_os(os)
        {
            return true;
        }
        if let Some(f) = &s.fact
            && self.matches_fact(s.port, f)
        {
            return true;
        }
        s.port.is_some_and(|p| {
            (s.service.is_some() || s.product.is_some())
                && self.matches_port(p, s.service.as_deref(), s.product.as_deref())
        })
    }
}

/// A compiled name pattern.
pub struct NamePattern {
    pub id: String,
    pub re: Regex,
    pub samples: Vec<String>,
}

/// The evidence catalogues.
pub struct Catalogue {
    pub devices: Vec<Device>,
    pub consumer: Vec<NamePattern>,
    pub scanner: Vec<NamePattern>,
    /// The AS-type list; empty while none is bundled.
    pub as_types: HashMap<i64, AsType>,
}

impl Catalogue {
    /// The built-in catalogues.
    pub fn builtin() -> &'static Catalogue {
        &CATALOGUE
    }

    /// Parse and validate the catalogue files by name: `devices.toml`,
    /// `names.toml` and, when present, [`AS_TYPES`]. Other names are an
    /// error, so a misnamed file cannot be silently ignored.
    pub fn parse(files: &[(&str, &str)]) -> Result<Catalogue> {
        let mut c = Catalogue {
            devices: vec![],
            consumer: vec![],
            scanner: vec![],
            as_types: HashMap::new(),
        };
        for (name, text) in files {
            match *name {
                "devices.toml" => {
                    let f: DevicesFile =
                        toml::from_str(text).with_context(|| format!("parsing {name}"))?;
                    for e in f.device {
                        c.devices
                            .push(compile_device(e).with_context(|| format!("in {name}"))?);
                    }
                }
                "names.toml" => {
                    let f: NamesFile =
                        toml::from_str(text).with_context(|| format!("parsing {name}"))?;
                    c.consumer = compile_names(f.consumer).with_context(|| format!("in {name}"))?;
                    c.scanner = compile_names(f.scanner).with_context(|| format!("in {name}"))?;
                }
                AS_TYPES => {
                    let f: AsTypesFile =
                        toml::from_str(text).with_context(|| format!("parsing {name}"))?;
                    for e in f.entries {
                        if c.as_types.insert(e.asn, e.kind).is_some() {
                            bail!("{name}: AS{} listed twice", e.asn);
                        }
                    }
                }
                other => bail!("unknown evidence catalogue {other}"),
            }
        }
        Ok(c)
    }

    /// The device and proxy entries that match one scan: per open port and
    /// kind the first matching entry, the first CPE entry matching the OS
    /// guess, and per fact port and kind the first matching entry.
    pub fn hits(
        &self,
        ports: &[PortSeen],
        os_guess: Option<&str>,
        facts: &[(Option<i64>, &str)],
    ) -> Vec<Hit> {
        let mut out = vec![];
        for &(port, service, product) in ports {
            for kind in [DeviceKind::Proxy, DeviceKind::Cpe] {
                if let Some(d) = self
                    .devices
                    .iter()
                    .find(|d| d.kind == kind && d.matches_port(port, service, product))
                {
                    out.push(Hit {
                        kind,
                        id: d.id.clone(),
                        label: d.label.clone(),
                        seen: Seen::Port(port, product.map(str::to_string)),
                    });
                }
            }
        }
        if let Some(os) = os_guess.filter(|o| !o.is_empty())
            && let Some(d) = self.devices.iter().find(|d| d.matches_os(os))
        {
            out.push(Hit {
                kind: d.kind,
                id: d.id.clone(),
                label: d.label.clone(),
                seen: Seen::Os(os.to_string()),
            });
        }
        for &(port, kind) in facts {
            if let Some(d) = self.devices.iter().find(|d| d.matches_fact(port, kind)) {
                out.push(Hit {
                    kind: d.kind,
                    id: d.id.clone(),
                    label: d.label.clone(),
                    seen: Seen::Fact(port, kind.to_string()),
                });
            }
        }
        out
    }

    /// The scan-fact kinds any entry reads.
    fn fact_kinds(&self) -> BTreeSet<&str> {
        self.devices
            .iter()
            .filter_map(|d| d.fact.as_deref())
            .collect()
    }
}

fn regex(p: &Option<String>) -> Result<Option<Regex>> {
    p.as_deref()
        .map(|p| Regex::new(p).with_context(|| format!("pattern {p}")))
        .transpose()
}

fn compile_device(e: DeviceEntry) -> Result<Device> {
    let id = e.id.clone();
    let on_port = e.product.is_some() || e.service.is_some();
    let ways = [on_port, e.os_guess.is_some(), e.fact.is_some()]
        .iter()
        .filter(|w| **w)
        .count();
    if ways != 1 {
        bail!("{id}: give product/service, os_guess or fact, exactly one of them");
    }
    if e.os_guess.is_some() && !e.ports.is_empty() {
        bail!("{id}: an OS guess has no port");
    }
    if e.sample.is_empty() {
        bail!("{id}: no sample");
    }
    let d = Device {
        id: e.id,
        kind: e.kind,
        label: e.label,
        ports: e.ports,
        product: regex(&e.product)?,
        service: regex(&e.service)?,
        os_guess: regex(&e.os_guess)?,
        fact: e.fact,
        samples: e.sample,
    };
    if let Some(s) = d.samples.iter().find(|s| !d.matches(s)) {
        bail!("{id}: its sample {s:?} does not match");
    }
    Ok(d)
}

fn compile_names(entries: Vec<NameEntry>) -> Result<Vec<NamePattern>> {
    entries
        .into_iter()
        .map(|e| {
            let re = Regex::new(&e.pattern).with_context(|| format!("{}: pattern", e.id))?;
            if e.sample.is_empty() {
                bail!("{}: no sample", e.id);
            }
            if let Some(s) = e.sample.iter().find(|s| !re.is_match(s)) {
                bail!("{}: its sample {s} does not match", e.id);
            }
            Ok(NamePattern {
                id: e.id,
                re,
                samples: e.sample,
            })
        })
        .collect()
}

// ---- Derivation -----------------------------------------------------------

/// One evidence row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
pub struct EvidenceRow {
    pub ip_id: i64,
    pub kind: String,
    pub value: String,
    pub ref_kind: String,
    pub ref_id: i64,
    pub first_ts: String,
    pub last_ts: String,
}

/// An open port as a scan stored it: scan id, port, service, product,
/// device type.
type PortRow = (i64, i64, Option<String>, Option<String>, Option<String>);
/// An open port as a signature reads it: port, service, product.
type PortSeen<'a> = (i64, Option<&'a str>, Option<&'a str>);
/// An evidence row's key: ip id, kind, value, ref kind, ref id.
type RowKey = (i64, String, String, String, i64);

/// The rows a pass reads.
#[derive(Default)]
pub(crate) struct Input {
    /// id, IP text, ASN, last seen, seen (not only looked up).
    ips: Vec<(i64, String, Option<i64>, String, bool)>,
    /// Finished scans: id, ip id, finished at, OS guess.
    scans: Vec<(i64, i64, String, Option<String>)>,
    /// Open ports of finished scans: scan id, port, service, product,
    /// device type.
    ports: Vec<PortRow>,
    /// Facts of the kinds the catalogue reads: scan id, port, kind.
    facts: Vec<(i64, Option<i64>, String)>,
    /// Reverse and PTR names: id, ip id, name, first and last seen.
    names: Vec<(i64, i64, String, String, String)>,
    /// Instance keys: id, ip id, kind, fingerprint, when seen.
    keys: Vec<(i64, i64, String, String, String)>,
    /// Canaries served to another address that came back from this one in
    /// a header or the body: using ip id, value hash, using request id, ts.
    canaries: Vec<(i64, i64, i64, String)>,
    /// Tor exits (rule 1).
    tor: BTreeSet<i64>,
}

impl Input {
    pub(crate) async fn read(conn: &mut sqlx::SqliteConnection, cat: &Catalogue) -> Result<Input> {
        let ips: Vec<(i64, String, Option<i64>, String, i64)> =
            sqlx::query_as("SELECT id, ip, asn, last_seen, unseen FROM ips")
                .fetch_all(&mut *conn)
                .await?;
        let facts = cat.fact_kinds();
        Ok(Input {
            ips: ips
                .into_iter()
                .map(|(id, ip, asn, last, unseen)| (id, ip, asn, last, unseen == 0))
                .collect(),
            scans: sqlx::query_as(
                "SELECT id, ip_id, finished_at, os_guess FROM scans WHERE finished_at IS NOT NULL",
            )
            .fetch_all(&mut *conn)
            .await?,
            ports: sqlx::query_as(
                "SELECT p.scan_id, p.port, p.service, p.product, p.devicetype
                 FROM ports p JOIN scans s ON s.id = p.scan_id
                 WHERE s.finished_at IS NOT NULL AND p.state = 'open'",
            )
            .fetch_all(&mut *conn)
            .await?,
            facts: sqlx::query_as(
                "SELECT f.scan_id, f.port, f.kind FROM scan_facts f
                 WHERE f.kind IN (SELECT value FROM json_each(?))",
            )
            .bind(serde_json::to_string(&facts)?)
            .fetch_all(&mut *conn)
            .await?,
            names: sqlx::query_as(
                "SELECT id, ip_id, lower(name), first_seen, last_seen FROM ip_names
                 WHERE source IN ('rdns', 'ptr')",
            )
            .fetch_all(&mut *conn)
            .await?,
            keys: sqlx::query_as(
                "SELECT h.id, h.ip_id, h.kind, h.fingerprint,
                        COALESCE(s.finished_at, s.started_at, p.finished_at, '')
                 FROM host_keys h
                 LEFT JOIN scans s ON s.id = h.scan_id
                 LEFT JOIN probes p ON p.id = h.probe_id
                 WHERE h.kind IN ('ssh-hostkey', 'tls-cert', 'http-etag')",
            )
            .fetch_all(&mut *conn)
            .await?,
            canaries: sqlx::query_as(
                "SELECT DISTINCT u.ip_id, c.value_hash, u.id, u.ts
                 FROM request_tokens t
                 JOIN canaries c ON c.value_hash = t.value_hash
                 JOIN requests u ON u.id = t.request_id
                 WHERE c.ip_id != u.ip_id
                   AND (t.place = 'body' OR t.place LIKE 'header:%')",
            )
            .fetch_all(&mut *conn)
            .await?,
            tor: sqlx::query_scalar("SELECT id FROM ips WHERE is_tor_exit = 1")
                .fetch_all(&mut *conn)
                .await?
                .into_iter()
                .collect(),
        })
    }
}

/// What a pass derived.
pub(crate) struct Output {
    pub rows: Vec<EvidenceRow>,
    /// Device rows left out as older than the address by [`STALE_SECS`].
    pub stale: usize,
    /// Device types and OS guesses no CPE entry read, by addresses.
    pub unmatched_devicetype: Vec<(String, usize)>,
    pub unmatched_os: Vec<(String, usize)>,
}

/// Whether evidence seen at `ts` is too old for an address last seen at
/// `last`.
fn stale(ts: &str, last: &str) -> bool {
    use super::campaigns::epoch;
    matches!((epoch(ts), epoch(last)), (Some(t), Some(l)) if l - t > STALE_SECS)
}

/// The /24 (IPv4) or /48 (IPv6) of an address, as text.
fn prefix(ip: &str) -> Option<String> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let len = if addr.is_ipv4() { 24 } else { 48 };
    Some(ipnet::IpNet::new(addr, len).ok()?.trunc().to_string())
}

pub(crate) fn compute(input: &Input, cat: &Catalogue) -> Output {
    let mut rows: BTreeMap<RowKey, (String, String)> = BTreeMap::new();
    let mut add =
        |ip: i64, kind: &str, value: &str, rk: &str, rid: i64, first: &str, last: &str| {
            let e = rows
                .entry((ip, kind.into(), value.into(), rk.into(), rid))
                .or_insert_with(|| (first.to_string(), last.to_string()));
            if first < e.0.as_str() {
                e.0 = first.to_string();
            }
            if last > e.1.as_str() {
                e.1 = last.to_string();
            }
        };
    let last_seen: HashMap<i64, &str> = input
        .ips
        .iter()
        .map(|(id, _, _, last, _)| (*id, last.as_str()))
        .collect();

    // device.*: per finished scan, its open ports, OS guess and facts.
    let mut ports: HashMap<i64, Vec<PortSeen>> = HashMap::new();
    for (scan, port, service, product, _) in &input.ports {
        ports
            .entry(*scan)
            .or_default()
            .push((*port, service.as_deref(), product.as_deref()));
    }
    let mut facts: HashMap<i64, Vec<(Option<i64>, &str)>> = HashMap::new();
    for (scan, port, kind) in &input.facts {
        facts.entry(*scan).or_default().push((*port, kind.as_str()));
    }
    let mut stale_rows = 0;
    let mut os_unmatched: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    let mut scan_ip: HashMap<i64, i64> = HashMap::new();
    for (scan, ip, at, os) in &input.scans {
        scan_ip.insert(*scan, *ip);
        let hits = cat.hits(
            ports.get(scan).map_or(&[][..], Vec::as_slice),
            os.as_deref(),
            facts.get(scan).map_or(&[][..], Vec::as_slice),
        );
        if let Some(os) = os.as_deref().filter(|o| !o.is_empty())
            && !hits.iter().any(|h| matches!(h.seen, Seen::Os(_)))
        {
            os_unmatched.entry(os).or_default().insert(*ip);
        }
        if hits.is_empty() {
            continue;
        }
        if last_seen.get(ip).is_some_and(|l| stale(at, l)) {
            stale_rows += hits.len();
            continue;
        }
        for h in hits {
            add(*ip, h.kind.row_kind(), &h.id, "scan", *scan, at, at);
        }
    }
    // Device types on ports no CPE entry read.
    let mut dt_unmatched: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    for (scan, port, service, product, devicetype) in &input.ports {
        if let Some(dt) = devicetype.as_deref().filter(|d| !d.is_empty())
            && !cat.devices.iter().any(|d| {
                d.kind == DeviceKind::Cpe
                    && d.matches_port(*port, service.as_deref(), product.as_deref())
            })
            && let Some(ip) = scan_ip.get(scan)
        {
            dt_unmatched.entry(dt).or_default().insert(*ip);
        }
    }

    // name.*: the first matching pattern of each list.
    for (id, ip, name, first, last) in &input.names {
        if last_seen.get(ip).is_some_and(|l| stale(last, l)) {
            continue;
        }
        for (kind, list) in [
            ("name.consumer", &cat.consumer),
            ("name.scanner", &cat.scanner),
        ] {
            if let Some(p) = list.iter().find(|p| p.re.is_match(name)) {
                add(*ip, kind, &p.id, "name", *id, first, last);
            }
        }
    }

    // fleet.key: an instance key on this address and 2 to 50 others.
    // (kind, fingerprint) → ip → (lowest host_keys id, when seen).
    type Holders<'a> = BTreeMap<i64, (i64, &'a str)>;
    let mut by_key: HashMap<(&str, &str), Holders> = HashMap::new();
    for (id, ip, kind, fp, ts) in &input.keys {
        let e = by_key
            .entry((kind.as_str(), fp.as_str()))
            .or_default()
            .entry(*ip)
            .or_insert((*id, ts.as_str()));
        if *id < e.0 {
            *e = (*id, ts.as_str());
        }
    }
    for ((_, fp), ips) in &by_key {
        let others = ips.len() - 1;
        if (FLEET_KEY_MIN_OTHERS..=FLEET_KEY_MAX_OTHERS).contains(&others) {
            for (ip, (id, ts)) in ips {
                add(*ip, "fleet.key", fp, "host_key", *id, ts, ts);
            }
        }
    }

    // fleet.canary: a canary served elsewhere came back from here in a
    // header or the body (a path or query can be planted on a victim).
    for (ip, hash, req, ts) in &input.canaries {
        add(
            *ip,
            "fleet.canary",
            &hash.to_string(),
            "request",
            *req,
            ts,
            ts,
        );
    }

    // fleet.dense and net.*: per address.
    let mut per_prefix: HashMap<String, Vec<(i64, &str)>> = HashMap::new();
    for (id, ip, asn, last, seen) in &input.ips {
        if *seen && let Some(p) = prefix(ip) {
            per_prefix.entry(p).or_default().push((*id, last.as_str()));
        }
        if let Some(t) = asn.and_then(|a| cat.as_types.get(&a)) {
            let (kind, value) = t.row();
            add(*id, kind, value, "ip", *id, last, last);
        }
    }
    for (p, members) in &per_prefix {
        if members.len() >= DENSE_MIN {
            for (id, last) in members {
                add(*id, "fleet.dense", p, "ip", *id, last, last);
            }
        }
    }

    let ranked = |m: BTreeMap<&str, BTreeSet<i64>>| {
        let mut v: Vec<(String, usize)> = m.into_iter().map(|(k, s)| (k.into(), s.len())).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    Output {
        rows: rows
            .into_iter()
            .map(
                |((ip_id, kind, value, ref_kind, ref_id), (first_ts, last_ts))| EvidenceRow {
                    ip_id,
                    kind,
                    value,
                    ref_kind,
                    ref_id,
                    first_ts,
                    last_ts,
                },
            )
            .collect(),
        stale: stale_rows,
        unmatched_devicetype: ranked(dt_unmatched),
        unmatched_os: ranked(os_unmatched),
    }
}

/// What one evidence pass did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// Rows and addresses by kind.
    pub rows: BTreeMap<String, usize>,
    pub ips: BTreeMap<String, usize>,
    /// Device rows left out as stale.
    pub stale: usize,
    /// Entries in the AS-type list (0: none bundled).
    pub as_types: usize,
    pub unmatched_devicetype: Vec<(String, usize)>,
    pub unmatched_os: Vec<(String, usize)>,
    /// Addresses per verdict rule (1 to 6; 7 is everything else), and per
    /// row kind a rule-2 verdict rests on.
    pub rules: BTreeMap<u8, usize>,
    pub fleet_by: BTreeMap<String, usize>,
    pub seconds: f64,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.rows.values().sum();
        writeln!(f, "evidence: {total} rows in {:.2} s", self.seconds)?;
        for k in KINDS {
            writeln!(
                f,
                "  {k}: {} rows on {} addresses",
                self.rows.get(*k).unwrap_or(&0),
                self.ips.get(*k).unwrap_or(&0)
            )?;
        }
        writeln!(
            f,
            "stale device rows left out (scan older than the address by more than 24 h): {}",
            self.stale
        )?;
        if self.as_types == 0 {
            writeln!(f, "AS-type list: none bundled (no net.* rows)")?;
        } else {
            writeln!(f, "AS-type list: {} ASNs", self.as_types)?;
        }
        write!(f, "verdicts (addresses with evidence):")?;
        for n in 1..=7u8 {
            write!(f, " rule {n} {}", self.rules.get(&n).unwrap_or(&0))?;
        }
        writeln!(f)?;
        let by: Vec<String> = self
            .fleet_by
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        writeln!(
            f,
            "rule 2 rests on: {}",
            if by.is_empty() {
                "none".into()
            } else {
                by.join(", ")
            }
        )?;
        for (title, list) in [
            ("unmatched device types", &self.unmatched_devicetype),
            ("unmatched OS guesses", &self.unmatched_os),
        ] {
            write!(f, "{title} (addresses): ")?;
            if list.is_empty() {
                writeln!(f, "none")?;
                continue;
            }
            writeln!(f, "{} values", list.len())?;
            for (v, n) in list.iter().take(REPORT_UNMATCHED) {
                writeln!(f, "  {n:>5}  {v}")?;
            }
            if list.len() > REPORT_UNMATCHED {
                writeln!(f, "  … and {} more", list.len() - REPORT_UNMATCHED)?;
            }
        }
        Ok(())
    }
}

impl Store {
    /// Recompute every evidence row with the built-in catalogues (one read
    /// snapshot, then one write transaction).
    pub async fn recompute_evidence(&self) -> Result<Report> {
        self.recompute_evidence_with(Catalogue::builtin()).await
    }

    pub(crate) async fn recompute_evidence_with(&self, cat: &Catalogue) -> Result<Report> {
        let started = std::time::Instant::now();
        let mut tx = self.pool.begin().await?;
        let input = Input::read(&mut tx, cat).await?;
        tx.rollback().await?;
        let out = compute(&input, cat);

        let mut report = Report {
            stale: out.stale,
            as_types: cat.as_types.len(),
            unmatched_devicetype: out.unmatched_devicetype,
            unmatched_os: out.unmatched_os,
            ..Report::default()
        };
        let mut ips: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
        for r in &out.rows {
            *report.rows.entry(r.kind.clone()).or_default() += 1;
            ips.entry(&r.kind).or_default().insert(r.ip_id);
        }
        report.ips = ips.into_iter().map(|(k, s)| (k.into(), s.len())).collect();
        let mut per_ip: BTreeMap<i64, Vec<EvidenceRow>> = BTreeMap::new();
        for r in &out.rows {
            per_ip.entry(r.ip_id).or_default().push(r.clone());
        }
        for (ip, rows) in &per_ip {
            let v = verdict(rows, input.tor.contains(ip));
            *report.rules.entry(v.rule.number()).or_default() += 1;
            if v.rule == Rule::RentedFleet {
                let kinds: BTreeSet<&str> = v.rows.iter().map(|r| r.kind.as_str()).collect();
                for k in kinds {
                    *report.fleet_by.entry(k.to_string()).or_default() += 1;
                }
            }
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("DELETE FROM ip_evidence")
            .execute(&mut *tx)
            .await?;
        for r in &out.rows {
            sqlx::query(
                "INSERT INTO ip_evidence (ip_id, kind, value, ref_kind, ref_id, first_ts, last_ts, v)
                 VALUES (?,?,?,?,?,?,?,?)",
            )
            .bind(r.ip_id)
            .bind(&r.kind)
            .bind(&r.value)
            .bind(&r.ref_kind)
            .bind(r.ref_id)
            .bind(&r.first_ts)
            .bind(&r.last_ts)
            .bind(EVIDENCE_V)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        report.seconds = started.elapsed().as_secs_f64();
        Ok(report)
    }

    /// An address's evidence rows.
    pub async fn evidence_rows(&self, ip_id: i64) -> Result<Vec<EvidenceRow>> {
        Ok(sqlx::query_as(
            "SELECT ip_id, kind, value, ref_kind, ref_id, first_ts, last_ts
             FROM ip_evidence WHERE ip_id = ? ORDER BY kind, last_ts DESC, ref_id",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?)
    }
}

// ---- Verdict --------------------------------------------------------------

/// The verdict table's rules, first match wins (docs/detection.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// 1: a Tor exit (verified crawlers are never counter-scanned and keep
    /// their existing badge).
    Declared,
    /// 2: a shared instance key or a canary handed between addresses; or a
    /// dense prefix or a scanner name in a hosting AS.
    RentedFleet,
    /// 3: a hosting AS alone.
    Rented,
    /// 4: a consumer device answered, in a consumer ISP AS, in no fleet.
    ConsumerDevice,
    /// 5: proxy software answered, in a consumer ISP AS, in no fleet.
    ProxyOnConsumer,
    /// 6: a device or proxy answered; the AS type is not classified.
    DeviceOnly,
    /// 7: nothing to say.
    Unknown,
}

impl Rule {
    pub fn number(self) -> u8 {
        match self {
            Rule::Declared => 1,
            Rule::RentedFleet => 2,
            Rule::Rented => 3,
            Rule::ConsumerDevice => 4,
            Rule::ProxyOnConsumer => 5,
            Rule::DeviceOnly => 6,
            Rule::Unknown => 7,
        }
    }

    /// The verdict's name on the IP page; None where the page shows
    /// nothing new (rules 1 and 7).
    pub fn label(self) -> Option<&'static str> {
        match self {
            Rule::Declared | Rule::Unknown => None,
            Rule::RentedFleet => Some("rented fleet"),
            Rule::Rented => Some("rented"),
            Rule::ConsumerDevice => Some("consumer device answered"),
            Rule::ProxyOnConsumer => Some("proxy software on a consumer line"),
            Rule::DeviceOnly => Some("device evidence only"),
        }
    }
}

/// The verdict on an address and the rows behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub rule: Rule,
    /// The rows the rule rests on, then the context rows it shows.
    pub rows: Vec<EvidenceRow>,
}

/// Rules 1 to 7 over an address's evidence rows. `declared`: a Tor exit.
pub fn verdict(rows: &[EvidenceRow], declared: bool) -> Verdict {
    let has = |k: &str| rows.iter().any(|r| r.kind == k);
    let of = |kinds: &[&str]| -> Vec<EvidenceRow> {
        rows.iter()
            .filter(|r| kinds.contains(&r.kind.as_str()))
            .cloned()
            .collect()
    };
    let hosting = has("net.hosting");
    let eyeball = has("net.eyeball");
    let fleet = has("fleet.key") || has("fleet.canary");
    let (cpe, proxy) = (has("device.cpe"), has("device.proxy"));
    let devices = ["device.cpe", "device.proxy", "name.consumer"];
    let (rule, kinds): (Rule, &[&str]) = if declared {
        (Rule::Declared, &[])
    } else if fleet {
        (Rule::RentedFleet, &["fleet.key", "fleet.canary"])
    } else if hosting && has("fleet.dense") {
        (Rule::RentedFleet, &["fleet.dense", "net.hosting"])
    } else if hosting && has("name.scanner") {
        (Rule::RentedFleet, &["name.scanner", "net.hosting"])
    } else if hosting {
        (Rule::Rented, &["net.hosting"])
    } else if cpe && eyeball && !has("name.scanner") {
        (
            Rule::ConsumerDevice,
            &["device.cpe", "device.proxy", "net.eyeball", "name.consumer"],
        )
    } else if proxy && eyeball {
        (
            Rule::ProxyOnConsumer,
            &["device.proxy", "net.eyeball", "name.consumer"],
        )
    } else if (cpe || proxy) && !eyeball {
        (Rule::DeviceOnly, &devices)
    } else {
        (Rule::Unknown, &[])
    };
    Verdict {
        rule,
        rows: of(kinds),
    }
}

// ---- The IP page ----------------------------------------------------------

/// One evidence row as the IP page shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub kind: String,
    /// What was observed: the device or proxy, the key, the name.
    pub what: String,
    pub port: Option<i64>,
    /// Where it came from, and the page that shows it.
    pub source: String,
    pub href: Option<String>,
    pub date: String,
}

/// The verdict as the IP page shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub rule: Rule,
    pub label: &'static str,
    /// What was observed, in one sentence; never a claim about whose box
    /// it is.
    pub sentence: String,
    pub caveat: Option<&'static str>,
    pub lines: Vec<Line>,
}

/// The caveat on a device verdict.
pub const DEVICE_CAVEAT: &str = "What answered is the box on this address at scan time, \
     not necessarily the sender; who runs it is not observable from here.";
/// The caveat on a mobile ISP address.
pub const MOBILE_CAVEAT: &str = "mobile ISP address: usually many subscribers (CGNAT)";

fn day(ts: &str) -> String {
    ts.get(..10).unwrap_or(ts).to_string()
}

fn short(fp: &str) -> String {
    if fp.chars().count() > 20 {
        format!("{}…", fp.chars().take(20).collect::<String>())
    } else {
        fp.to_string()
    }
}

fn key_name(kind: &str) -> &str {
    match kind {
        "ssh-hostkey" => "SSH host key",
        "tls-cert" => "TLS certificate",
        "http-etag" => "HTTP ETag",
        other => other,
    }
}

impl Store {
    /// The verdict on an address with its evidence, as the IP page shows
    /// it; None where it shows nothing new (rules 1 and 7).
    pub async fn evidence_view(&self, ip_id: i64, tor_exit: bool) -> Result<Option<View>> {
        let rows = self.evidence_rows(ip_id).await?;
        let v = verdict(&rows, tor_exit);
        let Some(label) = v.rule.label() else {
            return Ok(None);
        };
        let cat = Catalogue::builtin();
        let mut lines = vec![];
        for r in &v.rows {
            lines.extend(self.lines_of(cat, r).await?);
        }
        // Devices newest first, then the rest in row order.
        let device = |l: &Line| l.kind.starts_with("device.");
        lines.sort_by(|a, b| {
            device(b)
                .cmp(&device(a))
                .then_with(|| (a.kind == "device.proxy").cmp(&(b.kind == "device.proxy")))
                .then_with(|| b.date.cmp(&a.date))
        });
        let mobile = rows
            .iter()
            .any(|r| r.kind == "net.eyeball" && r.value == "mobile");
        let first = |kinds: &[&str]| lines.iter().find(|l| kinds.contains(&l.kind.as_str()));
        let observed = |l: &Line| match l.port {
            Some(p) => format!("{} answered on {p} in {}", l.what, l.source),
            None => format!("{} in {}", l.what, l.source),
        };
        let sentence = match v.rule {
            Rule::RentedFleet => {
                first(&["fleet.key", "fleet.canary", "fleet.dense", "name.scanner"])
                    .map(|l| l.what.clone())
                    .unwrap_or_default()
            }
            Rule::Rented => "hosting AS".into(),
            Rule::ConsumerDevice => first(&["device.cpe"])
                .map(|l| format!("{}; the line is in a consumer ISP AS", observed(l)))
                .unwrap_or_default(),
            Rule::ProxyOnConsumer => first(&["device.proxy"])
                .map(|l| format!("{}; the line is in a consumer ISP AS", observed(l)))
                .unwrap_or_default(),
            Rule::DeviceOnly => first(&["device.cpe", "device.proxy"])
                .map(|l| format!("{}; AS type not classified", observed(l)))
                .unwrap_or_default(),
            Rule::Declared | Rule::Unknown => unreachable!("no label"),
        };
        let caveat = match v.rule {
            Rule::ConsumerDevice | Rule::ProxyOnConsumer if mobile => Some(MOBILE_CAVEAT),
            Rule::ConsumerDevice | Rule::ProxyOnConsumer | Rule::DeviceOnly => Some(DEVICE_CAVEAT),
            _ => None,
        };
        Ok(Some(View {
            rule: v.rule,
            label,
            sentence,
            caveat,
            lines,
        }))
    }

    /// The lines one evidence row stands for (a device row: every port of
    /// its scan the entry matched).
    async fn lines_of(&self, cat: &Catalogue, r: &EvidenceRow) -> Result<Vec<Line>> {
        let line = |what: String, port, source: String, href, date: &str| Line {
            kind: r.kind.clone(),
            what,
            port,
            source,
            href,
            date: day(date),
        };
        Ok(match r.kind.as_str() {
            "device.cpe" | "device.proxy" => {
                let Some((level, at, os)) = sqlx::query_as::<_, (i64, String, Option<String>)>(
                    "SELECT level, finished_at, os_guess FROM scans
                     WHERE id = ? AND finished_at IS NOT NULL",
                )
                .bind(r.ref_id)
                .fetch_optional(&self.read)
                .await?
                else {
                    return Ok(vec![]);
                };
                let ports: Vec<(i64, Option<String>, Option<String>)> = sqlx::query_as(
                    "SELECT port, service, product FROM ports
                     WHERE scan_id = ? AND state = 'open' ORDER BY port",
                )
                .bind(r.ref_id)
                .fetch_all(&self.read)
                .await?;
                let facts: Vec<(Option<i64>, String)> =
                    sqlx::query_as("SELECT port, kind FROM scan_facts WHERE scan_id = ?")
                        .bind(r.ref_id)
                        .fetch_all(&self.read)
                        .await?;
                let ports: Vec<PortSeen> = ports
                    .iter()
                    .map(|(p, s, d)| (*p, s.as_deref(), d.as_deref()))
                    .collect();
                let facts: Vec<(Option<i64>, &str)> =
                    facts.iter().map(|(p, k)| (*p, k.as_str())).collect();
                let source = format!("scan #{} (level {level}, {})", r.ref_id, day(&at));
                let href = Some(format!("/admin/scans/{}", r.ref_id));
                cat.hits(&ports, os.as_deref(), &facts)
                    .into_iter()
                    .filter(|h| h.kind.row_kind() == r.kind && h.id == r.value)
                    .map(|h| match h.seen {
                        Seen::Port(p, product) => line(
                            product.unwrap_or(h.label),
                            Some(p),
                            source.clone(),
                            href.clone(),
                            &at,
                        ),
                        Seen::Os(os) => line(
                            format!("nmap's OS guess {os}"),
                            None,
                            source.clone(),
                            href.clone(),
                            &at,
                        ),
                        Seen::Fact(p, kind) => line(
                            format!("{} ({kind})", h.label),
                            p,
                            source.clone(),
                            href.clone(),
                            &at,
                        ),
                    })
                    .collect()
            }
            "fleet.key" => {
                let Some((kind, port, scan)) = sqlx::query_as::<_, (String, i64, Option<i64>)>(
                    "SELECT kind, port, scan_id FROM host_keys WHERE id = ?",
                )
                .bind(r.ref_id)
                .fetch_optional(&self.read)
                .await?
                else {
                    return Ok(vec![]);
                };
                let n: i64 = sqlx::query_scalar(
                    "SELECT COUNT(DISTINCT ip_id) FROM host_keys WHERE kind = ? AND fingerprint = ?",
                )
                .bind(&kind)
                .bind(&r.value)
                .fetch_one(&self.read)
                .await?;
                let what = format!(
                    "one of {n} addresses sharing {} {}",
                    key_name(&kind),
                    short(&r.value)
                );
                let link = crate::store::links::LinkKind::of_host_kind(&kind)
                    .map(|k| crate::admin::views::link_href(k.key(), &r.value));
                match scan {
                    Some(s) => vec![line(
                        what,
                        Some(port),
                        format!("scan #{s}"),
                        Some(format!("/admin/scans/{s}")),
                        &r.last_ts,
                    )],
                    None => vec![line(what, Some(port), "a probe".into(), link, &r.last_ts)],
                }
            }
            "fleet.canary" => {
                let served: Vec<(String, String)> = sqlx::query_as(
                    "SELECT DISTINCT ci.ip, t.place FROM request_tokens t
                     JOIN canaries c ON c.value_hash = t.value_hash
                     JOIN ips ci ON ci.id = c.ip_id
                     WHERE t.request_id = ?1 AND c.value_hash = ?2 AND c.ip_id != ?3
                       AND (t.place = 'body' OR t.place LIKE 'header:%')
                     ORDER BY ci.ip",
                )
                .bind(r.ref_id)
                .bind(r.value.parse::<i64>().unwrap_or_default())
                .bind(r.ip_id)
                .fetch_all(&self.read)
                .await?;
                served
                    .into_iter()
                    .map(|(ip, place)| {
                        line(
                            format!("canary served to {ip} came back from here ({place})"),
                            None,
                            format!("request #{}", r.ref_id),
                            Some(format!("/admin/requests/{}", r.ref_id)),
                            &r.last_ts,
                        )
                    })
                    .collect()
            }
            "name.consumer" | "name.scanner" => {
                let name: Option<String> =
                    sqlx::query_scalar("SELECT name FROM ip_names WHERE id = ?")
                        .bind(r.ref_id)
                        .fetch_optional(&self.read)
                        .await?;
                let pattern = if r.kind == "name.consumer" {
                    "consumer-line"
                } else {
                    "scanner"
                };
                name.map(|n| {
                    line(
                        format!("named {n} ({pattern} pattern {})", r.value),
                        None,
                        "reverse DNS".into(),
                        None,
                        &r.last_ts,
                    )
                })
                .into_iter()
                .collect()
            }
            "fleet.dense" => vec![line(
                format!("one of {DENSE_MIN} or more sources in {}", r.value),
                None,
                "recorded addresses".into(),
                None,
                &r.last_ts,
            )],
            _ => vec![line(
                format!("AS type {}", r.value),
                None,
                "AS-type list".into(),
                None,
                &r.last_ts,
            )],
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn builtin() -> &'static Catalogue {
        Catalogue::builtin()
    }

    /// The rented fleets' banners (MIK-577): kind, port, service, product,
    /// OS guess.
    fn rented_banners() -> Vec<Sample> {
        let text = std::fs::read_to_string("tests/fixtures/rented-fleet-banners.tsv").unwrap();
        let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                Sample {
                    port: f[1].parse().ok(),
                    service: opt(f[2]),
                    product: opt(f[3]),
                    os_guess: opt(f[4]),
                    fact: None,
                }
            })
            .collect()
    }

    fn rented_names() -> Vec<String> {
        std::fs::read_to_string("tests/fixtures/rented-fleet-names.txt")
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    /// Every built-in catalogue file is one `Catalogue::parse` reads, and
    /// the device entries come in both kinds.
    #[test]
    fn the_builtin_catalogues_parse() {
        let c = builtin();
        assert!(c.devices.iter().any(|d| d.kind == DeviceKind::Proxy));
        assert!(c.devices.iter().any(|d| d.kind == DeviceKind::Cpe));
        assert!(!c.consumer.is_empty() && !c.scanner.is_empty());
        assert!(
            Catalogue::parse(&[("device.toml", "")]).is_err(),
            "a misnamed file"
        );
    }

    /// Each device entry matches its own samples (parse checks it) and no
    /// CPE entry matches a banner of the top-20 rented fleets. The proxy
    /// entries do, by design: those fleets run 3Proxy and Socks4A, and
    /// rule 2 places them before rule 6.
    #[test]
    fn device_entries_match_their_samples_and_no_rented_banner() {
        let banners = rented_banners();
        assert!(banners.len() > 200, "{}", banners.len());
        for d in &builtin().devices {
            for s in &d.samples {
                assert!(d.matches(s), "{} on {s:?}", d.id);
            }
            if d.kind == DeviceKind::Cpe {
                for b in &banners {
                    assert!(!d.matches(b), "{} matches the rented banner {b:?}", d.id);
                }
            }
        }
        // The proxy entries fire on 3xK Tech's image.
        let proxies: BTreeSet<&str> = banners
            .iter()
            .flat_map(|b| {
                builtin()
                    .devices
                    .iter()
                    .filter(move |d| d.kind == DeviceKind::Proxy && d.matches(b))
                    .map(|d| d.id.as_str())
            })
            .collect();
        assert_eq!(
            proxies,
            BTreeSet::from(["3proxy", "http-proxy", "socks"]),
            "{proxies:?}"
        );
    }

    /// The OS guesses that are fingerprint noise on rented hosts stay out.
    #[test]
    fn noisy_os_guesses_are_not_devices() {
        for os in [
            "Android TV OS 11 (Linux 4.19)",
            "3Com OfficeConnect 3CRWER100-75 wireless broadband router",
            "Crestron XPanel control system",
            "Linux 4.15 - 5.19",
        ] {
            assert!(builtin().hits(&[], Some(os), &[]).is_empty(), "{os}");
        }
    }

    /// Each name pattern matches its samples; no consumer pattern matches a
    /// rented fleet's name.
    #[test]
    fn name_patterns_match_their_samples_and_no_rented_name() {
        let names = rented_names();
        assert!(names.len() > 300, "{}", names.len());
        let c = builtin();
        for p in c.consumer.iter().chain(&c.scanner) {
            for s in &p.samples {
                assert!(p.re.is_match(s), "{} on {s}", p.id);
            }
        }
        for p in &c.consumer {
            for n in &names {
                assert!(!p.re.is_match(n), "{} matches the rented name {n}", p.id);
            }
        }
        assert!(!c.consumer.iter().any(|p| p.re.is_match("dynatrace.com")));
    }

    /// Per port and kind the first entry wins: a FRITZ!Box's TR-069 service
    /// is `fritzbox`, not the generic `tr069`; a port can carry a proxy and
    /// a device row.
    #[test]
    fn hits_take_the_first_entry_per_port_and_kind() {
        let c = builtin();
        let h = c.hits(
            &[
                (8089, Some("http"), Some("FRITZ!Box TR-069 service")),
                (8080, Some("http-proxy"), Some("MikroTik http proxy")),
                (22, Some("ssh"), Some("OpenSSH")),
            ],
            Some("OpenWrt 22.03 (Linux 5.10)"),
            &[(Some(1080), "socks.method")],
        );
        let got: Vec<(&str, &str)> = h
            .iter()
            .map(|h| (h.kind.row_kind(), h.id.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("device.cpe", "fritzbox"),
                ("device.proxy", "http-proxy"),
                ("device.cpe", "mikrotik"),
                ("device.cpe", "openwrt-luci"),
                ("device.proxy", "socks"),
            ]
        );
    }

    fn input() -> Input {
        let ts = |h: u32| format!("2026-10-1{} 12:00:00", h);
        let mut i = Input::default();
        // 1: a TR-069 router; 2: 3Proxy; 3..=5 share an SSH key; 6: its scan
        // is two days older than its last request; 7: a consumer PTR.
        for id in 1..=7 {
            i.ips
                .push((id, format!("192.0.2.{id}"), Some(64500 + id), ts(2), true));
        }
        i.scans = vec![
            (11, 1, ts(1), None),
            (12, 2, ts(2), Some("Linux 5.4".into())),
            (16, 6, ts(0), None),
        ];
        i.ports = vec![
            (
                11,
                7547,
                Some("http".into()),
                Some("Huawei TR-069 remote access".into()),
                Some("broadband router".into()),
            ),
            (
                12,
                7777,
                Some("http-proxy".into()),
                Some("3Proxy http proxy".into()),
                None,
            ),
            (
                12,
                22,
                Some("ssh".into()),
                Some("OpenSSH".into()),
                Some("PBX".into()),
            ),
            (
                16,
                2000,
                Some("bandwidth-test".into()),
                Some("MikroTik bandwidth-test server".into()),
                None,
            ),
        ];
        i.keys = (3..=5)
            .map(|ip| (30 + ip, ip, "ssh-hostkey".into(), "SHA256:k".into(), ts(1)))
            .collect();
        // Two addresses share another key: one other is not a fleet.
        i.keys.push((40, 1, "tls-cert".into(), "ab".into(), ts(1)));
        i.keys.push((41, 2, "tls-cert".into(), "ab".into(), ts(1)));
        i.names = vec![
            (70, 7, "dynamic-0.pool.example.de".into(), ts(1), ts(2)),
            (71, 5, "scan-0.example.org".into(), ts(1), ts(2)),
        ];
        i.canaries = vec![(4, 99, 400, ts(2))];
        i
    }

    fn kinds(out: &Output, ip: i64) -> Vec<(String, String)> {
        out.rows
            .iter()
            .filter(|r| r.ip_id == ip)
            .map(|r| (r.kind.clone(), r.value.clone()))
            .collect()
    }

    #[test]
    fn rows_are_derived_from_scans_names_keys_and_canaries() {
        let out = compute(&input(), builtin());
        let kv = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(kinds(&out, 1), [kv("device.cpe", "tr069")]);
        assert_eq!(kinds(&out, 2), [kv("device.proxy", "3proxy")]);
        assert_eq!(kinds(&out, 3), [kv("fleet.key", "SHA256:k")]);
        assert_eq!(
            kinds(&out, 4),
            [kv("fleet.canary", "99"), kv("fleet.key", "SHA256:k")]
        );
        assert_eq!(
            kinds(&out, 5),
            [kv("fleet.key", "SHA256:k"), kv("name.scanner", "scanner")]
        );
        assert!(kinds(&out, 6).is_empty(), "stale scan");
        assert_eq!(out.stale, 1);
        assert_eq!(
            kinds(&out, 7),
            [kv("name.consumer", "dynamic")],
            "first consumer pattern only"
        );
        let r = out.rows.iter().find(|r| r.ip_id == 1).unwrap();
        assert_eq!((r.ref_kind.as_str(), r.ref_id), ("scan", 11));
        // No AS list, few addresses: no net.* or fleet.dense rows.
        assert!(
            !out.rows
                .iter()
                .any(|r| r.kind.starts_with("net.") || r.kind == "fleet.dense")
        );
        assert_eq!(out.unmatched_devicetype, [("PBX".to_string(), 1)]);
        assert_eq!(out.unmatched_os, [("Linux 5.4".to_string(), 1)]);
    }

    /// The bundled AS-type list switches the `net.*` rows, and with them
    /// rules 3 to 5 and the rest of rule 2, on without a code change.
    #[test]
    fn an_as_type_list_switches_the_net_rules_on() {
        let mut files: Vec<(&str, &str)> = BUILTIN.to_vec();
        assert!(
            !files.iter().any(|(n, _)| *n == AS_TYPES),
            "no AS-type list is bundled in this slice"
        );
        let list = "[[as]]\nasn = 64501\ntype = \"fixed\"\n\
                    [[as]]\nasn = 64502\ntype = \"mobile\"\n\
                    [[as]]\nasn = 64505\ntype = \"hosting\"\n\
                    [[as]]\nasn = 64507\ntype = \"cloud\"\n";
        files.push((AS_TYPES, list));
        let cat = Catalogue::parse(&files).unwrap();
        let mut inp = input();
        // A dense /24 of 16 in the hosting AS 64507.
        for n in 0..16 {
            inp.ips.push((
                100 + n,
                format!("198.51.100.{n}"),
                Some(64507),
                "2026-10-12 12:00:00".into(),
                true,
            ));
        }
        let out = compute(&inp, &cat);
        let rules = |ip: i64| {
            let rows: Vec<EvidenceRow> =
                out.rows.iter().filter(|r| r.ip_id == ip).cloned().collect();
            verdict(&rows, false).rule
        };
        assert_eq!(rules(1), Rule::ConsumerDevice, "TR-069 in a fixed-line AS");
        assert_eq!(rules(2), Rule::ProxyOnConsumer, "3Proxy in a mobile AS");
        assert_eq!(rules(5), Rule::RentedFleet);
        assert_eq!(
            rules(100),
            Rule::RentedFleet,
            "fleet.dense with net.hosting"
        );
        // Without the list the same rows read as rule 6 and nothing.
        let plain = compute(&inp, builtin());
        let rules = |ip: i64| {
            let rows: Vec<EvidenceRow> = plain
                .rows
                .iter()
                .filter(|r| r.ip_id == ip)
                .cloned()
                .collect();
            verdict(&rows, false).rule
        };
        assert_eq!(rules(1), Rule::DeviceOnly);
        assert_eq!(rules(2), Rule::DeviceOnly);
        assert_eq!(
            rules(100),
            Rule::Unknown,
            "fleet.dense alone decides nothing"
        );
        assert!(
            Catalogue::parse(&[(
                AS_TYPES,
                "[[as]]\nasn = 1\ntype = \"fixed\"\n[[as]]\nasn = 1\ntype = \"cloud\"\n"
            )])
            .is_err()
        );
    }

    fn row(kind: &str) -> EvidenceRow {
        EvidenceRow {
            ip_id: 1,
            kind: kind.into(),
            value: "v".into(),
            ref_kind: "scan".into(),
            ref_id: 1,
            first_ts: String::new(),
            last_ts: String::new(),
        }
    }

    #[test]
    fn the_verdict_table_goes_first_match() {
        let v = |kinds: &[&str]| {
            let rows: Vec<EvidenceRow> = kinds.iter().map(|k| row(k)).collect();
            verdict(&rows, false).rule
        };
        assert_eq!(v(&[]), Rule::Unknown);
        assert_eq!(v(&["name.consumer"]), Rule::Unknown);
        assert_eq!(v(&["fleet.dense"]), Rule::Unknown);
        assert_eq!(v(&["device.cpe"]), Rule::DeviceOnly);
        assert_eq!(v(&["device.proxy", "name.consumer"]), Rule::DeviceOnly);
        assert_eq!(v(&["device.cpe", "fleet.key"]), Rule::RentedFleet);
        assert_eq!(v(&["device.proxy", "fleet.canary"]), Rule::RentedFleet);
        assert_eq!(v(&["device.cpe", "net.hosting"]), Rule::Rented);
        assert_eq!(v(&["net.hosting", "name.scanner"]), Rule::RentedFleet);
        assert_eq!(v(&["device.cpe", "net.eyeball"]), Rule::ConsumerDevice);
        assert_eq!(
            v(&["device.cpe", "net.eyeball", "name.scanner"]),
            Rule::Unknown,
            "a scanner name blocks rule 4, and rule 6 needs no net.* row"
        );
        assert_eq!(
            v(&["device.cpe", "device.proxy", "net.eyeball", "name.scanner"]),
            Rule::ProxyOnConsumer
        );
        assert_eq!(v(&["device.proxy", "net.eyeball"]), Rule::ProxyOnConsumer);
        assert_eq!(v(&["net.eyeball"]), Rule::Unknown);
        assert_eq!(
            v(&["device.cpe", "fleet.dense"]),
            Rule::DeviceOnly,
            "a dense eyeball /24 does not block the device rules"
        );
        let rows = [row("device.cpe")];
        assert_eq!(verdict(&rows, true).rule, Rule::Declared);
        // The verdict carries its rows, and the context.
        let rows = [row("device.cpe"), row("name.consumer"), row("fleet.dense")];
        let v = verdict(&rows, false);
        let kinds: Vec<&str> = v.rows.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["device.cpe", "name.consumer"]);
        assert_eq!(Rule::Unknown.label(), None, "rule 7 shows nothing");
        assert_eq!(Rule::Declared.label(), None);
    }

    /// The address a recorded nmap XML of a TR-069 router scanned, and the
    /// scan, stored through the scan ingest.
    pub(crate) async fn seed_tr069(s: &Store) -> (i64, i64) {
        let row = s.upsert_ip("203.0.113.47".parse().unwrap()).await.unwrap();
        s.insert_request(&crate::store::requests::NewRequest {
            ip_id: row.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        s.enqueue_scan(row.id, 1, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = crate::scan::nmap_xml::parse_nmap_xml(include_bytes!(
            "../../tests/fixtures/nmap-tr069.xml"
        ))
        .unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();
        let scan: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?")
            .bind(row.id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        (row.id, scan)
    }

    /// A recorded scan of a box answering TR-069 on 7547, fed through the
    /// ingest, gives a `device.cpe` row and a rule-6 sentence naming the
    /// device, the port, the scan and its date (the lab check of the
    /// design, without nmap on the host).
    #[tokio::test]
    async fn a_recorded_tr069_scan_gives_a_device_row_and_a_rule_6_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (ip, scan) = seed_tr069(&s).await;
        let r = s.recompute_evidence().await.unwrap();
        assert_eq!(r.ips.get("device.cpe"), Some(&1), "{r}");
        assert!(
            r.to_string().contains("device.cpe: 1 rows on 1 addresses"),
            "{r}"
        );
        let rows = s.evidence_rows(ip).await.unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            (
                rows[0].kind.as_str(),
                rows[0].value.as_str(),
                rows[0].ref_id
            ),
            ("device.cpe", "tr069", scan)
        );
        let v = s.evidence_view(ip, false).await.unwrap().unwrap();
        assert_eq!(v.rule, Rule::DeviceOnly);
        let today = &crate::store::data::now_ts()[..10];
        assert_eq!(
            v.sentence,
            format!(
                "TP-LINK TR-069 remote access answered on 7547 in scan #{scan} \
                 (level 1, {today}); AS type not classified"
            )
        );
        assert_eq!(
            v.lines[0].href.as_deref(),
            Some(&*format!("/admin/scans/{scan}"))
        );
        assert_eq!(v.caveat, Some(DEVICE_CAVEAT));
        // A Tor exit is rule 1: nothing new on the page.
        assert_eq!(s.evidence_view(ip, true).await.unwrap(), None);
        // The rows go with the address.
        assert!(s.delete_ip(ip).await.unwrap());
        assert!(s.evidence_rows(ip).await.unwrap().is_empty());
    }

    /// `ip_evidence` stays on the node: no replication, export, dataset,
    /// API or blocklist code reads it, and an export of an address with
    /// evidence carries none of it.
    #[tokio::test]
    async fn evidence_is_in_no_export_dataset_replication_or_blocklist_path() {
        fn sources(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            if path.is_dir() {
                for e in std::fs::read_dir(path).unwrap() {
                    sources(&e.unwrap().path(), out);
                }
            } else if path.extension().is_some_and(|x| x == "rs") {
                out.push(path.to_path_buf());
            }
        }
        let mut files = vec![];
        for p in [
            "src/export",
            "src/cluster",
            "src/store/export.rs",
            "src/store/publish.rs",
            "src/store/blocklist.rs",
            "src/store/recorder.rs",
            "src/admin/blocklist.rs",
            "src/admin/api_v1.rs",
        ] {
            sources(std::path::Path::new(p), &mut files);
        }
        assert!(files.len() > 20, "{files:?}");
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            for needle in [
                "ip_evidence",
                "evidence::",
                "recompute_evidence",
                "evidence_view",
            ] {
                assert!(!text.contains(needle), "{} reads {needle}", f.display());
            }
        }

        use futures::TryStreamExt;
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        seed_tr069(&s).await;
        s.recompute_evidence().await.unwrap();
        let parts: Vec<axum::body::Bytes> = crate::export::stream_requests(
            s.clone(),
            crate::export::ExportFilter::default(),
            crate::export::Format::Jsonl,
            Default::default(),
        )
        .try_collect()
        .await
        .unwrap();
        let out: String = parts.iter().map(|b| String::from_utf8_lossy(b)).collect();
        assert!(
            out.contains("TP-LINK TR-069"),
            "the scan itself is exported"
        );
        for needle in ["device.cpe", "\"tr069\"", "evidence"] {
            assert!(!out.contains(needle), "{needle} in the export");
        }
    }
}
