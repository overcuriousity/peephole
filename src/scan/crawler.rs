//! Known crawlers and verified research scanners are not counter-scanned. A
//! search engine, link preview or feed fetcher that follows a link to the
//! trap looks like a probe, and so does a research scanner (Censys, LeakIX,
//! Shodan) that documents its addresses; a counter-scan would hit the
//! service's operator, not an attacker. See docs/scanners.md.
//!
//! A crawler is recognised by forward-confirmed reverse DNS: the IP's PTR
//! name lies under a known crawler domain *and* that name resolves back to
//! the IP. A PTR record alone proves nothing (whoever holds the reverse
//! zone can claim `crawl-1.googlebot.com`), the forward lookup in the
//! crawler's own zone does.
//!
//! Every lookup is bounded by a timeout and cached. Failure modes:
//! - the PTR lookup fails or times out: not a crawler (an attacker could
//!   otherwise dodge every scan by breaking its own reverse zone, and real
//!   crawlers' reverse zones answer reliably);
//! - the PTR names a crawler domain but the forward lookup times out:
//!   treated as a crawler (the attacker does not control that zone, so a
//!   timeout there is our resolver's trouble, not a trick), cached only as
//!   long as a failed lookup.
//!
//! The PTR and forward lookups also serve reverse DNS of every source
//! (`intel::rdns`, `confirmed_names`), which keeps any forward-confirmed
//! name, crawler or not.
//!
//! The PTR query goes to the first `nameserver` in `/etc/resolv.conf` (the
//! standard library has no reverse lookup); forward lookups use tokio's
//! resolver (the system's `getaddrinfo`).
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::debug;

/// Domains whose forward-confirmed hosts are crawlers, link-preview or feed
/// fetchers (per the operators' published verification instructions).
/// `google.com` covers Google's link-preview and feed fetchers
/// (`*.google.com`); it does not cover `googleusercontent.com`, where
/// anyone's cloud VMs live.
pub const DOMAINS: &[&str] = &[
    "googlebot.com",
    "google.com",
    "search.msn.com",
    "crawl.yahoo.net",
    "applebot.apple.com",
    "yandex.ru",
    "yandex.net",
    "yandex.com",
    "crawl.baidu.com",
    "crawl.baidu.jp",
    "petalsearch.com",
    "crawl.amazonbot.amazon",
    // Verified research scanners (docs/scanners.md): Censys, LeakIX, Shodan.
    // Their operators publish these reverse zones; anything merely claiming
    // the UA (zgrab and friends) stays scannable.
    "censys-scanner.com",
    "scan.leakix.org",
    "shodan.io",
];

/// Per lookup (PTR, then forward).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Cache lifetime of a definite answer.
const CACHE_OK: Duration = Duration::from_secs(6 * 3600);
/// Cache lifetime after a failed lookup.
const CACHE_FAILED: Duration = Duration::from_secs(600);
/// Entries kept before expired ones are swept.
const CACHE_MAX: usize = 10_000;

/// Forward lookup of a host name (tokio's resolver; replaced in tests).
pub(crate) type Forward = std::sync::Arc<
    dyn Fn(String) -> futures::future::BoxFuture<'static, std::io::Result<Vec<IpAddr>>>
        + Send
        + Sync,
>;

pub(crate) fn system_forward() -> Forward {
    std::sync::Arc::new(|name: String| {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    })
}

/// The first `nameserver` of `/etc/resolv.conf`, where PTR queries go.
pub(crate) fn system_resolver() -> Option<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|t| nameserver(&t))
}

pub struct Crawlers {
    domains: Vec<String>,
    /// `None`: no resolver configured; the check is off.
    resolver: Option<SocketAddr>,
    forward: Forward,
    cache: Mutex<HashMap<IpAddr, (Instant, Option<String>)>>,
}

impl Crawlers {
    /// The built-in domains plus `extra`, asking the system resolver.
    pub fn new(extra: &[String]) -> Self {
        Self::with_resolver(extra, system_resolver())
    }

    pub fn with_resolver(extra: &[String], resolver: Option<SocketAddr>) -> Self {
        let mut domains: Vec<String> = DOMAINS.iter().map(|d| d.to_string()).collect();
        domains.extend(
            extra
                .iter()
                .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty()),
        );
        Self {
            domains,
            resolver,
            forward: system_forward(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The crawler host name `ip` was confirmed as, if it is one.
    pub async fn confirmed(&self, ip: IpAddr) -> Option<String> {
        let resolver = self.resolver?;
        // One cache entry per address, whatever its spelling.
        let ip = crate::net::canonical(ip);
        if let Some((until, v)) = self.cache.lock().unwrap().get(&ip)
            && *until > Instant::now()
        {
            return v.clone();
        }
        let (verdict, ttl) = match tokio::time::timeout(LOOKUP_TIMEOUT, ptr(resolver, ip)).await {
            Ok(Ok(names)) => self.confirm(ip, &names).await,
            Ok(Err(e)) => {
                debug!(%ip, error = %e, "reverse lookup failed");
                (None, CACHE_FAILED)
            }
            Err(_) => {
                debug!(%ip, "reverse lookup timed out");
                (None, CACHE_FAILED)
            }
        };
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_MAX {
            let now = Instant::now();
            cache.retain(|_, (until, _)| *until > now);
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(ip, (Instant::now() + ttl, verdict.clone()));
        verdict
    }

    /// The first PTR name under a crawler domain that resolves back to `ip`,
    /// and how long to cache that verdict.
    async fn confirm(&self, ip: IpAddr, names: &[String]) -> (Option<String>, Duration) {
        let ip = crate::net::canonical(ip);
        for name in names.iter().filter(|n| self.is_crawler_domain(n)) {
            match tokio::time::timeout(LOOKUP_TIMEOUT, (self.forward)(name.clone())).await {
                Ok(Ok(addrs)) => {
                    if addrs.into_iter().any(|a| crate::net::canonical(a) == ip) {
                        return (Some(name.clone()), CACHE_OK);
                    }
                }
                Ok(Err(_)) => {}
                // Fail safe: the crawler's own zone did not answer in time.
                // Only briefly: a resolver hiccup is no lasting exemption.
                Err(_) => return (Some(name.clone()), CACHE_FAILED),
            }
        }
        (None, CACHE_OK)
    }

    fn is_crawler_domain(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|d| {
            name.strip_suffix(d.as_str())
                .is_some_and(|p| p.ends_with('.'))
        })
    }
}

/// Most PTR names of one address checked forward.
pub(crate) const MAX_NAMES: usize = 4;

/// Special-use and local zones (RFC 6761, 6762, 7686, 8375, ICANN's
/// `internal`): a forward lookup there asks this host's own network, not
/// the source's.
const SPECIAL_USE: [&str; 8] = [
    "local",
    "localhost",
    "internal",
    "lan",
    "home.arpa",
    "invalid",
    "test",
    "onion",
];

/// `name` (lower-case, no trailing dot) lies in a [`SPECIAL_USE`] zone.
fn special_use(name: &str) -> bool {
    SPECIAL_USE
        .iter()
        .any(|z| name == *z || name.strip_suffix(z).is_some_and(|p| p.ends_with('.')))
}

/// The PTR names of `ip` that resolve back to it, as valid host names, in
/// the order the reverse zone gave them. Err when the PTR lookup fails or
/// times out; a name whose forward lookup fails or times out is left out
/// (unlike the crawler check, nothing is exempted here, so there is no
/// fail-safe to keep).
pub(crate) async fn confirmed_names(
    resolver: SocketAddr,
    forward: &Forward,
    ip: IpAddr,
) -> anyhow::Result<Vec<String>> {
    let ip = crate::net::canonical(ip);
    let names = tokio::time::timeout(LOOKUP_TIMEOUT, ptr(resolver, ip))
        .await
        .map_err(|_| anyhow::anyhow!("reverse lookup timed out"))??;
    let mut valid: Vec<String> = vec![];
    for n in names
        .iter()
        .filter_map(|n| crate::intel::dns::valid_name(n))
        .filter(|n| !special_use(n))
    {
        if !valid.contains(&n) {
            valid.push(n);
        }
    }
    let mut out = vec![];
    for name in valid.into_iter().take(MAX_NAMES) {
        // Absolute: a search domain must not complete a name the source's
        // reverse zone chose.
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(LOOKUP_TIMEOUT, forward(format!("{name}."))).await
            && addrs.into_iter().any(|a| crate::net::canonical(a) == ip)
        {
            out.push(name);
        }
    }
    Ok(out)
}

/// The first `nameserver` of a resolv.conf.
fn nameserver(conf: &str) -> Option<SocketAddr> {
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| {
            // Strip an IPv6 zone (`fe80::1%eth0`): not parseable as IpAddr.
            let addr = rest.trim().split('%').next()?;
            addr.parse::<IpAddr>().ok()
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
}

/// `in-addr.arpa` / `ip6.arpa` name of an address.
fn arpa(ip: IpAddr) -> String {
    match crate::net::canonical(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

const TYPE_PTR: u16 = 12;

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // recursion desired
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_PTR.to_be_bytes());
    q.extend_from_slice(&[0, 1]); // class IN
    q
}

/// PTR names of `ip`; empty when it has none (NXDOMAIN included).
async fn ptr(resolver: SocketAddr, ip: IpAddr) -> anyhow::Result<Vec<String>> {
    let bind: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(resolver).await?;
    let r = uuid::Uuid::new_v4();
    let id = u16::from_be_bytes([r.as_bytes()[0], r.as_bytes()[1]]);
    sock.send(&query(id, &arpa(ip))).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        // A stray or spoofed datagram with another id is not the answer.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            return parse_ptr_reply(&buf[..n]);
        }
    }
}

/// PTR names from a DNS reply.
fn parse_ptr_reply(m: &[u8]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(m.len() >= 12, "short reply");
    let flags = u16::from_be_bytes([m[2], m[3]]);
    anyhow::ensure!(flags & 0x8000 != 0, "not a reply");
    anyhow::ensure!(flags & 0x0200 == 0, "truncated reply");
    match flags & 0x000f {
        0 => {}
        3 => return Ok(vec![]), // NXDOMAIN
        rcode => anyhow::bail!("rcode {rcode}"),
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut at = 12;
    for _ in 0..qd {
        at = skip_name(m, at)? + 4;
    }
    let mut names = vec![];
    for _ in 0..an {
        at = skip_name(m, at)?;
        anyhow::ensure!(at + 10 <= m.len(), "short answer");
        let rtype = u16::from_be_bytes([m[at], m[at + 1]]);
        let rdlen = u16::from_be_bytes([m[at + 8], m[at + 9]]) as usize;
        let rdata = at + 10;
        anyhow::ensure!(rdata + rdlen <= m.len(), "short rdata");
        if rtype == TYPE_PTR {
            names.push(read_name(m, rdata)?);
        }
        at = rdata + rdlen;
    }
    Ok(names)
}

/// Offset just past the (possibly compressed) name at `at`.
fn skip_name(m: &[u8], mut at: usize) -> anyhow::Result<usize> {
    loop {
        let len = *m.get(at).ok_or_else(|| anyhow::anyhow!("short name"))? as usize;
        match len {
            0 => return Ok(at + 1),
            l if l & 0xc0 == 0xc0 => return Ok(at + 2),
            l => at += l + 1,
        }
    }
}

/// The name at `at`, following compression pointers (bounded).
fn read_name(m: &[u8], mut at: usize) -> anyhow::Result<String> {
    let mut labels: Vec<String> = vec![];
    for _ in 0..64 {
        let len = *m.get(at).ok_or_else(|| anyhow::anyhow!("short name"))? as usize;
        if len == 0 {
            return Ok(labels.join("."));
        }
        if len & 0xc0 == 0xc0 {
            let lo = *m
                .get(at + 1)
                .ok_or_else(|| anyhow::anyhow!("short pointer"))? as usize;
            at = ((len & 0x3f) << 8) | lo;
            continue;
        }
        let label = m
            .get(at + 1..at + 1 + len)
            .ok_or_else(|| anyhow::anyhow!("short label"))?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += len + 1;
    }
    anyhow::bail!("name too long or looping")
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn arpa_names() {
        assert_eq!(
            arpa("66.249.66.1".parse().unwrap()),
            "1.66.249.66.in-addr.arpa"
        );
        assert_eq!(
            arpa("2001:db8::567:89ab".parse().unwrap()),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(
            arpa("::ffff:66.249.66.1".parse().unwrap()),
            "1.66.249.66.in-addr.arpa"
        );
    }

    #[test]
    fn resolv_conf_nameserver() {
        let conf = "# comment\nsearch example\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n";
        assert_eq!(nameserver(conf), Some("127.0.0.53:53".parse().unwrap()));
        assert_eq!(
            nameserver("nameserver fe80::1%eth0\n"),
            Some("[fe80::1]:53".parse().unwrap())
        );
        assert_eq!(nameserver("search x\n"), None);
    }

    #[test]
    fn crawler_domains_match_on_label_boundaries() {
        let c = Crawlers::with_resolver(&["Example.ORG.".into()], None);
        assert!(c.is_crawler_domain("crawl-66-249-66-1.googlebot.com."));
        assert!(c.is_crawler_domain("rate-limited-proxy-66-249-90-77.google.com"));
        assert!(c.is_crawler_domain("msnbot-157-55-39-1.search.msn.com"));
        assert!(c.is_crawler_domain("bot.example.org"));
        assert!(!c.is_crawler_domain("googlebot.com"), "the apex is no host");
        assert!(!c.is_crawler_domain("evilgooglebot.com"));
        assert!(!c.is_crawler_domain("1.2.3.4.bc.googleusercontent.com"));
        assert!(!c.is_crawler_domain("googlebot.com.attacker.net"));
    }

    #[test]
    fn ptr_replies_parse() {
        assert_eq!(
            parse_ptr_reply(&reply(7, 0, Some("crawl-66-249-66-1.googlebot.com"))).unwrap(),
            ["crawl-66-249-66-1.googlebot.com"]
        );
        assert!(parse_ptr_reply(&reply(7, 3, None)).unwrap().is_empty());
        assert!(parse_ptr_reply(&reply(7, 2, None)).is_err(), "SERVFAIL");
        let mut truncated = reply(7, 0, None);
        truncated[2] |= 0x02;
        assert!(parse_ptr_reply(&truncated).is_err());
        // Garbage never panics.
        for len in 0..40 {
            let r = reply(7, 0, Some("a.b"));
            let _ = parse_ptr_reply(&r[..len.min(r.len())]);
        }
        // A pointer loop is an error, not a hang.
        let mut looped = reply(7, 0, Some("a"));
        let n = looped.len();
        looped[n - 3] = 0xc0;
        looped[n - 2] = (n - 3) as u8;
        assert!(parse_ptr_reply(&looped).is_err());
    }

    /// Forward lookups: `*.real.googlebot.com` resolves to 198.51.100.7,
    /// `*.real.censys-scanner.com` to 198.51.100.9, `*.slow.googlebot.com`
    /// never answers, anything else does not exist; a trailing dot is
    /// ignored. Except: relative `short.example` and absolute `*.internal.`
    /// resolve to 198.51.100.7 (a search domain, a local zone).
    fn fake_forward() -> Forward {
        std::sync::Arc::new(|name: String| {
            Box::pin(async move {
                // A relative name a search domain would complete.
                if name == "short.example" || name.ends_with(".internal.") {
                    return Ok(vec!["198.51.100.7".parse().unwrap()]);
                }
                let name = name.trim_end_matches('.');
                if name.ends_with(".real.googlebot.com") {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else if name.ends_with(".real.censys-scanner.com") {
                    Ok(vec!["198.51.100.9".parse().unwrap()])
                } else if name.ends_with(".slow.googlebot.com") {
                    std::future::pending().await
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        })
    }

    #[tokio::test]
    async fn confirmed_names_checks_every_name() {
        let run = |name: Option<&str>, ip: &str| {
            let answer = std::sync::Arc::new(Mutex::new(name.map(str::to_string)));
            let ip: IpAddr = ip.parse().unwrap();
            async move {
                let r = fake_resolver(answer).await;
                confirmed_names(r, &fake_forward(), ip).await
            }
        };
        // Any domain counts here, not only crawlers, once it resolves back.
        assert_eq!(
            run(Some("crawl-1.real.googlebot.com"), "198.51.100.7")
                .await
                .unwrap(),
            vec!["crawl-1.real.googlebot.com".to_string()]
        );
        assert!(
            run(Some("crawl-1.real.googlebot.com"), "198.51.100.8")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            run(Some("host.example.net"), "198.51.100.7")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            run(None, "198.51.100.7").await.unwrap().is_empty(),
            "NXDOMAIN"
        );
        assert!(
            run(Some("198.51.100.7"), "198.51.100.7")
                .await
                .unwrap()
                .is_empty(),
            "an address is no name"
        );
        assert!(run(Some("TIMEOUT"), "198.51.100.7").await.is_err());
        assert!(
            run(Some("x.slow.googlebot.com"), "198.51.100.7")
                .await
                .unwrap()
                .is_empty(),
            "a forward timeout is no confirmation here"
        );
        for (name, why) in [
            ("short.example", "looked up as an absolute name"),
            ("printer.internal", "a special-use name"),
            ("under_score.real.googlebot.com", "not a host name"),
        ] {
            assert!(
                run(Some(name), "198.51.100.7").await.unwrap().is_empty(),
                "{why}"
            );
        }
    }

    async fn check(name: Option<&str>, ip: &str) -> Option<String> {
        let answer = std::sync::Arc::new(Mutex::new(name.map(str::to_string)));
        let mut c = Crawlers::with_resolver(&[], Some(fake_resolver(answer).await));
        c.forward = fake_forward();
        c.confirmed(ip.parse().unwrap()).await
    }

    #[tokio::test]
    async fn only_forward_confirmed_crawlers_count() {
        // PTR under a crawler domain, resolving back to the IP: a crawler.
        assert_eq!(
            check(Some("crawl-1.real.googlebot.com"), "198.51.100.7")
                .await
                .as_deref(),
            Some("crawl-1.real.googlebot.com")
        );
        // ... resolving to another IP: a claim, not a crawler.
        assert_eq!(
            check(Some("crawl-1.real.googlebot.com"), "198.51.100.8").await,
            None
        );
        // ... not resolving at all: a claim.
        assert_eq!(
            check(Some("fake.googlebot.com"), "198.51.100.7").await,
            None
        );
        // Not a crawler domain, no PTR, a resolver that never answers: not
        // crawlers (the latter only after the timeout).
        assert_eq!(check(Some("host.example.net"), "198.51.100.7").await, None);
        assert_eq!(check(None, "198.51.100.7").await, None);
        let t = Instant::now();
        assert_eq!(check(Some("TIMEOUT"), "198.51.100.7").await, None);
        assert!(t.elapsed() < LOOKUP_TIMEOUT * 2, "bounded");
        // The crawler's own zone timing out: treated as a crawler.
        assert!(
            check(Some("x.slow.googlebot.com"), "198.51.100.7")
                .await
                .is_some()
        );
        // No resolver: the check is off.
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(Crawlers::with_resolver(&[], None).confirmed(ip).await, None);
    }

    #[tokio::test]
    async fn research_scanners_are_forward_confirmed() {
        // A Censys scanner host, confirmed: exempt like any crawler.
        assert_eq!(
            check(
                Some("66-132-186-177.real.censys-scanner.com"),
                "198.51.100.9"
            )
            .await
            .as_deref(),
            Some("66-132-186-177.real.censys-scanner.com")
        );
        // ... claiming the name from another IP: not a scanner.
        assert_eq!(
            check(
                Some("66-132-186-177.real.censys-scanner.com"),
                "198.51.100.7"
            )
            .await,
            None
        );
        // A lookalike zone: not a scanner domain at all.
        assert_eq!(
            check(Some("x.real.censys-scanner.com.evil.net"), "198.51.100.9").await,
            None
        );
    }

    #[test]
    fn research_scanner_domains_match_on_label_boundaries() {
        let c = Crawlers::with_resolver(&[], None);
        assert!(c.is_crawler_domain("177.186.132.66.censys-scanner.com."));
        assert!(c.is_crawler_domain("f20a02ce01.scan.leakix.org."));
        assert!(c.is_crawler_domain("census12.shodan.io."));
        assert!(
            !c.is_crawler_domain("censys-scanner.com."),
            "the apex is no host"
        );
        assert!(!c.is_crawler_domain("evilcensys-scanner.com."));
        assert!(!c.is_crawler_domain("censys-scanner.com.attacker.net."));
        assert!(
            !c.is_crawler_domain("evil.leakix.org."),
            "only hosts under scan.leakix.org scan for LeakIX"
        );
    }

    #[tokio::test]
    async fn answers_are_cached() {
        let answer = std::sync::Arc::new(Mutex::new(Some("a.real.googlebot.com".to_string())));
        let mut c = Crawlers::with_resolver(&[], Some(fake_resolver(answer.clone()).await));
        c.forward = fake_forward();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(c.confirmed(ip).await.is_some());
        // The resolver changes its mind; the cached verdict stands.
        *answer.lock().unwrap() = None;
        assert!(c.confirmed(ip).await.is_some());
        // A mapped spelling shares the entry.
        assert!(
            c.confirmed("::ffff:198.51.100.7".parse().unwrap())
                .await
                .is_some()
        );
        assert_eq!(c.cache.lock().unwrap().len(), 1);
    }

    /// A forward lookup that timed out counts as a crawler, but is cached
    /// only for the failure lifetime.
    #[tokio::test]
    async fn forward_timeouts_are_cached_briefly() {
        let answer = std::sync::Arc::new(Mutex::new(Some("x.slow.googlebot.com".to_string())));
        let mut c = Crawlers::with_resolver(&[], Some(fake_resolver(answer).await));
        c.forward = fake_forward();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(c.confirmed(ip).await.is_some());
        let until = c.cache.lock().unwrap()[&ip].0;
        assert!(until <= Instant::now() + CACHE_FAILED);
    }
}

/// A fake PTR resolver for tests here and in `intel::rdns`.
#[cfg(test)]
pub(crate) mod testing {
    use super::{TYPE_PTR, query};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    /// A reply as a resolver sends it: the question, then a PTR answer
    /// whose name is a compression pointer to the question.
    pub(crate) fn reply(id: u16, rcode: u8, ptr_name: Option<&str>) -> Vec<u8> {
        let mut m = query(id, "1.66.249.66.in-addr.arpa");
        m[2] = 0x81;
        m[3] = 0x80 | rcode;
        if let Some(name) = ptr_name {
            m[7] = 1;
            m.extend_from_slice(&[0xc0, 12]); // name: the question's
            m.extend_from_slice(&TYPE_PTR.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
            let mut rdata = vec![];
            for label in name.split('.') {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
            rdata.push(0);
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(&rdata);
        }
        m
    }

    /// A fake resolver on localhost answering every PTR query with the
    /// name in `answer`; returns its address.
    pub(crate) async fn fake_resolver(answer: Arc<Mutex<Option<String>>>) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (_, from) = sock.recv_from(&mut buf).await.unwrap();
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let name = answer.lock().unwrap().clone();
                match name {
                    Some(n) if n == "TIMEOUT" => {}
                    Some(n) => {
                        let _ = sock.send_to(&reply(id, 0, Some(&n)), from).await;
                    }
                    None => {
                        let _ = sock.send_to(&reply(id, 3, None), from).await;
                    }
                }
            }
        });
        addr
    }
}
