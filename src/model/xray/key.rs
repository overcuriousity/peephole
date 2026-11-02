//! Private keys in attacker text: where they sit, so no pane shows them, and
//! the public fingerprint, the only form of a key ever kept. The bytes are
//! read for that alone: nothing is decrypted, stored or used.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use data_encoding::{BASE64_NOPAD, HEXLOWER};
use regex::bytes::Regex;
use sha2::{Digest, Sha256};

use super::{LayerKind, Xray, decode};

/// Fewest bytes a PEM body decodes to for it to count as a key: less is a
/// placeholder, and its value would be the same for everybody.
const MIN_PEM: usize = 32;

/// The part of a line of a key with no `END` marker that counts as key text
/// whatever comes after it. A shorter one needs a closing quote or the like:
/// `wget` on the next line is a command.
const KEY_TAIL_MIN: usize = 16;

/// Most lines of keys with no `END` marker searched for further on in a text.
/// Past this, all of the text after the first such key is masked.
const REPEATS_MAX: usize = 256;

const OPENSSH: &[u8] = b"OPENSSH PRIVATE KEY";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// `word` with each character plain or percent-encoded.
fn encoded(word: &str) -> String {
    let mut out = String::new();
    for b in word.bytes() {
        let hex: String = format!("{b:02X}")
            .chars()
            .map(|c| match c {
                'A'..='F' => format!("[{c}{}]", c.to_ascii_lowercase()),
                _ => c.to_string(),
            })
            .collect();
        out += &format!("(?:{}|%{hex})", char::from(b));
    }
    out
}

/// A `BEGIN` or `END` marker: `-----BEGIN RSA PRIVATE KEY-----`, dashes
/// optional, each character maybe percent-encoded and a blank maybe `+`.
fn marker(word: &str, tail: &str) -> Regex {
    let dash = "(?:-|%2[Dd])";
    let blank = r"(?:[ \t+]|%20|%09)+";
    let name = "(?:[A-Z0-9]|%[3-5][0-9A-Fa-f])+";
    Regex::new(&format!(
        "(?-u){dash}{{0,5}}{word}{blank}(?:{name}{blank}){{0,3}}{private}{blank}{key}{tail}{dash}{{0,5}}",
        word = encoded(word),
        private = encoded("PRIVATE"),
        key = encoded("KEY"),
    ))
    .expect("static regex")
}

static BEGIN: LazyLock<Regex> = LazyLock::new(|| marker("BEGIN", ""));
static END: LazyLock<Regex> = LazyLock::new(|| {
    marker(
        "END",
        "(?:(?:[ \\t+]|%20)+(?:[A-Z0-9]|%[3-5][0-9A-Fa-f])+)?",
    )
});

/// One key's place in a text. `head` ends the `BEGIN` marker, `body_end`
/// starts the `END` marker or ends the key text, and `ended` says there is
/// an `END` marker.
struct Block {
    start: usize,
    head: usize,
    body_end: usize,
    end: usize,
    ended: bool,
}

fn blocks(text: &[u8]) -> Vec<Block> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(begin) = BEGIN.find_at(text, from) {
        let (start, head) = (begin.start(), begin.end());
        let Some(end) = END.find_at(text, head) else {
            let body_end = unended(text, head);
            found.push(Block {
                start,
                head,
                body_end,
                end: body_end,
                ended: false,
            });
            from = body_end;
            continue;
        };
        found.push(Block {
            start,
            head,
            body_end: end.start(),
            end: end.end(),
            ended: true,
        });
        from = end.end();
    }
    found
}

/// Width of a byte of base64 at the start of `rest`, perhaps percent-encoded.
fn key_byte(rest: &[u8]) -> Option<usize> {
    match rest {
        [b'%', hex @ ..] => [&b"2B"[..], b"2F", b"3D"]
            .iter()
            .any(|h| hex.len() >= 2 && hex[..2].eq_ignore_ascii_case(h))
            .then_some(3),
        [b, ..] if b.is_ascii_alphanumeric() || b"+/=".contains(b) => Some(1),
        _ => None,
    }
}

/// Width of a line end at the start of `rest`: plain, written `\n` in a
/// script or a string, or percent-encoded.
fn line_end(rest: &[u8]) -> Option<usize> {
    match rest {
        [b'\n' | b'\r', ..] => Some(1),
        [b'\\', b'n' | b'r', ..] => Some(2),
        [b'%', b'0', b'A' | b'a' | b'D' | b'd', ..] => Some(3),
        _ => None,
    }
}

fn blank(rest: &[u8]) -> Option<usize> {
    match rest {
        [b' ' | b'\t', ..] => Some(1),
        [b'%', b'2', b'0', ..] | [b'%', b'0', b'9', ..] => Some(3),
        _ => None,
    }
}

/// Where the text of a key with no `END` marker stops: at the first line
/// that cannot be base64 key text, past the base64 such a line starts with
/// when that is the key's last line (`AAAA' > /tmp/k`). The line of the
/// `BEGIN` marker is read to its last word that can be key text: a key can
/// be written in one line.
fn unended(text: &[u8], head: usize) -> usize {
    let mut at = head;
    let mut marker_line = true;
    loop {
        loop {
            if let Some(width) = line_end(&text[at..]) {
                marker_line = false;
                at += width;
            } else if let Some(width) = blank(&text[at..]) {
                at += width;
            } else {
                break;
            }
        }
        if at >= text.len() {
            return text.len();
        }
        let rest = &text[at..];
        if !marker_line && (rest.starts_with(b"Proc-Type:") || rest.starts_with(b"DEK-Info:")) {
            while at < text.len() && line_end(&text[at..]).is_none() {
                at += 1;
            }
            continue;
        }
        let mut end = at;
        while let Some(width) = key_byte(&text[end..]) {
            end += width;
        }
        let mut after = end;
        while let Some(width) = blank(&text[after..]) {
            after += width;
        }
        let line_done = after >= text.len() || line_end(&text[after..]).is_some();
        if line_done || (marker_line && after > end) {
            at = after;
            continue;
        }
        let closed = b"'\"`\\)<>;,&|".contains(&text[end]);
        return if marker_line || end - at >= KEY_TAIL_MIN || (closed && end > at) {
            end
        } else {
            at
        };
    }
}

fn merged(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// The ranges of `layer` to mask, sorted and apart: every private key in it,
/// from a `BEGIN … PRIVATE KEY` marker through its `END` marker or the end of
/// the text, unencoded or percent-encoded, and the text any key below it was
/// decoded from.
pub fn mask_ranges(xray: &Xray, layer: usize) -> Vec<(usize, usize)> {
    all_masks(xray).into_iter().nth(layer).unwrap_or_default()
}

/// Whether a layer holds a private key, or text one was decoded from.
pub fn holds_key(xray: &Xray) -> bool {
    all_masks(xray).iter().any(|layer| !layer.is_empty())
}

/// `text` with every private key in it, unencoded or percent-encoded,
/// replaced: for a value shown without its layers.
pub fn masked(text: &str) -> String {
    let bytes = text.as_bytes();
    let (mut out, mut at) = (vec![], 0);
    for (start, end) in ranges(bytes) {
        if start >= at {
            out.extend_from_slice(&bytes[at..start]);
            out.extend_from_slice(b"[private key]");
            at = end;
        }
    }
    out.extend_from_slice(&bytes[at.min(bytes.len())..]);
    String::from_utf8_lossy(&out).into_owned()
}

/// Where the first key marker of `text` starts.
pub(super) fn marker_start(text: &[u8]) -> Option<usize> {
    BEGIN.find(text).map(|m| m.start())
}

/// Where the keys of `text` sit, sorted, and nothing about the layers around
/// it.
pub(super) fn ranges(text: &[u8]) -> Vec<(usize, usize)> {
    let blocks = blocks(text);
    let mut found: Vec<(usize, usize)> = blocks.iter().map(|b| (b.start, b.end)).collect();
    found.extend(repeats(text, &blocks));
    found.sort_unstable();
    found
}

/// Where lines of the keys with no `END` marker come again after the first
/// of them: such a key's mask stops early, and its text is still key text
/// when a later word repeats it. One search, however many keys there are.
fn repeats(text: &[u8], blocks: &[Block]) -> Vec<(usize, usize)> {
    let cut: Vec<&Block> = blocks.iter().filter(|b| !b.ended).collect();
    let Some(from) = cut.first().map(|b| b.end) else {
        return vec![];
    };
    let body = cut.iter().flat_map(|b| lines(&text[b.head..b.body_end]));
    let words = body.flat_map(|l| l.split(u8::is_ascii_whitespace));
    let words: BTreeSet<&[u8]> = words.filter(|w| w.len() >= KEY_TAIL_MIN).collect();
    if words.is_empty() {
        return vec![];
    }
    let rest = vec![(from, text.len())];
    if words.len() > REPEATS_MAX {
        return rest;
    }
    let patterns = words
        .iter()
        .map(|w| regex::escape(&String::from_utf8_lossy(w)))
        .collect::<Vec<_>>()
        .join("|");
    match Regex::new(&format!("(?-u){patterns}")) {
        Ok(search) => search
            .find_iter(&text[from..])
            .map(|m| (from + m.start(), from + m.end()))
            .collect(),
        Err(_) => rest,
    }
}

/// `range` of `text` and every exact repeat of it: decoding opens the same
/// text once, so a repeated run has no layer of its own.
fn with_repeats(text: &[u8], (start, end): (usize, usize)) -> Vec<(usize, usize)> {
    let Some(run) = text.get(start..end).filter(|r| !r.is_empty()) else {
        return vec![(start, end)];
    };
    let mut found: Vec<(usize, usize)> = text
        .windows(run.len())
        .enumerate()
        .filter(|(_, window)| *window == run)
        .map(|(at, _)| (at, at + run.len()))
        .collect();
    found.push((start, end));
    found
}

/// [`mask_ranges`] of every layer.
pub(super) fn all_masks(xray: &Xray) -> Vec<Vec<(usize, usize)>> {
    let mut masks: Vec<Vec<(usize, usize)>> = xray.layers.iter().map(|l| ranges(&l.text)).collect();
    let holders: Vec<usize> = (0..masks.len()).filter(|&i| !masks[i].is_empty()).collect();
    for holder in holders {
        let mut at = holder;
        while let Some(parent) = xray.layers[at].parent {
            let layer = &xray.layers[at];
            // The query and the path are no part of the body, their parent.
            // Other text with no place in its parent may be anywhere in it.
            if matches!(layer.kind, LayerKind::Query | LayerKind::Path) {
                break;
            }
            let text = &xray.layers[parent].text;
            match layer.from {
                Some(s) => masks[parent].extend(with_repeats(text, (s.start, s.end))),
                None => masks[parent].push((0, text.len())),
            }
            at = parent;
        }
    }
    masks.into_iter().map(merged).collect()
}

/// The fingerprints of the keys in `text`, with their ranges. A marker alone
/// gives none: only a key with a readable body is one operator's.
pub(super) fn fingerprints(text: &[u8]) -> Vec<(usize, usize, String)> {
    let mut found = Vec::new();
    for b in blocks(text) {
        let label = text[b.start..b.head]
            .strip_prefix(b"-----BEGIN ")
            .and_then(|l| l.strip_suffix(b"-----"));
        let Some(label) = label else { continue };
        let body = &text[b.head..b.body_end];
        let value = if label == OPENSSH {
            openssh(body)
        } else if b.ended {
            pem(label, body)
        } else {
            None
        };
        if let Some(value) = value {
            found.push((b.start, b.end, value));
        }
    }
    found
}

/// The lines of a key's body, trimmed. A body inside a script or a string
/// may write its line ends as `\n`.
fn lines(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < body.len() {
        let width = match (body[i], body.get(i + 1)) {
            (b'\n' | b'\r', _) => 1,
            (b'\\', Some(b'n' | b'r')) => 2,
            _ => {
                i += 1;
                continue;
            }
        };
        out.push(body[start..i].trim_ascii());
        i += width;
        start = i;
    }
    out.push(body[start..].trim_ascii());
    out.retain(|l| !l.is_empty());
    out
}

/// `ssh-keygen -lf`: SHA-256 of the public section, which is in the clear
/// even when the key is encrypted, and comes first, so a cut key has it too.
fn openssh(body: &[u8]) -> Option<String> {
    let mut clean = Vec::new();
    'body: for line in lines(body) {
        for &b in line {
            if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
                break 'body;
            }
            clean.push(b);
        }
    }
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    let bytes = decode::base64_lenient(&clean)?;
    let blob = public_blob(&bytes)?;
    Some(format!(
        "SHA256:{}",
        BASE64_NOPAD.encode(&Sha256::digest(blob))
    ))
}

/// A length-prefixed string, and what follows it.
fn string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    (len <= rest.len()).then(|| rest.split_at(len))
}

fn public_blob(bytes: &[u8]) -> Option<&[u8]> {
    let rest = bytes.strip_prefix(OPENSSH_MAGIC)?;
    let (_cipher, rest) = string(rest)?;
    let (_kdf, rest) = string(rest)?;
    let (_options, rest) = string(rest)?;
    let (count, rest) = rest.split_first_chunk::<4>()?;
    if *count == [0; 4] {
        return None;
    }
    let (blob, _) = string(rest)?;
    let (kind, _) = string(blob)?;
    [&b"ssh-"[..], b"ecdsa-", b"sk-"]
        .iter()
        .any(|p| kind.starts_with(p))
        .then_some(blob)
}

/// SHA-256 of the label, header lines and base64, so the line width and line
/// ends make no difference.
fn pem(label: &[u8], body: &[u8]) -> Option<String> {
    let mut normal = label.to_vec();
    let mut base64: Vec<u8> = Vec::new();
    for line in lines(body) {
        if line.contains(&b':') {
            normal.push(b'\n');
            normal.extend_from_slice(line);
        } else {
            base64.extend(line.iter().filter(|b| !b.is_ascii_whitespace()));
        }
    }
    if decode::base64_lenient(&base64)?.len() < MIN_PEM {
        return None;
    }
    normal.push(b'\n');
    normal.extend_from_slice(&base64);
    Some(format!(
        "sha256-pem:{}",
        HEXLOWER.encode(&Sha256::digest(&normal))
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{Policy, Source, parse};
    use super::*;
    use data_encoding::BASE64;

    /// Generated with `ssh-keygen -t ed25519 -N ''` for this test and used
    /// nowhere else. `ssh-keygen -lf` prints [`KEY_SHA256`] for it.
    const KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDw7cwpJG1bH9MJooBRnKlcC07AF0gxH3+QpTsT7TOBqgAAAJD7XCYu+1wm
LgAAAAtzc2gtZWQyNTUxOQAAACDw7cwpJG1bH9MJooBRnKlcC07AF0gxH3+QpTsT7TOBqg
AAAEAwX6JZz1pflaka0HyBpeulAKL4W6dYo2lPvuR/aUzpq/DtzCkkbVsf0wmigFGcqVwL
TsAXSDEff5ClOxPtM4GqAAAADXBlZXBob2xlLXRlc3Q=
-----END OPENSSH PRIVATE KEY-----
";
    const KEY_SHA256: &str = "SHA256:YlhoqO0PTGuB+gVzKzRA4bFUfYo6LJqJj0kM4dtuQEE";

    fn pem(label: &str, body: &str) -> String {
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    /// Not a key: base64 of bytes that only have the shape of one.
    fn fake_body() -> String {
        BASE64.encode(&[0x5au8; 96])
    }

    fn body(text: &[u8]) -> Xray {
        parse(
            Source::Request {
                method: "POST",
                path: "/",
                query: None,
                body: Some(text),
                sender: None,
            },
            Policy::embedded(),
        )
    }

    fn one_value(text: &[u8]) -> String {
        let found = fingerprints(text);
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].2.clone()
    }

    #[test]
    fn openssh_key_fingerprint_matches_ssh_keygen() {
        assert_eq!(one_value(KEY.as_bytes()), KEY_SHA256);
    }

    #[test]
    fn fingerprint_survives_wrapping_and_escaped_line_ends() {
        let flat = KEY.replace('\n', "\\n");
        assert_eq!(one_value(flat.as_bytes()), KEY_SHA256);
        let crlf = KEY.replace('\n', "\r\n");
        assert_eq!(one_value(crlf.as_bytes()), KEY_SHA256);
    }

    #[test]
    fn a_cut_openssh_key_still_shows_its_public_section() {
        let cut = &KEY[..KEY.find("LgAAAA").unwrap()];
        assert_eq!(
            one_value(format!("echo '{cut}' > /tmp/k").as_bytes()),
            KEY_SHA256
        );
    }

    #[test]
    fn other_pem_hashes_the_normalised_text() {
        let b = fake_body();
        let a = one_value(pem("RSA PRIVATE KEY", &b).as_bytes());
        assert!(a.starts_with("sha256-pem:"), "{a}");
        assert_eq!(a.len(), "sha256-pem:".len() + 64);
        let (x, y) = b.split_at(40);
        let wrapped = pem("RSA PRIVATE KEY", &format!("{x}\r\n{y}"));
        assert_eq!(one_value(wrapped.as_bytes()), a);
        let other = BASE64.encode(&[0x5bu8; 96]);
        assert_ne!(one_value(pem("RSA PRIVATE KEY", &other).as_bytes()), a);
    }

    /// Scanners and docs carry these. A value for them would tie everyone
    /// who sends one together.
    #[test]
    fn a_marker_with_no_key_gives_no_piece() {
        for text in [
            "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            "grep '-----BEGIN OPENSSH PRIVATE KEY-----' ~/.ssh/*".to_string(),
            pem("RSA PRIVATE KEY", ""),
            pem("RSA PRIVATE KEY", "..."),
            pem("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA"),
            pem("OPENSSH PRIVATE KEY", ""),
            pem("OPENSSH PRIVATE KEY", &fake_body()),
            pem("EC PRIVATE KEY", "not base64 at all !!!"),
            format!("-----BEGIN RSA PRIVATE KEY-----\n{}", fake_body()),
        ] {
            assert_eq!(fingerprints(text.as_bytes()), [], "{text}");
        }
    }

    #[test]
    fn key_masked_by_marker_alone() {
        for text in [
            "head -----BEGIN OPENSSH PRIVATE KEY-----\nabc",
            "head -----BEGIN PRIVATE KEY",
        ] {
            let x = body(text.as_bytes());
            assert_eq!(mask_ranges(&x, 0), [(5, text.len())], "{text}");
        }
    }

    #[test]
    fn a_key_with_no_end_stops_at_the_first_line_that_is_no_key_text() {
        let begin = "-----BEGIN RSA PRIVATE KEY-----";
        let line = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=";
        for (tail, kept) in [
            ("wget http://example.org/x", "wget http://example.org/x"),
            ("' > /tmp/k; id", "' > /tmp/k; id"),
            ("AAAA' > /tmp/k", "' > /tmp/k"),
            ("  \\", "\\"),
        ] {
            let text = format!("{begin}\n{line}\n{tail}\n");
            let x = Xray::new(text.as_bytes());
            let end = text.rfind(kept).unwrap();
            assert_eq!(mask_ranges(&x, 0), [(0, end)], "{tail}");
        }
        // Written with `\n`, on the line of the marker, with PEM headers.
        for (text, kept) in [
            (format!("'{begin}\\n{line}\\nAA' > k; id"), "' > k; id"),
            (format!("{begin} {line} AAAA | tee k"), "| tee k"),
            (format!("{begin}{line}?x=1"), "?x=1"),
            (
                format!("{begin}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES,00\n\n{line}\nid x\n"),
                "id x",
            ),
            (format!("{begin}%0A{line}%0AAA&a=b"), "&a=b"),
        ] {
            let x = Xray::new(text.as_bytes());
            let start = text.find("-----").unwrap();
            let end = text.rfind(kept).unwrap();
            assert_eq!(mask_ranges(&x, 0), [(start, end)], "{text}");
        }
    }

    #[test]
    fn a_line_of_a_key_with_no_end_is_masked_where_it_comes_again() {
        let line = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
        let key = format!("-----BEGIN RSA PRIVATE KEY-----\n{line}\n");
        let text = format!("{key}sh /tmp/k {line}; id");
        let at = text.rfind(line).unwrap();
        let x = Xray::new(text.as_bytes());
        assert_eq!(mask_ranges(&x, 0), [(0, key.len()), (at, at + line.len())]);
        assert!(!masked(&text).contains(line), "{}", masked(&text));
    }

    #[test]
    fn too_many_lines_mask_the_rest_of_the_text() {
        let body: String = (0..300)
            .map(|n| format!("AAAAAAAAAAAAAAAAAAAA{n}\n"))
            .collect();
        let key = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}");
        let text = format!("{key}id x");
        let x = Xray::new(text.as_bytes());
        assert_eq!(mask_ranges(&x, 0), [(0, text.len())]);
    }

    #[test]
    fn two_keys_with_no_end_are_both_masked() {
        let a = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n";
        let text = format!("{a}id x\n-----BEGIN EC PRIVATE KEY-----\nBBBB\n");
        let x = Xray::new(text.as_bytes());
        let second = text.find("-----BEGIN EC").unwrap();
        assert_eq!(mask_ranges(&x, 0), [(0, a.len()), (second, text.len())]);
    }

    #[test]
    fn unparsable_body_is_masked_through_the_end_marker() {
        let block = pem("RSA PRIVATE KEY", "!!! not a key !!!");
        let text = format!("head {}tail", block);
        let x = body(text.as_bytes());
        assert_eq!(mask_ranges(&x, 0), [(5, 5 + block.trim_end().len())]);
        assert_eq!(x.pieces, []);
    }

    #[test]
    fn key_is_masked_in_raw_layer_when_unencoded() {
        let text = format!("x {KEY}y -----BEGIN EC PRIVATE KEY-----\nzz\n");
        let x = body(text.as_bytes());
        let first = 2 + KEY.trim_end().len();
        assert_eq!(
            mask_ranges(&x, 0),
            [
                (2, first),
                (text.find("-----BEGIN EC").unwrap(), text.len())
            ]
        );
    }

    #[test]
    fn key_is_masked_when_percent_encoded() {
        for marker in [
            "-----BEGIN%20OPENSSH%20PRIVATE%20KEY-----",
            "-----BEGIN+OPENSSH+PRIVATE+KEY-----",
            "%2D%2D%2D%2D%2DBEGIN%20RSA%20PRIVATE%20KEY%2d%2d%2d%2d%2d",
            "%2d%2d%2d%2d%2d%42%45%47%49%4e%20%50%52%49%56%41%54%45%20%4B%45%59",
        ] {
            let text = format!("q {marker}%0Ab3BlbnNz");
            let x = Xray::new(text.as_bytes());
            assert_eq!(mask_ranges(&x, 0), [(2, text.len())], "{marker}");
        }
        let text =
            "a -----BEGIN%20RSA%20PRIVATE%20KEY-----%0AAA%0A-----END%20RSA%20PRIVATE%20KEY----- b";
        let x = Xray::new(text.as_bytes());
        assert_eq!(mask_ranges(&x, 0), [(2, text.len() - 2)]);
    }

    #[test]
    fn decoded_layers_and_what_they_came_from_are_masked() {
        let encoded = BASE64.encode(KEY.as_bytes());
        let text = format!("{encoded} tail");
        let x = body(text.as_bytes());
        let layer = x
            .layers
            .iter()
            .position(|l| l.text == KEY.as_bytes())
            .unwrap();
        assert_ne!(layer, 0);
        assert_eq!(mask_ranges(&x, layer), [(0, KEY.trim_end().len())]);
        assert_eq!(mask_ranges(&x, 0), [(0, encoded.len())]);
    }

    #[test]
    fn a_repeated_encoded_key_is_masked_each_time() {
        let encoded = BASE64.encode(KEY.as_bytes());
        let text = format!("{encoded} and {encoded}");
        let x = body(text.as_bytes());
        let second = encoded.len() + " and ".len();
        assert_eq!(
            mask_ranges(&x, 0),
            [(0, encoded.len()), (second, text.len())]
        );
    }

    #[test]
    fn a_key_in_the_query_does_not_mask_the_body() {
        let x = parse(
            Source::Request {
                method: "POST",
                path: "/",
                query: Some("k=-----BEGIN%20RSA%20PRIVATE%20KEY-----%0Aabc"),
                body: Some(b"plain body"),
                sender: None,
            },
            Policy::embedded(),
        );
        assert_eq!(mask_ranges(&x, 0), []);
        assert!(!mask_ranges(&x, 1).is_empty());
    }

    #[test]
    fn a_layer_with_no_key_has_no_mask() {
        let x = body(b"just text, BEGIN nothing, PRIVATE KEY alone");
        assert_eq!(mask_ranges(&x, 0), []);
        assert_eq!(mask_ranges(&x, 99), []);
    }
}
