//! Private keys in attacker text: where they sit, so no pane shows them, and
//! the public fingerprint, the only form of a key ever kept. The bytes are
//! read for that alone: nothing is decrypted, stored or used.

use std::sync::LazyLock;

use data_encoding::{BASE64_NOPAD, HEXLOWER};
use regex::bytes::Regex;
use sha2::{Digest, Sha256};

use super::{LayerKind, Xray, decode};

/// Fewest bytes a PEM body decodes to for it to count as a key: less is a
/// placeholder, and its value would be the same for everybody.
const MIN_PEM: usize = 32;

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
/// starts the `END` marker, and `ended` says there is one.
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
            found.push(Block {
                start,
                head,
                body_end: text.len(),
                end: text.len(),
                ended: false,
            });
            break;
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

/// [`mask_ranges`] of every layer.
pub(super) fn all_masks(xray: &Xray) -> Vec<Vec<(usize, usize)>> {
    let mut masks: Vec<Vec<(usize, usize)>> = xray
        .layers
        .iter()
        .map(|l| blocks(&l.text).iter().map(|b| (b.start, b.end)).collect())
        .collect();
    let holders: Vec<usize> = (0..masks.len()).filter(|&i| !masks[i].is_empty()).collect();
    for holder in holders {
        let mut at = holder;
        while let Some(parent) = xray.layers[at].parent {
            let layer = &xray.layers[at];
            // The query is no part of the body, its parent. Other text
            // with no place in its parent may be anywhere in it.
            if layer.kind == LayerKind::Query {
                break;
            }
            let whole = (0, xray.layers[parent].text.len());
            masks[parent].push(layer.from.map_or(whole, |s| (s.start, s.end)));
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
            "head -----BEGIN RSA PRIVATE KEY-----\n!!! not a key !!!\n",
            "head -----BEGIN PRIVATE KEY",
        ] {
            let x = body(text.as_bytes());
            assert_eq!(mask_ranges(&x, 0), [(5, text.len())], "{text}");
        }
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
