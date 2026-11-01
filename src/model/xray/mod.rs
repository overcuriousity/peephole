//! X-ray of an attacker request body: opens it layer by layer (base64,
//! gzip, percent and `\x` escapes, hex) into a flat tree, so what the
//! attacker hid inside what is visible to the rules above. Attackers feed
//! this directly, so it is bounded and total: fixed limits, no recursion
//! (a work queue over an arena), and nothing found is fetched, executed or
//! resolved.

pub mod container;
pub mod decode;

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

/// What the parser is told. Defined properly with the rules.
#[derive(Debug, Clone, Default)]
pub struct Policy {}

pub use container::{Source, parse};

/// Filled in by the piece extractor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Piece {}

/// Filled in by the recipe matcher.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recipe {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Xray {
    pub layers: Vec<Layer>,
    pub pieces: Vec<Piece>,
    pub opaque: Vec<Opaque>,
    pub recipes: Vec<Recipe>,
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
/// what is left to decode, and `pieces` is the cap the piece extractor
/// counts against.
#[derive(Debug, Clone)]
pub struct Budget {
    depth: usize,
    output: usize,
    layers: usize,
    // Read by the piece extractor.
    #[allow(dead_code)]
    pieces: usize,
}

impl Default for Budget {
    fn default() -> Budget {
        Budget {
            depth: MAX_DEPTH,
            output: MAX_OUTPUT,
            layers: MAX_LAYERS,
            pieces: MAX_PIECES,
        }
    }
}
