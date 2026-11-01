//! The body X-ray as the pages show it: the parsed layers cut into
//! highlighted segments, the pieces, and the recipe as steps with branches.
//!
//! Everything here is plain text for askama to escape. Segments hold the
//! lossy text of the bytes, split on character boundaries; a highlight's
//! `data-l` value is made here from indexes (`l3`, `p0`), never from
//! attacker text. Private key material is withheld from every segment and
//! from the hex view. Addresses in pieces and steps are defanged, and
//! nothing here becomes a link.

use crate::model::defang::defang;
use crate::model::xray::{
    Grade, LayerKind, Node, OpaqueReason, PieceKind, Role, Span, Step, Xray, mask_ranges,
};

/// Most bytes of the raw body shown (the store's display limit).
pub const RAW_SHOWN: usize = crate::store::inspect::BODY_LIMIT;

/// Most bytes of one decoded layer shown.
const LAYER_SHOWN: usize = 16 * 1024;

/// Longest value or step text shown.
const TEXT_SHOWN: usize = 200;

/// Deepest indent a class exists for.
const MAX_INDENT: usize = 8;

/// A run of text with one highlight, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seg {
    pub text: String,
    /// The `data-l` value pairing it with its counterpart.
    pub link: Option<String>,
    /// Private key material stood here; `text` says so.
    pub masked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceView {
    pub kind: &'static str,
    pub role: &'static str,
    pub grade: &'static str,
    pub value: String,
    pub link: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepView {
    /// Indent, in steps of one.
    pub depth: usize,
    /// `first try` and `if that fails` head a branch; they carry no text.
    pub branch: bool,
    pub label: &'static str,
    pub text: String,
    pub link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueView {
    pub why: &'static str,
    pub bytes: usize,
    pub link: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerView {
    pub n: usize,
    pub depth: usize,
    pub title: &'static str,
    pub name: Option<String>,
    /// Pairs the layer with the text it was opened from.
    pub link: Option<String>,
    /// Padding fields folded into this one.
    pub collapsed: usize,
    pub segs: Vec<Seg>,
    pub cut: bool,
    pub bytes: usize,
    pub pieces: Vec<PieceView>,
    pub steps: Vec<StepView>,
    pub opaque: Vec<OpaqueView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayView {
    /// The original bytes, as highlighted segments.
    pub raw: Vec<Seg>,
    pub raw_cut: bool,
    /// Size of the original body.
    pub total: usize,
    /// Base64 of the original bytes shown, private keys overwritten, for the hex view.
    pub hex_b64: String,
    /// The layers in tree order. The raw layer is listed only when it has
    /// pieces, steps or opaque ranges of its own.
    pub layers: Vec<LayerView>,
}

impl XrayView {
    /// Whether anything but the raw body was found.
    pub fn is_plain(&self) -> bool {
        self.layers.is_empty()
    }
}

impl LayerView {
    pub fn indent(&self) -> usize {
        self.depth.min(MAX_INDENT)
    }
}

impl StepView {
    pub fn indent(&self) -> usize {
        self.depth.min(MAX_INDENT)
    }
}

/// One shown character and the bytes it came from.
struct Unit {
    start: usize,
    end: usize,
    ch: char,
}

/// The characters of `bytes` as lossy text reads them: each invalid run is
/// one U+FFFD, controls are shown as their symbols. Stops after `limit`
/// bytes; the flag says whether more followed.
fn units(bytes: &[u8], limit: usize) -> (Vec<Unit>, bool) {
    let mut out = Vec::new();
    let mut at = 0;
    'chunks: for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            let end = at + ch.len_utf8();
            if end > limit {
                break 'chunks;
            }
            out.push(Unit {
                start: at,
                end,
                ch: shown(ch),
            });
            at = end;
        }
        let bad = chunk.invalid().len();
        if bad > 0 {
            if at + bad > limit {
                break;
            }
            out.push(Unit {
                start: at,
                end: at + bad,
                ch: '\u{fffd}',
            });
            at += bad;
        }
    }
    (out, at < bytes.len())
}

/// A character as shown: controls and direction marks cannot hide or
/// reorder what is around them.
fn shown(ch: char) -> char {
    match ch {
        '\n' | '\t' => ch,
        '\0'..='\u{1f}' => char::from_u32(0x2400 + ch as u32).unwrap_or('\u{fffd}'),
        '\u{7f}' => '\u{2421}',
        '\u{80}'..='\u{9f}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' => '\u{fffd}',
        '\u{2066}'..='\u{2069}' | '\u{feff}' => '\u{fffd}',
        _ => ch,
    }
}

/// A highlight over a byte range of one layer.
struct Mark {
    start: usize,
    end: usize,
    link: String,
}

/// `layer`'s text as segments: marks and key masks cut on character
/// boundaries. The innermost mark wins where marks overlap.
fn segments(
    text: &[u8],
    limit: usize,
    marks: &[Mark],
    masks: &[(usize, usize)],
) -> (Vec<Seg>, bool) {
    let (units, cut) = units(text, limit);
    let snap = |p: usize| units.partition_point(|u| u.start < p);
    let mut points = vec![0, units.len()];
    for m in marks {
        points.push(snap(m.start));
        points.push(snap(m.end));
    }
    for &(a, b) in masks {
        points.push(snap(a));
        points.push(snap(b));
    }
    points.sort_unstable();
    points.dedup();
    let mut segs: Vec<Seg> = Vec::new();
    // Bytes withheld in the seg being built.
    let mut withheld = 0;
    for w in points.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b || a >= units.len() {
            continue;
        }
        let from = units[a].start;
        let to = units[b - 1].end;
        let best = marks
            .iter()
            .filter(|m| m.start <= from && from < m.end)
            .min_by_key(|m| m.end - m.start)
            .map(|m| m.link.clone());
        if masks.iter().any(|&(s, e)| s <= from && from < e) {
            match segs.last_mut() {
                Some(last) if last.masked => {
                    withheld += to - from;
                    last.text = withheld_text(withheld);
                    last.link = last.link.take().or(best);
                }
                _ => {
                    withheld = to - from;
                    segs.push(Seg {
                        text: withheld_text(withheld),
                        link: best,
                        masked: true,
                    });
                }
            }
            continue;
        }
        let part: String = units[a..b].iter().map(|u| u.ch).collect();
        match segs.last_mut() {
            Some(last) if !last.masked && last.link == best => last.text.push_str(&part),
            _ => segs.push(Seg {
                text: part,
                link: best,
                masked: false,
            }),
        }
    }
    (segs, cut)
}

fn withheld_text(bytes: usize) -> String {
    format!("[private key withheld, {bytes} bytes]")
}

/// `text` cut to [`TEXT_SHOWN`] characters.
fn clip(text: String) -> String {
    match text.char_indices().nth(TEXT_SHOWN) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text,
    }
}

/// Text of a span as shown in a step: defanged and cut.
fn span_text(x: &Xray, s: Span) -> String {
    let Some(layer) = x.layers.get(s.layer) else {
        return String::new();
    };
    let bytes = layer.text.get(s.start..s.end).unwrap_or_default();
    let (u, _) = units(bytes, TEXT_SHOWN * 4);
    clip(defang(&u.iter().map(|u| u.ch).collect::<String>()))
}

fn layer_title(kind: LayerKind) -> &'static str {
    match kind {
        LayerKind::Raw => "Body",
        LayerKind::Path => "Request path",
        LayerKind::Query => "Query",
        LayerKind::Form => "Form field",
        LayerKind::MultipartField => "Multipart field",
        LayerKind::Json => "JSON string",
        LayerKind::Xml => "XML text",
        LayerKind::Php => "PHP string",
        LayerKind::PhpCgi => "PHP-CGI body",
        LayerKind::Base64 => "base64",
        LayerKind::Gzip => "decompressed",
        LayerKind::Hex => "hex",
        LayerKind::Escapes => "escapes",
        LayerKind::Shell => "shell text",
    }
}

fn piece_kind(kind: PieceKind) -> &'static str {
    match kind {
        PieceKind::Exploit => "exploit",
        PieceKind::Recipe => "recipe",
        PieceKind::Tag => "tag",
        PieceKind::ShellProfile => "webshell",
        PieceKind::Stager => "stager",
        PieceKind::Key => "key",
    }
}

fn piece_role(role: Role) -> &'static str {
    match role {
        Role::Exploit => "exploit",
        Role::Tag => "claimed tag",
        Role::Recipe => "recipe",
        Role::Stager => "stager",
        Role::SelfHosted => "self-hosted",
        Role::Queried => "only queried",
        Role::Key => "key",
        Role::File => "file",
        Role::Opaque => "opaque",
    }
}

fn piece_grade(grade: Grade) -> &'static str {
    match grade {
        Grade::Seen => "seen",
        Grade::Claimed => "claimed",
        Grade::External => "external",
    }
}

fn why(reason: OpaqueReason) -> &'static str {
    match reason {
        OpaqueReason::HighEntropy => {
            "Not opened: random-looking data, probably compressed or encrypted."
        }
        OpaqueReason::UnknownEncoding => "Not opened: an encoding the X-ray does not know.",
        OpaqueReason::TooDeep => "Not opened: nested deeper than the X-ray goes.",
        OpaqueReason::OverLimit => "Not opened: the size or layer limit was reached.",
    }
}

/// The steps of a recipe, one row each, branches headed by a row of their
/// own. Rows with a span link to it in the layer's text.
fn flatten(
    x: &Xray,
    nodes: &[Node],
    depth: usize,
    recipe: usize,
    next: &mut usize,
    marks: &mut Vec<(usize, Mark)>,
    out: &mut Vec<StepView>,
) {
    for node in nodes {
        match node {
            Node::Pipe(inner) => flatten(x, inner, depth, recipe, next, marks, out),
            Node::Try { first, fallback } => {
                for (label, branch) in [("first try", first), ("if that fails", fallback)] {
                    if branch.is_empty() {
                        continue;
                    }
                    out.push(StepView {
                        depth,
                        branch: true,
                        label,
                        text: String::new(),
                        link: None,
                    });
                    flatten(x, branch, depth + 1, recipe, next, marks, out);
                }
            }
            Node::Step(step) => {
                let mut link_to = |span: Span| {
                    let link = format!("s{recipe}-{}", *next);
                    *next += 1;
                    marks.push((
                        span.layer,
                        Mark {
                            start: span.start,
                            end: span.end,
                            link: link.clone(),
                        },
                    ));
                    link
                };
                let (label, text, link) = match step {
                    Step::Prepare(name) => ("prepare", clip(defang(name)), None),
                    Step::Write(span) => (
                        "write",
                        span.map_or("a file".to_string(), |s| {
                            format!("a file, {} bytes", s.end - s.start)
                        }),
                        span.map(&mut link_to),
                    ),
                    Step::Fetch {
                        tool,
                        target,
                        saves,
                    } => (
                        "fetch",
                        format!(
                            "{} {}{}",
                            clip(defang(tool)),
                            span_text(x, *target),
                            if *saves { "" } else { " (only queried)" }
                        ),
                        Some(link_to(*target)),
                    ),
                    Step::Run { what, tag } => (
                        "run",
                        match tag {
                            Some(t) => format!("{} (tag {})", clip(defang(what)), clip(defang(t))),
                            None => clip(defang(what)),
                        },
                        None,
                    ),
                    Step::Arm => ("arm", "make a file executable".to_string(), None),
                    Step::Wipe => ("wipe", "remove files".to_string(), None),
                    Step::Cleanup => ("clean up", "remove traces".to_string(), None),
                    Step::Other(name) => ("other", clip(defang(name)), None),
                };
                out.push(StepView {
                    depth,
                    branch: false,
                    label,
                    text,
                    link,
                });
            }
        }
    }
}

/// The view of a parsed source.
pub fn xray_view(x: &Xray) -> XrayView {
    let n = x.layers.len();
    let mut marks: Vec<Vec<Mark>> = (0..n).map(|_| Vec::new()).collect();
    let push = |marks: &mut Vec<Vec<Mark>>, s: Span, link: String| {
        if let Some(v) = marks.get_mut(s.layer) {
            v.push(Mark {
                start: s.start,
                end: s.end,
                link,
            });
        }
    };
    for (i, l) in x.layers.iter().enumerate() {
        if let Some(s) = l.from {
            push(&mut marks, s, format!("l{i}"));
        }
    }
    for (i, o) in x.opaque.iter().enumerate() {
        push(&mut marks, o.at, format!("o{i}"));
    }
    let mut pieces: Vec<Vec<PieceView>> = (0..n).map(|_| Vec::new()).collect();
    for (i, p) in x.pieces.iter().enumerate() {
        let link = format!("p{i}");
        push(&mut marks, p.at, link.clone());
        if let Some(v) = pieces.get_mut(p.at.layer) {
            v.push(PieceView {
                kind: piece_kind(p.kind),
                role: piece_role(p.role),
                grade: piece_grade(p.grade),
                value: clip(defang(&p.value)),
                link,
            });
        }
    }
    let mut steps: Vec<Vec<StepView>> = (0..n).map(|_| Vec::new()).collect();
    for (r, recipe) in x.recipes.iter().enumerate() {
        let mut found = Vec::new();
        let mut next = 0;
        let mut rows = Vec::new();
        flatten(x, &recipe.nodes, 0, r, &mut next, &mut found, &mut rows);
        for (layer, m) in found {
            if let Some(v) = marks.get_mut(layer) {
                v.push(m);
            }
        }
        if let Some(v) = steps.get_mut(recipe.layer) {
            v.extend(rows);
        }
    }
    let mut opaque: Vec<Vec<OpaqueView>> = (0..n).map(|_| Vec::new()).collect();
    for (i, o) in x.opaque.iter().enumerate() {
        if let Some(v) = opaque.get_mut(o.at.layer) {
            v.push(OpaqueView {
                why: why(o.reason),
                bytes: o.at.end - o.at.start,
                link: format!("o{i}"),
            });
        }
    }

    let (raw, raw_cut) = match x.layers.first() {
        Some(l) => segments(&l.text, RAW_SHOWN, &marks[0], &mask_ranges(x, 0)),
        None => (Vec::new(), false),
    };

    // Tree order: a layer, then what was opened from it.
    let mut kids: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut roots = Vec::new();
    for (i, l) in x.layers.iter().enumerate() {
        match l.parent {
            Some(p) if p < n && p != i => kids[p].push(i),
            _ => roots.push(i),
        }
    }
    let mut order = Vec::with_capacity(n);
    let mut stack: Vec<usize> = roots.into_iter().rev().collect();
    while let Some(i) = stack.pop() {
        order.push(i);
        stack.extend(kids[i].iter().rev());
    }

    let mut layers = Vec::new();
    for i in order {
        let l = &x.layers[i];
        let (segs, cut) = if i == 0 {
            (Vec::new(), false)
        } else {
            segments(&l.text, LAYER_SHOWN, &marks[i], &mask_ranges(x, i))
        };
        let (own_pieces, own_steps, own_opaque) = (
            std::mem::take(&mut pieces[i]),
            std::mem::take(&mut steps[i]),
            std::mem::take(&mut opaque[i]),
        );
        if i == 0 && own_pieces.is_empty() && own_steps.is_empty() && own_opaque.is_empty() {
            continue;
        }
        layers.push(LayerView {
            n: i,
            depth: x.depth(i),
            title: layer_title(l.kind),
            name: l
                .name
                .as_ref()
                .map(|b| clip(String::from_utf8_lossy(b).chars().map(shown).collect())),
            link: l.from.map(|_| format!("l{i}")),
            collapsed: l.collapsed,
            segs,
            cut,
            bytes: l.text.len(),
            pieces: own_pieces,
            steps: own_steps,
            opaque: own_opaque,
        });
    }
    XrayView {
        raw,
        raw_cut,
        total: x.layers.first().map_or(0, |l| l.text.len()),
        hex_b64: masked_b64(x),
        layers,
    }
}

/// Base64 of the original bytes (the first [`RAW_SHOWN`]) with every
/// private key range overwritten, for the hex view.
fn masked_b64(x: &Xray) -> String {
    let Some(l) = x.layers.first() else {
        return String::new();
    };
    let mut bytes = l.text[..l.text.len().min(RAW_SHOWN)].to_vec();
    for (a, b) in mask_ranges(x, 0) {
        let (a, b) = (a.min(bytes.len()), b.min(bytes.len()));
        bytes[a..b].fill(b'*');
    }
    data_encoding::BASE64.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::xray::{Policy, Source, parse};

    fn upload(text: &[u8]) -> Xray {
        parse(
            Source::Upload {
                name: None,
                text,
                sender: None,
            },
            Policy::embedded(),
        )
    }

    fn joined(segs: &[Seg]) -> String {
        segs.iter().map(|s| s.text.as_str()).collect()
    }

    #[test]
    fn segments_split_on_char_boundaries_of_lossy_text() {
        // Latin-1 bytes, a NUL and a cut UTF-8 sequence.
        let text: &[u8] = b"caf\xe9 \x00 x\xe2\x82";
        let marks = [
            Mark {
                start: 3,
                end: 5,
                link: "p0".into(),
            },
            Mark {
                start: 8,
                end: 10,
                link: "p1".into(),
            },
        ];
        let (segs, cut) = segments(text, 1000, &marks, &[]);
        assert!(!cut);
        let all = joined(&segs);
        assert_eq!(all, String::from_utf8_lossy(text).replace('\0', "\u{2400}"));
        // The mark on byte 3 covers the whole invalid byte, not half a char.
        assert_eq!(segs[1].link.as_deref(), Some("p0"));
        assert_eq!(segs[1].text, "\u{fffd} ");
        // A cut sequence is one replacement character with its mark.
        let last = segs.last().unwrap();
        assert_eq!(
            (last.text.as_str(), last.link.as_deref()),
            ("\u{fffd}", Some("p1"))
        );
        assert!(segs.iter().all(|s| !s.text.is_empty()));
        // The limit cuts between characters.
        let (segs, cut) = segments("aé€".as_bytes(), 2, &[], &[]);
        assert!(cut);
        assert_eq!(joined(&segs), "a");
    }

    #[test]
    fn masked_ranges_replace_key_text() {
        let body = b"<?php system('id'); ?>\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABgQDexample\n-----END OPENSSH PRIVATE KEY-----\n";
        let x = upload(body);
        let v = xray_view(&x);
        let all = joined(&v.raw);
        assert!(!all.contains("PRIVATE KEY"), "{all}");
        assert!(!all.contains("AAAAB3NzaC1yc2E"), "{all}");
        assert!(all.contains("<?php system"));
        assert!(v.raw.iter().any(|s| s.masked));
        let hex = data_encoding::BASE64.decode(v.hex_b64.as_bytes()).unwrap();
        assert!(
            !String::from_utf8_lossy(&hex).contains("PRIVATE KEY"),
            "the hex view withholds the key too"
        );
    }
}
