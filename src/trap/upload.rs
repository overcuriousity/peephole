//! The trap's upload sink (MIK-121): which requests drop a file, the file
//! as the trap keeps it, and the answer that tells the client it landed.
//!
//! The file is hostile. It is only hashed and stored (`store::uploads`).
//! Nothing here executes, unpacks or renders it, and no answer is derived
//! from its bytes: an answer depends on the kind, the request path and the
//! sanitised client file name only.
use super::decoy::{self, Decoy};
use crate::canary::site;
use crate::store::uploads::MAX_CONTENT;

/// Most bytes of an upload request body read and kept: the file's cap
/// plus room for the multipart framing and form fields around it.
pub const KEEP: usize = MAX_CONTENT + 64 * 1024;
/// Past [`KEEP`] the rest is read and counted, up to this many bytes in
/// all, so the file's full size is known for most real uploads.
pub const DRAIN: u64 = 16 * 1024 * 1024;
/// Most multipart parts looked at; the file must be among the first.
const MAX_PARTS: usize = 16;
/// The longest request path taken as an upload's answered path (as the
/// store accepts it).
const MAX_PATH: usize = 2048;
/// The longest client file name kept, in bytes (as the store accepts it).
const MAX_FILENAME: usize = 255;

/// Upload scripts a multipart POST is taken as an upload to, in any
/// directory. Not `/wp-admin/admin-ajax.php`: most of its actions are no
/// upload.
const SCRIPTS: [&str; 13] = [
    "/upload.php",
    "/uploader.php",
    "/upload_file.php",
    "/fileupload.php",
    "/up.php",
    "/filemanager/upload.php",
    "/elfinder/php/connector.php",
    "/general/index/UploadFile.php",
    "/ueditor/php/action_upload.php",
    "/mobile/api/api.ali.php",
    "/developmentserver/metadatauploader",
    "/wp-file-manager/lib/php/connector.minimal.php",
    "/laravel-filemanager/upload",
];

/// What kind of upload a request is (`uploads.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Put,
    WpPlugin,
    WpTheme,
    WpMedia,
    Script,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Put => "put",
            Kind::WpPlugin => "wp_plugin",
            Kind::WpTheme => "wp_theme",
            Kind::WpMedia => "wp_media",
            Kind::Script => "script",
        }
    }

    /// The multipart field the file must come in; None: any file field.
    fn field(self) -> Option<&'static str> {
        match self {
            Kind::WpPlugin => Some("pluginzip"),
            Kind::WpTheme => Some("themezip"),
            Kind::WpMedia => Some("async-upload"),
            Kind::Put | Kind::Script => None,
        }
    }
}

/// Whether a request is an upload, from its method, path, query and
/// `Content-Type` only: decided before the body is read, so that only
/// these requests keep more than the usual body cap.
pub fn detect(
    method: &str,
    path: &str,
    query: Option<&str>,
    content_type: Option<&str>,
) -> Option<Kind> {
    if path.len() > MAX_PATH {
        return None;
    }
    if method == "PUT" {
        return Some(Kind::Put);
    }
    let multipart = content_type
        .and_then(|c| c.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("multipart/form-data"));
    if method != "POST" || !multipart {
        return None;
    }
    let action = |a: &str| {
        query.is_some_and(|q| q.split('&').any(|kv| kv.strip_prefix("action=") == Some(a)))
    };
    if path.ends_with("/wp-admin/update.php") {
        if action("upload-plugin") {
            return Some(Kind::WpPlugin);
        }
        if action("upload-theme") {
            return Some(Kind::WpTheme);
        }
        return None;
    }
    if path.ends_with("/wp-admin/async-upload.php") || path.ends_with("/wp-admin/media-new.php") {
        return Some(Kind::WpMedia);
    }
    SCRIPTS
        .iter()
        .any(|s| path.ends_with(s))
        .then_some(Kind::Script)
}

/// The file part of a multipart body.
#[derive(Debug, Default, PartialEq)]
pub struct Part {
    /// The client's file name, as sent.
    pub filename: Option<String>,
    /// At most [`MAX_CONTENT`] bytes.
    pub data: Vec<u8>,
    /// Bytes of the part seen in the kept body.
    pub seen: u64,
    /// The part ended within the kept body.
    pub complete: bool,
}

/// The first file part of `body` (multipart, as `content_type` says): the
/// one in `kind`'s field, or for an upload script the first with a file
/// name. None: no such part among the first [`MAX_PARTS`].
///
/// A `cut` body (not all of it was kept) is closed with a final delimiter
/// where it ends, so the part it cuts short ends there; it is the file
/// when nothing follows the file before that delimiter.
pub async fn parse_multipart(
    content_type: &str,
    body: &[u8],
    kind: Kind,
    cut: bool,
) -> Option<Part> {
    let boundary = multer::parse_boundary(content_type).ok()?;
    let close = if cut {
        format!("\r\n--{boundary}--\r\n").into_bytes()
    } else {
        Vec::new()
    };
    // The parser's bounds are the kept body's (plus the delimiter added to
    // a cut body), not the 1 MiB content cap: at exactly 1 MiB multer fails
    // a larger file without yielding any of it. The cap is applied as the
    // file is read. Parsing holds a copy of the body and the file (about
    // 2 MiB) only while it runs, outside `BODY_BUDGET`; the body it parses
    // is held against that budget meanwhile, so at most `BODY_BUDGET / KEEP`
    // parses run at once.
    let limits = multer::SizeLimit::new()
        .whole_stream((KEEP + close.len()) as u64)
        .per_field((KEEP + close.len()) as u64);
    let chunks = [
        axum::body::Bytes::copy_from_slice(body),
        axum::body::Bytes::from(close),
    ];
    let stream = futures::stream::iter(chunks.map(Ok::<_, std::convert::Infallible>));
    let mut mp = multer::Multipart::with_constraints(
        stream,
        boundary,
        multer::Constraints::new().size_limit(limits),
    );
    for _ in 0..MAX_PARTS {
        let mut field = mp.next_field().await.ok()??;
        let wanted = match kind.field() {
            Some(name) => field.name() == Some(name),
            None => field.file_name().is_some(),
        };
        if !wanted {
            continue;
        }
        let mut part = Part {
            filename: field.file_name().map(|f| clip(f, MAX_FILENAME).to_string()),
            ..Default::default()
        };
        loop {
            match field.chunk().await {
                Ok(Some(c)) => {
                    part.seen += c.len() as u64;
                    let take = MAX_CONTENT.saturating_sub(part.data.len()).min(c.len());
                    part.data.extend_from_slice(&c[..take]);
                }
                Ok(None) => {
                    part.complete = true;
                    break;
                }
                // Malformed: what came is kept.
                Err(_) => break,
            }
        }
        drop(field);
        if cut && part.complete && matches!(mp.next_field().await, Ok(None)) {
            part.complete = false;
        }
        return Some(part);
    }
    None
}

/// `s` cut to at most `max` bytes on a character boundary.
fn clip(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A client file name as a path segment: its last component, only
/// `[A-Za-z0-9._-]`, no leading dots, at most 64 characters (the extension
/// kept). Empty when no name is left before the extension (`../`,
/// `.htaccess`, `名前.php`).
pub fn sanitize_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let kept: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if kept.starts_with('.') && !kept.trim_start_matches('.').contains('.') {
        return String::new();
    }
    let kept = kept.trim_start_matches('.');
    if kept.len() <= 64 {
        return kept.to_string();
    }
    match kept.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 8 => {
            format!("{}.{ext}", &stem[..63 - ext.len()])
        }
        _ => kept[..64].to_string(),
    }
}

/// The name a file is answered under: the sanitised client name, or else
/// 8 hex characters from `seed`, with the original extension when it is
/// `[a-z0-9]{1,5}`.
pub fn file_name(client: Option<&str>, seed: &str) -> String {
    let clean = client.map(sanitize_name).unwrap_or_default();
    if !clean.is_empty() {
        return clean;
    }
    use sha2::Digest;
    let hex = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(seed.as_bytes())[..4]);
    let ext = client
        .and_then(|c| c.rsplit_once('.'))
        .map(|(_, e)| e)
        .filter(|e| {
            (1..=5).contains(&e.len())
                && e.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    match ext {
        Some(e) => format!("{hex}.{e}"),
        None => hex,
    }
}

/// What a file looks like from its first 16 bytes, never from the
/// client's `Content-Type`.
pub fn sniff(data: &[u8]) -> &'static str {
    let head = &data[..data.len().min(16)];
    let lower = head.to_ascii_lowercase();
    let trimmed = lower.trim_ascii_start();
    let html = trimmed.starts_with(b"<!doctype html") || trimmed.starts_with(b"<html");
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        "zip"
    } else if head.starts_with(b"\x1f\x8b") {
        "gzip"
    } else if head.starts_with(b"\x7fELF") {
        "elf"
    } else if lower.starts_with(b"<?php") || head.starts_with(b"<?=") {
        "php"
    } else if head.starts_with(b"#!") {
        "script"
    } else if html {
        "html"
    } else if text(head) {
        "text"
    } else {
        "binary"
    }
}

/// Printable UTF-8 (a character cut at the end allowed) with no control
/// bytes but tab, CR and LF.
fn text(b: &[u8]) -> bool {
    let valid = match std::str::from_utf8(b) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    };
    valid
        && b.iter()
            .all(|&c| c >= 0x20 && c != 0x7f || matches!(c, b'\t' | b'\r' | b'\n'))
}

/// An upload as the trap took it, to record once the request is.
#[derive(Debug)]
pub struct Upload {
    pub kind: Kind,
    pub filename: Option<String>,
    /// The kept bytes, at most [`MAX_CONTENT`].
    pub content: Vec<u8>,
    /// The full size as received (more than kept when `truncated`).
    pub size: i64,
    pub truncated: bool,
    pub sniffed: &'static str,
    pub answered_path: String,
    pub path_is_prefix: bool,
    /// Content-bearing uploads per source per hour, as set when it came.
    pub per_source: u32,
}

/// The upload in a request [`detect`] took as `kind`, from its kept body
/// (`received`: the bytes received when that is not the whole body).
/// None when a multipart body carries no file part. `seed` names a file
/// the client gave no usable name; `ym` is the `YYYY/MM` of WordPress's
/// media folders.
#[allow(clippy::too_many_arguments)]
pub async fn take(
    kind: Kind,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
    received: Option<u64>,
    seed: &str,
    ym: &str,
    per_source: u32,
) -> Option<Upload> {
    let (filename, data, size) = match kind {
        Kind::Put => {
            let size = received.unwrap_or(body.len() as u64);
            let name = path.rsplit('/').next().filter(|n| !n.is_empty());
            let data = body[..body.len().min(MAX_CONTENT)].to_vec();
            (name.map(|n| clip(n, MAX_FILENAME).to_string()), data, size)
        }
        _ => {
            let part = parse_multipart(content_type?, body, kind, received.is_some()).await?;
            // A part cut off with the body: what of the body was not kept
            // is counted to it (it may include the closing boundary).
            let size = match received {
                Some(r) if !part.complete => part.seen + r.saturating_sub(body.len() as u64),
                _ => part.seen,
            };
            (part.filename, part.data, size)
        }
    };
    let truncated = size > data.len() as u64;
    let name = || file_name(filename.as_deref(), seed);
    let slug = || {
        let n = name();
        match n.strip_suffix(".zip") {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => n,
        }
    };
    let (answered_path, path_is_prefix) = match kind {
        // One leading slash: `//host/x` would be a protocol-relative
        // `Location`, pointing the client elsewhere.
        Kind::Put => (format!("/{}", path.trim_start_matches('/')), false),
        Kind::WpPlugin => (format!("/wp-content/plugins/{}/", slug()), true),
        Kind::WpTheme => (format!("/wp-content/themes/{}/", slug()), true),
        Kind::WpMedia => (format!("/wp-content/uploads/{ym}/{}", name()), false),
        Kind::Script => (format!("/uploads/{}", name()), false),
    };
    Some(Upload {
        kind,
        filename,
        sniffed: sniff(&data),
        size: i64::try_from(size).unwrap_or(i64::MAX),
        truncated,
        content: data,
        answered_path,
        path_is_prefix,
        per_source,
    })
}

impl Upload {
    /// What the client is told: that the file landed at the answered path.
    /// Nothing in it comes from the file's bytes.
    pub fn reply(&self, host: Option<&str>, word: &str) -> Decoy {
        let p = &self.answered_path;
        let (status, ct, body, extra) = match self.kind {
            Kind::Put => (201, TEXT, String::new(), Some(("location", p.clone()))),
            Kind::WpPlugin => (200, HTML, decoy::wp_installed("Plugin", word), None),
            Kind::WpTheme => (200, HTML, decoy::wp_installed("Theme", word), None),
            Kind::WpMedia => {
                let site = format!("{word}.internal");
                let url = format!("http://{}{p}", site::return_host(host, &site));
                (200, JSON, decoy::wp_media_json(&url), None)
            }
            Kind::Script => (200, TEXT, format!("{p}\n"), None),
        };
        let mut headers = vec![
            ("content-type", ct.to_string()),
            ("x-content-type-options", "nosniff".to_string()),
        ];
        headers.extend(extra);
        Decoy {
            name: format!("upload:{}", self.kind.as_str()),
            status,
            headers,
            body,
        }
    }
}

const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=UTF-8";
const JSON: &str = "application/json; charset=UTF-8";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_takes_the_five_kinds_and_nothing_else() {
        let mp = Some("multipart/form-data; boundary=x");
        fn d(m: &str, p: &str, q: Option<&str>) -> Option<Kind> {
            detect(m, p, q, Some("multipart/form-data; boundary=x"))
        }
        assert_eq!(detect("PUT", "/x/a.php", None, None), Some(Kind::Put));
        assert_eq!(
            d("POST", "/wp-admin/update.php", Some("action=upload-plugin")),
            Some(Kind::WpPlugin)
        );
        assert_eq!(
            d(
                "POST",
                "/blog/wp-admin/update.php",
                Some("a=1&action=upload-theme")
            ),
            Some(Kind::WpTheme)
        );
        assert_eq!(d("POST", "/wp-admin/update.php", Some("action=x")), None);
        assert_eq!(
            d("POST", "/wp-admin/async-upload.php", None),
            Some(Kind::WpMedia)
        );
        assert_eq!(
            d("POST", "/wp-admin/media-new.php", None),
            Some(Kind::WpMedia)
        );
        for s in SCRIPTS {
            assert_eq!(
                d("POST", &format!("/a/b{s}"), None),
                Some(Kind::Script),
                "{s}"
            );
        }
        assert_eq!(d("POST", "/upload.php5", None), None);
        assert_eq!(d("POST", "/myupload.php", None), None);
        assert_eq!(d("POST", "/wp-admin/admin-ajax.php", None), None);
        // A form that is not multipart, or another method, is no upload.
        assert_eq!(
            detect(
                "POST",
                "/upload.php",
                None,
                Some("application/x-www-form-urlencoded")
            ),
            None
        );
        assert_eq!(detect("GET", "/upload.php", None, mp), None);
        assert_eq!(
            detect("PUT", &format!("/{}", "a".repeat(MAX_PATH)), None, None),
            None
        );
    }

    #[test]
    fn sanitize_name_keeps_a_safe_segment() {
        let cases = [
            ("shell.php", "shell.php"),
            ("../../etc/passwd", "passwd"),
            ("..\\..\\win.ini", "win.ini"),
            ("../", ""),
            ("..", ""),
            ("", ""),
            ("a\0b.php", "ab.php"),
            ("ünï<cödé>.php", "ncd.php"),
            ("名前.php", ""),
            (".htaccess", ""),
            ("..x.php", "x.php"),
            ("a b;c&d.phtml", "abcd.phtml"),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize_name(input), want, "{input:?}");
        }
        let long = format!("{}.php", "a".repeat(1000));
        let s = sanitize_name(&long);
        assert_eq!(s.len(), 64);
        assert!(s.ends_with("a.php"));
        let no_ext = "b".repeat(1000);
        assert_eq!(sanitize_name(&no_ext), "b".repeat(64));
        for s in [sanitize_name(&long), sanitize_name("x/../../y\0z")] {
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            );
        }
    }

    #[test]
    fn file_name_falls_back_to_hex_with_a_plain_extension() {
        assert_eq!(file_name(Some("s.php"), "t"), "s.php");
        let r = file_name(None, "t");
        assert_eq!(r.len(), 8);
        assert!(r.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(file_name(None, "t"), r, "the same seed, the same name");
        assert_eq!(file_name(Some("名前.php"), "t"), format!("{r}.php"));
        assert_eq!(file_name(Some("/.."), "t"), r);
        assert_eq!(file_name(Some("../.zip"), "t"), format!("{r}.zip"));
        assert_eq!(file_name(Some("ü.ü"), "t"), r);
        assert_eq!(file_name(Some("ü.p5"), "t"), format!("{r}.p5"));
        assert_eq!(file_name(Some("ü.PHP"), "t"), r, "upper case is not kept");
        assert_eq!(file_name(Some(".htaccess"), "t"), r, "too long");
    }

    #[test]
    fn sniff_reads_the_magic_bytes() {
        let cases: [(&[u8], &str); 12] = [
            (b"PK\x03\x04rest", "zip"),
            (b"\x1f\x8b\x08\x00", "gzip"),
            (b"\x7fELF\x02\x01\x01", "elf"),
            (b"<?php system($_GET['c']);", "php"),
            (b"<?PHP echo 1;", "php"),
            (b"<?= `id` ?>", "php"),
            (b"#!/bin/sh\nid", "script"),
            (b"  <!DOCTYPE html><p>", "html"),
            (b"<html><body>", "html"),
            (b"hello world\n", "text"),
            (b"", "text"),
            (b"\x00\x01\x02\xff", "binary"),
        ];
        for (data, want) in cases {
            assert_eq!(sniff(data), want, "{data:?}");
        }
        // Text cut inside a character at the 16th byte is still text.
        assert_eq!(sniff("aaaaaaaaaaaaaaaü".as_bytes()), "text");
    }

    fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
        let mut b = Vec::new();
        for (name, file, data) in parts {
            b.extend_from_slice(b"--XyZ\r\nContent-Disposition: form-data; name=\"");
            b.extend_from_slice(name.as_bytes());
            b.push(b'"');
            if let Some(f) = file {
                b.extend_from_slice(format!("; filename=\"{f}\"").as_bytes());
            }
            b.extend_from_slice(b"\r\n\r\n");
            b.extend_from_slice(data);
            b.extend_from_slice(b"\r\n");
        }
        b.extend_from_slice(b"--XyZ--\r\n");
        ("multipart/form-data; boundary=XyZ".into(), b)
    }

    #[tokio::test]
    async fn the_first_file_part_is_kept() {
        let (ct, body) = multipart(&[
            ("_wpnonce", None, b"abc"),
            ("pluginzip", Some("evil.zip"), b"PK\x03\x04zz"),
            ("pluginzip", Some("second.zip"), b"other"),
        ]);
        let p = parse_multipart(&ct, &body, Kind::WpPlugin, false)
            .await
            .unwrap();
        assert_eq!(p.filename.as_deref(), Some("evil.zip"));
        assert_eq!(p.data, b"PK\x03\x04zz");
        assert!(p.complete);
        // An upload script takes the first part with a file name.
        let p = parse_multipart(&ct, &body, Kind::Script, false)
            .await
            .unwrap();
        assert_eq!(p.filename.as_deref(), Some("evil.zip"));
        // No file in the wanted field: none.
        assert!(
            parse_multipart(&ct, &body, Kind::WpTheme, false)
                .await
                .is_none()
        );
        assert!(
            parse_multipart("multipart/form-data", &body, Kind::Script, false)
                .await
                .is_none()
        );
        assert!(
            parse_multipart(&ct, b"garbage", Kind::Script, false)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn only_the_first_parts_are_looked_at() {
        let filler: Vec<(&str, Option<&str>, &[u8])> = vec![("f", None, b"x"); MAX_PARTS];
        let mut parts = filler.clone();
        parts.push(("file", Some("late.php"), b"<?php"));
        let (ct, body) = multipart(&parts);
        assert!(
            parse_multipart(&ct, &body, Kind::Script, false)
                .await
                .is_none()
        );
        let mut parts = filler[1..].to_vec();
        parts.push(("file", Some("in-time.php"), b"<?php"));
        let (ct, body) = multipart(&parts);
        assert!(
            parse_multipart(&ct, &body, Kind::Script, false)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_large_part_is_cut_at_the_cap_and_sized_in_full() {
        let big = vec![b'A'; MAX_CONTENT + 1000];
        let (ct, body) = multipart(&[("file", Some("big.txt"), &big)]);
        let u = take(
            Kind::Script,
            "/upload.php",
            Some(&ct),
            &body,
            None,
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(u.content.len(), MAX_CONTENT);
        assert_eq!(u.size, big.len() as i64);
        assert!(u.truncated);
        // The body itself cut short: the rest received counts to the file.
        let kept = &body[..KEEP.min(body.len()) - 10];
        let u = take(
            Kind::Script,
            "/upload.php",
            Some(&ct),
            kept,
            Some(body.len() as u64),
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(u.content.len(), MAX_CONTENT);
        assert!(u.size >= big.len() as i64 && u.size <= body.len() as i64);
        // Cut in a field after the file: the file is whole.
        let (ct, body) = multipart(&[("file", Some("a.php"), b"<?php"), ("x", None, &big)]);
        let p = parse_multipart(&ct, &body[..1000], Kind::Script, true)
            .await
            .unwrap();
        assert!(p.complete && p.data == b"<?php");
        let u = take(
            Kind::Script,
            "/up.php",
            Some(&ct),
            &body[..1000],
            Some(body.len() as u64),
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!((u.size, u.truncated), (5, false));
    }

    #[tokio::test]
    async fn answered_paths_and_replies_per_kind() {
        let (ct, body) = multipart(&[("pluginzip", Some("x/../Evil Plug.zip"), b"PK\x03\x04")]);
        let u = take(
            Kind::WpPlugin,
            "/wp-admin/update.php",
            Some(&ct),
            &body,
            None,
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(u.answered_path, "/wp-content/plugins/EvilPlug/");
        assert!(u.path_is_prefix);
        assert_eq!(u.sniffed, "zip");
        let r = u.reply(None, "acme");
        assert_eq!((r.status, r.name.as_str()), (200, "upload:wp_plugin"));
        assert!(r.body.contains("Plugin installed successfully."));

        let (ct, body) = multipart(&[("async-upload", Some("a.php"), b"<?php")]);
        let u = take(
            Kind::WpMedia,
            "/wp-admin/async-upload.php",
            Some(&ct),
            &body,
            None,
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(u.answered_path, "/wp-content/uploads/2026/10/a.php");
        let r = u.reply(Some("example.test\"<x>"), "acme");
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["success"], true);
        // A Host no decoy would echo: the site's name instead.
        assert_eq!(
            v["data"]["url"],
            "http://acme.internal/wp-content/uploads/2026/10/a.php"
        );
        let r = u.reply(Some("203.0.113.7:8080"), "acme");
        assert!(
            r.body
                .contains("http://203.0.113.7:8080/wp-content/uploads/2026/10/a.php")
        );

        let u = take(
            Kind::Put,
            "/x/a.php",
            None,
            b"<?php",
            None,
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        let r = u.reply(None, "acme");
        assert_eq!(r.status, 201);
        assert!(r.headers.contains(&("location", "/x/a.php".into())));
        assert!(
            r.headers
                .contains(&("x-content-type-options", "nosniff".into()))
        );
        assert_eq!(u.filename.as_deref(), Some("a.php"));
        // Never a protocol-relative `Location`.
        let u = take(
            Kind::Put,
            "//evil.example/x",
            None,
            b"x",
            None,
            "t",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(u.answered_path, "/evil.example/x");

        let (ct, body) = multipart(&[("file", Some(""), b"#!/bin/sh")]);
        let u = take(
            Kind::Script,
            "/up.php",
            Some(&ct),
            &body,
            None,
            "seed",
            "2026/10",
            6,
        )
        .await
        .unwrap();
        assert_eq!(
            u.answered_path,
            format!("/uploads/{}", file_name(None, "seed"))
        );
        assert_eq!(u.reply(None, "w").body, format!("{}\n", u.answered_path));
    }
}
