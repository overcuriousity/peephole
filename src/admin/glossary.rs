//! One line per fingerprint the admin pages show: what it is computed from
//! and what a match means. The single source of these strings: templates
//! read them through [`help`] (hover titles) and `_fingerprint_glossary.html`
//! (the visible list), so a page cannot drift from another.
use crate::store::links::LinkKind;

/// The key of a path shape, beside the [`LinkKind`] keys; the campaign
/// edge kind `paths` reads the same.
pub const PATH_SHAPE: &str = "path-shape";

/// The line of a [`LinkKind`].
pub fn kind_help(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::Fp => {
            "A hash of what the trap page's script reads from the browser (canvas, WebGL renderer, font count, audio, screen, time zone, platform). A match: very likely the same browser on the same machine."
        }
        LinkKind::Ssh => {
            "The SHA256 fingerprint of the source's SSH host key, from a counter-scan. A match: the same key, so one operator or one copied image."
        }
        LinkKind::Tls => {
            "SHA-256 of the source's TLS certificate, from a counter-scan. A match: the same certificate, so one operator or one copied image."
        }
        LinkKind::Canary => {
            "A credential served in a decoy that names the request it was served to. Seen again: the later request's sender got it from the first."
        }
        LinkKind::Ja4 => {
            "JA4 (FoxIO): the TLS ClientHello the source sent us: version, ciphers, extensions, ALPN. A match: the same client software, not the same operator."
        }
        LinkKind::Ja4h => {
            "JA4H (FoxIO): the HTTP request head the source sent us: method, version, cookie and referer flags, header names, language. A match: the same HTTP client, not the same operator."
        }
        LinkKind::Ua => {
            "The User-Agent header as sent. A match says little: any client can set it."
        }
        LinkKind::Hassh => {
            "HASSH-server: a hash of the algorithm lists the source's SSH server offers, from a counter-scan. A match: the same SSH server software and settings, not the same operator."
        }
        LinkKind::Ja4x => {
            "JA4X (FoxIO): how the source's TLS certificate was built (the order of its issuer, subject and extension fields), not what it says, from a counter-scan. A match: the same certificate-making tool."
        }
        LinkKind::Favicon => {
            "Shodan's favicon hash (MurmurHash3 of the icon) of the source's web port, from a probe. A match: the same icon, often the same product or panel."
        }
        LinkKind::Jarm => {
            "JARM (Salesforce): how the source's TLS server answers ten unusual ClientHellos, from a probe. A match: the same TLS server stack and settings."
        }
        LinkKind::HttpBody => {
            "SHA-256 of the first 4 KiB of the page the source's web port serves at /, from a probe. A match: the same page, so the same product or deployment."
        }
        LinkKind::Http404 => {
            "SHA-256 of the first 4 KiB of the page the source's web port serves for a random missing path, from a probe. A match: the same web server or framework default."
        }
        LinkKind::HttpEtag => {
            "The ETag header of a file the source's web server serves, from a counter-scan. A match: the same file, not the same operator."
        }
    }
}

const PATH_SHAPE_HELP: &str = "A request path with the parts that vary per target or run (ids, hashes, random names) replaced by placeholders. Matching sets of rare shapes: the same target list or tool; campaigns join IPs on them as soft edges.";

/// The line of `key`: a [`LinkKind`] key, [`PATH_SHAPE`] or `paths`; `""`
/// for anything else.
pub fn help(key: &str) -> &'static str {
    match key {
        PATH_SHAPE | "paths" => PATH_SHAPE_HELP,
        _ => LinkKind::parse(key).map(kind_help).unwrap_or_default(),
    }
}

/// The line of a `host_keys.kind`; `""` for one no link kind reads.
pub fn host_help(kind: &str) -> &'static str {
    LinkKind::of_host_kind(kind)
        .map(kind_help)
        .unwrap_or_default()
}

/// The visible list: `(name, line)` of every listed fingerprint, then the
/// path shape.
pub fn entries() -> Vec<(&'static str, &'static str)> {
    LinkKind::LIST
        .into_iter()
        .map(|k| (k.name(), kind_help(k)))
        .chain([("Path shape", PATH_SHAPE_HELP)])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fingerprint_has_a_line() {
        for k in LinkKind::ALL {
            let h = kind_help(k);
            assert!(h.contains("A match") || h.contains("again"), "{k:?}: {h}");
            assert_eq!(help(k.key()), h);
        }
        assert_eq!(help("paths"), help(PATH_SHAPE));
        assert!(help(PATH_SHAPE).contains("placeholders"));
        assert_eq!(help("nope"), "");
        assert_eq!(host_help(crate::model::hostkeys::HASSH), help("hassh"));
        assert_eq!(host_help("ssh2-enum-algos"), "");
        assert_eq!(entries().len(), LinkKind::LIST.len() + 1);
    }
}
