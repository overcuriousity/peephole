//! The shape of a request path: its normalized form, with the parts that
//! vary per target or per run (ids, hashes, random names) replaced by
//! placeholders, so two scanners sweeping the same list share shapes even
//! when their random file names differ. Campaign clustering compares the
//! IPs' sets of shapes.

/// Version of the rules below; rows derived by an older version are derived
/// again (`requests.shape_v`, `skipped_batches.shape_v`).
pub const SHAPE_V: i64 = 1;

/// Longest shape kept, in bytes (and longest decoded path looked at).
pub const SHAPE_MAX: usize = 512;

/// Long segments that are real names, not random tokens, even when written
/// in mixed case or with digits.
pub const NOT_RANDOM: &[&str] = &[
    "administrator",
    "autodiscover",
    "configuration",
    "phpmyadmin",
    "reportserver",
    "webresource",
    "wp-content",
    "wp-includes",
    "xmlrpc",
];

/// The shape of a request path: its hash (as the derived tables store
/// values, [`crate::canary::hash`]) and its text. Total: any input gives a
/// shape of at most [`SHAPE_MAX`] bytes.
///
/// Decoded as the rules see it ([`crate::classify::normalize`]), query
/// dropped, lowercased, empty segments dropped (so `//` and a trailing `/`
/// go), and per segment: a UUID → `{uuid}`, digits → `{n}`, 8 or more hex
/// characters → `{hex}`, a long random-looking token → `{rand}`; a file
/// name has its stem replaced the same way and keeps its extension.
pub fn shape(path: &str) -> (i64, String) {
    let text = text(path);
    (crate::canary::hash(&text), text)
}

fn text(path: &str) -> String {
    let raw = path.split_once('?').map_or(path, |(p, _)| p);
    let decoded = crate::classify::normalize(raw);
    let decoded = cut(&decoded, SHAPE_MAX);
    let mut out = String::new();
    for seg in decoded.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(&segment(seg));
        if out.len() >= SHAPE_MAX {
            break;
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    cut(&out, SHAPE_MAX).to_string()
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn segment(seg: &str) -> String {
    if let Some(p) = placeholder(seg) {
        return p.into();
    }
    match seg.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => match placeholder(stem) {
            Some(p) => format!("{p}.{}", ext.to_lowercase()),
            None => seg.to_lowercase(),
        },
        _ => seg.to_lowercase(),
    }
}

/// The placeholder a whole segment (or file stem) stands for, if any. Case
/// is looked at before lowercasing: mixed case is a sign of a random token.
fn placeholder(s: &str) -> Option<&'static str> {
    let b = s.as_bytes();
    if is_uuid(b) {
        Some("{uuid}")
    } else if b.iter().all(u8::is_ascii_digit) {
        Some("{n}")
    } else if b.len() >= 8 && b.iter().all(u8::is_ascii_hexdigit) {
        Some("{hex}")
    } else if is_random(s) {
        Some("{rand}")
    } else {
        None
    }
}

fn is_uuid(b: &[u8]) -> bool {
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// 12 or more characters of letters, digits, `-` and `_` (no `.`), not a
/// known name, and either letters with digits or case changing often (more
/// than every third character: `ReportServer` is a name, `aZkQxLmPwRtY` is
/// not).
fn is_random(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 12
        || !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        || NOT_RANDOM.iter().any(|w| w.eq_ignore_ascii_case(s))
    {
        return false;
    }
    let letters = b.iter().any(u8::is_ascii_alphabetic);
    let digits = b.iter().any(u8::is_ascii_digit);
    let changes = b
        .windows(2)
        .filter(|w| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase()
        })
        .count();
    (letters && digits) || changes * 3 > b.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let cases = [
            // The root and empty forms.
            ("/", "/"),
            ("", "/"),
            ("//", "/"),
            ("/?x=1", "/"),
            // .env sweeps: kept as they are, slashes collapsed.
            ("/.env", "/.env"),
            ("/api/.env", "/api/.env"),
            ("//backend//.env/", "/backend/.env"),
            ("/.env.production", "/.env.production"),
            ("/.ENV", "/.env"),
            ("/.git/config", "/.git/config"),
            // phpunit.
            (
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "/vendor/phpunit/phpunit/src/util/php/eval-stdin.php",
            ),
            (
                "/lib/phpunit/src/Util/PHP/eval-stdin.php?cmd=id",
                "/lib/phpunit/src/util/php/eval-stdin.php",
            ),
            // Webshell names: real names kept, random ones replaced.
            ("/shell.php", "/shell.php"),
            ("/wp-content/plugins/fox.php", "/wp-content/plugins/fox.php"),
            ("/alfa.php", "/alfa.php"),
            ("/a8f3c2d1.php", "/{hex}.php"),
            ("/A8F3C2D1.PHP", "/{hex}.php"),
            ("/upload/xK9qLm2pZr7T.php", "/upload/{rand}.php"),
            ("/aZkQxLmPwRtY.jsp", "/{rand}.jsp"),
            // Ids.
            (
                "/files/0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a/view",
                "/files/{uuid}/view",
            ),
            ("/0F8E7D6C-5B4A-4392-8170-6F5E4D3C2B1A.json", "/{uuid}.json"),
            ("/user/12345", "/user/{n}"),
            ("/2024/01/backup.zip", "/{n}/{n}/backup.zip"),
            ("/123.php", "/{n}.php"),
            ("/cache/deadbeefcafebabe", "/cache/{hex}"),
            ("/abcdef1", "/abcdef1"),
            ("/token/abcdefgh12345678xyz", "/token/{rand}"),
            // Real long names stay.
            ("/wp-content/uploads/", "/wp-content/uploads"),
            ("/phpMyAdmin/index.php", "/phpmyadmin/index.php"),
            ("/PHPMYADMIN/", "/phpmyadmin"),
            ("/Administrator/", "/administrator"),
            ("/ReportServer", "/reportserver"),
            (
                "/autodiscover/autodiscover.xml",
                "/autodiscover/autodiscover.xml",
            ),
            ("/xmlrpc.php", "/xmlrpc.php"),
            ("/wp-login.php", "/wp-login.php"),
            ("/cgi-bin/luci", "/cgi-bin/luci"),
            ("/jquery-3.6.0.min.js", "/jquery-3.6.0.min.js"),
            // Decoding: percent (twice), IIS %u, overlong UTF-8.
            ("/%2e%65nv", "/.env"),
            ("/%252eenv", "/.env"),
            ("/%u002eenv", "/.env"),
            ("/%c0%ae%c0%ae/etc/passwd", "/../etc/passwd"),
            ("/a%2Fb", "/a/b"),
            // A query on a decoded path is not a query.
            ("/a%3fb", "/a?b"),
            // Not a path at all.
            ("*", "/*"),
        ];
        assert!(cases.len() >= 30);
        for (path, want) in cases {
            let (h, t) = shape(path);
            assert_eq!(t, want, "shape of {path:?}");
            assert_eq!(h, crate::canary::hash(want));
        }
    }

    #[test]
    fn not_random_names_are_lowercase_and_long() {
        for w in NOT_RANDOM {
            assert_eq!(*w, w.to_lowercase());
            assert!(w.len() >= 6, "{w}");
        }
    }

    #[test]
    fn long_paths_are_bounded() {
        for p in [
            "/a".repeat(1000),
            "/1".repeat(1000),
            format!("/{}", "x".repeat(5000)),
            "/é".repeat(1000),
            "/%ff".repeat(1000),
        ] {
            let (_, t) = shape(&p);
            assert!(t.len() <= SHAPE_MAX, "{} bytes", t.len());
            assert!(t.starts_with('/'));
        }
    }

    #[test]
    fn random_input_never_panics_and_is_bounded() {
        // A fixed xorshift so a failure reproduces.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        const ALPHABET: &[u8] = b"/%.?uUcCeE0123456789abcdefAF-_xZ\xc0\xae\xff";
        for _ in 0..5000 {
            let len = (next() % 1500) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if r % 2 == 0 {
                        ALPHABET[(r >> 8) as usize % ALPHABET.len()]
                    } else {
                        (r >> 16) as u8
                    }
                })
                .collect();
            let (h, t) = shape(&String::from_utf8_lossy(&bytes));
            assert!(t.len() <= SHAPE_MAX);
            assert!(t.starts_with('/'));
            assert_eq!(h, crate::canary::hash(&t));
        }
    }
}
