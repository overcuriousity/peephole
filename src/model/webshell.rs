//! What a request sends a webshell (`trap::webshell`), read the same by the
//! trap and by the store's public tallies.

/// The parameters a webshell reads its command from, first present wins.
const PARAMS: [&str; 8] = [
    "cmd", "c", "command", "exec", "execute", "run", "shell", "x",
];

/// The longest command kept, in bytes.
pub(crate) const MAX_CMD: usize = 256;

/// The verbs the public dashboard names; any other counts as `other`.
const VERBS: [&str; 21] = [
    "id", "whoami", "uname", "pwd", "hostname", "echo", "ls", "cat", "cd", "ps", "wget", "curl",
    "chmod", "rm", "nc", "bash", "sh", "python", "perl", "php", "base64",
];

/// The command a request sends its webshell: the first of [`PARAMS`]
/// present in the query, else in the form body, cut to [`MAX_CMD`] bytes.
pub fn extract_command(query: Option<&str>, form: Option<&[u8]>) -> Option<String> {
    let parse = |s: &[u8]| serde_urlencoded::from_bytes::<Vec<(String, String)>>(s).ok();
    let query = query.and_then(|q| parse(q.as_bytes())).unwrap_or_default();
    let form = form.and_then(parse).unwrap_or_default();
    PARAMS.iter().find_map(|name| {
        query
            .iter()
            .chain(form.iter())
            .find(|(k, _)| k == name)
            .map(|(_, v)| cut(v, MAX_CMD).to_string())
    })
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

/// The command's verb for the public dashboard: its first word without
/// its folder, lowercased, if on the list, else `other`.
pub fn verb(cmd: &str) -> &'static str {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let name = first.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    VERBS
        .iter()
        .find(|v| **v == name)
        .copied()
        .unwrap_or("other")
}
