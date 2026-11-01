//! Decoys, always on: plausible answers to the first-stage probes scanners
//! send before they attack, so the second stage lands in the trap too.
//!
//! [`choose`] decides which answer a request gets; [`render`] builds it.
//! `render` is a pure function of its [`Input`] and the answer's name, so
//! any stored decoy row can be rendered again byte for byte
//! (`peephole decoy render`). Version 1 serves canaries derived from the
//! page token ([`crate::canary`]); version 0 (rows with no `decoy_v`)
//! served `canary-<ref>`. Version 3 adds an ETag canary to the web decoys
//! that answer 200; version 4 the file-manager page; version 5 the node's
//! own AI decoy identity (`decoy_in` `"i"`, [`crate::model::ai_id`]).
pub mod ai;
pub mod llm;
pub mod mcp;
pub mod sse;

use crate::canary::site;
use crate::canary::{ETAG_DECOYS, Kind, v0_ref, value};

/// What a decoy is rendered from: all of it stored with the row.
pub struct Input<'a> {
    pub v: i64,
    pub page_token: &'a str,
    /// The request's host ([`site::request_host`]).
    pub host: Option<&'a str>,
    /// The site word the node served under ([`site::word`]), stored with
    /// the row: the node's key can change (a standalone node's history is
    /// adopted under its cluster key), the word served cannot.
    pub word: &'a str,
    /// The row's time, unix seconds.
    pub ts: i64,
    pub method: &'a str,
    pub path: &'a str,
    /// What an MCP or LLM decoy is rendered from ([`ai::DecoyIn`] as JSON).
    pub decoy_in: Option<&'a str>,
}

/// Which places of the request carried a canary this node knows.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Presented {
    /// `Authorization` (Basic, Bearer, …).
    pub basic: bool,
    pub cookie: bool,
    pub body: bool,
}

/// A decoy answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoy {
    /// As recorded in `answer` after `decoy:`.
    pub name: String,
    pub status: u16,
    /// Lower-case names; `content-type` always first.
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=UTF-8";
/// WordPress's login cookie lifetime without "remember me".
const WP_SESSION_SECS: i64 = 172_800;

/// A file manager's landing page, as the probes before an upload ask for
/// it: answered with an upload form even from a tarpitted source, or the
/// probe would never get to the upload. Curated: no shell names, no other
/// `*.php`, or the webshell probes would read as answered.
pub fn file_manager(method: &str, path: &str, query: Option<&str>) -> bool {
    if !matches!(method, "GET" | "HEAD") {
        return false;
    }
    let file = path.rsplit('/').next().unwrap_or("");
    matches!(
        file,
        "wp_filemanager.php" | "elfinder.html" | "elfinder.php"
    ) || (path.ends_with("/wp-admin/admin.php")
        && query.is_some_and(|q| q.split('&').any(|kv| kv == "page=wp_file_manager")))
}

/// The answer for this request, first match wins: the wp-login POST,
/// the file-manager page, wp-admin and git routes; a canary in
/// `Authorization`; the probe decoys. None: the trap 404.
pub fn choose(
    method: &str,
    path: &str,
    query: Option<&str>,
    p: Presented,
    word: &str,
) -> Option<&'static str> {
    let get = matches!(method, "GET" | "HEAD");
    let file = path.rsplit('/').next().unwrap_or("");
    let repo = format!("/git/{word}.git");
    if method == "POST" && file == "wp-login.php" && p.body {
        return Some("wp-login-ok");
    }
    if file_manager(method, path, query) {
        return Some("file-manager");
    }
    if get && (path == "/wp-admin" || path.starts_with("/wp-admin/")) && p.cookie {
        return Some("wp-admin");
    }
    if get
        && path == format!("{repo}/info/refs")
        && query.is_some_and(|q| q.split('&').any(|kv| kv == "service=git-upload-pack"))
    {
        return Some(if p.basic { "git-refs" } else { "git-auth" });
    }
    if method == "POST" && path == format!("{repo}/git-upload-pack") && p.basic {
        return Some("git-pack");
    }
    if p.basic {
        return Some("admin");
    }
    if get && file == ".env" {
        return Some("dotenv");
    }
    if get && path.ends_with("/.git/config") {
        return Some("git-config");
    }
    if get && path.ends_with("/.git/HEAD") {
        return Some("git-head");
    }
    if file == "wp-login.php" && matches!(method, "GET" | "HEAD" | "POST") {
        return Some(if method == "POST" {
            "wp-login-failed"
        } else {
            "wp-login"
        });
    }
    if get
        && matches!(
            file,
            "phpinfo.php" | "info.php" | "php_info.php" | "phpinfo"
        )
    {
        return Some("phpinfo");
    }
    None
}

/// Whether the trap answers this request itself, so that a file dropped at
/// its path does not take it over: the landing page, or a decoy for what
/// this request presented. `p` and `word` as for [`choose`].
pub fn answers_itself(
    method: &str,
    path: &str,
    query: Option<&str>,
    p: Presented,
    word: &str,
) -> bool {
    path == "/" || choose(method, path, query, p, word).is_some()
}

/// Each [`Presented`] that can change an answer, on its own: the trap can
/// find them together, but no rule of [`choose`] asks for two. The trap
/// looks for a cookie canary under `/wp-admin`, a body canary on a wp-login
/// POST and a Basic one anywhere (`trap::credentials`).
const EVERY: [Presented; 4] = [
    Presented {
        basic: false,
        cookie: false,
        body: false,
    },
    Presented {
        basic: true,
        cookie: false,
        body: false,
    },
    Presented {
        basic: false,
        cookie: true,
        body: false,
    },
    Presented {
        basic: false,
        cookie: false,
        body: true,
    },
];

/// Whether the trap has an answer of its own for this path, whoever asks:
/// [`answers_itself`] under each thing the trap can find presented. For
/// rows read later, which keep neither the presentation nor, for most, the
/// site word: the answer here is about the path, so the trap itself, which
/// knows both, asks [`answers_itself`], and a dropped file at
/// `/wp-admin/x.php` keeps answering a request with no canary cookie. The
/// `admin` page does not count: a Basic canary opens it on any path, which
/// says something of the request and nothing of the path.
pub fn keeps_its_own_answer(method: &str, path: &str, query: Option<&str>) -> bool {
    // Any repository is taken for the node's: the word is not in the row.
    let word = path
        .strip_prefix("/git/")
        .and_then(|r| r.split_once(".git/"))
        .map_or("", |(w, _)| w);
    path == "/"
        || EVERY
            .into_iter()
            .any(|p| choose(method, path, query, p, word).is_some_and(|name| name != "admin"))
}

/// The decoy `name` as version `inp.v` renders it (None: unknown).
pub fn render(inp: &Input, name: &str) -> Option<Decoy> {
    if inp.v >= 2 {
        let d = ai::DecoyIn::parse(inp.decoy_in);
        if let Some(n) = name.strip_prefix("mcp:") {
            return mcp::render(inp, &d, n);
        }
        if let Some(n) = name.strip_prefix("llm:") {
            return llm::render(inp, &d, n);
        }
    }
    let (status, mut headers, body): (u16, Vec<(&'static str, String)>, String) = match inp.v {
        0 => {
            let r = v0_ref(inp.page_token);
            match name {
                "dotenv" => (200, ct(TEXT), v0_dotenv(&r)),
                "git-config" => (200, ct(TEXT), v0_git_config(&r)),
                "git-head" => (200, ct(TEXT), "ref: refs/heads/main\n".into()),
                "wp-login" => (200, ct(HTML), wp_login(false)),
                "wp-login-failed" => (200, ct(HTML), wp_login(true)),
                "phpinfo" => (200, ct(HTML), phpinfo("web01", APACHE)),
                _ => return None,
            }
        }
        1..=5 => {
            let word = inp.word;
            let site_name = format!("{word}.internal");
            match name {
                "dotenv" => (200, ct(TEXT), dotenv_text(inp)),
                "git-config" => (200, ct(TEXT), git_config_text(inp)),
                "git-head" => (200, ct(TEXT), "ref: refs/heads/main\n".into()),
                "wp-login" => (200, ct(HTML), wp_login(false)),
                "wp-login-failed" => (200, ct(HTML), wp_login(true)),
                "wp-login-ok" => (
                    302,
                    vec![
                        ("content-type", HTML.into()),
                        ("location", "/wp-admin/".into()),
                        ("set-cookie", wp_cookie(inp.page_token, &site_name, inp.ts)),
                    ],
                    String::new(),
                ),
                "wp-admin" => (200, ct(HTML), wp_admin(word)),
                "admin" => (200, ct(HTML), admin_page(word)),
                "git-auth" => (
                    401,
                    vec![
                        ("content-type", TEXT.into()),
                        ("www-authenticate", "Basic realm=\"Git\"".into()),
                    ],
                    "Unauthorized\n".into(),
                ),
                "git-refs" => (
                    200,
                    vec![
                        (
                            "content-type",
                            "application/x-git-upload-pack-advertisement".into(),
                        ),
                        ("cache-control", "no-cache".into()),
                    ],
                    git_refs(&site_name),
                ),
                "git-pack" => (500, ct(TEXT), String::new()),
                "phpinfo" => (200, ct(HTML), phpinfo(word, server_software(inp))),
                "file-manager" if inp.v >= 4 => (200, ct(HTML), FILE_MANAGER.into()),
                _ => return None,
            }
        }
        _ => return None,
    };
    if inp.v >= 3 && ETAG_DECOYS.contains(&name) {
        headers.push(("etag", format!("\"{}\"", value(inp.page_token, Kind::Etag))));
    }
    Some(Decoy {
        name: name.to_string(),
        status,
        headers,
        body,
    })
}

/// The version-1 `.env` body for this request.
pub(super) fn dotenv_text(inp: &Input) -> String {
    let site_name = format!("{}.internal", inp.word);
    let ret = site::return_host(inp.host, &site_name);
    v1_dotenv(inp.page_token, inp.word, &site_name, &ret)
}

/// The version-1 `.git/config` body for this request.
pub(super) fn git_config_text(inp: &Input) -> String {
    let site_name = format!("{}.internal", inp.word);
    let ret = site::return_host(inp.host, &site_name);
    v1_git_config(inp.page_token, inp.word, &ret)
}

pub(super) fn ct(v: &str) -> Vec<(&'static str, String)> {
    vec![("content-type", v.to_string())]
}

pub(super) fn hex(data: &[u8], n: usize) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect::<String>()[..n].to_string()
}

fn v1_dotenv(tok: &str, word: &str, site_name: &str, ret: &str) -> String {
    let v = |k| value(tok, k);
    let mut name = word.to_string();
    name[..1].make_ascii_uppercase();
    format!(
        "APP_NAME={name}
APP_ENV=production
APP_KEY=base64:{app}
APP_DEBUG=false
APP_URL=https://{site_name}

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE={word}_production
DB_USERNAME={word}
DB_PASSWORD={db}

REDIS_HOST=127.0.0.1
REDIS_PASSWORD={redis}
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.{site_name}
MAIL_PORT=587
MAIL_USERNAME=noreply@{site_name}
MAIL_PASSWORD={mail}
MAIL_FROM_ADDRESS=noreply@{site_name}

AWS_ACCESS_KEY_ID={aws_key}
AWS_SECRET_ACCESS_KEY={aws_secret}
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET={word}-uploads

ADMIN_URL=http://{ret}/admin/
ADMIN_USER=admin
ADMIN_PASSWORD={admin}
",
        app = v(Kind::AppKey),
        db = v(Kind::DbPassword),
        redis = v(Kind::RedisPassword),
        mail = v(Kind::MailPassword),
        aws_key = v(Kind::AwsKey),
        aws_secret = v(Kind::AwsSecret),
        admin = v(Kind::AdminPassword),
    )
}

fn v1_git_config(tok: &str, word: &str, ret: &str) -> String {
    format!(
        "[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote \"origin\"]
\turl = http://deploy:{token}@{ret}/git/{word}.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch \"main\"]
\tremote = origin
\tmerge = refs/heads/main
",
        token = value(tok, Kind::GitToken)
    )
}

/// `wordpress_logged_in_<hash>=admin|<expiry>|<token>|<hmac>`, as WordPress
/// builds it; the token is the canary.
fn wp_cookie(tok: &str, site_name: &str, ts: i64) -> String {
    let exp = ts + WP_SESSION_SECS;
    let token = value(tok, Kind::WpSession);
    let mac = hex(format!("admin|{exp}|{token}").as_bytes(), 64);
    format!(
        "wordpress_logged_in_{}=admin%7C{exp}%7C{token}%7C{mac}; path=/; HttpOnly",
        hex(format!("https://{site_name}").as_bytes(), 32)
    )
}

fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

fn git_refs(site_name: &str) -> String {
    let main = hex(format!("{site_name} refs/heads/main").as_bytes(), 40);
    let tag = hex(format!("{site_name} refs/tags/v1.4.2").as_bytes(), 40);
    let mut out = pkt("# service=git-upload-pack\n");
    out.push_str("0000");
    out.push_str(&pkt(&format!(
        "{main} HEAD\0multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main agent=git/2.39.2\n"
    )));
    out.push_str(&pkt(&format!("{main} refs/heads/main\n")));
    out.push_str(&pkt(&format!("{tag} refs/tags/v1.4.2\n")));
    out.push_str("0000");
    out
}

fn wp_admin(word: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Dashboard &lsaquo; {word} &#8212; WordPress</title>
<meta name="robots" content="noindex, noarchive">
</head>
<body class="wp-admin wp-core-ui no-js index-php">
<div id="wpwrap"><div id="adminmenumain"><ul id="adminmenu">
<li><a href="index.php">Dashboard</a></li><li><a href="edit.php">Posts</a></li><li><a href="upload.php">Media</a></li>
<li><a href="plugins.php">Plugins</a></li><li><a href="users.php">Users</a></li><li><a href="options-general.php">Settings</a></li>
</ul></div>
<div id="wpcontent"><div id="wpbody-content"><div class="wrap"><h1>Dashboard</h1>
<div id="welcome-panel" class="welcome-panel"><h2>Welcome to WordPress!</h2></div>
</div></div></div></div>
</body>
</html>
"#
    )
}

/// WordPress's page after a plugin or theme zip upload (`what`: `Plugin`
/// or `Theme`). The upload sink's answer (`trap::upload`); it names no
/// file, so nothing of the upload is in it.
pub fn wp_installed(what: &str, word: &str) -> String {
    let lower = what.to_ascii_lowercase();
    format!(
        r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Update {what} &lsaquo; {word} &#8212; WordPress</title>
<meta name="robots" content="noindex, noarchive">
</head>
<body class="wp-admin wp-core-ui no-js update-php">
<div id="wpwrap"><div id="wpcontent"><div id="wpbody-content"><div class="wrap">
<h1>Installing {what} from uploaded file</h1>
<p>Unpacking the package&#8230;</p>
<p>Installing the {lower}&#8230;</p>
<p>{what} installed successfully.</p>
</div></div></div></div>
</body>
</html>
"#
    )
}

/// WordPress's `async-upload.php` answer for a media file at `url`.
pub fn wp_media_json(url: &str) -> String {
    serde_json::json!({ "success": true, "data": { "url": url } }).to_string()
}

fn admin_page(word: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{word} — Administration</title><meta name="robots" content="noindex"></head>
<body>
<header><h1>{word} administration</h1><nav><a href="users">Users</a> · <a href="orders">Orders</a> · <a href="settings">Settings</a> · <a href="logs">Logs</a></nav></header>
<main><p>Signed in as admin.</p><table><tr><th>Queue</th><td>0 pending</td></tr><tr><th>Cache</th><td>warm</td></tr></table></main>
</body>
</html>
"#
    )
}

fn v0_dotenv(c: &str) -> String {
    format!(
        "APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:Y2FuYXJ5LW5vdC1hLXJlYWwta2V5LTAwMDAwMDAwMDA=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=app
DB_PASSWORD=canary-{c}

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=canary-{c}
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.invalid
MAIL_PORT=587
MAIL_USERNAME=noreply@example.invalid
MAIL_PASSWORD=canary-{c}

AWS_ACCESS_KEY_ID=AKIACANARY{c10}
AWS_SECRET_ACCESS_KEY=canary/{c}/not+a+real+secret
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=app-uploads
",
        c10 = c.to_ascii_uppercase().chars().take(10).collect::<String>()
    )
}

fn v0_git_config(c: &str) -> String {
    format!(
        "[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote \"origin\"]
\turl = https://deploy:canary-{c}@git.example.invalid/web/site.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch \"main\"]
\tremote = origin
\tmerge = refs/heads/main
"
    )
}

fn wp_login(failed: bool) -> String {
    let error = if failed {
        "<div id=\"login_error\"><strong>Error:</strong> The password you entered for that \
         username is incorrect. <a href=\"wp-login.php?action=lostpassword\">Lost your \
         password?</a><br></div>"
    } else {
        ""
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Log In &lsaquo; Site &#8212; WordPress</title>
<meta name="robots" content="max-image-preview:large, noindex, noarchive">
<meta name="viewport" content="width=device-width">
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{error}
<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required"></p>
<div class="user-pass-wrap"><label for="user_pass">Password</label>
<div class="wp-pwd"><input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required"></div></div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1"></p>
</form>
<p id="nav"><a href="wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body>
</html>
"#
    )
}

/// The file-manager page: fixed, whatever was uploaded before. Its form
/// posts to an upload script `upload::detect` takes.
const FILE_MANAGER: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>File Manager</title>
<link rel="stylesheet" href="css/elfinder.min.css">
</head>
<body>
<div id="elfinder">
<h3>File Manager</h3>
<form action="/filemanager/upload.php" method="post" enctype="multipart/form-data">
<input type="hidden" name="cmd" value="upload">
<input type="hidden" name="target" value="l1_Lw">
<input type="file" name="upload[]" multiple>
<input type="submit" value="Upload">
</form>
</div>
</body>
</html>
"#;

/// `SERVER_SOFTWARE` before personas, and for a row without one.
const APACHE: &str = "Apache/2.4.57 (Debian)";

/// The phpinfo decoy's `SERVER_SOFTWARE`: the persona's (decoy version 5,
/// `decoy_in` `"p"`), else [`APACHE`].
fn server_software(inp: &Input) -> &'static str {
    if inp.v < 5 {
        return APACHE;
    }
    ai::DecoyIn::parse(inp.decoy_in)
        .p
        .as_deref()
        .and_then(crate::trap::persona::by_name)
        .map_or(APACHE, |p| p.server_software())
}

/// The `decoy_in` a decoy outside the AI decoys is rendered from under
/// `persona` (None: it does not depend on the persona).
pub fn persona_in(name: &str, persona: &str) -> Option<String> {
    (name == "phpinfo").then(|| {
        ai::DecoyIn {
            p: Some(persona.to_string()),
            ..Default::default()
        }
        .to_json()
    })
}

fn phpinfo(host: &str, server_software: &str) -> String {
    let rows = [
        (
            "System",
            format!("Linux {host} 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 x86_64"),
        ),
        ("Build Date", "Nov 21 2023 19:07:44".to_string()),
        ("Server API", "Apache 2.0 Handler".to_string()),
        (
            "Loaded Configuration File",
            "/etc/php/7.4/apache2/php.ini".to_string(),
        ),
        ("PHP API", "20190902".to_string()),
        ("Zend Extension Build", "API320190902,NTS".to_string()),
        (
            "Registered PHP Streams",
            "https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar".to_string(),
        ),
        ("allow_url_fopen", "On".to_string()),
        ("disable_functions", "no value".to_string()),
        ("DOCUMENT_ROOT", "/var/www/html".to_string()),
        ("SERVER_SOFTWARE", server_software.to_string()),
    ];
    let mut body = String::from(
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"DTD/xhtml1-transitional.dtd\">\n\
         <html xmlns=\"http://www.w3.org/1999/xhtml\"><head>\n\
         <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n\
         <title>PHP 7.4.33 - phpinfo()</title><meta name=\"ROBOTS\" content=\"NOINDEX,NOFOLLOW,NOARCHIVE\" /></head>\n\
         <body><div class=\"center\">\n\
         <table><tr class=\"h\"><td><h1 class=\"p\">PHP Version 7.4.33</h1></td></tr></table>\n<table>\n",
    );
    for (k, v) in rows {
        body.push_str(&format!(
            "<tr><td class=\"e\">{k} </td><td class=\"v\">{v} </td></tr>\n"
        ));
    }
    body.push_str("</table>\n</div></body></html>\n");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";
    const NODE: [u8; 32] = [7; 32];

    fn inp<'a>(v: i64, host: Option<&'a str>, method: &'a str, path: &'a str) -> Input<'a> {
        Input {
            v,
            page_token: TOK,
            host,
            word: crate::canary::site::word(Some(&NODE)),
            ts: 1_791_000_000,
            method,
            path,
            decoy_in: None,
        }
    }

    #[test]
    fn version_two_renders_every_version_one_name_unchanged() {
        for name in [
            "dotenv",
            "git-config",
            "git-head",
            "wp-login",
            "wp-login-failed",
            "wp-login-ok",
            "wp-admin",
            "admin",
            "git-auth",
            "git-refs",
            "git-pack",
            "phpinfo",
        ] {
            let one = inp(1, None, "GET", "/");
            let two = inp(2, None, "GET", "/");
            assert_eq!(render(&one, name), render(&two, name), "{name}");
            let (three, four) = (inp(3, None, "GET", "/"), inp(4, None, "GET", "/"));
            assert_eq!(render(&three, name), render(&four, name), "{name}");
            assert_eq!(
                render(&four, name),
                render(&inp(5, None, "GET", "/"), name),
                "{name}"
            );
        }
        assert_eq!(render(&inp(3, None, "GET", "/"), "file-manager"), None);
    }

    #[test]
    fn file_manager_answers_its_landing_pages_only() {
        let n = crate::canary::site::word(Some(&NODE));
        for (m, p, q) in [
            ("GET", "/hellopress/wp_filemanager.php", None),
            ("HEAD", "/wp_filemanager.php", None),
            ("GET", "/elfinder/elfinder.html", None),
            ("GET", "/admin/elfinder/elfinder.php", None),
            ("GET", "/wp-admin/admin.php", Some("page=wp_file_manager")),
        ] {
            assert_eq!(choose(m, p, q, none(), n), Some("file-manager"), "{p}");
        }
        for (m, p, q) in [
            ("POST", "/wp_filemanager.php", None),
            ("GET", "/filemanager.php", None),
            ("GET", "/shell.php", None),
            ("GET", "/wp-admin/admin.php", Some("page=other")),
        ] {
            assert_eq!(choose(m, p, q, none(), n), None, "{m} {p}");
        }
        // Its form posts where an upload is taken.
        let d = render(&inp(4, None, "GET", "/wp_filemanager.php"), "file-manager").unwrap();
        let action = d
            .body
            .split("action=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(
            crate::trap::upload::detect("POST", action, None, Some("multipart/form-data; b=x")),
            Some(crate::trap::upload::Kind::Script)
        );
    }

    #[test]
    fn decoy_input_round_trips_and_stays_small() {
        use ai::DecoyIn;
        let d = DecoyIn {
            rpc: Some(serde_json::json!(7)),
            m: Some("tools/call".into()),
            arg: Some("x".repeat(128)),
            model: Some("m".repeat(128)),
            tool: Some("t".repeat(64)),
            deployment: Some("d".repeat(64)),
            ..Default::default()
        };
        let s = d.to_json();
        assert!(s.len() <= ai::MAX_LEN, "{}", s.len());
        assert_eq!(DecoyIn::parse(Some(&s)).rpc, d.rpc);
        assert_eq!(DecoyIn::parse(Some("not json")), DecoyIn::default());
        assert_eq!(DecoyIn::parse(None), DecoyIn::default());
    }

    fn none() -> Presented {
        Presented::default()
    }

    #[test]
    fn choose_keeps_todays_answers_without_a_canary() {
        let n = crate::canary::site::word(Some(&NODE));
        assert_eq!(choose("GET", "/.env", None, none(), n), Some("dotenv"));
        assert_eq!(choose("GET", "/api/.env", None, none(), n), Some("dotenv"));
        assert_eq!(
            choose("GET", "/.git/config", None, none(), n),
            Some("git-config")
        );
        assert_eq!(
            choose("GET", "/.git/HEAD", None, none(), n),
            Some("git-head")
        );
        assert_eq!(
            choose("GET", "/blog/wp-login.php", None, none(), n),
            Some("wp-login")
        );
        assert_eq!(
            choose("POST", "/wp-login.php", None, none(), n),
            Some("wp-login-failed")
        );
        assert_eq!(
            choose("GET", "/phpinfo.php", None, none(), n),
            Some("phpinfo")
        );
        for (m, p) in [
            ("GET", "/"),
            ("GET", "/.env.bak"),
            ("POST", "/.env"),
            ("GET", "/wp-admin/"),
            ("GET", "/admin/"),
            ("DELETE", "/wp-login.php"),
        ] {
            assert_eq!(choose(m, p, None, none(), n), None, "{m} {p}");
        }
    }

    #[test]
    fn choose_with_canaries_follows_the_spec_precedence() {
        let n = crate::canary::site::word(Some(&NODE));
        let repo = format!("/git/{n}.git");
        let basic = Presented {
            basic: true,
            ..none()
        };
        let cookie = Presented {
            cookie: true,
            ..none()
        };
        let body = Presented {
            body: true,
            ..none()
        };
        assert_eq!(
            choose("POST", "/wp-login.php", None, body, n),
            Some("wp-login-ok")
        );
        assert_eq!(
            choose("GET", "/wp-admin/", None, cookie, n),
            Some("wp-admin")
        );
        assert_eq!(
            choose("GET", "/wp-admin/index.php", None, cookie, n),
            Some("wp-admin")
        );
        assert_eq!(choose("GET", "/admin/", None, basic, n), Some("admin"));
        assert_eq!(
            choose("GET", "/.env", None, basic, n),
            Some("admin"),
            "Basic canary before path decoys"
        );
        let refs = format!("{repo}/info/refs");
        let svc = Some("service=git-upload-pack");
        assert_eq!(choose("GET", &refs, svc, none(), n), Some("git-auth"));
        assert_eq!(choose("GET", &refs, svc, basic, n), Some("git-refs"));
        assert_eq!(
            choose("GET", &refs, None, none(), n),
            None,
            "dumb HTTP is not served"
        );
        assert_eq!(
            choose("GET", "/git/other.git/info/refs", svc, none(), n),
            None
        );
        let pack = format!("{repo}/git-upload-pack");
        assert_eq!(choose("POST", &pack, None, basic, n), Some("git-pack"));
        assert_eq!(choose("POST", &pack, None, none(), n), None);
    }

    #[test]
    fn a_path_keeps_its_answer_under_any_presentation() {
        let n = crate::canary::site::word(Some(&NODE));
        let refs = format!("/git/{n}.git/info/refs");
        let pack = format!("/git/{n}.git/git-upload-pack");
        let svc = Some("service=git-upload-pack");
        let page = Some("page=wp_file_manager");
        for (m, p, q) in [
            ("GET", "/", None),
            ("POST", "/", None),
            ("PUT", "/", None),
            // No presentation needed.
            ("GET", "/.env", None),
            ("HEAD", "/api/.env", None),
            ("GET", "/.git/config", None),
            ("GET", "/.git/HEAD", None),
            ("GET", "/blog/wp-login.php", None),
            ("POST", "/wp-login.php", None),
            ("GET", "/phpinfo.php", None),
            ("GET", "/elfinder.html", None),
            ("GET", "/wp-admin/admin.php", page),
            ("GET", refs.as_str(), svc),
            // A cookie canary.
            ("GET", "/wp-admin", None),
            ("GET", "/wp-admin/", None),
            ("HEAD", "/wp-admin/x.php", None),
            // A Basic canary.
            ("POST", pack.as_str(), None),
            // The site word is the node's: any repository is one.
            ("GET", "/git/other.git/info/refs", svc),
            ("POST", "/git/other.git/git-upload-pack", None),
        ] {
            assert!(keeps_its_own_answer(m, p, q), "{m} {p} {q:?}");
        }
    }

    #[test]
    fn a_path_with_no_answer_of_its_own_is_the_files() {
        // `Presented::basic` answers any path with the admin page: that
        // says something of the request, nothing of the path.
        let n = crate::canary::site::word(Some(&NODE));
        assert_eq!(choose("GET", "/up/a.php", None, EVERY[1], n), Some("admin"));
        for (m, p, q) in [
            ("GET", "/up/a.php", None),
            ("POST", "/up/a.php", Some("cmd=id")),
            ("POST", "/.env", None),
            ("PUT", "/.env", None),
            ("PUT", "/wp-admin/x.php", None),
            ("DELETE", "/wp-login.php", None),
            ("GET", "/git/other.git/info/refs", None),
            ("GET", "/git/.git/config.php", None),
            ("POST", "/git/a.git/b.git/git-upload-pack", None),
        ] {
            assert!(!keeps_its_own_answer(m, p, q), "{m} {p} {q:?}");
        }
    }

    #[test]
    fn what_the_trap_answers_is_also_kept() {
        let n = crate::canary::site::word(Some(&NODE));
        let refs = format!("/git/{n}.git/info/refs");
        let pack = format!("/git/{n}.git/git-upload-pack");
        for (m, p) in [
            ("GET", "/"),
            ("GET", "/.env"),
            ("POST", "/wp-login.php"),
            ("GET", "/wp-admin/x.php"),
            ("GET", refs.as_str()),
            ("POST", pack.as_str()),
        ] {
            for presented in EVERY {
                let q = Some("service=git-upload-pack");
                if answers_itself(m, p, q, presented, n) {
                    assert!(keeps_its_own_answer(m, p, q), "{m} {p} {presented:?}");
                }
            }
        }
    }

    #[test]
    fn the_trap_decides_by_what_this_request_presented() {
        let n = crate::canary::site::word(Some(&NODE));
        let pack = format!("/git/{n}.git/git-upload-pack");
        // As before the check moved here: a dropped file answers unless
        // this request's own presentation gets a decoy.
        for (m, p, unlocks) in [
            ("GET", "/wp-admin/x.php", EVERY[2]),
            ("POST", pack.as_str(), EVERY[1]),
            ("GET", "/up/a.php", EVERY[1]),
        ] {
            assert!(!answers_itself(m, p, None, EVERY[0], n), "{m} {p}");
            assert!(answers_itself(m, p, None, unlocks, n), "{m} {p}");
        }
        assert!(answers_itself("GET", "/", None, EVERY[0], n));
        assert!(answers_itself("GET", "/.env", None, EVERY[0], n));
        // A word that is not this node's is no route here.
        assert!(!answers_itself(
            "GET",
            "/git/other.git/info/refs",
            Some("service=git-upload-pack"),
            EVERY[0],
            n
        ));
    }

    #[test]
    fn v1_dotenv_carries_derived_secrets_and_return_links() {
        let d = render(&inp(1, Some("203.0.113.7"), "GET", "/.env"), "dotenv").unwrap();
        assert_eq!((d.status, d.name.as_str()), (200, "dotenv"));
        let site = crate::canary::site::site(Some(&NODE));
        assert!(d.body.contains(&format!("APP_URL=https://{site}\n")));
        assert!(d.body.contains("ADMIN_URL=http://203.0.113.7/admin/\n"));
        for kind in [
            Kind::DbPassword,
            Kind::AwsKey,
            Kind::AwsSecret,
            Kind::AdminPassword,
            Kind::RedisPassword,
            Kind::MailPassword,
        ] {
            assert!(d.body.contains(&value(TOK, kind)), "{kind:?}");
        }
        assert!(
            d.body
                .contains(&format!("APP_KEY=base64:{}\n", value(TOK, Kind::AppKey)))
        );
        assert!(!d.body.to_ascii_lowercase().contains("canary"));
        let local = render(&inp(1, Some("localhost"), "GET", "/.env"), "dotenv").unwrap();
        assert!(
            local
                .body
                .contains(&format!("ADMIN_URL=http://{site}/admin/\n"))
        );
    }

    #[test]
    fn v1_git_config_points_back_with_the_token() {
        let d = render(
            &inp(1, Some("forensics.cc24.dev"), "GET", "/.git/config"),
            "git-config",
        )
        .unwrap();
        let w = crate::canary::site::word(Some(&NODE));
        assert!(d.body.contains(&format!(
            "url = http://deploy:{}@forensics.cc24.dev/git/{w}.git\n",
            value(TOK, Kind::GitToken)
        )));
    }

    #[test]
    fn wp_login_ok_sets_a_canary_session_cookie() {
        let d = render(&inp(1, None, "POST", "/wp-login.php"), "wp-login-ok").unwrap();
        assert_eq!(d.status, 302);
        assert!(d.headers.contains(&("location", "/wp-admin/".to_string())));
        let cookie = &d
            .headers
            .iter()
            .find(|(k, _)| *k == "set-cookie")
            .unwrap()
            .1;
        assert!(cookie.starts_with("wordpress_logged_in_"));
        assert!(cookie.contains(&format!(
            "admin%7C{}%7C{}%7C",
            1_791_000_000 + 172_800,
            value(TOK, Kind::WpSession)
        )));
    }

    #[test]
    fn git_routes_challenge_then_answer() {
        let a = render(&inp(1, None, "GET", "/git/x.git/info/refs"), "git-auth").unwrap();
        assert_eq!(a.status, 401);
        assert!(
            a.headers
                .contains(&("www-authenticate", "Basic realm=\"Git\"".to_string()))
        );
        let r = render(&inp(1, None, "GET", "/git/x.git/info/refs"), "git-refs").unwrap();
        assert_eq!(r.status, 200);
        assert!(r.body.starts_with("001e# service=git-upload-pack\n0000"));
        assert!(r.body.contains(" refs/heads/main\n"));
        assert!(r.body.ends_with("0000"));
        // Every pkt-line length is right.
        let mut rest = &r.body["001e# service=git-upload-pack\n0000".len()..];
        while rest != "0000" {
            let n = usize::from_str_radix(&rest[..4], 16).unwrap();
            rest = &rest[n..];
        }
        assert_eq!(
            render(
                &inp(1, None, "POST", "/git/x.git/git-upload-pack"),
                "git-pack"
            )
            .unwrap()
            .status,
            500
        );
    }

    #[test]
    fn version_zero_renders_todays_bodies() {
        let d = render(&inp(0, None, "GET", "/.env"), "dotenv").unwrap();
        assert!(d.body.contains("DB_PASSWORD=canary-0f8e7d6c5b4a\n"));
        assert!(d.body.contains("AWS_ACCESS_KEY_ID=AKIACANARY0F8E7D6C5B\n"));
        let g = render(&inp(0, None, "GET", "/.git/config"), "git-config").unwrap();
        assert!(
            g.body
                .contains("deploy:canary-0f8e7d6c5b4a@git.example.invalid")
        );
        assert!(
            render(&inp(0, None, "GET", "/x"), "wp-admin").is_none(),
            "v0 had no wp-admin"
        );
        assert!(render(&inp(6, None, "GET", "/.env"), "dotenv").is_none());
    }

    #[test]
    fn phpinfo_server_software_follows_the_persona_in_decoy_in() {
        let soft = |v: i64, din: Option<&str>| {
            let d = render(
                &Input {
                    decoy_in: din,
                    ..inp(v, None, "GET", "/phpinfo.php")
                },
                "phpinfo",
            )
            .unwrap();
            let at = d.body.find("SERVER_SOFTWARE").unwrap();
            d.body[at..].split("class=\"v\">").nth(1).unwrap()[..24].to_string()
        };
        for p in &crate::trap::persona::ALL {
            let din = persona_in("phpinfo", p.name).unwrap();
            assert!(
                soft(5, Some(&din)).starts_with(p.server_software()),
                "{}",
                p.name
            );
            // Version 4 knew no persona.
            assert!(soft(4, Some(&din)).starts_with(APACHE));
        }
        // A version-5 row without "p" (written before personas rendered).
        assert!(soft(5, None).starts_with(APACHE));
        assert!(soft(5, Some(r#"{"p":"nope"}"#)).starts_with(APACHE));
        assert_eq!(persona_in("dotenv", "gitlab"), None);
    }

    #[test]
    fn golden_decoys() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decoys");
        let bless = std::env::var_os("PEEPHOLE_BLESS").is_some();
        let cases: &[(i64, &str, &str, &str)] = &[
            (0, "GET", "/.env", "dotenv"),
            (0, "GET", "/.git/config", "git-config"),
            (0, "GET", "/.git/HEAD", "git-head"),
            (0, "GET", "/wp-login.php", "wp-login"),
            (0, "POST", "/wp-login.php", "wp-login-failed"),
            (0, "GET", "/phpinfo.php", "phpinfo"),
            (1, "GET", "/.env", "dotenv"),
            (1, "GET", "/.git/config", "git-config"),
            (1, "GET", "/.git/HEAD", "git-head"),
            (1, "GET", "/wp-login.php", "wp-login"),
            (1, "POST", "/wp-login.php", "wp-login-failed"),
            (1, "POST", "/wp-login.php", "wp-login-ok"),
            (1, "GET", "/wp-admin/", "wp-admin"),
            (1, "GET", "/admin/", "admin"),
            (1, "GET", "/git/x.git/info/refs", "git-auth"),
            (1, "GET", "/git/x.git/info/refs", "git-refs"),
            (1, "POST", "/git/x.git/git-upload-pack", "git-pack"),
            (1, "GET", "/phpinfo.php", "phpinfo"),
            (3, "GET", "/.env", "dotenv"),
            (3, "GET", "/.git/config", "git-config"),
            (3, "GET", "/.git/HEAD", "git-head"),
            (3, "GET", "/wp-login.php", "wp-login"),
            (3, "POST", "/wp-login.php", "wp-login-failed"),
            (3, "GET", "/wp-admin/", "wp-admin"),
            (3, "GET", "/admin/", "admin"),
            (3, "GET", "/git/x.git/info/refs", "git-refs"),
            (3, "GET", "/phpinfo.php", "phpinfo"),
            (3, "POST", "/wp-login.php", "wp-login-ok"),
            (3, "POST", "/git/x.git/git-upload-pack", "git-pack"),
            (4, "GET", "/wp_filemanager.php", "file-manager"),
        ];
        for (v, m, p, name) in cases {
            let d = render(&inp(*v, Some("203.0.113.7"), m, p), name).unwrap();
            let mut text = format!("{}\n", d.status);
            for (k, val) in &d.headers {
                text.push_str(&format!("{k}: {val}\n"));
            }
            text.push('\n');
            text.push_str(&d.body);
            let file = dir.join(format!("v{v}-{name}.txt"));
            if bless {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&file, &text).unwrap();
            }
            let want = std::fs::read_to_string(&file).unwrap_or_else(|_| {
                panic!("{} missing: run with PEEPHOLE_BLESS=1", file.display())
            });
            assert_eq!(
                text,
                want,
                "{} changed: bump DECOY_V instead",
                file.display()
            );
        }
    }
}
