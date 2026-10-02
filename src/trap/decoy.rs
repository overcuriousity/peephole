//! Opt-in decoys (`trap.decoys`): plausible answers to the first-stage
//! probes scanners send before they attack, so the second stage (a login
//! with harvested credentials, an exploit for the PHP version shown) lands
//! in the trap too. Nothing here is real: every credential is a canary
//! that names the request it was served to (`canary-<ref>`, the first
//! characters of that request's page token), so a later use of it can be
//! traced back to the request that harvested it.

/// A decoy answer, served with status 200.
pub struct Decoy {
    pub content_type: &'static str,
    pub body: String,
}

/// The decoy for this request, if it is one of the probes we answer.
/// `canary` is the request's reference (short, hex).
pub fn decoy(method: &str, path: &str, canary: &str) -> Option<Decoy> {
    let get = matches!(method, "GET" | "HEAD");
    let text = |body: String| {
        Some(Decoy {
            content_type: "text/plain; charset=utf-8",
            body,
        })
    };
    let html = |body: String| {
        Some(Decoy {
            content_type: "text/html; charset=UTF-8",
            body,
        })
    };
    let file = path.rsplit('/').next().unwrap_or("");
    if get && file == ".env" {
        return text(dotenv(canary));
    }
    if get && path.ends_with("/.git/config") {
        return text(git_config(canary));
    }
    if get && path.ends_with("/.git/HEAD") {
        return text("ref: refs/heads/main\n".into());
    }
    if file == "wp-login.php" && matches!(method, "GET" | "HEAD" | "POST") {
        return html(wp_login(method == "POST"));
    }
    if get
        && matches!(
            file,
            "phpinfo.php" | "info.php" | "php_info.php" | "phpinfo"
        )
    {
        return html(phpinfo());
    }
    None
}

fn dotenv(c: &str) -> String {
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

fn git_config(c: &str) -> String {
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

fn phpinfo() -> String {
    let rows = [
        (
            "System",
            "Linux web01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 x86_64",
        ),
        ("Build Date", "Nov 21 2023 19:07:44"),
        ("Server API", "Apache 2.0 Handler"),
        ("Loaded Configuration File", "/etc/php/7.4/apache2/php.ini"),
        ("PHP API", "20190902"),
        ("Zend Extension Build", "API320190902,NTS"),
        (
            "Registered PHP Streams",
            "https, ftps, compress.zlib, php, file, glob, data, http, ftp, phar",
        ),
        ("allow_url_fopen", "On"),
        ("disable_functions", "no value"),
        ("DOCUMENT_ROOT", "/var/www/html"),
        ("SERVER_SOFTWARE", "Apache/2.4.57 (Debian)"),
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

    #[test]
    fn probes_get_decoys_and_others_do_not() {
        let d = decoy("GET", "/.env", "ab12cd34ef56").unwrap();
        assert!(d.body.contains("DB_PASSWORD=canary-ab12cd34ef56"));
        assert!(d.body.contains("AKIACANARYAB12CD34EF"));
        assert!(decoy("GET", "/api/.env", "x").is_some());
        assert!(
            decoy("GET", "/.git/config", "x")
                .unwrap()
                .body
                .contains("canary-x@")
        );
        assert_eq!(
            decoy("GET", "/.git/HEAD", "x").unwrap().body,
            "ref: refs/heads/main\n"
        );
        let login = decoy("GET", "/blog/wp-login.php", "x").unwrap();
        assert!(login.body.contains("name=\"pwd\"") && !login.body.contains("login_error"));
        assert!(
            decoy("POST", "/wp-login.php", "x")
                .unwrap()
                .body
                .contains("login_error")
        );
        assert!(
            decoy("GET", "/phpinfo.php", "x")
                .unwrap()
                .body
                .contains("PHP Version")
        );
        for (m, p) in [
            ("GET", "/"),
            ("GET", "/.env.bak"),
            ("GET", "/env"),
            ("POST", "/.env"),
            ("GET", "/.git/config.bak"),
            ("GET", "/wp-login.php.bak"),
            ("DELETE", "/wp-login.php"),
        ] {
            assert!(decoy(m, p, "x").is_none(), "{m} {p}");
        }
    }
}
