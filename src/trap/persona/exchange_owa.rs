//! A corporate webmail logon page on a Windows mail server.
use super::Persona;

pub const PERSONA: Persona = Persona {
    name: "exchange-owa",
    product: "Exchange Server 2019 OWA",
    server: Some("Microsoft-IIS/10.0"),
    extra_headers: &[("x-powered-by", "ASP.NET")],
    landing,
    mcp_servers: &[
        "mail-ops",
        "exch-admin",
        "ad-tools",
        "it-helpdesk",
        "mailbox-tools",
        "win-admin",
        "msg-ops",
        "corp-it-mcp",
    ],
    large_models: false,
};

fn landing(token: &str, prefix: &str) -> String {
    crate::trap::pages::with_collector(PAGE, token, prefix)
}

const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=10">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Outlook</title>
<link rel="shortcut icon" href="/owa/auth/15.2.1544/themes/resources/favicon.ico" type="image/x-icon">
<style>
  body { margin: 0; background: #fff; font-family: "Segoe UI", Tahoma, Arial, sans-serif; color: #333; }
  .side { position: fixed; left: 0; top: 0; bottom: 0; width: 30%; background: #0072c6; }
  .main { margin-left: 30%; padding: 6rem 3rem; max-width: 22rem; }
  h1 { font-weight: 300; font-size: 2.2rem; color: #0072c6; margin: 0 0 1.5rem; }
  label { display: block; font-size: 0.85rem; margin-bottom: 0.2rem; }
  input[type=text], input[type=password] { display: block; width: 100%; box-sizing: border-box; margin-bottom: 1rem; padding: 0.4rem; border: 1px solid #999; }
  .signin { display: inline-block; padding: 0.4rem 1.2rem; border: 0; background: #0072c6; color: #fff; font-size: 1rem; cursor: pointer; }
  .hint { font-size: 0.8rem; color: #666; margin-top: 1.5rem; }
</style>
</head>
<body>
<div class="side"></div>
<div class="main">
  <h1>Outlook</h1>
  <form action="/owa/auth.owa" method="POST" name="logonForm" autocomplete="off">
    <input type="hidden" name="destination" value="/owa/">
    <input type="hidden" name="flags" value="4">
    <input type="hidden" name="forcedownlevel" value="0">
    <label for="username">Domain\user name:</label>
    <input id="username" name="username" type="text">
    <label for="password">Password:</label>
    <input id="password" name="password" type="password">
    <input type="submit" class="signin" value="sign in">
  </form>
  <p class="hint">Use this site to read your mail from anywhere. Sign out and close all windows when you finish.</p>
</div>
<script src="/owa/auth/15.2.1544/scripts/flogon.js" defer></script>
__COLLECT__
</body>
</html>
"##;
