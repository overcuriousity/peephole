//! An SSL-VPN portal's logon page on a firewall appliance.
use super::Persona;

pub const PERSONA: Persona = Persona {
    name: "fortinet",
    product: "FortiGate SSL-VPN",
    // The appliance's web server sends no `Server` header.
    server: None,
    extra_headers: &[],
    landing,
    mcp_servers: &[
        "netops-tools",
        "fw-admin",
        "vpn-ops",
        "net-mcp",
        "edge-tools",
        "noc-assistant",
        "fw-automation",
        "netsec-ops",
    ],
    large_models: false,
};

fn landing(token: &str, prefix: &str) -> String {
    crate::trap::pages::with_collector(PAGE, token, prefix)
}

const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>SSL VPN Portal</title>
<style>
  body { margin: 0; background: #2b2f36; font-family: Arial, Helvetica, sans-serif; color: #222; }
  .box { width: 22rem; margin: 8rem auto 0; background: #fff; border-radius: 4px; box-shadow: 0 2px 12px rgba(0,0,0,.4); }
  .bar { background: #c8102e; color: #fff; padding: 0.8rem 1.2rem; font-size: 1rem; font-weight: bold; border-radius: 4px 4px 0 0; }
  form { padding: 1.2rem; }
  input { display: block; width: 100%; box-sizing: border-box; margin: 0 0 0.8rem; padding: 0.5rem; border: 1px solid #bbb; border-radius: 3px; }
  button { width: 100%; padding: 0.55rem; border: 0; border-radius: 3px; background: #2f6fb3; color: #fff; font-weight: bold; cursor: pointer; }
  .note { padding: 0 1.2rem 1rem; color: #777; font-size: 0.75rem; }
</style>
</head>
<body>
<div class="box">
  <div class="bar">Please Login</div>
  <form action="/remote/logincheck" method="post" name="f" autocomplete="off">
    <input type="hidden" name="ajax" value="1">
    <input type="hidden" name="realm" value="">
    <input type="text" name="username" placeholder="Username" autofocus>
    <input type="password" name="credential" placeholder="Password">
    <button type="submit" id="login_button">Login</button>
  </form>
  <p class="note">Use the VPN client for full tunnel access.</p>
</div>
<script src="/sslvpn/js/login.js" defer></script>
__COLLECT__
</body>
</html>
"##;
