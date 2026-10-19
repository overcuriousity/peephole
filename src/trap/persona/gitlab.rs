//! A self-managed code host's sign-in page.
use super::Persona;

pub const PERSONA: Persona = Persona {
    name: "gitlab",
    product: "GitLab CE 17.4",
    server: Some("nginx"),
    extra_headers: &[],
    landing,
    mcp_servers: &[
        "ci-tools",
        "gitlab-ops",
        "runner-admin",
        "repo-tools",
        "pipeline-mcp",
        "scm-ops",
        "build-tools",
        "release-ops",
    ],
    large_models: false,
};

fn landing(token: &str, prefix: &str) -> String {
    crate::trap::pages::with_collector(PAGE, token, prefix)
}

const PAGE: &str = r##"<!DOCTYPE html>
<html class="gl-light" lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta content="GitLab" property="og:site_name">
<meta content="Sign in" property="og:title">
<title>Sign in · GitLab</title>
<link rel="icon" href="/assets/favicon.png">
<style>
  body { margin: 0; background: #fbfafd; color: #333238; font-family: "GitLab Sans", -apple-system, "Segoe UI", Roboto, sans-serif; }
  .page { max-width: 24rem; margin: 5rem auto; padding: 0 1rem; }
  h1 { font-size: 1.5rem; text-align: center; margin: 0 0 1.5rem; }
  .panel { background: #fff; border: 1px solid #dcdcde; border-radius: 4px; padding: 1.5rem; }
  label { display: block; font-weight: 600; font-size: 0.875rem; margin-bottom: 0.25rem; }
  input[type=text], input[type=password] { display: block; width: 100%; box-sizing: border-box; margin-bottom: 1rem; padding: 0.5rem 0.75rem; border: 1px solid #89888d; border-radius: 4px; }
  .remember { font-size: 0.875rem; margin-bottom: 1rem; }
  button { width: 100%; padding: 0.55rem; border: 0; border-radius: 4px; background: #1f75cb; color: #fff; font-weight: 600; cursor: pointer; }
  .foot { text-align: center; font-size: 0.875rem; margin-top: 1rem; }
  .foot a { color: #1f75cb; }
</style>
</head>
<body class="login-page navless">
<div class="page">
  <h1>GitLab Community Edition</h1>
  <div class="panel">
    <form class="new_user" id="new_user" action="/users/sign_in" accept-charset="UTF-8" method="post">
      <input type="hidden" name="authenticity_token" value="" autocomplete="off">
      <label for="user_login">Username or primary email</label>
      <input type="text" name="user[login]" id="user_login" autocomplete="username" autofocus>
      <label for="user_password">Password</label>
      <input type="password" name="user[password]" id="user_password" autocomplete="current-password">
      <div class="remember"><label><input type="checkbox" name="user[remember_me]" value="1"> Remember me</label></div>
      <button type="submit" data-testid="sign-in-button">Sign in</button>
    </form>
  </div>
  <p class="foot"><a href="/users/password/new">Forgot your password?</a> · <a href="/explore">Explore</a> · <a href="/help">Help</a></p>
</div>
<script src="/assets/webpack/runtime.bundle.js" defer></script>
__COLLECT__
</body>
</html>
"##;
