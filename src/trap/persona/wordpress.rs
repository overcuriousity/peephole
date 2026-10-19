//! A small company blog on WordPress with the default block theme.
use super::Persona;

pub const PERSONA: Persona = Persona {
    name: "wordpress",
    product: "WordPress 6.6",
    server: Some("Apache/2.4.62 (Debian)"),
    extra_headers: &[],
    landing,
    mcp_servers: &[
        "wp-ops",
        "wp-admin-tools",
        "site-maint",
        "cms-tools",
        "wp-deploy",
        "content-ops",
        "wp-mcp",
        "web-admin",
    ],
    large_models: false,
};

fn landing(token: &str, prefix: &str) -> String {
    crate::trap::pages::with_collector(PAGE, token, prefix)
}

const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress 6.6.2">
<title>Notes from the workshop</title>
<link rel="https://api.w.org/" href="/wp-json/">
<link rel="alternate" type="application/rss+xml" title="Notes from the workshop &raquo; Feed" href="/feed/">
<link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.6.2" media="all">
<link rel="stylesheet" id="theme-style-css" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" media="all">
<style>
  body { margin: 0; font-family: Georgia, serif; color: #1c1c1c; background: #f9f9f9; }
  .wrap { max-width: 44rem; margin: 0 auto; padding: 2rem 1.25rem; }
  header { border-bottom: 1px solid #ddd; padding-bottom: 1rem; margin-bottom: 2rem; }
  header a { color: inherit; text-decoration: none; font-size: 1.4rem; }
  nav a { margin-right: 1rem; color: #555; font-size: 0.9rem; }
  article { margin-bottom: 2.5rem; }
  article h2 a { color: #1c1c1c; }
  .meta { color: #777; font-size: 0.85rem; }
  footer { border-top: 1px solid #ddd; padding-top: 1rem; color: #777; font-size: 0.85rem; }
</style>
</head>
<body class="home blog wp-embed-responsive">
<div class="wrap">
<header class="wp-block-template-part">
  <a href="/" rel="home">Notes from the workshop</a>
  <nav><a href="/about/">About</a><a href="/contact/">Contact</a><a href="/wp-login.php">Log in</a></nav>
</header>
<main class="wp-block-group">
  <article class="post type-post status-publish">
    <h2 class="wp-block-post-title"><a href="/?p=42">Moving the build server</a></h2>
    <p class="meta">Posted by admin</p>
    <p>The old build box is retired. Jobs now run on the new host; ask in the usual channel if anything is missing.</p>
  </article>
  <article class="post type-post status-publish">
    <h2 class="wp-block-post-title"><a href="/?p=1">Hello world!</a></h2>
    <p class="meta">Posted by admin</p>
    <p>First post on the new site. The old wiki pages move here over the next weeks.</p>
  </article>
</main>
<footer class="wp-block-template-part">
  <p>Powered by WordPress</p>
</footer>
</div>
<script src="/wp-includes/js/wp-embed.min.js?ver=6.6.2" defer></script>
__COLLECT__
</body>
</html>
"##;
