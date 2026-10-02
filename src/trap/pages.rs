/// The trap page; `prefix` is where the helper endpoints live (validated
/// by `TrapConfig`: a path without quotes or markup).
pub fn trap_page(token: &str, prefix: &str) -> String {
    include_str!("../../templates/trap.html")
        .replace("__PAGE_TOKEN__", token)
        .replace("__PREFIX__", prefix)
}

pub fn claim_confirmation() -> String {
    r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Thank you</title>
<style>
  :root { --bg: #f6f5f0; --surface: #ffffff; --fg: #1f2024; --muted: #66686f; --border: #d9d5c9; color-scheme: light; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0a0b10; --surface: #171a24; --fg: #e4e6ee; --muted: #8a8ea6; --border: #22263a; color-scheme: dark; }
  }
  body { margin: 0; background: var(--bg); color: var(--fg); font-family: ui-sans-serif, system-ui, sans-serif; font-size: 15px; line-height: 1.55; padding: 3rem 1rem; }
  main { max-width: 40rem; margin: 0 auto; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; }
  h1 { font-size: 1.2rem; margin: 0 0 0.5rem; }
  p { margin: 0; color: var(--muted); }
</style>
</head><body>
<main><section class="card"><h1>Thank you.</h1>
<p>The administrator has been notified. If you left an email address it will only be used to clarify this incident.</p></section></main>
</body></html>"#
        .to_string()
}
