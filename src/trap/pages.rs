pub fn trap_page(token: &str) -> String {
    include_str!("../../templates/trap.html").replace("__PAGE_TOKEN__", token)
}

pub fn claim_confirmation() -> String {
    r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>Thank you</title>
<style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;max-width:640px;margin:4rem auto;padding:0 1rem}</style>
</head><body>
<h1>Thank you.</h1>
<p>The admin was notified. If you want to be contacted for clarification, you may have left an email address — we will only use it for that purpose.</p>
</body></html>"#.to_string()
}
