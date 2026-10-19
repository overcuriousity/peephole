//! A self-hosted chat UI in front of a local model server.
use super::Persona;

pub const PERSONA: Persona = Persona {
    name: "gpu-box",
    product: "Open WebUI on Ollama",
    server: Some("uvicorn"),
    extra_headers: &[],
    landing,
    mcp_servers: &[
        "ml-ops",
        "gpu-tools",
        "inference-ops",
        "model-runner",
        "ml-infra",
        "train-tools",
        "llm-ops",
        "cuda-host",
    ],
    large_models: true,
};

fn landing(token: &str, prefix: &str) -> String {
    crate::trap::pages::with_collector(PAGE, token, prefix)
}

const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="theme-color" content="#171717">
<meta name="robots" content="noindex,nofollow">
<title>Open WebUI</title>
<link rel="icon" href="/static/favicon.png">
<link rel="manifest" href="/manifest.json">
<style>
  html, body { margin: 0; height: 100%; background: #171717; color: #e5e5e5; font-family: system-ui, -apple-system, sans-serif; }
  .shell { min-height: 100%; display: flex; align-items: center; justify-content: center; }
  .card { width: 20rem; }
  h1 { font-size: 1.4rem; font-weight: 600; text-align: center; margin: 0 0 1.5rem; }
  label { display: block; font-size: 0.8rem; color: #a3a3a3; margin-bottom: 0.25rem; }
  input { display: block; width: 100%; box-sizing: border-box; margin-bottom: 1rem; padding: 0.6rem 0.8rem; border: 0; border-radius: 0.75rem; background: #262626; color: inherit; }
  button { width: 100%; padding: 0.6rem; border: 0; border-radius: 9999px; background: #e5e5e5; color: #171717; font-weight: 600; cursor: pointer; }
  .alt { margin-top: 1rem; text-align: center; font-size: 0.8rem; color: #a3a3a3; }
</style>
</head>
<body>
<div id="app" class="shell">
  <div class="card">
    <h1>Sign in to Open WebUI</h1>
    <form method="post" action="/api/v1/auths/signin" autocomplete="off">
      <label>Email<input type="email" name="email" placeholder="you@example.com"></label>
      <label>Password<input type="password" name="password"></label>
      <button type="submit">Sign in</button>
    </form>
    <p class="alt">Don't have an account? Ask an admin to create one.</p>
  </div>
</div>
<script type="module" src="/_app/immutable/entry/start.js"></script>
__COLLECT__
</body>
</html>
"##;
