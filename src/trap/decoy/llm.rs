//! The LLM gateway decoy: an internal gateway (LiteLLM / one-api style) in
//! front of local Ollama models and "upstream" OpenAI and Anthropic
//! models. Every answer is one fixed reply, in the shape the API asks for.
use super::ai::{Ask, DecoyIn, MAX_FIELD, cut};
use super::{Decoy, Input};
use serde_json::Value;

/// The API style, the path after its prefix, and the Azure deployment.
fn route<'a>(ask: &Ask<'a>) -> Option<(&'static str, &'a str, Option<&'a str>)> {
    let p = ask.path;
    if let Some(r) = p.strip_prefix("/openai/deployments/") {
        let (dep, _) = r.split_once('/')?;
        return Some(("azure", &r[dep.len()..], Some(dep)));
    }
    for pre in ["/api/anthropic/v1", "/anthropic/v1"] {
        if let Some(r) = p.strip_prefix(pre) {
            return Some(("anthropic", r, None));
        }
    }
    for pre in ["/openai/v1", "/api/v1", "/litellm/v1"] {
        if let Some(r) = p.strip_prefix(pre) {
            return Some(("openai", r, None));
        }
    }
    if let Some(r) = p.strip_prefix("/v1") {
        let anthropic_hdr =
            ask.header("anthropic-version").is_some() || ask.header("x-api-key").is_some();
        let anthropic = matches!(r, "/messages" | "/messages/count_tokens" | "/complete")
            || (r == "/models" && anthropic_hdr);
        return Some((if anthropic { "anthropic" } else { "openai" }, r, None));
    }
    p.strip_prefix("/api").map(|r| ("ollama", r, None))
}

pub fn choose(ask: &Ask) -> Option<(String, DecoyIn)> {
    let (api, rest, deployment) = route(ask)?;
    let get = matches!(ask.method, "GET" | "HEAD");
    let post = ask.method == "POST";
    let oai = matches!(api, "openai" | "azure");
    let ep = match (api, rest) {
        ("ollama", "/version" | "/tags" | "/ps") if get => &rest[1..],
        ("ollama", "/show" | "/pull" | "/chat" | "/generate") if post => &rest[1..],
        ("ollama", "/create" | "/delete" | "/copy" | "/embed" | "/embeddings") => "unsupported",
        (_, "/models") if get && (oai || api == "anthropic") => "models",
        (_, r) if oai && get && r.starts_with("/models/") => "models",
        (_, "/chat/completions") if oai && post => "chat-completions",
        (_, "/completions") if oai && post => "completions",
        (_, "/responses") if oai && post => "responses",
        (_, r)
            if oai
                && (matches!(r, "/embeddings" | "/moderations")
                    || r.starts_with("/images/")
                    || r.starts_with("/audio/")) =>
        {
            "unsupported"
        }
        ("anthropic", "/messages") if post => "messages",
        ("anthropic", "/messages/count_tokens") if post => "count-tokens",
        ("anthropic", "/complete") if post => "complete",
        _ => return None,
    };
    let body = if post { ask.json() } else { None };
    let field = |k: &str| body.as_ref().and_then(|b| b.get(k));
    let mut model = field("model").and_then(Value::as_str).map(str::to_string);
    if api == "ollama" && model.is_none() {
        model = field("name").and_then(Value::as_str).map(str::to_string);
    }
    if let Some(id) = rest.strip_prefix("/models/") {
        model = Some(id.to_string());
    }
    if api == "azure" && model.is_none() {
        model = deployment.map(str::to_string);
    }
    let by_default = api == "ollama" && matches!(ep, "chat" | "generate" | "pull");
    let d = DecoyIn {
        api: Some(api.into()),
        ep: Some(ep.into()),
        model: model.map(|m| cut(&m, MAX_FIELD)),
        stream: Some(
            field("stream")
                .and_then(Value::as_bool)
                .unwrap_or(by_default),
        ),
        deployment: deployment.map(|x| cut(x, 64)),
        n: (ep == "count-tokens").then_some((ask.body.len() / 4) as i64),
        ..Default::default()
    };
    Some((format!("llm:{ep}"), d))
}

pub fn render(_inp: &Input, _d: &DecoyIn, _name: &str) -> Option<Decoy> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pick(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Option<(String, DecoyIn)> {
        let h: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        choose(&Ask {
            method,
            path,
            query: None,
            headers: &h,
            body: body.as_bytes(),
        })
    }
    fn ep(method: &str, path: &str) -> Option<(String, String)> {
        pick(method, path, &[], r#"{"model":"gpt-4o"}"#).map(|(n, d)| (n, d.api.unwrap()))
    }

    #[test]
    fn every_api_style_and_prefix() {
        let e = |n: &str, a: &str| Some((n.to_string(), a.to_string()));
        assert_eq!(ep("GET", "/api/version"), e("llm:version", "ollama"));
        assert_eq!(ep("GET", "/api/tags"), e("llm:tags", "ollama"));
        assert_eq!(ep("POST", "/api/chat"), e("llm:chat", "ollama"));
        assert_eq!(ep("POST", "/api/pull"), e("llm:pull", "ollama"));
        assert_eq!(ep("POST", "/api/embed"), e("llm:unsupported", "ollama"));
        for pre in ["/v1", "/openai/v1", "/api/v1", "/litellm/v1"] {
            assert_eq!(
                ep("POST", &format!("{pre}/chat/completions")),
                e("llm:chat-completions", "openai"),
                "{pre}"
            );
            assert_eq!(
                ep("GET", &format!("{pre}/models")),
                e("llm:models", "openai"),
                "{pre}"
            );
        }
        assert_eq!(ep("POST", "/v1/responses"), e("llm:responses", "openai"));
        assert_eq!(
            ep("POST", "/v1/completions"),
            e("llm:completions", "openai")
        );
        assert_eq!(ep("POST", "/v1/embeddings"), e("llm:unsupported", "openai"));
        assert_eq!(
            ep("POST", "/v1/images/generations"),
            e("llm:unsupported", "openai")
        );
        for pre in ["/v1", "/anthropic/v1", "/api/anthropic/v1"] {
            assert_eq!(
                ep("POST", &format!("{pre}/messages")),
                e("llm:messages", "anthropic"),
                "{pre}"
            );
        }
        assert_eq!(
            ep("POST", "/v1/messages/count_tokens"),
            e("llm:count-tokens", "anthropic")
        );
        assert_eq!(ep("POST", "/v1/complete"), e("llm:complete", "anthropic"));
        let (n, d) = pick(
            "GET",
            "/v1/models",
            &[("anthropic-version", "2023-06-01")],
            "",
        )
        .unwrap();
        assert_eq!(
            (n.as_str(), d.api.as_deref()),
            ("llm:models", Some("anthropic"))
        );
        let (n, d) = pick(
            "POST",
            "/openai/deployments/gpt4o-prod/chat/completions",
            &[],
            "{}",
        )
        .unwrap();
        assert_eq!(
            (
                n.as_str(),
                d.api.as_deref(),
                d.deployment.as_deref(),
                d.model.as_deref()
            ),
            (
                "llm:chat-completions",
                Some("azure"),
                Some("gpt4o-prod"),
                Some("gpt4o-prod")
            )
        );
        // Not ours: wrong method, Kubernetes-style /api/v1, unknown paths.
        assert_eq!(ep("GET", "/v1/chat/completions"), None);
        assert_eq!(ep("GET", "/api/v1/pods"), None);
        assert_eq!(ep("GET", "/v1x/models"), None);
        assert_eq!(ep("GET", "/apix"), None);
    }

    #[test]
    fn model_stream_and_count() {
        let (_, d) = pick("POST", "/api/chat", &[], r#"{"model":"llama3.1:8b"}"#).unwrap();
        assert_eq!(
            (d.model.as_deref(), d.stream),
            (Some("llama3.1:8b"), Some(true)),
            "Ollama streams by default"
        );
        let (_, d) = pick("POST", "/api/chat", &[], r#"{"model":"x","stream":false}"#).unwrap();
        assert_eq!(d.stream, Some(false));
        let (_, d) = pick("POST", "/v1/chat/completions", &[], r#"{"model":"gpt-4o"}"#).unwrap();
        assert_eq!(d.stream, Some(false));
        let (_, d) = pick("POST", "/api/pull", &[], r#"{"name":"deepseek-r1:671b"}"#).unwrap();
        assert_eq!(
            d.model.as_deref(),
            Some("deepseek-r1:671b"),
            "legacy `name`"
        );
        let (_, d) = pick("GET", "/v1/models/gpt-4.1", &[], "").unwrap();
        assert_eq!(d.model.as_deref(), Some("gpt-4.1"));
        let body =
            r#"{"model":"claude-opus-5-5","messages":[{"role":"user","content":"hello there"}]}"#;
        let (_, d) = pick("POST", "/v1/messages/count_tokens", &[], body).unwrap();
        assert_eq!(d.n, Some((body.len() / 4) as i64));
        let (_, d) = pick(
            "POST",
            "/v1/chat/completions",
            &[],
            &format!(r#"{{"model":"{}"}}"#, "m".repeat(300)),
        )
        .unwrap();
        assert_eq!(d.model.unwrap().chars().count(), MAX_FIELD);
        // A body that is not JSON still gets the endpoint's answer (no model).
        let (n, d) = pick("POST", "/v1/messages", &[], "garbage").unwrap();
        assert_eq!((n.as_str(), d.model), ("llm:messages", None));
    }
}
