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
        ("ollama", "/delete") if ask.method == "DELETE" || post => "unsupported",
        ("ollama", "/create" | "/copy" | "/embed" | "/embeddings") if post => "unsupported",
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

use serde_json::json;

/// Local Ollama models: name, family, parameter size, bytes.
pub const LOCAL: [(&str, &str, &str, i64); 4] = [
    ("llama3.1:8b", "llama", "8.0B", 4_920_753_328),
    ("qwen2.5-coder:7b", "qwen2", "7.6B", 4_683_087_332),
    ("deepseek-r1:14b", "qwen2", "14.8B", 8_988_112_040),
    ("nomic-embed-text:latest", "nomic-bert", "137M", 274_302_450),
];
/// Upstream models the gateway proxies: id, owner, display name.
pub const UPSTREAM: [(&str, &str, &str); 6] = [
    ("gpt-4o", "openai", "GPT-4o"),
    ("gpt-4o-mini", "openai", "GPT-4o mini"),
    ("gpt-4.1", "openai", "GPT-4.1"),
    ("claude-sonnet-5-5", "anthropic", "Claude Sonnet 5.5"),
    ("claude-opus-5-5", "anthropic", "Claude Opus 5.5"),
    ("claude-haiku-4-5-20251001", "anthropic", "Claude Haiku 4.5"),
];
/// The one thing every model says.
pub const REPLY: &str = "I'm here to help. Could you share a bit more detail about what you need?";
const PROMPT_TOKENS: i64 = 24;
const REPLY_TOKENS: i64 = 17;
const JSON: &str = "application/json";
const NDJSON: &str = "application/x-ndjson";
const SSE: &str = "text/event-stream";
const PULL_ERR: &str = "max retries exceeded: read: connection reset by peer";

type Out = (u16, &'static str, String);

fn local(m: &str) -> Option<&'static (&'static str, &'static str, &'static str, i64)> {
    LOCAL
        .iter()
        .find(|l| l.0 == m || (!m.contains(':') && l.0 == format!("{m}:latest")))
}

/// Whether the gateway serves `model`.
pub fn listed(m: &str) -> bool {
    local(m).is_some() || UPSTREAM.iter().any(|u| u.0 == m)
}

/// `model` when it is safe to echo, else empty.
pub fn safe(m: &str) -> &str {
    let ok = !m.is_empty()
        && m.chars().count() <= 128
        && m.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'));
    if ok { m } else { "" }
}

fn pieces() -> impl Iterator<Item = &'static str> {
    REPLY.split_inclusive(' ')
}

fn rfc(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn id(inp: &Input, ep: &str, n: usize) -> String {
    super::hex(format!("{}:{ep}", inp.page_token).as_bytes(), n)
}

fn ok(v: serde_json::Value) -> Out {
    (200, JSON, v.to_string())
}

fn sse(events: impl IntoIterator<Item = (Option<&'static str>, String)>) -> String {
    events
        .into_iter()
        .map(|(e, d)| match e {
            Some(e) => format!("event: {e}\ndata: {d}\n\n"),
            None => format!("data: {d}\n\n"),
        })
        .collect()
}

pub fn render(inp: &Input, d: &DecoyIn, ep: &str) -> Option<Decoy> {
    let api = d.api.as_deref().unwrap_or("openai");
    let model = d.model.as_deref().unwrap_or("");
    let stream = d.stream.unwrap_or(false);
    let (status, ct, body): Out = match (api, ep) {
        ("ollama", "version") => ok(json!({"version": "0.6.5"})),
        ("ollama", "tags") => ok(json!({"models": LOCAL.iter().map(ollama_model).collect::<Vec<_>>()})),
        ("ollama", "ps") => {
            let mut m = ollama_model(&LOCAL[0]);
            m["expires_at"] = json!(rfc(inp.ts + 300));
            m["size_vram"] = json!(LOCAL[0].3);
            ok(json!({"models": [m]}))
        }
        ("ollama", "show") => match local(model) {
            Some(l) => ok(json!({
                "modelfile": format!("# Modelfile generated by \"ollama show\"\nFROM /usr/share/ollama/.ollama/models/blobs/sha256-{}\n", super::hex(l.0.as_bytes(), 64)),
                "parameters": "stop \"<|eot_id|>\"",
                "template": "{{ .Prompt }}",
                "details": ollama_model(l)["details"].clone(),
                "model_info": {"general.architecture": l.1},
            })),
            None => ollama_missing(model),
        },
        ("ollama", "pull") if stream => (
            200,
            NDJSON,
            format!("{}\n{}\n", json!({"status": "pulling manifest"}), json!({"error": PULL_ERR})),
        ),
        ("ollama", "pull") => (500, JSON, json!({"error": PULL_ERR}).to_string()),
        ("ollama", "chat" | "generate") if local(model).is_some() => ollama_reply(inp, model, ep == "chat", stream),
        ("ollama", "chat" | "generate") => ollama_missing(model),
        ("ollama", _) => (500, JSON, json!({"error": "llama runner process has terminated: exit status 2"}).to_string()),
        ("anthropic", "models") => {
            let c: Vec<_> = UPSTREAM.iter().filter(|u| u.1 == "anthropic").collect();
            ok(json!({
                "data": c.iter().map(|u| json!({"type": "model", "id": u.0, "display_name": u.2, "created_at": "2025-09-29T00:00:00Z"})).collect::<Vec<_>>(),
                "has_more": false,
                "first_id": c.first().map(|u| u.0),
                "last_id": c.last().map(|u| u.0),
            }))
        }
        ("anthropic", "messages" | "complete") if listed(model) => anthropic_reply(inp, model, ep, stream),
        ("anthropic", "messages" | "complete") => anthropic_missing(model),
        ("anthropic", "count-tokens") => ok(json!({"input_tokens": d.n.unwrap_or(0)})),
        (_, "models") => match d.model.as_deref() {
            None => ok(json!({"object": "list", "data": all_models()})),
            Some(m) if listed(m) => ok(oai_model(m)),
            Some(m) => openai_missing(api, m),
        },
        (_, "chat-completions" | "completions" | "responses") if listed(model) => openai_reply(inp, model, ep, stream),
        (_, "chat-completions" | "completions" | "responses") => openai_missing(api, model),
        (_, "unsupported") => (
            400,
            JSON,
            json!({"error": {"message": "This endpoint is not enabled on this gateway.", "type": "invalid_request_error", "param": null, "code": null}}).to_string(),
        ),
        _ => return None,
    };
    Some(Decoy {
        name: format!("llm:{ep}"),
        status,
        headers: vec![("content-type", ct.to_string())],
        body,
    })
}

fn ollama_model(l: &(&str, &str, &str, i64)) -> serde_json::Value {
    json!({
        "name": l.0, "model": l.0, "modified_at": "2025-09-14T10:22:41Z", "size": l.3,
        "digest": super::hex(l.0.as_bytes(), 64),
        "details": {
            "parent_model": "", "format": "gguf", "family": l.1, "families": [l.1],
            "parameter_size": l.2,
            "quantization_level": if l.1 == "nomic-bert" { "F16" } else { "Q4_K_M" },
        },
    })
}

fn all_models() -> Vec<serde_json::Value> {
    LOCAL
        .iter()
        .map(|l| l.0)
        .chain(UPSTREAM.iter().map(|u| u.0))
        .map(oai_model)
        .collect()
}

fn oai_model(m: &str) -> serde_json::Value {
    let owner = UPSTREAM
        .iter()
        .find(|u| u.0 == m)
        .map_or("library", |u| u.1);
    let id = local(m).map_or(m, |l| l.0);
    json!({"id": id, "object": "model", "created": 1_715_367_049, "owned_by": owner})
}

fn ollama_missing(m: &str) -> Out {
    (
        404,
        JSON,
        json!({"error": format!("model \"{}\" not found, try pulling it first", safe(m))})
            .to_string(),
    )
}

fn openai_missing(api: &str, m: &str) -> Out {
    let v = if api == "azure" {
        json!({"error": {"code": "DeploymentNotFound", "message": "The API deployment for this resource does not exist. If you created the deployment within the last 5 minutes, please wait a moment and try again."}})
    } else {
        json!({"error": {"message": format!("The model `{}` does not exist or you do not have access to it.", safe(m)), "type": "invalid_request_error", "param": null, "code": "model_not_found"}})
    };
    (404, JSON, v.to_string())
}

fn anthropic_missing(m: &str) -> Out {
    (404, JSON, json!({"type": "error", "error": {"type": "not_found_error", "message": format!("model: {}", safe(m))}}).to_string())
}

fn ollama_reply(inp: &Input, model: &str, chat: bool, stream: bool) -> Out {
    let at = rfc(inp.ts);
    let part = |text: &str, done: bool| {
        let mut v = json!({"model": model, "created_at": at, "done": done});
        if chat {
            v["message"] = json!({"role": "assistant", "content": text});
        } else {
            v["response"] = json!(text);
        }
        if done {
            for (k, n) in [
                ("total_duration", 1_873_250_333_i64),
                ("load_duration", 20_416_750),
                ("prompt_eval_count", PROMPT_TOKENS),
                ("prompt_eval_duration", 118_000_000),
                ("eval_count", REPLY_TOKENS),
                ("eval_duration", 1_730_000_000),
            ] {
                v[k] = json!(n);
            }
            v["done_reason"] = json!("stop");
        }
        v
    };
    if !stream {
        return ok(part(REPLY, true));
    }
    let mut body: String = pieces().map(|p| format!("{}\n", part(p, false))).collect();
    body.push_str(&format!("{}\n", part("", true)));
    (200, NDJSON, body)
}

fn openai_reply(inp: &Input, model: &str, ep: &str, stream: bool) -> Out {
    let ts = inp.ts;
    let usage = json!({"prompt_tokens": PROMPT_TOKENS, "completion_tokens": REPLY_TOKENS, "total_tokens": PROMPT_TOKENS + REPLY_TOKENS});
    match ep {
        "chat-completions" => {
            let cid = format!("chatcmpl-{}", id(inp, ep, 24));
            if !stream {
                return ok(json!({
                    "id": cid, "object": "chat.completion", "created": ts, "model": model,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": REPLY}, "finish_reason": "stop"}],
                    "usage": usage,
                }));
            }
            let chunk = |delta: serde_json::Value, finish: Option<&str>| {
                (None, json!({"id": cid, "object": "chat.completion.chunk", "created": ts, "model": model,
                              "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}).to_string())
            };
            let mut ev = vec![chunk(json!({"role": "assistant", "content": ""}), None)];
            ev.extend(pieces().map(|p| chunk(json!({"content": p}), None)));
            ev.push(chunk(json!({}), Some("stop")));
            ev.push((None, "[DONE]".to_string()));
            (200, SSE, sse(ev))
        }
        "completions" => {
            let cid = format!("cmpl-{}", id(inp, ep, 24));
            let obj = |text: &str, finish: Option<&str>| {
                json!({
                    "id": cid, "object": "text_completion", "created": ts, "model": model,
                    "choices": [{"text": text, "index": 0, "logprobs": null, "finish_reason": finish}],
                })
            };
            if !stream {
                let mut v = obj(REPLY, Some("stop"));
                v["usage"] = usage;
                return ok(v);
            }
            let mut ev: Vec<_> = pieces().map(|p| (None, obj(p, None).to_string())).collect();
            ev.push((None, obj("", Some("stop")).to_string()));
            ev.push((None, "[DONE]".to_string()));
            (200, SSE, sse(ev))
        }
        _ => {
            let rid = format!("resp_{}", id(inp, ep, 32));
            let mid = format!("msg_{}", id(inp, "msg", 32));
            let full = |status: &str, text: Option<&str>| {
                json!({
                    "id": rid, "object": "response", "created_at": ts, "status": status, "model": model,
                    "parallel_tool_calls": true, "tool_choice": "auto", "tools": [],
                    "output": match text {
                        Some(t) => json!([{"type": "message", "id": mid, "status": "completed", "role": "assistant",
                                           "content": [{"type": "output_text", "text": t, "annotations": []}]}]),
                        None => json!([]),
                    },
                    "usage": if text.is_some() { json!({"input_tokens": PROMPT_TOKENS, "output_tokens": REPLY_TOKENS, "total_tokens": PROMPT_TOKENS + REPLY_TOKENS}) } else { json!(null) },
                })
            };
            if !stream {
                return ok(full("completed", Some(REPLY)));
            }
            let mut seq = 0;
            let mut next = |e: &'static str, mut v: serde_json::Value| {
                v["type"] = json!(e);
                v["sequence_number"] = json!(seq);
                seq += 1;
                (Some(e), v.to_string())
            };
            let mut ev = vec![next(
                "response.created",
                json!({"response": full("in_progress", None)}),
            )];
            ev.push(next(
                "response.in_progress",
                json!({"response": full("in_progress", None)}),
            ));
            ev.push(next(
                "response.output_item.added",
                json!({
                    "output_index": 0,
                    "item": {
                        "type": "message", "id": mid, "status": "in_progress", "role": "assistant",
                        "content": []
                    }
                }),
            ));
            ev.push(next(
                "response.content_part.added",
                json!({
                    "item_id": mid, "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []}
                }),
            ));
            for p in pieces() {
                ev.push(next(
                    "response.output_text.delta",
                    json!({"item_id": mid, "output_index": 0, "content_index": 0, "delta": p}),
                ));
            }
            ev.push(next(
                "response.output_text.done",
                json!({"item_id": mid, "output_index": 0, "content_index": 0, "text": REPLY}),
            ));
            ev.push(next(
                "response.content_part.done",
                json!({
                    "item_id": mid, "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": REPLY, "annotations": []}
                }),
            ));
            ev.push(next(
                "response.output_item.done",
                json!({
                    "output_index": 0,
                    "item": {
                        "type": "message", "id": mid, "status": "completed", "role": "assistant",
                        "content": [{"type": "output_text", "text": REPLY, "annotations": []}]
                    }
                }),
            ));
            ev.push(next(
                "response.completed",
                json!({"response": full("completed", Some(REPLY))}),
            ));
            (200, SSE, sse(ev))
        }
    }
}

fn anthropic_reply(inp: &Input, model: &str, ep: &str, stream: bool) -> Out {
    if ep == "complete" {
        let cid = format!("compl_{}", id(inp, ep, 24));
        let piece = |text: &str, stop: Option<&str>| {
            json!({"type": "completion", "id": cid, "completion": text,
                   "stop_reason": stop, "stop": stop.map(|_| "\n\nHuman:"), "model": model})
        };
        if !stream {
            return ok(piece(&format!(" {REPLY}"), Some("stop_sequence")));
        }
        let mut ev: Vec<_> = pieces()
            .enumerate()
            .map(|(i, p)| {
                let t = if i == 0 {
                    format!(" {p}")
                } else {
                    p.to_string()
                };
                (Some("completion"), piece(&t, None).to_string())
            })
            .collect();
        ev.push((
            Some("completion"),
            piece("", Some("stop_sequence")).to_string(),
        ));
        return (200, SSE, sse(ev));
    }
    let mid = format!("msg_{}", id(inp, ep, 24));
    if !stream {
        return ok(json!({
            "id": mid, "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": REPLY}],
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": {"input_tokens": PROMPT_TOKENS, "output_tokens": REPLY_TOKENS},
        }));
    }
    let e = |name: &'static str, v: serde_json::Value| (Some(name), v.to_string());
    let mut ev = vec![
        e(
            "message_start",
            json!({"type": "message_start", "message": {
            "id": mid, "type": "message", "role": "assistant", "model": model, "content": [],
            "stop_reason": null, "stop_sequence": null,
            "usage": {"input_tokens": PROMPT_TOKENS, "output_tokens": 1}}}),
        ),
        e("ping", json!({"type": "ping"})),
        e(
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
    ];
    ev.extend(pieces().map(|p| e("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}}))));
    ev.push(e(
        "content_block_stop",
        json!({"type": "content_block_stop", "index": 0}),
    ));
    ev.push(e("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": REPLY_TOKENS}})));
    ev.push(e("message_stop", json!({"type": "message_stop"})));
    (200, SSE, sse(ev))
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
        assert_eq!(ep("DELETE", "/api/delete"), e("llm:unsupported", "ollama"));
        assert_eq!(ep("GET", "/api/embed"), None);
        assert_eq!(ep("GET", "/api/create"), None);
        assert_eq!(ep("DELETE", "/api/copy"), None);
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

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";

    fn run(din: DecoyIn) -> Decoy {
        let s = din.to_json();
        let i = Input {
            v: 2,
            page_token: TOK,
            host: None,
            word: "shop",
            ts: 1_791_000_000,
            method: "POST",
            path: "/",
            decoy_in: Some(&s),
        };
        render(&i, &din, din.ep.as_deref().unwrap()).unwrap()
    }
    fn d(api: &str, ep: &str, model: Option<&str>, stream: bool) -> DecoyIn {
        DecoyIn {
            api: Some(api.into()),
            ep: Some(ep.into()),
            model: model.map(String::from),
            stream: Some(stream),
            ..Default::default()
        }
    }
    fn js(r: &Decoy) -> serde_json::Value {
        serde_json::from_str(&r.body).unwrap()
    }
    fn sse_data(r: &Decoy) -> Vec<String> {
        r.body
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .map(String::from)
            .collect()
    }

    #[test]
    fn ollama_native() {
        assert_eq!(
            js(&run(d("ollama", "version", None, false)))["version"],
            "0.6.5"
        );
        let tags = js(&run(d("ollama", "tags", None, false)));
        assert_eq!(tags["models"].as_array().unwrap().len(), 4);
        let r = run(d("ollama", "chat", Some("llama3.1:8b"), true));
        assert_eq!(r.headers[0].1, "application/x-ndjson");
        let lines: Vec<serde_json::Value> = r
            .body
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let text: String = lines
            .iter()
            .filter_map(|l| l["message"]["content"].as_str())
            .collect();
        assert_eq!(text, REPLY);
        assert_eq!(lines.last().unwrap()["done"], true);
        let g = js(&run(d(
            "ollama",
            "generate",
            Some("qwen2.5-coder:7b"),
            false,
        )));
        assert_eq!(
            (g["response"].as_str(), g["done"].as_bool()),
            (Some(REPLY), Some(true))
        );
        let miss = run(d("ollama", "chat", Some("gpt-4o"), false));
        assert_eq!(miss.status, 404);
        assert_eq!(
            js(&miss)["error"],
            "model \"gpt-4o\" not found, try pulling it first"
        );
        let pull = run(d("ollama", "pull", Some("deepseek-r1:671b"), true));
        assert!(pull.body.lines().last().unwrap().contains("\"error\""));
        assert_eq!(run(d("ollama", "pull", None, false)).status, 500);
        assert_eq!(
            run(d("ollama", "show", Some("nomic-embed-text"), false)).status,
            200,
            "untagged = :latest"
        );
    }

    #[test]
    fn openai_style() {
        let m = js(&run(d("openai", "models", None, false)));
        assert_eq!(
            m["data"].as_array().unwrap().len(),
            LOCAL.len() + UPSTREAM.len()
        );
        let c = js(&run(d("openai", "chat-completions", Some("gpt-4o"), false)));
        assert_eq!(c["object"], "chat.completion");
        assert_eq!(c["choices"][0]["message"]["content"], REPLY);
        assert!(c["id"].as_str().unwrap().starts_with("chatcmpl-"));
        let s = run(d("openai", "chat-completions", Some("gpt-4o"), true));
        assert_eq!(s.headers[0].1, "text/event-stream");
        let data = sse_data(&s);
        assert_eq!(data.last().unwrap(), "[DONE]");
        let text: String = data[..data.len() - 1]
            .iter()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter_map(|v| {
                v["choices"][0]["delta"]["content"]
                    .as_str()
                    .map(String::from)
            })
            .collect();
        assert_eq!(text, REPLY);
        assert_eq!(
            js(&run(d("openai", "completions", Some("gpt-4o-mini"), false)))["choices"][0]["text"],
            REPLY
        );
        let r = js(&run(d("openai", "responses", Some("gpt-4.1"), false)));
        assert_eq!(
            (
                r["parallel_tool_calls"].as_bool(),
                r["tool_choice"].as_str(),
                r["tools"].as_array().map(Vec::len)
            ),
            (Some(true), Some("auto"), Some(0))
        );
        assert_eq!(r["output"][0]["content"][0]["text"], REPLY);
        let rs = run(d("openai", "responses", Some("gpt-4.1"), true));
        let events: Vec<&str> = rs
            .body
            .lines()
            .filter_map(|l| l.strip_prefix("event: "))
            .collect();
        assert_eq!(events.first(), Some(&"response.created"));
        assert_eq!(events.last(), Some(&"response.completed"));
        // Full Responses stream event sequence (deltas vary by REPLY length)
        let expected_base = [
            "response.created",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            // Multiple response.output_text.delta events interspersed here
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ];
        let non_delta: Vec<&str> = events
            .iter()
            .filter(|e| !e.contains("delta"))
            .copied()
            .collect();
        assert_eq!(
            non_delta, expected_base,
            "Responses stream non-delta events out of order"
        );
        // Count delta events (one per piece of REPLY)
        let delta_count = events
            .iter()
            .filter(|e| *e == &"response.output_text.delta")
            .count();
        assert_eq!(
            delta_count,
            REPLY.split_inclusive(' ').count(),
            "delta event count"
        );
        // Verify each event corresponds to valid JSON
        for line in rs.body.lines() {
            if let Some(event_name) = line.strip_prefix("event: ") {
                let data_line = line
                    .lines()
                    .next()
                    .and_then(|_| rs.body.lines().skip_while(|l| *l != line).nth(1))
                    .and_then(|l| l.strip_prefix("data: "));
                if let Some(data_str) = data_line {
                    let parsed: serde_json::Value =
                        serde_json::from_str(data_str).expect("valid JSON");
                    if let Some(t) = parsed.get("type").and_then(|x| x.as_str()) {
                        assert_eq!(t, event_name, "Event type in data mismatches event line");
                    }
                }
            }
        }
        let miss = run(d("openai", "chat-completions", Some("o9-ultra"), false));
        assert_eq!(
            (miss.status, js(&miss)["error"]["code"].as_str()),
            (404, Some("model_not_found"))
        );
        let az = run(DecoyIn {
            deployment: Some("nope".into()),
            ..d("azure", "chat-completions", Some("nope"), false)
        });
        assert_eq!(js(&az)["error"]["code"], "DeploymentNotFound");
        assert_eq!(run(d("openai", "unsupported", None, false)).status, 400);
    }

    #[test]
    fn anthropic_style() {
        let m = js(&run(d("anthropic", "models", None, false)));
        assert!(
            m["data"]
                .as_array()
                .unwrap()
                .iter()
                .all(|x| x["id"].as_str().unwrap().starts_with("claude-"))
        );
        assert_eq!(m["has_more"], false);
        let msg = js(&run(d(
            "anthropic",
            "messages",
            Some("claude-opus-5-5"),
            false,
        )));
        assert_eq!(
            (msg["type"].as_str(), msg["stop_reason"].as_str()),
            (Some("message"), Some("end_turn"))
        );
        assert_eq!(msg["content"][0]["text"], REPLY);
        let s = run(d("anthropic", "messages", Some("claude-opus-5-5"), true));
        let events: Vec<&str> = s
            .body
            .lines()
            .filter_map(|l| l.strip_prefix("event: "))
            .collect();
        assert_eq!(
            &events[..3],
            ["message_start", "ping", "content_block_start"]
        );
        assert_eq!(
            &events[events.len() - 3..],
            ["content_block_stop", "message_delta", "message_stop"]
        );
        let text: String = sse_data(&s)
            .iter()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter_map(|v| v["delta"]["text"].as_str().map(String::from))
            .collect();
        assert_eq!(text, REPLY);
        let ct = js(&run(DecoyIn {
            n: Some(12),
            ..d("anthropic", "count-tokens", None, false)
        }));
        assert_eq!(ct["input_tokens"], 12);
        assert_eq!(
            js(&run(d(
                "anthropic",
                "complete",
                Some("claude-haiku-4-5-20251001"),
                false
            )))["type"],
            "completion"
        );
        let legacy = js(&run(d(
            "anthropic",
            "complete",
            Some("claude-opus-5-5"),
            false,
        )));
        assert_eq!(
            (legacy["stop_reason"].as_str(), legacy["stop"].as_str()),
            (Some("stop_sequence"), Some("\n\nHuman:"))
        );
        let ls = run(d("anthropic", "complete", Some("claude-opus-5-5"), true));
        let parts: Vec<serde_json::Value> = sse_data(&ls)
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(!ls.body.contains("event: ping"));
        assert!(
            parts[..parts.len() - 1]
                .iter()
                .all(|v| v["stop_reason"].is_null())
        );
        assert_eq!(parts.last().unwrap()["stop_reason"], "stop_sequence");
        let text: String = parts
            .iter()
            .map(|v| v["completion"].as_str().unwrap())
            .collect();
        assert_eq!(text, format!(" {REPLY}"));
        let miss = run(d("anthropic", "messages", Some("claude-2"), false));
        assert_eq!(
            (miss.status, js(&miss)["error"]["type"].as_str()),
            (404, Some("not_found_error"))
        );
    }

    #[test]
    fn model_names_are_reflected_only_when_safe() {
        let miss = js(&run(d(
            "openai",
            "chat-completions",
            Some("<script>alert(1)</script>"),
            false,
        )));
        assert!(!miss["error"]["message"].as_str().unwrap().contains('<'));
        assert_eq!(safe("llama3:70b-instruct"), "llama3:70b-instruct");
        assert_eq!(safe("a b"), "");
    }

    #[test]
    fn rendering_is_pure() {
        let x = d("anthropic", "messages", Some("claude-opus-5-5"), true);
        assert_eq!(run(x.clone()), run(x));
    }
}
