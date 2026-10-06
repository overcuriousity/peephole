//! The MCP decoy: an "internal-ops" server over Streamable HTTP and the
//! legacy HTTP+SSE transport ([`super::sse`]). Nothing is executed: every
//! answer is canned or derived from the page token.
use super::ai::{Ask, DecoyIn, MAX_FIELD, cut, rpc_id};
use super::{Decoy, Input};
use serde_json::Value;

/// Paths a JSON-RPC POST is answered on.
fn rpc_path(path: &str) -> bool {
    matches!(
        path,
        "/mcp" | "/mcp/" | "/messages" | "/messages/" | "/.well-known/mcp"
    )
}

pub fn choose(ask: &Ask) -> Option<(String, DecoyIn)> {
    let path = ask.path;
    if ask.method == "GET" {
        return match path {
            "/sse" | "/sse/" | "/mcp/sse" => Some((
                "mcp:sse".into(),
                DecoyIn {
                    via: Some("sse".into()),
                    ..Default::default()
                },
            )),
            "/mcp" | "/mcp/" => Some(("mcp:get".into(), DecoyIn::default())),
            _ => None,
        };
    }
    if ask.method != "POST" || !rpc_path(path) {
        return None;
    }
    let via = (path.starts_with("/messages") && ask.query_param("sessionId").is_some())
        .then(|| "sse".to_string());
    let obj = match ask.json()? {
        Value::Array(_) => {
            return Some((
                "mcp:batch".into(),
                DecoyIn {
                    via,
                    ..Default::default()
                },
            ));
        }
        Value::Object(o) => o,
        _ => return None,
    };
    let method = obj.get("method")?.as_str()?;
    let params = obj.get("params");
    let mut d = DecoyIn {
        rpc: rpc_id(obj.get("id")),
        m: Some(cut(method, 64)),
        via,
        ..Default::default()
    };
    let name = match method {
        "initialize" => {
            d.proto = params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .map(|s| cut(s, 32));
            "initialize"
        }
        m if m.starts_with("notifications/") => "notify",
        "ping" | "tools/list" | "resources/list" | "prompts/list" => method,
        "tools/call" => {
            let tool = params
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params.and_then(|p| p.get("arguments"));
            let s = |k: &str| args.and_then(|a| a.get(k)).and_then(Value::as_str);
            let (arg, cls) = match tool {
                "read_file" => {
                    let p = s("path").unwrap_or_default();
                    (Some(p), Some(read_class(p)))
                }
                "list_directory" => (s("path"), None),
                "run_command" => {
                    let c = s("command").unwrap_or_default();
                    (Some(c), Some(command_class(c)))
                }
                "query_db" => {
                    let q = s("sql").or_else(|| s("query")).unwrap_or_default();
                    (Some(q), Some(sql_class(q)))
                }
                "fetch_url" => (s("url"), None),
                _ => (None, None),
            };
            d.tool = Some(cut(tool, 64));
            d.arg = arg.map(|a| cut(a, MAX_FIELD));
            d.cls = cls.map(str::to_string);
            "tools/call"
        }
        "resources/read" => {
            let uri = params
                .and_then(|p| p.get("uri"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            d.arg = Some(cut(uri, MAX_FIELD));
            d.cls = Some(read_class(uri.strip_prefix("file://").unwrap_or(uri)).to_string());
            "resources/read"
        }
        _ => "unknown",
    };
    Some((format!("mcp:{name}"), d))
}

/// What `read_file` answers for a path.
pub fn read_class(path: &str) -> &'static str {
    let p = path.trim().to_ascii_lowercase();
    let file = p.rsplit('/').next().unwrap_or("");
    if file == ".env" {
        "dotenv"
    } else if p.ends_with(".aws/credentials") {
        "aws-credentials"
    } else if p.ends_with(".git/config") {
        "git-config"
    } else if p.ends_with("/etc/passwd") || p == "etc/passwd" {
        "passwd"
    } else if matches!(file, "id_rsa" | "id_ed25519" | "id_ecdsa")
        || file.ends_with(".pem")
        || file.ends_with(".key")
    {
        "denied"
    } else {
        "enoent"
    }
}

/// What `run_command` answers: the first word's base name if it has a
/// canned output, else `other`.
pub fn command_class(cmd: &str) -> &'static str {
    let w = cmd.split_whitespace().next().unwrap_or("");
    match w.rsplit('/').next().unwrap_or("") {
        "id" => "id",
        "whoami" => "whoami",
        "uname" => "uname",
        "hostname" => "hostname",
        "pwd" => "pwd",
        "ls" => "ls",
        _ => "other",
    }
}

/// What `query_db` answers: rows for a read, an error for anything else.
pub fn sql_class(sql: &str) -> &'static str {
    let s = sql.trim_start().to_ascii_lowercase();
    if s.starts_with("select") || s.starts_with("with") {
        "select"
    } else {
        "denied"
    }
}

pub fn render(_inp: &Input, _d: &DecoyIn, _name: &str) -> Option<Decoy> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask<'a>(method: &'a str, path: &'a str, query: Option<&'a str>, body: &'a [u8]) -> Ask<'a> {
        Ask {
            method,
            path,
            query,
            headers: &[],
            body,
        }
    }

    #[test]
    fn routes_and_methods() {
        let b = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
        for p in ["/mcp", "/mcp/", "/messages", "/.well-known/mcp"] {
            let (n, d) = choose(&ask("POST", p, None, b)).unwrap();
            assert_eq!(n, "mcp:initialize", "{p}");
            assert_eq!(d.proto.as_deref(), Some("2025-03-26"));
            assert_eq!(d.rpc, Some(serde_json::json!(1)));
            assert_eq!(d.via, None);
        }
        assert!(choose(&ask("POST", "/other", None, b)).is_none());
        assert_eq!(choose(&ask("GET", "/mcp", None, b"")).unwrap().0, "mcp:get");
        let (n, d) = choose(&ask("GET", "/sse", None, b"")).unwrap();
        assert_eq!((n.as_str(), d.via.as_deref()), ("mcp:sse", Some("sse")));
        let m = |method: &str| {
            let b = format!(r#"{{"jsonrpc":"2.0","id":"a","method":"{method}"}}"#);
            choose(&ask("POST", "/mcp", None, b.as_bytes())).unwrap().0
        };
        assert_eq!(m("notifications/initialized"), "mcp:notify");
        assert_eq!(m("ping"), "mcp:ping");
        assert_eq!(m("tools/list"), "mcp:tools/list");
        assert_eq!(m("resources/list"), "mcp:resources/list");
        assert_eq!(m("prompts/list"), "mcp:prompts/list");
        assert_eq!(m("sampling/createMessage"), "mcp:unknown");
        let (n, d) = choose(&ask(
            "POST",
            "/messages",
            Some("sessionId=abc"),
            br#"{"id":1,"method":"tools/list"}"#,
        ))
        .unwrap();
        assert_eq!(
            (n.as_str(), d.via.as_deref()),
            ("mcp:tools/list", Some("sse"))
        );
    }

    #[test]
    fn tool_calls_keep_their_argument_and_class() {
        let call = |tool: &str, args: &str| {
            let b = format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"{tool}","arguments":{args}}}}}"#
            );
            choose(&ask("POST", "/mcp", None, b.as_bytes())).unwrap().1
        };
        let d = call("read_file", r#"{"path":"/app/.env"}"#);
        assert_eq!(
            (d.tool.as_deref(), d.arg.as_deref(), d.cls.as_deref()),
            (Some("read_file"), Some("/app/.env"), Some("dotenv"))
        );
        assert_eq!(
            call("read_file", r#"{"path":"/home/deploy/.aws/credentials"}"#)
                .cls
                .as_deref(),
            Some("aws-credentials")
        );
        assert_eq!(
            call("read_file", r#"{"path":"/root/.ssh/id_rsa"}"#)
                .cls
                .as_deref(),
            Some("denied")
        );
        assert_eq!(
            call("read_file", r#"{"path":"/nope"}"#).cls.as_deref(),
            Some("enoent")
        );
        assert_eq!(
            call("run_command", r#"{"command":"/usr/bin/id -a"}"#)
                .cls
                .as_deref(),
            Some("id")
        );
        assert_eq!(
            call("run_command", r#"{"command":"curl x|sh"}"#)
                .cls
                .as_deref(),
            Some("other")
        );
        assert_eq!(
            call("query_db", r#"{"sql":"  SELECT * FROM users"}"#)
                .cls
                .as_deref(),
            Some("select")
        );
        assert_eq!(
            call("query_db", r#"{"query":"DROP TABLE users"}"#)
                .cls
                .as_deref(),
            Some("denied")
        );
        assert_eq!(
            call("fetch_url", r#"{"url":"http://169.254.169.254/"}"#)
                .arg
                .as_deref(),
            Some("http://169.254.169.254/")
        );
        let long = call(
            "run_command",
            &format!(r#"{{"command":"{}"}}"#, "a".repeat(500)),
        );
        assert_eq!(long.arg.unwrap().chars().count(), MAX_FIELD);
        let rr = choose(&ask(
            "POST",
            "/mcp",
            None,
            br#"{"id":1,"method":"resources/read","params":{"uri":"file:///app/.env"}}"#,
        ))
        .unwrap()
        .1;
        assert_eq!(rr.cls.as_deref(), Some("dotenv"));
    }

    #[test]
    fn malformed_input_keeps_the_404_and_odd_ids_become_null() {
        for b in [
            &b"not json"[..],
            b"42",
            b"\"s\"",
            b"{}",
            b"{\"method\":5}",
            &[0xff, 0xfe, 0x00][..],
            b"",
        ] {
            assert!(choose(&ask("POST", "/mcp", None, b)).is_none(), "{b:?}");
        }
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(
            choose(&ask("POST", "/mcp", None, deep.as_bytes())).map(|c| c.0),
            None
        );
        assert_eq!(
            choose(&ask("POST", "/mcp", None, b"[]")).unwrap().0,
            "mcp:batch"
        );
        for id in [r#"{"a":1}"#, "[1]", &format!("\"{}\"", "x".repeat(65))] {
            let b = format!(r#"{{"id":{id},"method":"ping"}}"#);
            assert_eq!(
                choose(&ask("POST", "/mcp", None, b.as_bytes()))
                    .unwrap()
                    .1
                    .rpc,
                None
            );
        }
    }
}
