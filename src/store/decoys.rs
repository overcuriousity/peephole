//! The Decoys page's aggregates and the wall's "What they asked our fake
//! AI": over full rows with an MCP or LLM decoy answer. Sessions are
//! linked by the `mcp-session` canary and the tokens of later requests.
use super::Store;
use super::browse::{Audience, PAGE_SIZE, Page};
use super::stats::{Named, Range};
use anyhow::Result;

/// Least AI decoy requests in a range before the wall shows its card.
pub const AI_TILE_MIN: i64 = 5;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct McpFunnel {
    pub sessions: i64,
    pub listed: i64,
    pub called: i64,
    pub reused: i64,
    pub sse_opened: i64,
    pub sse_pushed: i64,
    pub sse_lost: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct McpSession {
    pub id: String,
    pub ips: String,
    pub first: String,
    pub last: String,
    pub steps: i64,
    pub tools: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ToolCall {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub tool: String,
    pub arg: String,
    pub cls: String,
}

#[derive(Debug, Default, Clone)]
pub struct LlmSummary {
    pub by_api: Vec<Named>,
    pub listings: i64,
    pub calls: i64,
    pub listed: i64,
    pub unlisted: i64,
    pub pulls: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ModelRow {
    pub model: String,
    pub api: String,
    pub requests: i64,
    pub ips: i64,
}

#[derive(Debug, Clone)]
pub struct PromptRow {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub api: String,
    pub model: String,
    pub prompt: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AiDecoys {
    pub tools: Vec<Named>,
    pub models: Vec<Named>,
    pub apis: Vec<Named>,
    pub total: i64,
    /// The largest count in `tools` / `models` (at least 1): bar scales.
    pub tools_max: i64,
    pub models_max: i64,
}

/// The session canaries served in the range, and the requests carrying them.
const SESSIONS: &str = "WITH s AS (
    SELECT c.value_hash AS h, c.request_id AS rid FROM canaries c JOIN requests r ON r.id = c.request_id
    WHERE c.kind = 'mcp-session'{w}),
  carrier AS (SELECT s.h, t.request_id AS rid FROM s JOIN request_tokens t ON t.value_hash = s.h)";

impl Store {
    pub async fn mcp_funnel(&self, r: Range) -> Result<McpFunnel> {
        let (w, since) = r.ts_clause("r.ts");
        let sql = format!(
            "{SESSIONS}
             SELECT (SELECT COUNT(DISTINCT h) FROM s),
               (SELECT COUNT(DISTINCT carrier.h) FROM carrier JOIN requests r ON r.id = carrier.rid WHERE r.answer = 'decoy:mcp:tools/list'),
               (SELECT COUNT(DISTINCT carrier.h) FROM carrier JOIN requests r ON r.id = carrier.rid WHERE r.answer = 'decoy:mcp:tools/call'),
               (SELECT COUNT(DISTINCT carrier.h) FROM carrier JOIN canaries c2 ON c2.request_id = carrier.rid
                  JOIN request_tokens t2 ON t2.value_hash = c2.value_hash AND t2.request_id <> carrier.rid
                  WHERE c2.kind <> 'mcp-session')",
            SESSIONS = SESSIONS.replace("{w}", &w)
        );
        let mut q = sqlx::query_as::<_, (i64, i64, i64, i64)>(sqlx::AssertSqlSafe(sql));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let (sessions, listed, called, reused) = q.fetch_one(&self.read).await?;
        let sse = format!(
            "SELECT COALESCE(SUM(r.answer = 'decoy:mcp:sse'), 0),
                    COALESCE(SUM(r.answer LIKE 'decoy:mcp:%' AND json_extract(r.decoy_in, '$.via') = 'sse'
                                 AND r.answer NOT IN ('decoy:mcp:sse', 'decoy:mcp:no-session', 'decoy:mcp:busy')
                                 AND COALESCE(json_extract(r.decoy_in, '$.m'), '') NOT LIKE 'notifications/%'), 0),
                    COALESCE(SUM(r.answer = 'decoy:mcp:no-session'), 0)
             FROM requests r WHERE r.decoy_in IS NOT NULL{w}"
        );
        let mut q = sqlx::query_as::<_, (i64, i64, i64)>(sqlx::AssertSqlSafe(sse));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let (sse_opened, sse_pushed, sse_lost) = q.fetch_one(&self.read).await?;
        Ok(McpFunnel {
            sessions,
            listed,
            called,
            reused,
            sse_opened,
            sse_pushed,
            sse_lost,
        })
    }

    pub async fn mcp_sessions(&self, r: Range, limit: i64) -> Result<Vec<McpSession>> {
        let (w, since) = r.ts_clause("r.ts");
        // The id as served is recomputed from the starting request's token.
        let sql = format!(
            "{SESSIONS}, rows AS (
               SELECT s.h, s.rid AS start, s.rid AS rid FROM s
               UNION SELECT carrier.h, s.rid, carrier.rid FROM carrier JOIN s ON s.h = carrier.h)
             SELECT (SELECT page_token FROM requests WHERE id = g.st) AS id, g.ips, g.first, g.last, g.steps, g.tools FROM (
             SELECT MIN(rows.start) AS st, group_concat(DISTINCT i.ip) AS ips, MIN(r.ts) AS first, MAX(r.ts) AS last,
                    COUNT(DISTINCT rows.rid) AS steps,
                    COALESCE(group_concat(DISTINCT json_extract(r.decoy_in, '$.tool')), '') AS tools
             FROM rows JOIN requests r ON r.id = rows.rid JOIN ips i ON i.id = r.ip_id
             GROUP BY rows.h) g ORDER BY g.last DESC LIMIT ?",
            SESSIONS = SESSIONS.replace("{w}", &w)
        );
        let mut q = sqlx::query_as::<_, McpSession>(sqlx::AssertSqlSafe(sql));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let mut rows = q.bind(limit).fetch_all(&self.read).await?;
        for s in &mut rows {
            s.id = crate::trap::decoy::mcp::session_id(&s.id);
        }
        Ok(rows)
    }

    pub async fn mcp_calls(
        &self,
        r: Range,
        tool: Option<&str>,
        page: u32,
    ) -> Result<Page<ToolCall>> {
        let (w, since) = r.ts_clause("r.ts");
        let tw = if tool.is_some() {
            " AND COALESCE(json_extract(r.decoy_in, '$.tool'), json_extract(r.decoy_in, '$.m')) = ?"
        } else {
            ""
        };
        let page = page.max(1);
        let mut q = sqlx::query_as::<_, ToolCall>(sqlx::AssertSqlSafe(format!(
            "SELECT r.id, r.ts, i.ip,
                    COALESCE(json_extract(r.decoy_in, '$.tool'), json_extract(r.decoy_in, '$.m'), '') AS tool,
                    COALESCE(json_extract(r.decoy_in, '$.arg'), '') AS arg,
                    COALESCE(json_extract(r.decoy_in, '$.cls'), '') AS cls
             FROM requests r JOIN ips i ON i.id = r.ip_id
             WHERE r.decoy_in IS NOT NULL AND r.answer IN ('decoy:mcp:tools/call', 'decoy:mcp:resources/read'){w}{tw}
             ORDER BY r.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            i64::from(page - 1) * PAGE_SIZE
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        if let Some(t) = tool {
            q = q.bind(t);
        }
        Ok(Page::from_rows(q.fetch_all(&self.read).await?, page))
    }

    pub async fn llm_summary(&self, r: Range) -> Result<LlmSummary> {
        let (w, since) = r.ts_clause("r.ts");
        let base = format!(
            "FROM requests r WHERE r.decoy_in IS NOT NULL AND r.answer LIKE 'decoy:llm:%'{w}"
        );
        let mut q = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(format!(
            "SELECT COALESCE(json_extract(r.decoy_in, '$.api'), 'unknown') AS name, COUNT(*) AS count {base} GROUP BY 1 ORDER BY 2 DESC"
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let by_api = q.fetch_all(&self.read).await?;
        let mut q = sqlx::query_as::<_, (String, Option<String>)>(sqlx::AssertSqlSafe(format!(
            "SELECT r.answer, json_extract(r.decoy_in, '$.model') {base}"
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let mut s = LlmSummary {
            by_api,
            ..Default::default()
        };
        for (answer, model) in q.fetch_all(&self.read).await? {
            match answer.trim_start_matches("decoy:llm:") {
                "tags" | "models" if model.is_none() => s.listings += 1,
                "chat" | "generate" | "chat-completions" | "completions" | "responses"
                | "messages" | "complete" => {
                    s.calls += 1;
                    if model
                        .as_deref()
                        .is_some_and(crate::trap::decoy::llm::listed)
                    {
                        s.listed += 1
                    } else {
                        s.unlisted += 1
                    }
                }
                "pull" => s.pulls += 1,
                _ => {}
            }
        }
        Ok(s)
    }

    pub async fn llm_models(&self, r: Range) -> Result<Vec<ModelRow>> {
        let (w, since) = r.ts_clause("r.ts");
        let mut q = sqlx::query_as::<_, ModelRow>(sqlx::AssertSqlSafe(format!(
            "SELECT json_extract(r.decoy_in, '$.model') AS model, COALESCE(json_extract(r.decoy_in, '$.api'), '') AS api,
                    COUNT(*) AS requests, COUNT(DISTINCT r.ip_id) AS ips
             FROM requests r WHERE r.decoy_in IS NOT NULL AND r.answer LIKE 'decoy:llm:%' AND json_extract(r.decoy_in, '$.model') IS NOT NULL{w}
             GROUP BY 1, 2 ORDER BY requests DESC LIMIT 100")));
        if let Some(m) = since {
            q = q.bind(m);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    pub async fn llm_prompts(&self, r: Range, page: u32) -> Result<Page<PromptRow>> {
        let (w, since) = r.ts_clause("r.ts");
        let page = page.max(1);
        type Row = (
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<Vec<u8>>,
        );
        let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(format!(
            "SELECT r.id, r.ts, i.ip, json_extract(r.decoy_in, '$.api'), json_extract(r.decoy_in, '$.model'),
                    r.headers_json, r.body
             FROM requests r JOIN ips i ON i.id = r.ip_id WHERE r.decoy_in IS NOT NULL AND r.answer IN
               ('decoy:llm:chat', 'decoy:llm:generate', 'decoy:llm:chat-completions', 'decoy:llm:completions',
                'decoy:llm:responses', 'decoy:llm:messages', 'decoy:llm:complete'){w}
             ORDER BY r.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            i64::from(page - 1) * PAGE_SIZE
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let items = q
            .fetch_all(&self.read)
            .await?
            .into_iter()
            .map(|(id, ts, ip, api, model, h, body)| {
                let headers: Vec<(String, String)> = serde_json::from_str(&h).unwrap_or_default();
                let b =
                    crate::classify::decoded_body(&headers, body.as_deref().unwrap_or_default())
                        .into_owned();
                PromptRow {
                    id,
                    ts,
                    ip,
                    api: api.unwrap_or_default(),
                    model: model.unwrap_or_default(),
                    prompt: last_prompt(&b),
                }
            })
            .collect();
        Ok(Page::from_rows(items, page))
    }

    pub async fn web_decoys(&self, r: Range) -> Result<Vec<Named>> {
        let (w, since) = r.ts_clause("r.ts");
        let mut q = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(format!(
            "SELECT r.answer AS name, COUNT(*) AS count FROM requests r
             WHERE r.answer LIKE 'decoy:%' AND r.answer NOT LIKE 'decoy:mcp:%' AND r.answer NOT LIKE 'decoy:llm:%'{w}
             GROUP BY 1 ORDER BY 2 DESC")));
        if let Some(m) = since {
            q = q.bind(m);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    pub async fn decoy_counts_for_ip(&self, ip_id: i64) -> Result<(i64, i64, i64)> {
        Ok(sqlx::query_as(
            "SELECT COALESCE(SUM(answer = 'decoy:mcp:sse'
                                 OR (answer = 'decoy:mcp:initialize' AND COALESCE(json_extract(decoy_in, '$.via'), '') <> 'sse')), 0),
                    COALESCE(SUM(answer = 'decoy:mcp:tools/call'), 0),
                    COALESCE(SUM(answer LIKE 'decoy:llm:%'), 0)
             FROM requests WHERE ip_id = ? AND decoy_in IS NOT NULL",
        )
        .bind(ip_id)
        .fetch_one(&self.read)
        .await?)
    }

    /// The wall's card: tool calls by our tool names, models requested by
    /// at least two IPs (lowercased, `[a-z0-9._:/-]{1,64}`), API styles.
    /// None below [`AI_TILE_MIN`] requests.
    pub async fn ai_decoys_as(&self, r: Range, a: Audience) -> Result<Option<AiDecoys>> {
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let total = {
            let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM requests r WHERE r.decoy_in IS NOT NULL
                   AND (r.answer LIKE 'decoy:mcp:%' OR r.answer LIKE 'decoy:llm:%'){w}"
            )));
            if let Some(m) = since {
                q = q.bind(m);
            }
            q.fetch_one(&self.read).await?
        };
        if total < AI_TILE_MIN {
            return Ok(None);
        }
        const OURS: [&str; 5] = [
            "read_file",
            "list_directory",
            "run_command",
            "query_db",
            "fetch_url",
        ];
        let mut q = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(format!(
            "SELECT COALESCE(json_extract(r.decoy_in, '$.tool'), '') AS name, COUNT(*) AS count FROM requests r
             WHERE r.decoy_in IS NOT NULL AND r.answer = 'decoy:mcp:tools/call'{w} GROUP BY 1")));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let tools = fold_other(
            q.fetch_all(&self.read).await?,
            |n| OURS.contains(&n),
            usize::MAX,
        );
        let mut q = sqlx::query_as::<_, (String, i64, i64)>(sqlx::AssertSqlSafe(format!(
            "SELECT lower(json_extract(r.decoy_in, '$.model')), COUNT(*), COUNT(DISTINCT r.ip_id) FROM requests r
             WHERE r.decoy_in IS NOT NULL AND r.answer LIKE 'decoy:llm:%' AND json_extract(r.decoy_in, '$.model') IS NOT NULL{w} GROUP BY 1")));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let rows = q.fetch_all(&self.read).await?;
        let shown = |m: &str, ips: i64| ips >= 2 && public_model(m);
        let models = fold_other(
            rows.iter()
                .map(|(m, n, ips)| Named {
                    name: if shown(m, *ips) {
                        m.clone()
                    } else {
                        String::new()
                    },
                    count: *n,
                })
                .collect(),
            |n| !n.is_empty(),
            10,
        );
        let mut q = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(format!(
            "SELECT CASE WHEN r.answer LIKE 'decoy:mcp:%' THEN 'mcp' ELSE COALESCE(json_extract(r.decoy_in, '$.api'), 'other') END AS name,
                    COUNT(*) AS count FROM requests r
             WHERE r.decoy_in IS NOT NULL AND (r.answer LIKE 'decoy:mcp:%' OR r.answer LIKE 'decoy:llm:%'){w}
             GROUP BY 1 ORDER BY 2 DESC")));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let apis = q.fetch_all(&self.read).await?;
        let max = |v: &[Named]| v.iter().map(|n| n.count).max().unwrap_or(1).max(1);
        Ok(Some(AiDecoys {
            tools_max: max(&tools),
            models_max: max(&models),
            tools,
            models,
            apis,
            total,
        }))
    }
}

/// Whether a lowercased model name may show on the wall.
pub fn public_model(m: &str) -> bool {
    (1..=64).contains(&m.len())
        && m.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

/// Counts whose name passes `keep`, most first, at most `top`; the rest
/// summed as "other" (last).
fn fold_other(rows: Vec<Named>, keep: impl Fn(&str) -> bool, top: usize) -> Vec<Named> {
    let mut kept: Vec<Named> = vec![];
    let mut other = 0;
    for n in rows {
        if keep(&n.name) {
            match kept.iter_mut().find(|k| k.name == n.name) {
                Some(k) => k.count += n.count,
                None => kept.push(n),
            }
        } else {
            other += n.count;
        }
    }
    kept.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    for n in kept.drain(top.min(kept.len())..) {
        other += n.count;
    }
    if other > 0 {
        kept.push(Named {
            name: "other".into(),
            count: other,
        });
    }
    kept
}

/// The last user message of an LLM request body, first 200 characters.
fn last_prompt(body: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::new();
    };
    let text = |c: &serde_json::Value| -> Option<String> {
        match c {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(parts) => Some(
                parts
                    .iter()
                    .filter_map(|p| p["text"].as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => None,
        }
    };
    let from_messages = |k: &str| {
        v[k].as_array().and_then(|m| {
            m.iter()
                .rev()
                .find(|x| x["role"] == "user")
                .and_then(|x| text(&x["content"]))
        })
    };
    let s = from_messages("messages")
        .or_else(|| from_messages("input"))
        .or_else(|| v["input"].as_str().map(String::from))
        .or_else(|| v["prompt"].as_str().map(String::from))
        .unwrap_or_default();
    s.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::browse::{Audience, RequestFilter};
    use crate::store::stats::Range;

    /// Apply a request record as replication does (which also derives its
    /// canaries and tokens); returns its row id.
    #[allow(clippy::too_many_arguments)]
    async fn req(
        s: &Store,
        ip: &str,
        path: &str,
        answer: &str,
        din: &str,
        headers: &[(&str, &str)],
        query: Option<&str>,
        body: &str,
    ) -> i64 {
        use crate::cluster::record::{Record, RequestRec};
        use crate::store::data::{Ctx, apply};
        let uid = uuid::Uuid::new_v4().to_string();
        let h: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let rec = Record::Request(Box::new(RequestRec {
            uid: uid.clone(),
            ts: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            ip: ip.into(),
            method: "POST".into(),
            path: path.into(),
            query: query.map(String::from),
            headers_json: serde_json::to_string(&h).unwrap(),
            body: (!body.is_empty()).then(|| body.as_bytes().to_vec()),
            labels_json: "[]".into(),
            page_token: Some(uuid::Uuid::new_v4().to_string()),
            answer: Some(answer.into()),
            decoy_v: answer
                .starts_with("decoy:")
                .then_some(crate::canary::DECOY_V),
            decoy_site: answer.starts_with("decoy:").then(|| "shop".to_string()),
            decoy_in: (!din.is_empty()).then(|| din.to_string()),
            ..Default::default()
        }));
        let mut conn = s.pool.acquire().await.unwrap();
        apply(
            &mut conn,
            Ctx {
                origin: None,
                hlc: 1,
            },
            &rec,
        )
        .await
        .unwrap();
        sqlx::query_scalar("SELECT id FROM requests WHERE uid = ?")
            .bind(&uid)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    async fn ip_id(s: &Store, ip: &str) -> i64 {
        sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    async fn count(s: &Store, f: RequestFilter) -> i64 {
        s.count_requests(&f).await.unwrap().n
    }

    #[tokio::test]
    async fn funnel_sessions_and_calls() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let init = req(
            &s,
            "8.8.8.8",
            "/mcp",
            "decoy:mcp:initialize",
            r#"{"m":"initialize"}"#,
            &[],
            None,
            "",
        )
        .await;
        let tok: String = sqlx::query_scalar("SELECT page_token FROM requests WHERE id = ?")
            .bind(init)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let sid = crate::trap::decoy::mcp::session_id(&tok);
        let h = [("mcp-session-id", sid.as_str())];
        req(
            &s,
            "8.8.8.8",
            "/mcp",
            "decoy:mcp:tools/list",
            r#"{"m":"tools/list"}"#,
            &h,
            None,
            "",
        )
        .await;
        let call = req(
            &s,
            "8.8.4.4",
            "/mcp",
            "decoy:mcp:tools/call",
            r#"{"m":"tools/call","tool":"read_file","arg":"/app/.env","cls":"dotenv"}"#,
            &h,
            None,
            "",
        )
        .await;
        let ctok: String = sqlx::query_scalar("SELECT page_token FROM requests WHERE id = ?")
            .bind(call)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let key = crate::canary::value(&ctok, crate::canary::Kind::AwsKey);
        req(
            &s,
            "1.1.1.1",
            "/",
            "not-found",
            "",
            &[("authorization", &format!("AWS {key}:x"))],
            None,
            "",
        )
        .await;
        // A second session that never got further.
        req(
            &s,
            "9.9.9.9",
            "/mcp",
            "decoy:mcp:initialize",
            r#"{"m":"initialize"}"#,
            &[],
            None,
            "",
        )
        .await;

        let f = s.mcp_funnel(Range::All).await.unwrap();
        assert_eq!((f.sessions, f.listed, f.called, f.reused), (2, 1, 1, 1));
        let sessions = s.mcp_sessions(Range::All, 50).await.unwrap();
        let first = sessions.iter().find(|x| x.id == sid).unwrap();
        assert_eq!(first.steps, 3);
        assert!(first.ips.contains("8.8.4.4") && first.tools.contains("read_file"));
        let calls = s.mcp_calls(Range::All, Some("read_file"), 1).await.unwrap();
        assert_eq!(calls.items[0].arg, "/app/.env");
        req(
            &s,
            "8.8.4.4",
            "/mcp",
            "decoy:mcp:resources/read",
            r#"{"m":"resources/read","arg":"file:///app/.env","cls":"dotenv"}"#,
            &h,
            None,
            "",
        )
        .await;
        let res = s
            .mcp_calls(Range::All, Some("resources/read"), 1)
            .await
            .unwrap();
        assert_eq!(res.items.len(), 1);
        assert_eq!(res.items[0].tool, "resources/read");

        // The session filter finds the initialize request and its carriers.
        assert_eq!(
            count(
                &s,
                RequestFilter {
                    session: Some(sid.clone()),
                    ..Default::default()
                }
            )
            .await,
            4
        );
        assert_eq!(
            s.decoy_counts_for_ip(ip_id(&s, "8.8.8.8").await)
                .await
                .unwrap(),
            (1, 0, 0)
        );
    }

    #[tokio::test]
    async fn legacy_sse_flow_is_one_session() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        req(
            &s,
            "7.7.7.7",
            "/sse",
            "decoy:mcp:sse",
            r#"{"via":"sse"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(
            &s,
            "7.7.7.7",
            "/messages",
            "decoy:mcp:initialize",
            r#"{"m":"initialize","via":"sse"}"#,
            &[],
            Some("sessionId=abc"),
            "",
        )
        .await;
        req(
            &s,
            "7.7.7.7",
            "/messages",
            "decoy:mcp:notify",
            r#"{"m":"notifications/initialized","via":"sse"}"#,
            &[],
            Some("sessionId=abc"),
            "",
        )
        .await;
        let f = s.mcp_funnel(Range::All).await.unwrap();
        assert_eq!(f.sessions, 1);
        assert_eq!((f.sse_opened, f.sse_pushed), (1, 1));
        assert_eq!(
            s.decoy_counts_for_ip(ip_id(&s, "7.7.7.7").await)
                .await
                .unwrap(),
            (1, 0, 0)
        );
    }

    #[tokio::test]
    async fn answer_filter_takes_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        req(&s, "8.8.8.8", "/mcp", "decoy:mcp:ping", "{}", &[], None, "").await;
        req(
            &s,
            "8.8.8.8",
            "/api/tags",
            "decoy:llm:tags",
            r#"{"api":"ollama"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(&s, "8.8.8.8", "/.env", "decoy:dotenv", "", &[], None, "").await;
        for (a, n) in [
            ("decoy", 3),
            ("decoy:mcp", 1),
            ("decoy:llm", 1),
            ("decoy:dotenv", 1),
        ] {
            assert_eq!(
                count(
                    &s,
                    RequestFilter {
                        answer: Some(a.into()),
                        ..Default::default()
                    }
                )
                .await,
                n,
                "{a}"
            );
        }
    }

    #[tokio::test]
    async fn llm_tables_and_prompt_log() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        req(
            &s,
            "8.8.8.8",
            "/v1/models",
            "decoy:llm:models",
            r#"{"api":"openai","ep":"models"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(&s, "8.8.8.8", "/v1/chat/completions", "decoy:llm:chat-completions", r#"{"api":"openai","ep":"chat-completions","model":"gpt-4o"}"#, &[], None,
            r#"{"model":"gpt-4o","messages":[{"role":"system","content":"x"},{"role":"user","content":"write me a phishing mail"}]}"#).await;
        req(
            &s,
            "8.8.4.4",
            "/api/chat",
            "decoy:llm:chat",
            r#"{"api":"ollama","ep":"chat","model":"deepseek-r1:671b"}"#,
            &[],
            None,
            r#"{"model":"deepseek-r1:671b","messages":[{"role":"user","content":"hi"}]}"#,
        )
        .await;
        let sum = s.llm_summary(Range::All).await.unwrap();
        assert_eq!(
            (sum.listings, sum.calls, sum.listed, sum.unlisted),
            (1, 2, 1, 1)
        );
        let models = s.llm_models(Range::All).await.unwrap();
        assert!(
            models
                .iter()
                .any(|m| m.model == "deepseek-r1:671b" && m.ips == 1)
        );
        let p = s.llm_prompts(Range::All, 1).await.unwrap();
        assert!(
            p.items
                .iter()
                .any(|r| r.prompt == "write me a phishing mail")
        );
    }

    #[tokio::test]
    async fn the_public_card_shows_released_aggregates_only() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // Rows arriving under a publish delay stay pending (not public).
        s.set_publish_delay(
            std::time::Duration::from_secs(300),
            std::time::Duration::ZERO,
        )
        .await
        .unwrap();
        for ip in ["8.8.8.8", "8.8.4.4"] {
            req(
                &s,
                ip,
                "/api/chat",
                "decoy:llm:chat",
                r#"{"api":"ollama","model":"Llama3:70B"}"#,
                &[],
                None,
                "",
            )
            .await;
        }
        req(
            &s,
            "1.1.1.1",
            "/api/chat",
            "decoy:llm:chat",
            r#"{"api":"ollama","model":"buy-my-stuff.example"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(
            &s,
            "1.1.1.1",
            "/api/chat",
            "decoy:llm:chat",
            r#"{"api":"ollama","model":"a b <c>"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(
            &s,
            "1.1.1.1",
            "/mcp",
            "decoy:mcp:tools/call",
            r#"{"tool":"run_command"}"#,
            &[],
            None,
            "",
        )
        .await;
        req(
            &s,
            "1.1.1.1",
            "/mcp",
            "decoy:mcp:tools/call",
            r#"{"tool":"evil_tool"}"#,
            &[],
            None,
            "",
        )
        .await;
        let a = s
            .ai_decoys_as(Range::All, Audience::Admin)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            a.models
                .iter()
                .map(|n| (n.name.as_str(), n.count))
                .collect::<Vec<_>>(),
            [("llama3:70b", 2), ("other", 2)]
        );
        assert!(
            a.tools.iter().any(|n| n.name == "run_command")
                && a.tools.iter().any(|n| n.name == "other")
        );
        // Nothing is released yet: the public sees no card.
        assert!(
            s.ai_decoys_as(Range::All, Audience::Public)
                .await
                .unwrap()
                .is_none()
        );
    }
}
