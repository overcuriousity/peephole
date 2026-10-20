//! Admin › Traps (MCP, LLM, Web): what the MCP and LLM decoys drew out, and how often the
//! web decoys were served.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppResult, render};
use crate::admin::views::{Chrome, Nav};
use crate::store::browse::Page;
use crate::store::decoys::{LlmSummary, McpFunnel, McpSession, ModelRow, PromptRow, ToolCall};
use crate::store::stats::{Named, Range};
use askama::Template;
use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin/traps/mcp", get(|u, st, q| page(u, st, q, "mcp")))
        .route("/admin/traps/llm", get(|u, st, q| page(u, st, q, "llm")))
        .route("/admin/traps/web", get(|u, st, q| page(u, st, q, "web")))
}

#[derive(serde::Deserialize, Default)]
pub struct DecoysQuery {
    pub range: Option<String>,
    pub tool: Option<String>,
    pub page: Option<u32>,
}

#[derive(Template)]
#[template(path = "admin_decoys.html")]
struct DecoysPage {
    chrome: Chrome,
    range: Range,
    /// The nav; the decoy children carry the current range.
    nav: Nav,
    tab: &'static str,
    tool: Option<String>,
    /// Query string for the pager (ends in `&`).
    qs: String,
    funnel: McpFunnel,
    /// Each session with the short form of its id.
    sessions: Vec<(String, McpSession)>,
    calls: Option<Page<ToolCall>>,
    llm: LlmSummary,
    models: Vec<ModelRow>,
    prompts: Option<Page<PromptRow>>,
    web: Vec<Named>,
}

async fn page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<DecoysQuery>,
    tab: &'static str,
) -> AppResult<Response> {
    let range = Range::parse(q.range.as_deref());
    let page = q.page.unwrap_or(1);
    let tool = q.tool.filter(|t| !t.trim().is_empty());
    let mut qs = format!("range={}&", range.key());
    if let (Some(t), "mcp") = (&tool, tab) {
        qs.push_str(&format!("tool={}&", crate::admin::public::urlencode(t)));
    }
    let mut p = DecoysPage {
        chrome: Chrome::new(true, "admin"),
        range,
        nav: Nav::new("traps", tab)
            .carrying(format!("range={}", range.key()), &["mcp", "llm", "web"]),
        tab,
        tool: tool.clone(),
        qs,
        funnel: McpFunnel::default(),
        sessions: vec![],
        calls: None,
        llm: LlmSummary::default(),
        models: vec![],
        prompts: None,
        web: vec![],
    };
    match tab {
        "mcp" => {
            p.funnel = st.store.mcp_funnel(range).await?;
            p.sessions = st
                .store
                .mcp_sessions(range, 50)
                .await?
                .into_iter()
                .map(|s| (s.id.chars().take(8).collect(), s))
                .collect();
            p.calls = Some(st.store.mcp_calls(range, tool.as_deref(), page).await?);
        }
        "llm" => {
            p.llm = st.store.llm_summary(range).await?;
            p.models = st.store.llm_models(range).await?;
            p.prompts = Some(st.store.llm_prompts(range, page).await?);
        }
        _ => p.web = st.store.web_decoys(range).await?,
    }
    Ok(render(&p)?.into_response())
}
