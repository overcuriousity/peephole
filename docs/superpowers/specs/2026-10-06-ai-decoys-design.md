# AI decoys: MCP and LLM gateway (roadmap item 1)

Date: 2026-10-06 · Status: implemented (branch `ai-decoys`).
Roadmap: `docs/roadmap.md`, item 1 "Stateful decoys, MCP and AI first".

## Goal

Answer MCP and LLM-API probes with something plausible instead of the trap
404, so the next steps are recorded: for MCP, `initialize` → `tools/list` →
`tools/call` with its arguments; for LLM APIs, which models are listed,
pulled and prompted, and with which API style. The rules already label these
probes (`mcp-probe`, `mcp-abuse`, `ai-infra-probe`); today nothing follows.

Success:

- Real clients (official MCP SDK over both transports, MCP Inspector, the
  `ollama` CLI, the `openai` and `anthropic` SDKs, streaming on and off) get
  through the decoys without a protocol error.
- Every answer is rendered from what is stored with the row, so
  `peephole decoy render` reproduces it byte for byte and every node derives
  the same canaries.
- An MCP session, and canaries handed out by its tools, link back to the
  request that started it, across IPs and nodes.
- Nothing is ever executed or fetched. No request bytes are reflected beyond
  the limits below.
- The wall shows only aggregates: tool names (ours) and model names (raw,
  filtered, from at least 2 IPs).

## Decisions

| Topic | Decision |
|---|---|
| Where state lives | Nowhere server-side, except the per-node legacy SSE streams. Session ids are canaries derived from the page token |
| Render input | A new `decoy_in` column: compact JSON parsed from the request by `choose`; `render` reads only it, the page token, the row time and the site word |
| `tools/call` results | Canary content for reads and DB queries, canned output for commands, timeouts for URL fetches |
| LLM replies | One fixed short reply, correctly framed per API and streamed when asked |
| LLM persona | An internal LLM gateway (LiteLLM / one-api style): local Ollama models plus "upstream" OpenAI and Anthropic models |
| MCP transports | Streamable HTTP and legacy HTTP+SSE, both fully |
| Public model names | Raw, lowercased, `[a-z0-9._:/-]{1,64}`, shown only when ≥ 2 distinct IPs asked; else "other" |
| Decoy version | `DECOY_V` 1 → 2; version 2 renders every version-1 name unchanged plus the new ones |

Rejected: rendering from the stored body (light rows and truncated or
compressed bodies could not be answered; aggregates would parse bodies in
SQL); a replicated server-side session table (breaks render purity, nothing
in scope needs it).

## MCP decoy, Streamable HTTP

Routes: `POST /mcp`, `/mcp/`, `/messages` (without `sessionId`) and
`/.well-known/mcp`, when the body parses as a JSON-RPC object with a
`method`. `GET /mcp` answers `405`. A JSON array (batch) answers JSON-RPC
error `-32600`. A body that does not parse keeps the trap 404.

| method | answer | `answer` |
|---|---|---|
| `initialize` | the client's protocol version if known, else `2025-06-18`; `serverInfo {name:"internal-ops", version:"0.3.1"}`; capabilities `tools`, `resources`; header `Mcp-Session-Id` = `mcp-session` canary of this request | `decoy:mcp:initialize` |
| `notifications/*` | `202`, empty | `decoy:mcp:notify` |
| `ping` | `{}` | `decoy:mcp:ping` |
| `tools/list` | the five tools below with JSON schemas | `decoy:mcp:tools/list` |
| `tools/call` | see below | `decoy:mcp:tools/call` |
| `resources/list` | `file:///app/.env`, `file:///home/deploy/.aws/credentials` | `decoy:mcp:resources/list` |
| `resources/read` | as `read_file` for that path | `decoy:mcp:resources/read` |
| `prompts/list` | empty | `decoy:mcp:prompts/list` |
| other | `-32601 Method not found` | `decoy:mcp:unknown` |

Session ids are not checked: a missing or foreign one is answered all the
same; token reuse links it to its `initialize` anyway.

Tools:

- `read_file(path)`: the path maps to a class.
  - `.env` → the version-1 dotenv decoy.
  - `.aws/credentials` → a new AWS credentials file with `aws-key` and
    `aws-secret` canaries.
  - `.git/config` → the version-1 git-config decoy.
  - `/etc/passwd` → a fixed file.
  - `id_rsa`, `id_ed25519`, `*.pem` → `Permission denied`.
  - anything else → `ENOENT`.
- `list_directory(path)`: a fixed tree (`/app`, `/home/deploy`) consistent
  with `read_file`.
- `run_command(command)`: `id`, `whoami`, `uname -a`, `hostname`, `pwd`,
  `ls` get canned output; anything else
  `sh: 1: <first word>: not found`, exit 127.
- `query_db(sql)`: a `SELECT` returns a fixed 3-row `users` table whose
  `api_token` column holds `app-key` canaries; anything else
  `ERROR: permission denied for schema public`.
- `fetch_url(url)`: always `connection timed out`; records the pivot target.
- Unknown tool: `isError: true`, `Unknown tool`.

## MCP decoy, legacy HTTP+SSE

A per-node `SseHub`:

- `GET /sse`, `/sse/`, `/mcp/sse` takes a place from its own pool
  (`mcp_sse_pool`, default 64; `mcp_sse_per_source`, default 2), handing
  the listener slots back as the tarpit does. Pool full: the trap 404.
- The stream sends `event: endpoint` with
  `data: /messages?sessionId=<mcp-session canary of this GET>`, then
  `: ping` every 15 s, and ends after `mcp_sse_hold_secs` (default 300) or
  120 s without a message.
- The hub maps session id → bounded channel (16 messages), removed when the
  stream ends.
- `POST /messages?sessionId=X` is rendered as for Streamable HTTP.
  - X open on this node: the answer is pushed as `event: message`; the POST
    gets `202 Accepted`; `answer` = `decoy:mcp:<method>`, `decoy_in` has
    `"via":"sse"`.
  - X unknown here: `404 Could not find session`; `answer` =
    `decoy:mcp:no-session`, `decoy_in` still holds method and tool.
- The GET's row is written when the stream ends, with `held_ms` and
  `answer` = `decoy:mcp:sse`. A node crash mid-stream loses it, as with the
  tarpit.

## LLM gateway decoy

Models (fixed): local `llama3.1:8b`, `qwen2.5-coder:7b`, `deepseek-r1:14b`,
`nomic-embed-text`; upstream `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`,
`claude-sonnet-5-5`, `claude-opus-5-5`, `claude-haiku-4-5-20251001`. Ollama spells the embedding model
`nomic-embed-text:latest`. Any key
is accepted, none required.

The fixed reply: "I'm here to help. Could you share a bit more detail about
what you need?", with fixed token counts. Ids are derived from the page
token (`chatcmpl-<hex>`, `msg_<…>`, `resp_<…>`); `created` is the row time.
Streams are sent at once, not dripped.

**Ollama native:** `GET /api/version` (`0.6.5`), `/api/tags` and `/api/ps`
(local models, `llama3.1:8b` loaded), `POST /api/show` (listed model:
modelfile and details; else 404). `POST /api/pull` streams NDJSON progress,
then `{"error":"max retries exceeded: … connection reset by peer"}`.
`/api/chat`, `/api/generate`: listed model → the reply (NDJSON when
streaming, Ollama's default); unlisted → 404
`model "x" not found, try pulling it first`. `create`, `delete`, `copy`,
`embed`, `embeddings` → a plausible error.

**OpenAI-style**, under `/v1`, `/openai/v1`, `/api/v1`, `/litellm/v1` and
Azure's `/openai/deployments/{name}/…?api-version=`:

- `GET /models`, `GET /models/{id}`: all models, OpenAI format.
- `POST /chat/completions`: `chat.completion`, or SSE
  `chat.completion.chunk` ending `data: [DONE]`. `tools`, `tool_choice`
  recorded and ignored.
- `POST /completions`: legacy `text_completion`.
- `POST /responses`: a Responses `response`, or its SSE sequence
  `response.created` … `response.completed`.
- `embeddings`, `moderations`, `images/*`, `audio/*`: OpenAI-shaped errors.
- Unlisted model: `404 model_not_found`.

**Anthropic-style**, under `/v1`, `/anthropic/v1`, `/api/anthropic/v1`;
where a path is shared with OpenAI (`/v1/models`), an `anthropic-version` or
`x-api-key` header picks Anthropic:

- `POST /messages`: a `message` with `stop_reason: "end_turn"`, or SSE
  `message_start`, `content_block_start`, `content_block_delta`,
  `content_block_stop`, `message_delta`, `message_stop`. `system`, `tools`,
  `metadata` recorded and ignored.
- `POST /messages/count_tokens`: `{"input_tokens": N}`, N = body length / 4.
- `POST /complete`: legacy Text Completions.
- `GET /models`: the Claude models, Anthropic list format (`data`,
  `has_more`, `first_id`).
- Unlisted model: `404 {"type":"error","error":{"type":"not_found_error",…}}`.

`answer` = `decoy:llm:<ep>`, `<ep>` one of `version`, `tags`, `ps`, `show`,
`pull`, `chat`, `generate`, `models`, `chat-completions`, `completions`,
`responses`, `messages`, `count-tokens`, `complete`, `unsupported`.

Not covered: AWS Bedrock and Vertex AI (attacked at the cloud's endpoints,
not at random IPs); Jupyter, Gradio, Open WebUI, vector databases (keep the
404; possible later items).

## Rules

- `ai-infra-probe` gains `/api/v1/(chat/completions|models)`,
  `/(anthropic|api/anthropic|litellm)/v1/` and `/v1/complete`.
- New `llm-key-use` (weight 3), header-only (a rule's matchers are
  OR-combined, so it cannot also require a path): it matches LLM-provider key
  shapes on any path, i.e. an attempt to spend someone's inference:
  `Authorization: Bearer sk-…`, `x-api-key: sk-ant-…`, Azure's `api-key`
  header.

## Data model

- Migration `0009_decoy_in.sql`: `decoy_in TEXT` on `requests` and
  `skipped_requests`; index `ON requests(ts) WHERE decoy_in IS NOT NULL`.
- `decoy_in`: compact JSON, ≤ 512 bytes. Model, tool, path, command, SQL,
  URL fields cut to 128 characters. JSON-RPC `id` kept when a number or a
  string ≤ 64 characters, else the answer uses `null`. Shapes:
  - MCP: `{"rpc":…, "m":"tools/call", "tool":"read_file", "arg":"…",
    "cls":"aws-credentials", "via":"sse"}`.
  - LLM: `{"api":"ollama|openai|anthropic|azure", "ep":"chat",
    "model":"…", "stream":true, "deployment":"…"}`.
- Cluster records: `decoy_in: Option<String>`,
  `serde(default, skip_serializing_if = "Option::is_none")`, like `held_ms`.
  Older nodes store such rows but cannot re-render version 2 until they
  upgrade.
- Canaries: new `Kind::McpSession` (`mcp-session`), UUID-shaped, found by the
  existing token scan in headers and `?sessionId=`.
  `canary::served(v, token, name)` becomes
  `served(v, token, name, decoy_in)`; `derive_request` and `derive_batch`
  select `decoy_in`. `TOKENS_V` is unchanged: no backfill.
- `peephole decoy render UID` reads `decoy_in`; for an SSE-pushed POST it
  prints the `event: message` frame.
- Export: a `decoy_in` column beside `answer` and `decoy_v`.

Reflection limits: response bodies are canned and under 8 KiB. From the
request only the command's first word (≤ 32 characters, `[A-Za-z0-9._/-]`),
the JSON-RPC `id` and the model name when it matches
`[A-Za-z0-9._:/-]{1,128}` come back.

## Code layout

AI decoy routes skip the tarpit, and AI decoys are chosen before the
version-1 decoys.

- `src/trap/decoy.rs` becomes `src/trap/decoy/mod.rs` (version-1 decoys,
  `choose`, `render` dispatch), with `decoy/mcp.rs`, `decoy/llm.rs` and
  `decoy/sse.rs` (`SseHub`).
- `choose` returns the name and the `decoy_in` value; it parses the body
  once (decompressed as `classify::decoded_body` does).
- Settings `mcp_sse_pool`, `mcp_sse_per_source`, `mcp_sse_hold_secs` in
  `TrapConfig`.

## Admin

New tab **Decoys** (Overview · Analytics · Scans · Links · Decoys · Inbox ·
Cluster · System), with the range picker and sub-tabs:

- **MCP**: funnel (sessions started → listed tools → called a tool → a
  canary from tool output reused), counted per session via `canaries` ⋈
  `request_tokens`; legacy SSE beside it (streams opened → messages pushed →
  `no-session`). Every number links to `/requests`. Sessions table (short
  id, IPs, first/last seen, steps, tools) linking to
  `/requests?session=<id>`, a new `RequestFilter` field (the initializing
  request plus every request carrying the token). Tool-call log (time, IP,
  session, tool, argument ≤ 128, answer class), paged, filterable by tool.
- **LLM**: tiles per API style; funnel (listed models → chat call → listed
  / unlisted model; pulls apart); models table (model, API, requests,
  distinct IPs, listed); prompt log (time, IP, API, model, first 200
  characters of the last user message, decoded from the body at view time).
- **Web**: requests per existing decoy name, linking to Requests.

Switching the range on the Decoys page goes back to the MCP tab. SSE light
rows do not keep `held_ms`.

Elsewhere: the request page shows `decoy_in`; quick filters "MCP decoy" and
"LLM decoy" on Requests; the IP page gets "MCP sessions N · tool calls M ·
LLM calls K".

## Public wall

Card "What they asked our fake AI": tool calls by tool name (unknown tools
as "other"); models requested (raw, lowercased, `[a-z0-9._:/-]{1,64}`, from
≥ 2 distinct IPs, else "other"; top 10); split by API style. Released rows
only (`Audience::Public`), hidden below a minimum count like
`CANARY_TILE_MIN`. In `/api/stats` as `ai_decoys`.

## Docs

CHANGELOG; item 1 off `docs/roadmap.md`; the three settings in
`docs/operations.md`; the wall card under the README's privacy rules.

## Testing

- Decoys: parse and `choose` for every endpoint and prefix (Azure path,
  Anthropic by header); `render` pure (same input, same bytes); version-1
  names unchanged under version 2; every JSON body parses; JSON-RPC ids
  echoed; NDJSON lines parse; OpenAI chunks end in `[DONE]`; Anthropic and
  Responses event order; reflection limits.
- Canaries: `served()` per `read_file` class; `mcp-session` found in the
  header and in `?sessionId=`.
- `SseHub` (tokio, paused time): endpoint event; push into the stream;
  unknown session → 404; pool and per-source caps; idle and hold expiry; row
  written with `held_ms`.
- Store: migration; record round-trip with and without `decoy_in`; public
  and admin aggregates (pending rows hidden, 2-IP threshold, name filter,
  "other"); funnel counts; `session` filter.
- Integration (`tests/`): `initialize` → `tools/list` →
  `tools/call read_file .env` with the session header, then the served AWS
  key reused from another IP; rows, canary link and funnel agree.
- Manual before release: MCP Python SDK client (both transports), MCP
  Inspector, `ollama` CLI via `OLLAMA_HOST`, `openai` and `anthropic` SDKs
  with streaming on and off; none may hit a protocol error.
