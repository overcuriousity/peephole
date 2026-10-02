# peephole — classification expansion design spec

Date: 2026-10-02
Status: approved by user (brainstorming complete)

## 1. Purpose

Significantly expand the classification rules so the trap (1) assesses threat
correctly enough to drive the counter-scan, (2) produces meaningful labels for
the web interface, and (3) tags each signature family with a recognized
taxonomy. Coverage is extended to current attack families (SSRF, webshells,
deserialization, template/NoSQL/XML injection, cloud and API recon) and to
agentic-AI attacks (AI-infrastructure probing, MCP abuse), conservatively.

## 2. Decisions locked during brainstorming

- **Levels unchanged.** Rule weight stays 1..=4 and equals severity and scan
  level. No new scan levels, no decoupled severity scale, no nmap preset or
  cluster-protocol changes. The expansion is rules-plus-plumbing only.
- **OWASP, not MITRE ATT&CK.** Hybrid taxonomy per rule: OAT IDs (OWASP
  Automated Threats, e.g. `OAT-014`) for scanner/behavioral families, Top 10
  2021 classes (e.g. `A03:2021`) for payload families. Carried in an optional
  `owasp` rule field, stored per request, shown as badges in the web UI,
  included in exports.
- **AI coverage is conservative.** High-confidence signatures only:
  AI-infrastructure path probes and MCP/JSON-RPC wire patterns. No
  jailbreak/prompt-injection content matching, no AI-crawler UA labels (AI
  crawlers remain the verified-crawler module's domain).
- **Fresh installs everywhere.** No migration file: the new `owasp_json`
  column is added directly to the initial schema (`0001_initial.sql`).
- **Label colors in the UI**, resolved by suffix first (`-probe` → recon
  color), then a short explicit map, then neutral — no registry to maintain.

## 3. Weight rubric (convention for all rules, old and new)

- **1** — single weak tell (behavioral floor only)
- **2** — automated reconnaissance: tooling UAs, sensitive-path discovery,
  infra fingerprinting
- **3** — exploit-adjacent: app-specific CVE probes, XSS, credential attacks,
  webshell existence probes, writes
- **4** — unambiguous exploit payload or post-exploitation: SQLi, RCE,
  traversal, SSRF-to-metadata, deserialization, webshell interaction

Every rule file's header documents its family's weight rationale.

## 4. Rule-set changes

### 4.1 Existing files (labels/weights unchanged; every rule gains `owasp`)

- `sqli.toml` (`A03:2021`): add `waitfor delay`, `pg_sleep`, `dbms_pipe`,
  `xp_cmdshell`, `load_file`, `into outfile` / `into dumpfile`.
- `xss.toml` (`A03:2021`): target gains `<svg`, `<img`, `<iframe`,
  `alert(` / `confirm(` / `prompt(`, `document.cookie`, `fromCharCode`;
  body gains `<svg` and more event handlers.
- `traversal.toml` (`A01:2021`): add `..;` (Tomcat), PHP wrappers
  (`php://filter`, `phar://`, `expect://`, `zip://`), `/etc/shadow`,
  `/proc/version`.
- `rce.toml` (`A03:2021`): mirror the body rule's `;wget|curl|busybox|chmod|tftp`
  dropper chain into the target rule; add Solr/Geoserver-style RCE paths.
- `paths.toml` (`OAT-018`): backups and dumps (`backup.sql`, `dump.sql`,
  `www.zip`, `.env.bak` / `.old` / `.save`), framework debug surfaces
  (`/_profiler`, `/app_dev.php`, `/telescope`, `elmah.axd`, `/debug/vars`),
  `web.config`, `composer.json`, `.terraform`, `tfstate`, `.kube/config`,
  `id_rsa`, `.pem`, `server.key`.
- `appliances.toml` (`OAT-014`): Realtek `/picsdesc.xml`, Huawei
  `/ctrlt/DeviceUpgrade`, Netgear `/setup.cgi`, Linksys `/JNAP/`, Hikvision
  `/SDK/`, Dahua `/RPC2_Login`, Zyxel.
- `scanners.toml`: split into two rules — attack tools (sqlmap, nuclei, …;
  `OAT-004`) and research scanners (Censys, Expanse, LeakIX, plus new:
  Shadowserver, BinaryEdge, stretchoid, zmap; `OAT-018`).

### 4.2 New files

| File | Labels (weight) | OWASP | Catches |
|---|---|---|---|
| `ssrf.toml` | `ssrf` (4) | `A10:2021` | Cloud metadata IPs/hostnames (`169.254.169.254`, `metadata.google.internal`, `169.254.170.2`, `100.100.100.200`) anywhere in the target; URL-ish params (`url=`, `callback=`, `webhook=`, …) pointing at loopback / RFC1918 / decimal / hex IP forms |
| `injection.toml` | `ssti` (4), `nosqli` (4), `xxe` (4), `crlf-injection` (3) | `A03:2021` | `{{7*7}}` / `${7*7}` / `#{…}` template probes; `$where`, `[$ne]=`, JSON `"$gt":` operators; `<!ENTITY` + `SYSTEM`, parameter entities; `%0d%0a` in the target |
| `webshells.toml` | `webshell-probe` (3), `webshell` (4) | `A08:2021` | Known shell filenames (`/shell.php`, `/alfa.php`, `/wso.php`, `/c99`, `/r57`, `/b374k`, short names like `/x.php`); PHP under upload/image dirs; `.php` hidden under `.well-known/`; weight 4 when a shell path carries command params (`?cmd=`, China Chopper's `?z0=` / `z1=` / `z2=`) |
| `deserialization.toml` | `deserialization` (4) | `A08:2021` | Java `rO0AB` / `AC ED 00 05`, .NET `AAEAAAD`, PHP `O:<n>:"…"`, pickle `__reduce__` / `cos\nsystem`, Node `_$$ND_FUNC$$_` |
| `ai.toml` | `ai-infra-probe` (2), `mcp-probe` (3), `mcp-abuse` (4) | `OAT-004` | OpenAI-style `/v1/models`, `/v1/chat/completions`; Ollama `/api/generate`, `/api/chat`, `/api/tags` (root-anchored; documented as the family's one naming-collision risk); Jupyter `/api/terminals`, `/tree`; Gradio `/gradio_api`; MLflow `/api/2.0/mlflow`; Chroma / Qdrant / Weaviate API paths; model files (`.gguf`, `.safetensors`, `.ckpt`, `.onnx`); `/.well-known/ai-plugin.json`; MCP: `/mcp`, `/sse`, JSON-RPC `tools/list` / `tools/call` bodies; `mcp-abuse` = `resources/read` with `file://` URIs |
| `cloud.toml` | `cloud-infra-probe` (3) | `A05:2021` | Kubernetes `/api/v1/namespaces` / `pods` / `secrets`, Docker `/_ping` and `/v1.NN/containers`, Consul `/v1/agent` / `kv`, Vault `/v1/sys/`, etcd `/v2/keys`, Envoy `/config_dump` |
| `api.toml` | `api-recon` (2), `graphql-introspection` (3) | `OAT-004` | `/graphql`, `/swagger*.{json,yaml}`, `/openapi.json`, `/api-docs`, `/redoc`; introspection via `__schema` / `__type` / `IntrospectionQuery` |
| `auth.toml` | `credential-attack` (3) | `OAT-008`, `A07:2021` | Default credential pairs in bodies (`admin:admin`, `root:root`, Mirai/IoT defaults such as `t0talc0ntr0l4!`, `antslq`) |
| `cms.toml` | `app-probe` (3) | `A06:2021` | WebLogic `/wls-wsat`, `/console`; Jenkins `/script`; Drupal user paths; Joomla `com_*`; Magento `/downloader`, `app/etc/local.xml`; ThinkPHP `invokefunction`; Confluence `/setup/setupadministrator` (CVE-2023-22515); TeamCity `/app/rest/`; OFBiz `/webtools/control`; ColdFusion `/CFIDE/`; SharePoint `/_layouts/`; Zimbra `/zimbraAdmin` |

`load_dir` already reads every `*.toml` in sorted order; new files need no
loader changes. Behavioral labels generated in code (`probe`, `path-scanner`,
`form-interaction`, …) are unchanged and carry no OWASP tags.

## 5. `owasp` field plumbing

1. **Rule schema** (`src/classify/rules.rs`): optional
   `owasp: Option<Vec<String>>` on `Rule`. Validation: every entry must match
   `A(0[1-9]|10):2021` or `OAT-0\d\d`; a typo fails at load so `check-config`
   catches it. The tag is optional for operator rules; a meta-test requires it
   on all *shipped* rules.
2. **Classifier** (`src/classify/mod.rs`): `CompiledRule` carries the tags;
   `Verdict` gains `owasp: Vec<String>`, collected from all hit rules, sorted
   and deduped like `labels`. Matching, weights, and scan-level logic are
   untouched.
3. **Storage**: `requests` gains `owasp_json TEXT NOT NULL DEFAULT '[]'`
   directly in `0001_initial.sql` (fresh installs; no migration).
   `NewRequest` (`src/store/requests.rs`) gains the field; `src/trap/mod.rs`
   populates it from the verdict next to `labels_json`. fp-claims store `'[]'`.
4. **Cluster**: `RequestRec` (`src/cluster/record.rs`) gains
   `owasp_json: Option<String>` with the established
   `#[serde(default, skip_serializing_if = "Option::is_none")]` pattern, so old
   signed records rebuild byte-for-byte and old nodes ignore the field. No
   protocol bump — it is opaque payload, like severity.
5. **Export**: `owasp_json` joins the every-field export in `src/export/`.
6. **ID→name table**: a small static map in the admin views
   (`A03:2021` → "Injection", `OAT-014` → "Vulnerability Scanning", …), used
   for badge tooltips.

## 6. Web UI

- **OWASP badges**: wherever labels render (`templates/requests.html`,
  `request.html`, `wall.html`), a second badge row shows the request's OWASP
  tags. New `.badge-owasp` class — visually distinct from label badges
  (outlined/monospace) — with a `title` tooltip from the ID→name table.
  Filter semantics are unchanged (no OWASP filter input; the JSON is in the
  DB and exports).
- **Label colors**: `label_class(&str) -> &str` in `src/admin/views.rs`.
  Suffix rule first: any label ending in `-probe` → recon color (blue), which
  automatically covers future probe families. Then an explicit map: injection
  (`sqli`, `xss`, `ssti`, `nosqli`, `xxe`, `crlf-injection`) → red;
  execution/impact (`rce`, `deserialization`, `ssrf`, `path-traversal`) →
  deep red/purple; interaction (`form-interaction`, `write-method`,
  `credential-attack`) → orange; post-exploitation (`webshell`, `mcp-abuse`)
  → near-black; automation/bot tells (`automation`, `inhuman-behavior`,
  `proxy-probe`, `unusual-method`) → gray; anything else → today's neutral
  accent. Colors are tokens in `assets/css/00-tokens.css` (light + dark,
  following the existing `--sev-*` pattern) as `badge-cat-*` classes.

## 7. Testing

- Per-family corpus tests in `src/classify/mod.rs`: every label pinned with
  attack examples (raw, percent-encoded, double-encoded where relevant) *and*
  benign near-miss examples (English prose, `/learn-powershell`-style slugs,
  framework URLs) so false-positive regressions fail CI.
- Meta-tests: all shipped rules carry a valid `owasp` tag; `label_class`
  returns a known class for every shipped label.
- Existing tests that must keep passing: the full classify corpus, rules
  validation, capture/integration/cluster tests (no level semantics change).
- Storage/cluster/export round-trip tests for `owasp_json` where sibling
  fields already have them.

## 8. Docs

- README: classification paragraph updated with the family list and OWASP
  tagging.
- `docs/operations.md`: new taxonomy section (families, weight rubric, label
  colors) so operators can decode the wall.
- Each new rule file's header documents its family's weight rationale.

## 9. Out of scope

- New scan levels, severity/scan-level decoupling, nmap preset changes,
  cluster protocol bumps.
- Prompt-injection / jailbreak content signatures, AI-crawler UA labels.
- OWASP filter inputs in the UI.
- Behavioral-ladder changes (thresholds, new behavioral labels).
