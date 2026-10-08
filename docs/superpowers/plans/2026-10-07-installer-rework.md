# Installer rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the first-install questions of `install.sh` as agreed, and ship the four code changes that came out of it: password login, routed RPC for outbound-only nodes, GreyNoise removal, and an untrusted-PROXY-header hint.

**Architecture:** Four independent code parts (B–E) land first, in parallel where the DAG allows; the installer (A) is rewritten last in three sequential tasks because it calls the new `peephole admin password` CLI and every task edits `install.sh` and `tests/install-smoke.sh`.

**Tech Stack:** Rust (axum, sqlx/SQLite, serde/CBOR, tokio), askama templates, bash (`install.sh`), new crates `argon2` and `rpassword`.

**Spec:** `docs/superpowers/specs/2026-10-07-installer-rework-design.md`

## Global Constraints

- Branch `installer-rework`; every task commits there (worktree implementers rebase onto it first and builds use `CARGO_TARGET_DIR=/home/user01/peephole/target`).
- `export PATH=$HOME/.cargo/bin:$PATH` before any cargo command.
- Implementers run only the focused tests named in their task (no full `cargo test`).
- Code style: match surrounding code — short doc comments, the project's plain wording, no new abstractions beyond the task.
- Protocol v4 is not deployed: new `Msg` variants go into it without a version bump.
- Passwords: at least 12 characters; Argon2id PHC string in `intel_meta`; never in config, never on a command line.
- Routed RPC: body at most 1 MiB each way; allowed paths exactly `/rpc/v1/lookup`, `/rpc/v1/resolve`, `/rpc/v1/probe`.
- The installer never changes the firewall; it may print ufw commands.
- certbot always runs with `--register-unsafely-without-email`; no "expiry notices" wording anywhere.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01WzLtCCTQe4po3RL3X75QQd
  ```

## Review Focus

- A password containing shell or TOML special characters (`"`, `\`, `$`, spaces) set through the installer must arrive intact in the hash (stdin, no `toml_safe`) — test in Task 6 and Task 9.
- Removing the last passkey while the method is `both` and no password is stored must be refused, never leave the admin locked out — test in Task 5.
- An outbound-only node that is asked via routed RPC while its long-poll is momentarily down must produce a clean decline ("did not answer in time"), and the held offer must be released as today — test in Task 4.
- An admin domain typed as `https://Peephole.Example.net/admin/` must end up as `peephole.example.net` in `rp_id`, `origin` and `server_name` — test in Task 7.
- A re-run (upgrade) must still ask nothing, even with the new always-asked questions (own addresses, advertise) — test in Task 9.

## DAG

```
Task 1 (GreyNoise) ─────────────┐
Task 2 (PROXY hint)             │
Task 3 (routed RPC core) → Task 4 (call sites)
Task 5 (password store+CLI) → Task 6 (password web)
                                ├→ Task 7 (installer: roles…domain) → Task 8 (installer: password, nginx) → Task 9 (installer: cluster, keys, docs)
Task 5 ─────────────────────────────────────────────────────────────↗ (Task 8 needs the CLI)
```

Wave 1 in parallel: Tasks 1, 2, 3, 5. Wave 2: Tasks 4, 6, 7 (7 after 1). Then 8 (after 5 and 7), then 9.

---

### Task 1: Remove GreyNoise

**Files:**
- Delete: `src/intel/greynoise.rs`
- Modify: `src/intel/mod.rs` (lines 5, 19, 72–80, 114, 195–205), `src/intel/api.rs:6`, `src/config.rs` (56, 199–230, 796–797, tests 1474, 1503–), `src/credits/share.rs:158`, `src/admin/public.rs` (786, 821–, test 1871), `src/store/requests.rs` (test 405–450), `src/store/browse.rs:73`, `templates/ips.html`, `README.md`, `docs/cluster.md`, `docs/dataset.md`, `docs/operations.md`, `deploy/config.example.toml`, `install.sh`, `tests/install-smoke.sh`, `CHANGELOG.md`

**Interfaces:**
- Produces: `crate::intel::GREYNOISE` no longer exists; `Config` has no `greynoise` field.

- [ ] **Step 1: Write the failing test** — in `src/config.rs` tests, replace `greynoise_budgets_follow_the_free_plan_unless_set` with:

```rust
    #[test]
    fn an_old_greynoise_section_is_ignored() {
        let cfg = parse(&format!(
            "{BASE}[roles]\nlistener = false\nweb = false\n\n[greynoise]\napi_key = \"k\"\n"
        ))
        .unwrap();
        assert!(cfg.abuseipdb.is_none() && cfg.shodan.is_none());
    }
```

(`parse` and `BASE` are the helpers `api_providers_are_off_unless_configured` uses; that test also loses its `cfg.greynoise.is_none()` assertion.)

- [ ] **Step 2: Remove every reference.** Run `grep -rni greynoise --exclude-dir=target --exclude-dir=.git . | grep -v docs/superpowers` and delete each use:
  - `src/intel/mod.rs`: `pub mod greynoise;`, `GREYNOISE` const, its `KNOWN_PROVIDERS` entry, the `GREYNOISE => greynoise::tags(data)` arm, the `if let Some(g) = &cfg.greynoise { … }` block.
  - `src/config.rs`: the `greynoise` field, `GreyNoiseConfig` and its `impl`, the `("greynoise", …)` key entry in the secrets list (796–797), the greynoise assertion in the internetdb test.
  - `src/credits/share.rs:158`: the test budget line — rewrite the test to use another weekly-limited fixture name (e.g. `Budget("weekly-test", Some(50.0 / 7.0))`) so the test keeps its meaning.
  - `src/admin/public.rs`: import, `GREYNOISE => &[ … ]` facts arm, and the test at 1871.
  - `src/store/requests.rs` test: switch the provider-tag test from greynoise to Shodan (`crate::intel::SHODAN`, tag `shodan:vpn`), same assertions.
  - `src/store/browse.rs:73`: doc example becomes `(`shodan:vpn`, `abuseipdb:…`)`.
  - `templates/ips.html`: the greynoise tag/filter mention.
  - docs, README, `deploy/config.example.toml`: the `[greynoise]` section and mentions.
  - `install.sh`: `GREYNOISE_API_KEY` header comment, the prompt (line 854), the `toml_safe`, and the `[greynoise]` config block.
  - `tests/install-smoke.sh`: answer strings lose the GreyNoise answer (`wizard: trap only…`: `printf 'y\nn\nn\nlocal\n\n\nabuse-key-1\n\n\nn\n'` becomes `printf 'y\nn\nn\nlocal\n\n\nabuse-key-1\n\nn\n'`; `taken trap port`: `printf 'local\ny\ny\nn\n\n\n\n\nn\n'` becomes `printf 'local\ny\ny\nn\n\n\n\nn\n'`); the `\[greynoise\]` grep alternative goes.
  - `CHANGELOG.md` under the unreleased heading: "Removed: GreyNoise Community enrichment. An existing `[greynoise]` section is ignored."

- [ ] **Step 3: Add a test that an unknown provider's finding from a peer is dropped.** In `src/credits/pay.rs` tests (or wherever `provider_info` is tested), add:

```rust
    #[test]
    fn a_removed_provider_is_unknown() {
        assert!(provider_info("greynoise-community").is_none());
    }
```

- [ ] **Step 4: Run focused tests**

Run: `cargo test --lib config:: intel:: credits:: admin::public store::requests`
Expected: PASS. Then `grep -rni greynoise --exclude-dir=target --exclude-dir=.git . | grep -v docs/superpowers | grep -v CHANGELOG` prints nothing. `bash -n install.sh && shellcheck install.sh tests/install-smoke.sh` clean.

- [ ] **Step 5: Commit** — `git commit -am "Remove GreyNoise enrichment"` (with the trailer; `git rm src/intel/greynoise.rs` first).

---

### Task 2: Hint for a PROXY header from an untrusted peer

**Files:**
- Modify: `src/trap/listen.rs` (enum `Unusable` ~388, `preface` ~399–460, accept loop ~340–360)
- Test: `src/trap/listen.rs` tests module

**Interfaces:**
- Produces: `Unusable::UntrustedProxy` variant (private).

- [ ] **Step 1: Write the failing test** in `listen.rs` tests:

```rust
    #[tokio::test]
    async fn a_proxy_header_from_an_untrusted_peer_is_named() {
        let (mut client, server) = tcp_pair().await; // use the helper the existing preface tests use; if none, bind a TcpListener on 127.0.0.1:0 and connect
        use tokio::io::AsyncWriteExt;
        client.write_all(b"PROXY TCP4 203.0.113.1 10.0.0.1 1234 443\r\n").await.unwrap();
        assert!(matches!(preface(server, false).await, Err(Unusable::UntrustedProxy)));
        let (mut client, server) = tcp_pair().await;
        client.write_all(&super::proxy_proto::SIG_V2[..]).await.unwrap();
        assert!(matches!(preface(server, false).await, Err(Unusable::UntrustedProxy)));
    }
```

- [ ] **Step 2: Run it** — `cargo test --lib trap::listen::tests::a_proxy_header_from_an_untrusted_peer_is_named` → FAIL (no variant).

- [ ] **Step 3: Implement.** Add to `enum Unusable`:

```rust
    /// A PROXY header from a peer outside `trusted_proxies`.
    UntrustedProxy,
```

In `preface`, before `let mut hello = …`, when `!expect_proxy`:

```rust
        if !expect_proxy {
            // A PROXY header from a peer we do not trust: most likely the
            // operator's own proxy, missing from trusted_proxies.
            while buf.len() < proxy_proto::SIG_V2.len() {
                if buf.starts_with(b"PROXY ") || !(proxy_proto::SIG_V2.starts_with(&buf) || b"PROXY ".starts_with(&buf[..buf.len().min(6)])) {
                    break;
                }
                fill(&mut stream, &mut buf).await.ok_or(Unusable::Other)?;
            }
            if buf.starts_with(b"PROXY ") || buf.starts_with(&proxy_proto::SIG_V2[..]) {
                return Err(Unusable::UntrustedProxy);
            }
        }
```

(The loop only reads more while the bytes so far could still be the start of a PROXY header; a TLS ClientHello starts with `0x16` and leaves at once.)

In the accept loop, next to the `Unusable::Proxy(why)` arm:

```rust
                        Err(Unusable::UntrustedProxy) => {
                            if warn_refusal_now(
                                &mut UNTRUSTED_WARNED.lock().unwrap(),
                                peer.ip(),
                                Instant::now(),
                            ) {
                                warn!(%peer, "trap: a PROXY header from a peer that is not in \
                                      trusted_proxies; if it is your proxy, add it there \
                                      (warned once an hour)");
                            } else {
                                debug!(%peer, "trap: PROXY header from an untrusted peer");
                            }
                            return;
                        }
```

and beside `REFUSALS_WARNED`:

```rust
static UNTRUSTED_WARNED: LazyLock<Mutex<HashMap<IpAddr, Instant>>> = LazyLock::new(Default::default);
```

- [ ] **Step 4: Run** `cargo test --lib trap::listen` → PASS (including the existing preface tests: a plain ClientHello from an untrusted peer still works).

- [ ] **Step 5: Commit** — "Trap: name a PROXY header from an untrusted peer".

---

### Task 3: Routed RPC core

**Files:**
- Create: `src/cluster/rpc/routed.rs`
- Modify: `src/cluster/rpc/mod.rs` (add `pub mod routed;`), `src/cluster/msg.rs` (enum `Msg`), `src/cluster/mod.rs` (start function ~967: register handler; add `call_any`)
- Test: `src/cluster/rpc/routed.rs` tests, `tests/cluster.rs` (one end-to-end test)

**Interfaces:**
- Produces:
  - `Msg::Rpc { path: String, body: serde_bytes::ByteBuf }`, `Msg::RpcReply { status: u16, body: serde_bytes::ByteBuf }`
  - `pub const ROUTED_PATHS: [&str; 3] = ["/rpc/v1/lookup", "/rpc/v1/resolve", "/rpc/v1/probe"];`
  - `pub const MAX_ROUTED_BODY: usize = 1 << 20;`
  - `pub fn routed::serve(node: &Arc<Node>)` — registers the message handler.
  - `impl Node { pub async fn call_any<Req: Serialize, Resp: DeserializeOwned>(self: &Arc<Self>, peer: NodeId, path: &str, body: &Req, timeout: Duration) -> Result<Resp> }`

- [ ] **Step 1: Write failing unit tests** in `routed.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_paid_request_paths_are_routed() {
        assert!(allowed("/rpc/v1/lookup") && allowed("/rpc/v1/resolve") && allowed("/rpc/v1/probe"));
        for p in ["/rpc/v1/push", "/rpc/v1/pull", "/rpc/v1/join", "/rpc/v1/intel", "/rpc/v1/msg"] {
            assert!(!allowed(p), "{p}");
        }
    }

    #[test]
    fn bodies_over_the_cap_are_refused() {
        assert!(fits(&vec![0u8; MAX_ROUTED_BODY]));
        assert!(!fits(&vec![0u8; MAX_ROUTED_BODY + 1]));
    }
}
```

- [ ] **Step 2: Run** `cargo test --lib cluster::rpc::routed` → FAIL (module missing).

- [ ] **Step 3: Implement `routed.rs`:**

```rust
//! Paid requests to a member nobody can dial (outbound-only): the request
//! travels as a directed message, which reaches it through the outbox it
//! long-polls, and is answered by the same code as a direct call.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::rpc::cbor;
use serde_bytes::ByteBuf;
use std::sync::Arc;

/// The calls that may arrive as messages: paid answers, nothing that syncs.
pub const ROUTED_PATHS: [&str; 3] = ["/rpc/v1/lookup", "/rpc/v1/resolve", "/rpc/v1/probe"];
/// Largest request or answer body sent as a message (outboxes are in memory).
pub const MAX_ROUTED_BODY: usize = 1 << 20;

pub fn allowed(path: &str) -> bool {
    ROUTED_PATHS.contains(&path)
}

pub fn fits(body: &[u8]) -> bool {
    body.len() <= MAX_ROUTED_BODY
}

fn reply(status: u16, body: Vec<u8>) -> Msg {
    Msg::RpcReply { status, body: ByteBuf::from(body) }
}

/// Answer routed calls the way the RPC handlers answer direct ones.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::Rpc { path, body } = msg else { return None };
            let node = weak.upgrade()?;
            if !allowed(&path) {
                return Some(reply(404, b"not routable".to_vec()));
            }
            if !fits(&body) {
                return Some(reply(413, b"request too large".to_vec()));
            }
            let out = match answer(&node, from, &path, &body).await {
                Ok(bytes) => bytes,
                Err(e) => return Some(reply(400, format!("{e:#}").into_bytes())),
            };
            Some(if fits(&out) { reply(200, out) } else { reply(413, b"answer too large".to_vec()) })
        })
    }));
}

async fn answer(node: &Arc<Node>, peer: NodeId, path: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    match path {
        "/rpc/v1/lookup" => {
            let req: crate::intel::lookup::LookupReq = cbor::decode(body)?;
            cbor::encode(&crate::intel::lookup::serve(node, peer, &req).await)
        }
        "/rpc/v1/resolve" => {
            let req: crate::intel::dns::ResolveReq = cbor::decode(body)?;
            cbor::encode(&crate::intel::dns::serve_resolve(node, peer, &req).await)
        }
        "/rpc/v1/probe" => {
            use crate::scan::probe::serve::{ProbeReq, ProbeResp};
            let req: ProbeReq = cbor::decode(body)?;
            let resp = match node.prober() {
                Some(p) => p.clone().serve(node, peer, &req).await,
                None => ProbeResp::Declined { why: "this node does not probe".into(), price_mc: None },
            };
            cbor::encode(&resp)
        }
        _ => anyhow::bail!("not routable"),
    }
}
```

Refactor `src/cluster/rpc/mod.rs`'s `probe` handler to share the `node.prober()` match (move it into a `pub(crate) async fn probe_answer(node, peer, &req) -> ProbeResp` in `routed.rs` or keep it in `rpc/mod.rs` and call it from both) — one copy only.

Add to `enum Msg` in `msg.rs`:

```rust
    /// A paid call to a member nobody can dial (`rpc::routed`); `body` is
    /// the CBOR request a direct call would POST to `path`.
    Rpc {
        path: String,
        body: serde_bytes::ByteBuf,
    },
    /// Its answer: the HTTP status a direct call would get, and the body.
    RpcReply {
        status: u16,
        body: serde_bytes::ByteBuf,
    },
```

In `src/cluster/mod.rs`, in the start function right before `tokio::spawn(rpc::server::serve(…))`: `rpc::routed::serve(&node);`. Add to `impl Node` beside `call`:

```rust
    /// Like [`Node::call`], also for a member nobody can dial: then the
    /// request goes as a message (only [`rpc::routed::ROUTED_PATHS`]).
    pub async fn call_any<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        self: &Arc<Self>,
        peer: NodeId,
        path: &str,
        body: &Req,
        timeout: Duration,
    ) -> Result<Resp> {
        if let Some(addr) = self.dial_address(&peer) {
            return tokio::time::timeout(timeout, self.call(peer, &addr, path, body))
                .await
                .map_err(|_| anyhow::anyhow!("{path}: no answer within {timeout:?}"))?;
        }
        let bytes = rpc::cbor::encode(body)?;
        if !rpc::routed::fits(&bytes) {
            bail!("{path}: request larger than {} bytes", rpc::routed::MAX_ROUTED_BODY);
        }
        let msg = msg::Msg::Rpc { path: path.into(), body: serde_bytes::ByteBuf::from(bytes) };
        match self.request(peer, msg, timeout).await? {
            msg::Msg::RpcReply { status: 200, body } => {
                rpc::cbor::decode(&body).with_context(|| format!("{path}: undecodable reply"))
            }
            msg::Msg::RpcReply { status, body } => bail!(
                "{path}: HTTP {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(300)])
            ),
            other => bail!("{path}: unexpected answer {other:?}"),
        }
    }
```

(Adjust imports: `msg`, `serde_bytes`; `Duration` is already imported in mod.rs.)

- [ ] **Step 4: Run** `cargo test --lib cluster::rpc::routed cluster::msg` → PASS (the msg encoding tests still pass: new variants are additive).

- [ ] **Step 5: End-to-end test** in `tests/cluster.rs`, next to `a_paid_lookup_moves_credits_from_the_asker_to_the_server`:

```rust
/// A server nobody can dial answers a routed call through its outbox.
#[tokio::test]
async fn an_outbound_only_member_answers_a_routed_call() {
    use peephole::intel::lookup::{LookupReq, LookupResp};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], Opts { advertise: false, ..DEFAULT }).await;
    eventually("b long-polls a", || async { na.node.status.polled_recently(&b.id) }).await;
    assert!(na.node.dial_address(&b.id).is_none());
    let req = LookupReq { ip: "203.0.113.5".into(), providers: vec![], offer_seq: None };
    let resp: LookupResp = na.node
        .call_any(b.id, "/rpc/v1/lookup", &req, std::time::Duration::from_secs(20))
        .await
        .unwrap();
    assert!(resp.findings.is_empty());
    let err = na.node
        .call_any::<_, LookupResp>(b.id, "/rpc/v1/push", &req, std::time::Duration::from_secs(20))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("404"), "{err:#}");
}
```

(If `status.polled_recently` is not `pub`, use whatever the outbound-only sync test at line 336 waits on, or wait for `knows(&na.node, b.id, true)`.)

Run: `cargo test --test cluster an_outbound_only_member_answers_a_routed_call` → PASS.

- [ ] **Step 6: Commit** — "Cluster: routed RPC for members nobody can dial".

---

### Task 4: Paid requests use routed RPC

**Depends on:** Task 3.

**Files:**
- Modify: `src/credits/pay.rs` (quote collection ~78–86, `make_offer` ~323–332, `offer_and_ask` ~573–595), `src/intel/dns.rs` (`choose` ~341, `ask` ~505–530, `describe` ~305–315), `src/scan/probe/ask.rs` (`vantages` ~55–58, the call ~150–165, `dialled_ip` ~44–48), `docs/cluster.md` (~356)
- Test: `tests/cluster.rs`

**Interfaces:**
- Consumes: `Node::call_any` (Task 3).

- [ ] **Step 1: Write failing tests** in `tests/cluster.rs` — copy `a_paid_lookup_moves_credits_from_the_asker_to_the_server` and `a_resolution_for_another_member_is_paid_and_a_failed_one_is_free` as `a_paid_lookup_from_an_outbound_only_server` and `a_resolution_by_an_outbound_only_member`, booting `nb` with `Opts { advertise: false, ..DEFAULT }` and, before asking, `eventually("b long-polls a", …)` as in Task 3. Assertions unchanged (same balances, same receipts). Add a third test, `an_unreachable_outbound_only_server_releases_the_offer`: boot `nb` outbound-only, wait until a knows b's price, shut `nb` down (drop it / send its shutdown), call `peephole::intel::lookup::cluster`, assert b's answer is declined with a reason containing "did not answer in time" or "no answer", and that `book.ledger.held(&a.id)` returns to 0 after the offer's expiry path the existing decline test uses.

- [ ] **Step 2: Run** `cargo test --test cluster outbound_only` → the new tests FAIL ("cannot be dialled from here").

- [ ] **Step 3: Implement.**
  - `pay.rs` quote collection: drop `|| node.dial_address(&id).is_none()`.
  - `make_offer`: drop the dial-address precondition block (the `let addr = if server != me { match node.dial_address … }` and its uses); where `addr` was used later only to call, it goes.
  - `offer_and_ask`: replace the `dial_address` + `node.call` with
    ```rust
        let call = node.call_any::<LookupReq, LookupResp>(
            server, "/rpc/v1/lookup", &req, crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT);
        let r = match call.await {
            Ok(r) => r,
            Err(e) if format!("{e:#}").contains("no answer") => return decline("did not answer in time".into()),
            Err(e) => return decline(format!("could not be asked: {e:#}")),
        };
        // A declined offer comes with a receipt of nothing: fetch it, so
        // what the offer held is free for the next one. A server nobody can
        // dial pushes its receipt with its own sync.
        if r.findings.is_empty() && r.charged_mc == 0
            && let Some(addr) = node.dial_address(&server)
            && let Err(e) = crate::cluster::sync::reconcile(node, server, &addr, false).await
        {
            tracing::debug!(?e, "sync after a declined offer failed");
        }
    ```
  - `dns.rs`: `choose` drops `&& node.dial_address(id).is_some()`; `ask` drops the dial-address guard and calls `node.call_any::<ResolveReq, ResolveResp>(id, "/rpc/v1/resolve", &req, <the timeout it uses today>)`; any post-decline reconcile gets the same `if let Some(addr)` guard. `describe` keeps `dial_address` (it is only a country hint; `public_addrs` comes first).
  - `probe/ask.rs`: `vantages` drops `|| node.dial_address(&id).is_none()`; the call becomes `call_any` with `RPC_TIMEOUT + SERVE_WAIT`, mapping errors like `offer_and_ask`; post-decline reconcile guarded the same way; `dialled_ip` falls back to the first announced public address:
    ```rust
    fn dialled_ip(node: &Node, id: &NodeId) -> Option<IpAddr> {
        node.dial_address(id)
            .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
            .map(|a| a.ip())
            .or_else(|| node.status.known(id)?.hb.public_addrs.first().copied())
    }
    ```
    (Check `public_addrs`' element type; parse if it is a `String`.)
  - `docs/cluster.md`: replace "An outbound-only member, and one of an earlier version, cannot be asked." with "A member of an earlier version cannot be asked; an outbound-only member is asked through the outbox it long-polls." Also add after the outbound-only sentence at ~47: "It answers paid lookups, resolutions and probes the same way."

- [ ] **Step 4: Run** `cargo test --test cluster paid_lookup resolution outbound_only probe` → PASS (old and new).

- [ ] **Step 5: Commit** — "Paid lookups, resolutions and probes reach outbound-only members".

---

### Task 5: Password login — store, guard, CLI

**Files:**
- Create: `src/admin/password.rs`
- Modify: `Cargo.toml` (add `argon2 = "0.5"`, `rpassword = "7"`), `src/admin/mod.rs` (`pub mod password;`), `src/store/auth.rs` (method, hash, guarded key delete), `src/admin/cli.rs` (two subcommands), `src/admin/system.rs` (`key_delete` uses the guarded delete)
- Test: `src/admin/password.rs`, `src/store/auth.rs`, `src/admin/cli.rs` tests

**Interfaces:**
- Produces:
  - `pub enum LoginMethod { Passkey, Password, Both }` in `src/store/auth.rs`, with `as_str()`, `FromStr`, `fn passkey(self) -> bool`, `fn password(self) -> bool`
  - `Store::login_method(&self) -> Result<LoginMethod>` (default `Passkey` when unset)
  - `Store::set_login_method(&self, m: LoginMethod) -> Result<()>` — refuses (bail) when the method would leave no usable sign-in: `Password` without a hash, `Passkey` without a key, `Both` without either
  - `Store::password_hash(&self) -> Result<Option<String>>`
  - `Store::set_password_hash(&self, phc: &str, keep_session: Option<&str>) -> Result<()>` — stores it, switches `Passkey` to `Both`, ends sessions with `cred_id IS NULL` except `keep_session`
  - `Store::delete_credential_guarded(&self, cred_id: &[u8]) -> Result<bool>` — one `BEGIN IMMEDIATE` transaction: deletes when another key remains, or when the method is `Both` and a password hash exists (then sets the method to `Password` if no key remains); returns whether it deleted
  - `admin::password::MIN_LEN: usize = 12`
  - `admin::password::hash(pw: &str) -> Result<String>` (Argon2id, random salt, PHC string)
  - `admin::password::verify(pw: &str, phc: &str) -> bool`
  - `admin::password::check_new(pw: &str) -> Result<(), &'static str>` ("at least 12 characters")
  - CLI: `peephole admin password [--stdin] [CONFIG]`, `peephole admin login-method passkey|password|both [CONFIG]`

- [ ] **Step 1: Failing tests.** `password.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_verify_and_special_characters_survive() {
        let pw = r#"a "quoted" \ $dollar pass"#;
        let phc = hash(pw).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify(pw, &phc));
        assert!(!verify("a quoted pass", &phc));
        assert!(!verify(pw, "not a phc string"));
    }
    #[test]
    fn short_passwords_are_refused() {
        assert!(check_new("elevenchars").is_err());
        assert!(check_new("twelve chars").is_ok());
    }
}
```

`store/auth.rs` tests (use the module's existing `Store` test constructor):

```rust
    #[tokio::test]
    async fn login_method_guard_and_last_key() {
        let s = test_store().await;
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Passkey);
        assert!(s.set_login_method(LoginMethod::Password).await.is_err(), "no password yet");
        s.save_credential(b"k1", "{}", "one").await.unwrap(); // match save_credential's real signature
        // Last key, method passkey: refused.
        assert!(!s.delete_credential_guarded(b"k1").await.unwrap());
        // Both, but no password: still refused.
        s.set_login_method(LoginMethod::Both).await.unwrap();
        assert!(!s.delete_credential_guarded(b"k1").await.unwrap());
        // With a password: the last key goes and the method becomes password.
        s.set_password_hash("$argon2id$v=19$x", None).await.unwrap();
        assert!(s.delete_credential_guarded(b"k1").await.unwrap());
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Password);
        assert!(s.set_login_method(LoginMethod::Passkey).await.is_err(), "no key left");
    }

    #[tokio::test]
    async fn setting_a_password_turns_passkey_into_both_and_ends_password_sessions() {
        let s = test_store().await;
        let a = s.create_session().await.unwrap();
        let b = s.create_session().await.unwrap();
        s.set_password_hash("$argon2id$v=19$x", Some(&b)).await.unwrap();
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Both);
        assert!(!s.validate_session(&a).await.unwrap());
        assert!(s.validate_session(&b).await.unwrap());
    }
```

- [ ] **Step 2: Run** `cargo test --lib admin::password store::auth` → FAIL.

- [ ] **Step 3: Implement.** `password.rs`:

```rust
//! The admin password: an alternative or addition to passkeys, one account,
//! stored as an Argon2id hash in the database.
use anyhow::Result;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use argon2::Argon2;

pub const MIN_LEN: usize = 12;

pub fn check_new(pw: &str) -> Result<(), &'static str> {
    if pw.chars().count() < MIN_LEN { Err("at least 12 characters") } else { Ok(()) }
}

pub fn hash(pw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing the password: {e}"))?
        .to_string())
}

pub fn verify(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}
```

(Enable the `argon2` features needed for `OsRng` — `std` and `password-hash` with `rand_core`/`getrandom`; check `cargo tree` and `cargo deny check licenses` passes.)

`store/auth.rs`: keys `const LOGIN_METHOD: &str = "admin_login_method"; const PASSWORD_HASH: &str = "admin_password_hash";`, the enum and methods per the Interfaces block. `set_login_method` counts credentials (`SELECT COUNT(*) FROM credentials`) and reads the hash; `delete_credential_guarded` runs in `self.pool.begin_with("BEGIN IMMEDIATE")`, reads count/method/hash inside the transaction, deletes the row and its sessions as `delete_credential_keeping_last` does, and writes the method with the same `INSERT … ON CONFLICT` used by `issue_setup_token`. Remove `delete_credential_keeping_last` if `key_delete` was its only caller (switch `src/admin/system.rs:key_delete` to `delete_credential_guarded`) and move its test to the new function.

`cli.rs`: extend `USAGE`:

```rust
pub const USAGE: &str = "usage: peephole admin reset-token [CONFIG]
       peephole admin password [--stdin] [CONFIG]
       peephole admin login-method passkey|password|both [CONFIG]";
```

`password`: load config (same web-role check as `reset-token`), read the password — with `--stdin` one line from stdin (strip only the trailing `\n`/`\r\n`), else `rpassword::prompt_password("New admin password: ")` twice and compare — `check_new`, `hash`, `store.set_password_hash(&phc, None)`, print "Password set. Sign-in: <method>." `login-method`: parse, `set_login_method`, print it; the guard's error text names what is missing ("no password is set: run peephole admin password first" / "no passkey is enrolled").

Unit-test the stdin line handling as a pure fn `fn stdin_password(input: &str) -> &str` in `cli.rs` tests (`"pw\n"` → `"pw"`, `"pw\r\n"` → `"pw"`, `" spaced pw \n"` → `" spaced pw "`).

- [ ] **Step 4: Run** `cargo test --lib admin::password store::auth admin::cli admin::system` → PASS. `cargo deny check licenses` → ok.

- [ ] **Step 5: Commit** — "Admin: password sign-in store, guard and CLI".

---

### Task 6: Password login — web

**Depends on:** Task 5.

**Files:**
- Modify: `src/admin/auth.rs` (route `/login/password`, `login_page` passes the method), `templates/login.html`, `src/admin/system.rs` (keys page: method + password forms; routes `/admin/system/signin`, `/admin/system/password`), `templates/admin_keys.html`, `src/admin/limit.rs` (verify `/login/password` is covered; it is under `/login/`)
- Test: `src/admin/auth.rs` tests, `tests/integration.rs` (or wherever admin HTTP tests live: grep for `"/login/start"`)

**Interfaces:**
- Consumes: `LoginMethod`, `Store::{login_method,set_login_method,password_hash,set_password_hash}`, `password::{verify,hash,check_new}`.

- [ ] **Step 1: Failing HTTP tests** (in the file where admin routes are exercised; follow its app/request helpers):
  - method `passkey`: `POST /login/password` with `password=…` → 403, no session cookie.
  - method `both` with hash of `"correct horse battery"`: wrong password → 401 "wrong password"; right one → 303 to `/admin` with the session cookie (`__Host-` prefix behind TLS as `session_cookie` does).
  - `GET /login` with method `password` shows the password form and no passkey button; with `passkey` the reverse.
  - Keys page `POST /admin/system/signin` `method=password` without a password → page shows the guard error, method unchanged.
  - `POST /admin/system/password` with a current password required when one exists: wrong current → error; new shorter than 12 → error; mismatch → error; valid → hash changes.
  - A password containing `"` and `\` set through the form verifies afterwards.

- [ ] **Step 2: Run** them → FAIL.

- [ ] **Step 3: Implement.**
  - `auth_routes()` adds `.route("/login/password", post(login_password))`.
  - ```rust
    #[derive(serde::Deserialize)]
    pub struct PasswordLogin { password: String }

    async fn login_password(
        State(state): State<Arc<AdminState>>,
        jar: CookieJar,
        axum::Form(f): axum::Form<PasswordLogin>,
    ) -> Response {
        let method = state.store.login_method().await.unwrap_or_default();
        if !method.password() {
            return (StatusCode::FORBIDDEN, "password sign-in is off").into_response();
        }
        let Ok(Some(phc)) = state.store.password_hash().await else {
            return (StatusCode::UNAUTHORIZED, "wrong password").into_response();
        };
        let ok = tokio::task::spawn_blocking(move || crate::admin::password::verify(&f.password, &phc))
            .await
            .unwrap_or(false);
        if !ok {
            tracing::info!("password sign-in rejected");
            return (StatusCode::UNAUTHORIZED, "wrong password").into_response();
        }
        let old = session_token(&state, &jar);
        match state.store.create_session_for(None, old.as_deref()).await {
            Ok(token) => (jar.add(session_cookie(&state.cfg, token)), Redirect::to("/admin")).into_response(),
            Err(e) => {
                tracing::warn!(?e, "could not create session");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
    ```
    (`LoginMethod: Default` = `Passkey`.)
  - `LoginPage` gets `passkey: bool, password: bool, error: Option<String>`; `login.html`:
    ```html
    <div class="card auth-card" data-webauthn="login">
      <img src="/assets/logo.svg?v={{ chrome.stamp }}" alt="">
      <h1>Admin login</h1>
      {% if passkey %}<button class="btn btn-primary btn-block" type="button" data-go>Authenticate with security key</button>{% endif %}
      {% if password %}
      <form method="post" action="/login/password" class="stack">
        <input type="text" name="username" value="admin" autocomplete="username" hidden>
        <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
        <button class="btn{% if !passkey %} btn-primary{% endif %} btn-block" type="submit">Sign in with password</button>
      </form>
      {% endif %}
      <div class="status" data-msg></div>
    </div>
    ```
    A failed form post re-renders the page with `error` "Wrong password." (status 401) rather than a bare text body, when the request came from the form (`Accept: text/html`); keep it simple: always render the page with the error.
  - Keys page: `KeysPage` gets `method: &'static str`, `has_password: bool`, `notice: Option<String>`; template adds a "Sign-in" card above the keys table: radio `passkey/password/both` posting to `/admin/system/signin`, and a password form (`current` shown when `has_password`, `new`, `again`, all `autocomplete` set) posting to `/admin/system/password`. Handlers take `SessionUser`, validate with `check_new`, verify `current` with `password::verify` in `spawn_blocking`, call the store, and re-render with a notice/error (follow how `key_delete` redirects; use a query-string notice if the page already has one, else render directly).
  - `can_delete` on the keys page: `keys.len() > 1 || (method == Both && has_password)`.

- [ ] **Step 4: Run** the focused admin tests → PASS.

- [ ] **Step 5: Commit** — "Admin: sign in with a password".

---

### Task 7: Installer — roles, front, proxies, own addresses, domain

**Depends on:** Task 1.

**Files:**
- Modify: `install.sh` (header comment 7–40, `prompt` 472–483, questions 653–825), `tests/install-smoke.sh`

**Interfaces:**
- Produces (bash): `normalize_domain <value>` → prints the bare lower-case host or returns 1; `valid_cidr <value>` → 0/1; `prompt` takes its default without a terminal; question order through the domain.

- [ ] **Step 1: Smoke-test expectations first.** Edit `tests/install-smoke.sh`:
  - fresh install: invoke as `PEEPHOLE_FRONT=remote bash install.sh` (a preset `PEEPHOLE_TRUSTED_PROXIES` no longer means remote); assert `grep -q '^scanner = false' /etc/peephole/config.toml` (scanner off without a terminal).
  - add `echo "== the admin domain is normalised"`: `reset_install; PEEPHOLE_FRONT=remote PEEPHOLE_DOMAIN='https://Peephole.Example.net/admin/' bash install.sh` → `grep -q '^rp_id = "peephole.example.net"'`, `grep -q '^origin = "https://peephole.example.net"'`, `grep -q 'server_name peephole.example.net;' /etc/peephole/nginx.example.conf`; and `PEEPHOLE_DOMAIN='not a domain'` fails with "not a host name" before anything is written.
  - add `echo "== a bad trusted proxy is refused"`: `PEEPHOLE_FRONT=remote PEEPHOLE_ROLES=listener PEEPHOLE_TRUSTED_PROXIES=10.0.0.0/33` fails naming `10.0.0.0/33`.
  - wizard answer strings gain the own-addresses answer (empty) after the front/proxy answers for every wizard that has the trap or scanner role; scanner answers that relied on the default `y` now type `y` explicitly (`wizard4` already does).
- [ ] **Step 2: Run the smoke test in a container** (needs a release binary):

```bash
export PATH=$HOME/.cargo/bin:$PATH
CARGO_TARGET_DIR=/home/user01/peephole/target cargo build --release
podman run --rm -v "$PWD":/src -w /src -e PEEPHOLE_BIN=target/release/peephole ubuntu:24.04 bash tests/install-smoke.sh
```
Expected: FAIL at the first changed expectation.

- [ ] **Step 3: Implement in `install.sh`:**
  - `prompt`: without a terminal, take the default when there is one:
    ```bash
    if [ "$INTERACTIVE" -ne 1 ]; then
        [ -n "$default" ] || die "missing required setting: ${var} (set it as an environment variable for non-interactive installs)"
        value="$default"
    else
        if [ -n "$default" ]; then say "${msg} [${default}]: "; else say "${msg}: "; fi
        read -r value <&3 || true
        [ -n "$value" ] || value="$default"
    fi
    ```
  - Scanner (Q2): default `n` always; the cost/benefit text is printed before the question (interactive) — exact text:
    ```
    The scanner counter-scans addresses that hit a trap and gives the cluster their open ports
    and services. Cost: nmap traffic from this machine's address to other people's machines.
    That draws abuse reports, and most hosting and cloud providers forbid scanning in their
    terms and may suspend the account. Run it only where scanning is allowed.
    ```
    plus `"This machine runs on ${CLOUD}."` when detected. Non-interactive default roles: `listener,web`. The preset-roles cloud `warn` stays.
  - Front (Q4): new explanatory text before the choice (spec §4 wording, three short paragraphs); delete the `if [ -n "${PEEPHOLE_TRUSTED_PROXIES:-}" ]; then front_default=remote` branch.
  - Proxies (Q5): before the question, list interfaces with prefixes (`ip -o addr show scope global | awk '{print $4}'`, fallback to `local_addresses`) and the examples; add
    ```bash
    valid_cidr() {
        local a="${1%/*}" p=""
        [[ "$1" == */* ]] && p="${1##*/}"
        valid_ip "$a" || return 1
        [ -z "$p" ] && return 0
        [[ "$p" =~ ^[0-9]{1,3}$ ]] || return 1
        if [[ "$a" == *:* ]]; then [ "$p" -le 128 ]; else [ "$p" -le 32 ]; fi
    }
    ```
    loop: on a bad entry, interactive → say "'<entry>' is not an address or CIDR" and ask again (unset the variable, re-prompt); preset/non-interactive → `die "PEEPHOLE_TRUSTED_PROXIES: '<entry>' is not an address or CIDR"`.
  - Own addresses (Q6): ask whenever interactive with trap or scanner role and the variable unset; default `${DETECTED_OWN:--}`; the explanation from the spec before it.
  - Domain (Q7):
    ```bash
    normalize_domain() {
        local d="${1,,}"
        d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d%.}"
        [[ "$d" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
        printf '%s' "$d"
    }
    ```
    question text: `Public domain of the admin site, without https:// or a path (e.g. peephole.example.net); its DNS must point here`; a line before it: "Changing it later makes enrolled passkeys unusable." Interactive bad value → "'<v>' is not a host name" and ask again; preset bad → `die "PEEPHOLE_DOMAIN: '<v>' is not a host name"`. Store the normalised value back in `PEEPHOLE_DOMAIN`.
  - Header comment: update `PEEPHOLE_ROLES` default, `PEEPHOLE_FRONT` default text, and drop "remote when PEEPHOLE_TRUSTED_PROXIES is set".

- [ ] **Step 4: Run** `bash -n install.sh && shellcheck install.sh tests/install-smoke.sh` and the container smoke test → PASS.

- [ ] **Step 5: Commit** — "Installer: scanner opt-in, clearer front, validated proxies and domain".

---

### Task 8: Installer — password, nginx preflight, no ACME email

**Depends on:** Tasks 5 and 7.

**Files:**
- Modify: `install.sh` (questions after the domain; `setup_nginx` ~1251; closing summary ~1440), `tests/install-smoke.sh`

**Interfaces:**
- Consumes: `peephole admin password --stdin CONFIG` (Task 5).
- Produces (bash): `nginx_preflight` → prints one line per check, sets `NGINX_PROBLEMS` (newline-separated reasons; empty when all pass); `setup_nginx` keeps its own checks as a safety net.

- [ ] **Step 1: Smoke expectations:**
  - `echo "== unattended password: hashed, never in the config"`: `reset_install; PEEPHOLE_FRONT=remote PEEPHOLE_ADMIN_PASSWORD='pa"ss \ $word 12' bash install.sh` → `! grep -q 'pa"ss' /etc/peephole/config.toml`; `sqlite3 /var/lib/peephole/peephole.db "SELECT value FROM intel_meta WHERE key='admin_password_hash'" | grep -q '^\$argon2id\$'`; method `both`; the log names password sign-in. A short one (`PEEPHOLE_ADMIN_PASSWORD=short`) fails before anything is written.
  - `echo "== wizard nginx: an unresolvable domain makes the default no"`: wizard with web role, domain `peephole.test` (does not resolve), accept every default → the log contains `does not resolve` (or `points to`) and the nginx site is not written; the manual steps are printed.
  - existing `PEEPHOLE_NGINX=1, certificate refused` case: drop `PEEPHOLE_ACME_EMAIL=…` and the `-m ops@peephole.test` grep; assert `--register-unsafely-without-email` in `/tmp/certbot.log`.
  - wizard answer strings gain: password question (`n`) after the domain for web-role wizards; the nginx question moves before the cluster/API answers.
- [ ] **Step 2: Run** the container smoke test → FAIL.
- [ ] **Step 3: Implement:**
  - Password (Q8, web only), after the domain:
    ```bash
    if has_role web; then
        if [ -z "${PEEPHOLE_ADMIN_PASSWORD:-}" ] && [ "$INTERACTIVE" -eq 1 ]; then
            say $'\nSign-in to the admin site: a passkey (security key, phone, password manager) is the\nstronger option; a password works from any browser. Either way the site needs HTTPS.\n'
            ask_yn want_password "Also allow signing in with a password?" n
            if [ "$want_password" = 1 ]; then
                while :; do
                    say "Admin password (at least 12 characters): "; IFS= read -rs p1 <&3 || true; say $'\n'
                    say "Again: "; IFS= read -rs p2 <&3 || true; say $'\n'
                    if [ "${#p1}" -lt 12 ]; then say $'Too short.\n'; continue; fi
                    [ "$p1" = "$p2" ] || { say $'They differ.\n'; continue; }
                    PEEPHOLE_ADMIN_PASSWORD="$p1"; break
                done
            fi
        fi
        if [ -n "${PEEPHOLE_ADMIN_PASSWORD:-}" ] && [ "${#PEEPHOLE_ADMIN_PASSWORD}" -lt 12 ]; then
            die "PEEPHOLE_ADMIN_PASSWORD: at least 12 characters"
        fi
    fi
    ```
    No `toml_safe` on it (it never enters the config). After the config is installed and before the first start (next to the `cluster join` block):
    ```bash
    if has_role web && [ -n "${PEEPHOLE_ADMIN_PASSWORD:-}" ]; then
        if printf '%s\n' "$PEEPHOLE_ADMIN_PASSWORD" | "$INSTALL_BIN" admin password --stdin "$CONFIG_FILE"; then
            PASSWORD_SET=1
        else
            warn "setting the admin password failed; set it with: peephole admin password"
        fi
        unset PEEPHOLE_ADMIN_PASSWORD
    fi
    ```
    Summary: after the enroll-key line, `[ "${PASSWORD_SET:-0}" = 1 ] && echo "  - Or sign in at https://${PEEPHOLE_DOMAIN}/login with your password."`. Header comment documents `PEEPHOLE_ADMIN_PASSWORD`.
  - nginx (Q9): move the whole `nginx_fits` block to right after the password question. Extract `setup_nginx`'s precondition checks into `nginx_preflight` (it must not change anything): existing site/stream file; other 443 sites when `stream_trap`; `sites-enabled/default` not a link; missing packages with `PEEPHOLE_SKIP_APT=1`; with the web role:
    ```bash
    resolved="$(getent ahosts "$PEEPHOLE_DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u)"
    mine="$(printf '%s\n' $if_addrs $DETECTED_OWN $(printf '%s' "${OWN_ADDRESSES:-}" | tr ',' ' ') | sort -u)"
    if [ -z "$resolved" ]; then
        problem "${PEEPHOLE_DOMAIN} does not resolve; the certificate request will fail"
    elif [ -z "$(comm -12 <(printf '%s\n' "$resolved") <(printf '%s\n' "$mine"))" ]; then
        problem "${PEEPHOLE_DOMAIN} points to $(printf '%s' "$resolved" | tr '\n' ' ')- not to this machine; the certificate request will fail"
    fi
    ```
    Then print "The installer will: …" (packages actually missing, certificate when web and none exists, default site disabled when trap, the site file, the stream include when `stream_trap`, `nginx -t` and reload; everything put back on failure) and "Port 80 must be reachable from the internet for the certificate." (web). Ask `ask_yn PEEPHOLE_NGINX "Set up nginx now?" "$([ -z "$NGINX_PROBLEMS" ] && echo y || echo n)"` after printing each problem. `stream_trap`, `if_addrs`, `DETECTED_OWN`, `OWN_ADDRESSES` are all known at this point; check `stream_trap` is defined before use (move its definition up if needed).
  - ACME: delete the `PEEPHOLE_ACME_EMAIL` prompt, its regex check and header comment line; `setup_nginx` always uses `--register-unsafely-without-email` (drop the `contact` array). Search docs for "expiry" / "ACME_EMAIL" and remove.
- [ ] **Step 4: Run** shellcheck and the container smoke test → PASS.
- [ ] **Step 5: Commit** — "Installer: password sign-in, nginx preflight, no ACME email".

---

### Task 9: Installer — cluster, keys, docs, CHANGELOG

**Depends on:** Task 8.

**Files:**
- Modify: `install.sh` (cluster block 826–842, config `[cluster]` block ~1087, join block ~1114, enrichment prompts 843–855, summary ufw lines ~1404), `tests/install-smoke.sh`, `docs/operations.md`, `docs/cluster.md`, `README.md`, `deploy/config.example.toml`, `CHANGELOG.md`

- [ ] **Step 1: Smoke expectations:**
  - global export adds `PEEPHOLE_CLUSTER_ADVERTISE=node.test:7443`; every wizard run unsets it (`env -u PEEPHOLE_CLUSTER_ADVERTISE`) and types an advertise answer.
  - every generated config has `[cluster]` with `node_name = "<hostname -s>"` unless preset, `listen = "0.0.0.0:7443"`, `advertise = …`; the trap-only wizard's "no `[cluster]`" assertion goes; its grep list keeps `webauthn|maxmind|admin_listen`.
  - `echo "== advertise is required"`: unattended with `env -u PEEPHOLE_CLUSTER_ADVERTISE` and no domain-backed default (`PEEPHOLE_FRONT=remote`) fails with `missing required setting: PEEPHOLE_CLUSTER_ADVERTISE`; with `PEEPHOLE_ROLES=listener,web PEEPHOLE_FRONT=local` and no advertise preset, the default `peephole.test:7443` is written.
  - `PEEPHOLE_CLUSTER=0` preset still writes `[cluster]` (ignored).
  - the forced-upgrade-with-wizard-variables case keeps passing (upgrade asks nothing; config untouched).
  - wizard answer strings: no cluster yes/no; node name (empty → hostname), advertise (typed), token (empty).
  - the trap-only wizard's question log contains `peephole cluster join`.
  - `wizard-bad`: the rejected-value case now uses an advertise of `bogus` (no port) → the installer re-asks interactively; for the "binary rejects" path use `PEEPHOLE_CLUSTER_LISTEN=bogus` preset instead.
- [ ] **Step 2: Run** the container smoke test → FAIL.
- [ ] **Step 3: Implement:**
  - Remove the "Take part in a cluster?" question and every `PEEPHOLE_CLUSTER` condition (config block, join block, summary). Header comment: `PEEPHOLE_CLUSTER` gone, `PEEPHOLE_CLUSTER_ADVERTISE` required, `PEEPHOLE_CLUSTER_NAME` default hostname, `PEEPHOLE_CLUSTER_LISTEN` default `0.0.0.0:<advertise port>`.
  - Node name: `prompt PEEPHOLE_CLUSTER_NAME "This node's name (other operators see it in their admin area)" "$(hostname -s 2>/dev/null || hostname)"`.
  - Advertise: explanation first —
    ```
    Other members dial this node at an address you publish. The port must be reachable from the
    internet; the installer does not change the firewall. To change it later: advertise and listen
    in /etc/peephole/config.toml, then restart peephole.
    ```
    default: `${PEEPHOLE_DOMAIN}:7443` when `has_role web` and front ≠ remote, else `${PUBLIC_ADDR:-${OWN_ADDRESSES%%,*}}:7443` when an address is known, else none; `prompt PEEPHOLE_CLUSTER_ADVERTISE "Address other nodes dial (host:port)" "$advertise_default"`; check `[[ "$v" =~ ^[^[:space:]:]+:[0-9]{1,5}$ || "$v" =~ ^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]]` and port 1–65535, re-ask / die like the domain. `PEEPHOLE_CLUSTER_LISTEN="${PEEPHOLE_CLUSTER_LISTEN:-0.0.0.0:${PEEPHOLE_CLUSTER_ADVERTISE##*:}}"`, then `claim_port` as today.
  - Token: `prompt_optional PEEPHOLE_JOIN_TOKEN "Invite token from a member (empty to start alone; join later with: peephole cluster join <token>)"`. Verify by reading `src/cluster/cli.rs` join + `src/cluster/mod.rs` whether a running daemon picks up a join: if the daemon reads members only at start, append "then systemctl restart peephole" to that hint, the summary and the failed-join warning.
  - Config `[cluster]` block always written; drop the outbound-only comment branch (advertise always set).
  - Shodan prompt: `Shodan API key (https://account.shodan.io; over the free InternetDB it adds product and version per port, OS, organisation, ISP, ASN, domains, IPv6 and the latest crawl instead of a weekly snapshot; host lookups need a membership or paid plan)`.
  - Summary ufw block: open the cluster port as `ufw allow ${port}/tcp` (always printed now that the port is always published), still only printed.
  - Docs: `docs/operations.md` installer section (new order, defaults, unattended variables), `docs/cluster.md` (outbound-only = hand-edited fallback: delete `advertise` and set `listen` to loopback; what it still does after Task 4), README install snippet if it lists variables, `deploy/config.example.toml` comments for `[cluster]`.
  - `CHANGELOG.md` (unreleased), "Installer" entries: scanner off by default (unattended: add `scanner` to `PEEPHOLE_ROLES`); `PEEPHOLE_FRONT=remote` needed where a preset `PEEPHOLE_TRUSTED_PROXIES` meant remote; `[cluster]` always written, `PEEPHOLE_CLUSTER_ADVERTISE` required, `PEEPHOLE_CLUSTER` and `PEEPHOLE_ACME_EMAIL` ignored; password sign-in (`PEEPHOLE_ADMIN_PASSWORD`); nginx preflight; domain normalised. Plus "Admin: password sign-in" and "Cluster: outbound-only members answer paid lookups, resolutions and probes" and the PROXY hint, if Tasks 2, 4, 6 did not add theirs.
- [ ] **Step 4: Run** shellcheck and the container smoke test → PASS; `cargo test --lib config::` (example config still parses, if a test reads it).
- [ ] **Step 5: Commit** — "Installer: cluster always on, required advertise address; docs".
