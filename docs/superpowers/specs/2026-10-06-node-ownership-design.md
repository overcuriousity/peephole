# Node ownership: one key per operator, replacing the config key

Date: 2026-10-06 · Status: draft for review.

Companion spec: [lookup credits](2026-10-06-lookup-credits-design.md). It
uses two things defined here: the list of an operator's own nodes
("siblings") and the owner command channel.

## Problem

Remote configuration today rests on a **config key**: a node with
`cluster.remote_config = true` creates a secret, its operator hands it to
whoever should configure the node, and that holder pastes it on their own
node (`cluster/confkey.rs`). This fits one case badly and one not at all:

- An operator with several nodes has one key per node to carry around, and
  the switch in the config file decides whether the node listens at all.
- Nothing says "these nodes belong to the same operator". The lookup
  credits need exactly that: an operator collects what their nodes earn.

## Goal

- One **ownership key** per operator. An authenticated admin creates it on
  the CLI or in the web interface and enters it on every node they own.
- Holding the key always grants everything an owner may do on an owned
  node. No switch in the config file.
- A node proves to its siblings that it has the same owner. Nobody else
  needs to be able to verify who owns what, and operators still do not need
  to know each other.
- A node that was broken into must not be able to take over its siblings.
- No node can claim to be owned by a key its admin never entered.

## Terms

| Term | Meaning |
|---|---|
| **Cluster** | All member nodes. Their operators need not know or trust each other. Every node judges every other for itself |
| **Fleet** | The nodes of one operator: those that hold a certificate of the same ownership key. A subset of a cluster. Its nodes prove membership to each other, not to the rest of the cluster |
| **Sibling** | Another node of this node's fleet |
| **Managing node** | A fleet node that keeps the ownership key and can therefore command its siblings |
| **Collecting node** | The fleet node that receives what the others earn; the fleet's one balance sits there |

## Decisions

| Topic | Decision |
|---|---|
| Key | 32 random bytes, shown once as `peephole-own1:…`. An Ed25519 key pair is derived from it; the public half is the **owner id** |
| What a node stores | The owner id and a **certificate**: the owner key's signature over the node's id. The secret itself only where the admin chooses to keep it |
| Managing node | A node that keeps the secret. Only it can send owner commands |
| Proof to siblings | The certificate, shown on request. Verified with the owner id the asking node already holds |
| Published? | No. Neither the owner id nor the certificate is replicated or put into membership records |
| Authority | A command signed by the owner key, checked by the target against its stored owner id |
| Replay | Each node keeps a command counter; a command names the counter it was made for |
| Scope | Runtime settings, block/unblock/purge, invite list and revoke, leave, change or drop the owner, send credits |
| Stays local | Everything in the config file, creating invites, passkeys |
| Config key | Removed with `cluster.remote_config`. No migration of keys |

## 1. The key and what derives from it

- **Ownership key**: 32 bytes from the system RNG, encoded like today's
  config key: `peephole-own1:` + base64url (no padding) of CBOR
  `{v: 1, seed: bytes}`.
- **Owner key pair**: `Ed25519KeyPair::from_seed_unchecked(seed)`, the call
  `cluster/identity.rs` already uses for node keys.
- **Owner id**: the 32-byte public key. Shown short (first 12 hex
  characters) in the admin area.
- **Certificate** for node `N`: the owner key's signature over
  `"peephole-owner-cert-v1\0" ‖ N.id`.

A node is **owned** when it stores an owner id and a certificate that
verifies for its own id. It is a **managing node** when it also stores the
seed.

Storage is the `settings` table, next to the keys the node already keeps
there: `owner.id`, `owner.cert`, `owner.seed` (managing nodes only),
`owner.counter`. The seed is protected like the node's own identity key:
by the file permissions of the data directory.

## 2. Taking and giving up ownership

All of these need an authenticated local admin: the CLI on the node (which
opens the database directly, like `peephole cluster …`) or a logged-in
session on its web interface.

| Action | CLI | Effect |
|---|---|---|
| Create | `peephole owner new` | Generates a key, prints it once, makes this node owned and managing. Refused on a node that already has an owner: release it first (a new key would silently orphan the fleet) |
| Adopt | `peephole owner adopt [--keep]` | Reads a key from standard input (never from the arguments, which end up in the shell history). Stores owner id and certificate; with `--keep` also the seed |
| Show | `peephole owner show` | Owner id (short), whether the key is kept here, known siblings |
| Forget key | `peephole owner forget-key [--force]` | Deletes the seed here. The node stays owned. While a rotation started here is unfinished, refused without `--force` (the keys it keeps are the only way to the nodes it moved or did not move yet) |
| Release | `peephole owner release` | Deletes owner id, certificate and seed. The node has no owner |

Adopting on a node that already has another owner replaces that owner. The
local admin is the root of trust of a node: whoever can log in there can
always change its owner.

The web interface offers the same on **Cluster › Ownership** (§6). A
created key is shown once and never again; a managing node can re-display
it only by the admin asking explicitly ("Show key", like today's config
key).

## 3. The fleet

A node needs to know its siblings: to list "my nodes", to decide whose
audits it believes, and to earn and spend credits with them as one entity
(credits spec, §9).

The rest of the cluster does not take part in this. To a node outside the
fleet, a fleet's nodes are ordinary members.

Discovery is a directed message, sent to every active member when
membership changes and every 10 minutes:

- `OwnerHello { tag, cert }`. `tag` is
  `SHA-256("peephole-owner-hello-v1\0" ‖ owner id ‖ sender id ‖ receiver id)`,
  `cert` is the sender's certificate.
- A receiver that is owned recomputes the tag with its own owner id. If it
  matches and the certificate verifies for the sender's id, the sender is a
  sibling; the receiver answers `OwnerHelloReply { cert }` with its own
  certificate, which the sender checks the same way.
- Any other receiver answers `OwnerHelloReply` with an empty certificate.
  The sender then knows the node is reachable and not a sibling, and
  drops it from its siblings if it was one (a node that was released).
  This tells the sender nothing that silence would not.
- No answer at all (unreachable) changes nothing.

The owner id never travels: the tag reveals it to nobody who does not have
it already, and an Ed25519 signature does not give away the public key.

Siblings are kept in a `siblings (node, cert, seen_at)` table and dropped
when the member leaves, is pruned, answers that it is no sibling, or when
this node's owner changes.

What a third party can see: a member that relays the two messages learns
that the two nodes answered each other, and every member sees nodes
forwarding credits to one collecting node. That is accepted; the owner is
not advertised, but which nodes form a fleet is not a secret either.

## 4. Owner commands

Replaces `Msg::ConfigSet`.

```
Msg::OwnerCmd   { counter: u64, cmd: OwnerCmd, sig: bytes }
Msg::OwnerReply { counter: u64, error: Option<String>, data: Option<OwnerData> }
```

`sig` is the owner key's signature over
`"peephole-owner-cmd-v1\0" ‖ sender id ‖ target id ‖ counter (u64, big endian) ‖ CBOR(cmd)`.
`cmd` travels as those CBOR bytes and the target checks the signature over
the bytes it received before it reads them, so a field a later version adds
to a command does not break the signature on an earlier one.

The target executes a command only when all of this holds:

1. It is owned.
2. `sig` verifies under its stored owner id.
3. `counter` equals its stored `owner.counter`.

It then increments the counter before it acts, so a replayed or relayed
copy is refused. A manager learns the counter from `OwnerCmd::Status`,
which is itself signed but accepted with any counter (it changes nothing).
Two managers racing: the second gets "the node changed meanwhile; reload",
as the settings form says today.

Directed messages are already signed by the sending node and relayed
verbatim (`cluster/msg.rs`). The owner signature is on top of that: it
proves the sender holds the owner key, which the node signature does not.

### Commands

| Command | What it does on the target |
|---|---|
| `Status` | Answers settings state (what `ConfigState` holds today), build, owner counter, block list, invites (id, label, uses, expiry; never the secret), credit balance |
| `Settings { base_version, changes }` | `Settings::apply_at`, as `ConfigSet` does today. `Changes` gains the credits collection node (credits spec) |
| `Block { node, subtree }`, `Unblock { node }` | The local block list (`cluster/block.rs`) |
| `Purge { node }` | Deletes a blocked peer's data there |
| `InviteRevoke { id }` | Revokes one of the target's invites |
| `Leave` | The target leaves the cluster and keeps its data |
| `Reown { owner_id, cert }` | Replaces owner id and certificate (key rotation, §5). The target verifies the new certificate for its own id first |
| `Release` | The target drops its owner |
| `SendCredits { to, mc }` | The target writes a credit transfer (credits spec) |

**Not offered remotely: creating an invite.** The answer would carry the
invite secret through whichever members relay it. Invites are created on
the node itself.

**Not reachable at all from outside:** listen and advertised addresses,
paths, WebAuthn, API keys, `never_scan`, `trusted_origins`, nmap arguments,
restart and upgrade. They stay in the config file. With nmap arguments
remotely settable, a stolen ownership key would amount to running commands
on every owned node.

### Log

Every command, accepted or refused, is written to
`owner_log (at, from_node, command, result)` on the target with a one-line
description ("settings: workers=2, scanner=off", "block 3f9a…"), shown on
the target's Ownership page and logged to the journal. `Status` is not
logged. Refusals for a bad signature are logged at most 10 times an hour
per sender.

## 5. Rotating the key

On a managing node, "Rotate key" (web only, since it needs the running
node to send messages):

1. Generates a new key and shows it once.
2. Sends `Reown` with the new owner id and a fresh certificate to every
   sibling, signed with the old key.
3. Switches this node to the new key.
4. Lists the siblings that did not answer. They stay on the old key. The
   old seed is kept under `owner.old_seed` until every sibling has moved or
   the admin discards it; the page keeps offering "Retry" for the rest.

From the review of the implementation (2026-10-06):

- The new key is stored (`owner.next_seed`) before the first `Reown` is
  sent and this node switches in one transaction, so a rotation that is cut
  short is finished with the same key instead of leaving siblings on a key
  nobody holds. The page offers "Finish rotation" while that key exists.
- The rotate dialog can leave siblings out. They stay on the old key and
  are no siblings afterwards: this is how a node that does not cooperate
  is put out (§9), since a hello with a valid old certificate would
  otherwise get it a fresh one.
- A second rotation, and forgetting the key in the web interface, are
  refused while nodes are still pending or a rotation is unfinished.
- A sibling that no longer takes the old key but answers under the new one
  counts as moved (the answer to its `Reown` was lost).

Rotation is the answer to a leaked key. A leaked key in the meantime lets
its holder do everything in §4 to the owned nodes, including `Reown`: an
operator who loses the race recovers on each node locally with
`peephole owner adopt`.

## 6. Admin interface

**Cluster › Ownership** (new sub-tab; the config-key block leaves
Cluster › Access):

- State: "No owner" with *Create key* and *Adopt with a key*; or "Owned by
  `3f9a0c1d2e4b`", "key kept here" / "key not kept here", with *Forget key
  here*, *Release this node*, *Rotate key*, *Show key*.
- **My nodes**: one row per sibling and this node: name, roles, version,
  reachable or last seen, credit balance, where it sends its credits.
  Without the key here, the table is read-only and says so.
- **Commands received**: the `owner_log`, newest first.

**Cluster › a member**, for a sibling when this node keeps the key: the
settings form that today appears for a held config key
(`_node_settings.html`), plus the actions *Block a peer there*, *Revoke an
invite there*, *Leave*, *Release*. The member's page carries a "yours"
badge for siblings.

The Members table shows the same "yours" badge. The "Remote configuration:
open/locked" line disappears from the member page.

## 7. What is removed

- `cluster.remote_config` and `PEEPHOLE_REMOTE_CONFIG`. A config file that
  still sets it loads, and the node logs once at start that the key is
  ignored and ownership replaces it.
- `cluster/confkey.rs`, the `config_keys` table, the `cluster.config_key`
  setting, `peephole cluster config-key …`, the three
  `/admin/cluster/config-key/*` routes.
- `Msg::ConfigSet` and `ConfigSetReply`: still decoded, answered with
  "config keys were replaced by the ownership key (this node runs a newer
  version)". Never sent.
- `Msg::ConfigGet` and `ConfigState` stay: the cluster pages show every
  member's pace from them. `State.open` is always `false`.
- `MemberInfo.remote_config` stays in the struct so old membership records
  decode; new records always carry `false`, and nothing reads it.

From the review (2026-10-06): the `config_keys` table is emptied, not
dropped, so a database restored to the previous version still opens there.

Existing config keys are not converted. After the upgrade no node is
remotely configurable until its admin enters an ownership key. The
changelog says so under "Changed" with the two commands to run.

## 8. Mixed versions

- An old node ignores `OwnerHello` and `OwnerCmd` (unknown message kinds)
  and is never a sibling.
- A new node refuses an old node's `ConfigSet` with the message above.
- Nothing here adds a replicated record kind.

Checked for the plan: a node cannot decode a message body with a `Msg`
variant it does not know (`Envelope::open` fails), so it can neither
handle nor relay it, and the sender gets an error. `PROTO_VERSION`
therefore goes to 3, and hellos and commands are sent only to members
whose `proto_max` is at least 3. A command whose only route leads through
an old member does not arrive; the page says the node did not answer.

## 9. Limits

Accepted as they are (2026-10-06): an operator who wants the benefits of a
fleet is responsible for protecting its key and its nodes.

- **The key is everything.** Whoever has it controls every owned node
  within §4. There is no second factor for commands.
- **A managing node is a target.** Its database holds the seed. Keep the
  key on as few nodes as needed, typically the one web node the operator
  logs in to.
- **Local admin beats owner.** Anyone who can log in to a node, or run the
  CLI on it, can release or re-adopt it. Ownership adds a remote door; it
  does not lock the local one.
- **Certificates do not expire.** A node that was adopted and then
  compromised keeps proving it is a sibling until the operator releases it
  (locally, or with `Release`) or rotates the key.

## 10. Testing

Unit:

- Key encode/parse round trip; wrong prefix, wrong length, wrong version.
- Certificate verifies for its node and for no other.
- Command signature covers sender, target, counter and command: changing
  any of them fails verification.
- Counter: a command is accepted once; a replay and a stale counter are
  refused; `Status` is accepted with any counter and changes nothing.
- Hello tag: equal for the same owner, different for another owner or
  another pair of nodes.

Integration (`tests/cluster.rs`):

- Two nodes adopted with one key find each other as siblings; a third node
  with another key, and one with none, do not answer.
- A managing node changes a sibling's pace; a node without the key cannot;
  the change appears in the target's `owner_log`.
- `Reown` moves a sibling to a new key; commands under the old key are
  refused afterwards.
- A command relayed through a third member is accepted once and its replay
  refused.
- An old `ConfigSet` is answered with the replacement message.
- Config with `remote_config = true` loads and warns.
