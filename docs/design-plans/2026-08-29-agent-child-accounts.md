# Agent Child Accounts Design

## Summary

This design lets a user and an autonomous agent cooperate — through the wallet and the
auth.md ceremony — to give the agent its **own account** (own DID, repo, and handle)
under the user's cryptographic ownership, instead of a credential to act as the user.

The custody mechanism is hierarchical deterministic (HD) key derivation reused from the
existing recovery-seed machinery: at the one moment the wallet already holds the
account's recovery seed in memory (share ceremony or share-recovery verification), it
derives one additional at-rest secret — a `delegation_seed` — and stores it in the
Keychain alongside existing per-DID secrets. Each child account's rotation key is then
derived on demand from that seed plus an incrementing index, using the same HKDF
construction and golden-vector pinning discipline already used for recovery keys.
Minting a child never requires a new secret prompt or new custody surface — it's a pure
function of a seed the wallet already protects, and compromising the delegation seed
exposes only the child subtree, never the parent recovery seed.

The approval flow layers on top of the existing anonymous auth.md claim ceremony rather
than replacing it: an agent optionally proposes a handle at registration, the user's
existing claim-approval screen gains a "create its own account" branch alongside today's
"give access to my account" branch, and the wallet builds and signs the child's DID
genesis op before submitting it in a new optional block on the existing claim-confirm
call. Server-side, that confirm call verifies and mints the child account and converts
the anonymous registration into it in a single transaction — no second registration row,
and a failure leaves only a harmlessly-reserved signing key. Everything downstream (the
agent's poll for credentials, its OAuth token exchange) is unchanged; only the DID that
ends up as `sub` differs. The seven implementation phases split roughly along these
three layers (crypto primitives, server plumbing, wallet custody and UI) so each can be
built and tested independently before the end-to-end ceremony is wired together.

## Definition of Done

1. **Crypto**: `crates/crypto` gains `derive_delegation_seed` + `derive_child_seed(i)`
   (HKDF-SHA256, domain-separated, golden-vector pinned like the recovery-seed derivation).
2. **Wallet custody**: delegation seed derived + persisted in per-DID Keychain during the
   share ceremony (new accounts) with a provisioning path for existing accounts; child keys
   derived on demand.
3. **Cooperative mint via auth.md**: at claim approval, the user can mint the anonymous
   agent its *own* child account instead of binding it — agent proposes a handle, user
   edits, approves; agent collects the child credential through the existing claim-grant
   poll. Server claim-confirm gains a child arm; auth.md doc, bruno, and conformance
   suites updated.
4. **Full wallet lifecycle**: list children, revoke, delete, re-mint assertion, integrated
   with the agents surface.
5. **Recovery**: recovery epilogue re-derives child keys from the server's child list,
   verified against plc.directory.
6. **Docs**: ADR amending ADR-0023; work sliced into Linear issues at the end.

## Acceptance Criteria

### agent-child-accounts.AC1: HD derivation primitives
- **agent-child-accounts.AC1.1 Success:** `derive_delegation_seed` is deterministic and matches its pinned golden vector
- **agent-child-accounts.AC1.2 Success:** `derive_child_seed(i)` matches pinned vectors and yields distinct seeds for distinct indices
- **agent-child-accounts.AC1.3 Success:** `derive_recovery_keypair(child_seed(i))` yields the pinned child keypair (leaf unchanged)

### agent-child-accounts.AC2: Wallet custody
- **agent-child-accounts.AC2.1 Success:** New-account share ceremony persists `{did}:delegation-seed` with read-back verification
- **agent-child-accounts.AC2.2 Success:** Share-recovery verification re-derives and persists the identical delegation seed
- **agent-child-accounts.AC2.3 Failure:** An unprovisioned identity choosing the child path is routed to "Enable agent accounts" — no mint attempted
- **agent-child-accounts.AC2.4 Success:** Identity removal deletes the delegation-seed and child-index Keychain entries
- **agent-child-accounts.AC2.5 Success:** Child index increments per successful mint; distinct children get distinct indices

### agent-child-accounts.AC3: Cooperative mint protocol
- **agent-child-accounts.AC3.1 Success:** Anonymous registration accepts `handle_hint`; claim-preview surfaces it
- **agent-child-accounts.AC3.2 Success:** Confirm-with-child atomically mints the child and converts the registration in place (one row: `did` = child DID, type `child`, `parent_did` set, status `claimed`)
- **agent-child-accounts.AC3.3 Success:** The agent's claim poll returns a credential with the child DID as subject; a record written with it lands in the child's repo
- **agent-child-accounts.AC3.4 Failure:** Invalid/taken handle rejects without consuming the claim attempt — registration stays claimable
- **agent-child-accounts.AC3.5 Failure:** Malformed genesis op or unreserved signing key rejects with no partial state
- **agent-child-accounts.AC3.6 Success:** Confirm *without* a child block behaves byte-identically to today (regression pin)
- **agent-child-accounts.AC3.7 Success:** `agent_auth` metadata advertises `child_provisioning`; served auth.md describes the flow
- **agent-child-accounts.AC3.8 Success:** tools/mcp conformance drives register→claim-as-child→post-as-child; `just bruno-check` green

### agent-child-accounts.AC4: Wallet lifecycle
- **agent-child-accounts.AC4.1 Success:** Children appear under My Agents with an own-account badge; detail shows handle/DID/scopes/status/audit
- **agent-child-accounts.AC4.2 Success:** Revoke from detail flips status; the child's assertion no longer exchanges at the token endpoint
- **agent-child-accounts.AC4.3 Success:** Delete deactivates and shows the purge date
- **agent-child-accounts.AC4.4 Success:** `POST /agent/child/assertion` returns a fresh assertion for an active child
- **agent-child-accounts.AC4.5 Failure:** Assertion re-mint refuses revoked children and agent-derived/non-parent callers

### agent-child-accounts.AC5: Recovery
- **agent-child-accounts.AC5.1 Success:** Recovery on a new device re-derives child keys that match each child's plc.directory audit log; index bookkeeping rebuilt from the server list
- **agent-child-accounts.AC5.2 Failure:** A derived key mismatching the plc log is surfaced to the user, never silently dropped

### agent-child-accounts.AC6: Documentation
- **agent-child-accounts.AC6.1 Success:** ADR amending ADR-0023 records the delegation-seed trade-off, rotation fan-out, SE-key omission, and grandchildren exclusion
- **agent-child-accounts.AC6.2 Success:** Exploration doc carries a superseded-by pointer; IPC reference regenerated; changelog fragments present

## Glossary

- **HD derivation (hierarchical deterministic)**: deriving a whole tree of keys from one root secret plus an index, so no additional secret needs to be generated or stored per key — the pattern behind Bitcoin HD wallets (BIP-32), applied here via HKDF instead.
- **HKDF-SHA256**: a standard key-derivation function that stretches/splits one secret into multiple independent-looking secrets using a domain-separating salt string, so secrets derived for different purposes can't be confused or cross-used.
- **Delegation seed**: the new at-rest secret this design introduces — derived once from the account's recovery seed and stored in the Keychain, it's the root from which every child account's key is derived.
- **Golden-vector test**: a test that pins a function's output against a hardcoded expected value, so any accidental change to the derivation logic is caught immediately (critical here since changing derivation would orphan existing child identities).
- **did:plc / DID**: the ATProto decentralized identifier scheme this codebase uses for every account (user or agent); `did:plc` identifiers are registered with and audited by `plc.directory`.
- **plc.directory**: the public ATProto PLC directory service that records the append-only audit log of key/handle changes for a DID; recovery re-derivation is checked against it.
- **Genesis op**: the first, self-signed operation in a DID's PLC audit log that establishes its initial keys and handle — creating a child account means building and signing one of these for the child DID.
- **rotationKeys**: the set of keys authorized to sign changes to a DID document; this design's children have a rotation key list of `[derived child key, PDS key]`, deliberately omitting the parent's device key to avoid a public parent↔child link.
- **Zeroizing**: a Rust wrapper type that scrubs a secret's memory on drop, used here for seeds while they're briefly held during derivation.
- **Keychain (per-DID namespace)**: the wallet's OS-backed secret store, where this codebase already namespaces secrets as `"{did}:suffix"`; the design adds new `delegation-seed` and `child-index` slots to that convention.
- **Share ceremony / share recovery**: the wallet's existing flows for splitting the recovery seed into recoverable shares (ceremony) and reconstructing it from shares on a new device (recovery) — the two points where the recovery seed is legitimately in memory and where delegation-seed derivation is inserted.
- **auth.md**: the WorkOS-published convention (implemented by this PDS and served at `/auth.md`) describing how autonomous agents self-onboard to a service — register, get approved, poll for credentials — without a human directly operating the agent's client.
- **Claim ceremony / claim-confirm / claim-grant poll**: the auth.md sequence where an anonymously-registered agent is approved by a human (claim-confirm) and then polls the token endpoint until it receives its usable credential (claim-grant poll).
- **agent_auth metadata block**: a discovery field in this PDS's authorization-server metadata that advertises which agent-auth capabilities it supports (this design adds a `child_provisioning` flag to it).
- **CIBA**: Client-Initiated Backchannel Authentication, an OAuth extension for out-of-band user approval of a client — cited as prior art for approving an agent asynchronously.
- **OIDC-A**: an OpenID Connect extension proposal for representing AI agents as identities distinct from the human who authorized them — cited as prior art for giving an agent its own subject/DID.
- **Route-isolation rule**: this codebase's convention that HTTP route handler modules may not import from one another directly; shared logic must be extracted into a separate module, which is why this design extracts a shared "mint core."
- **Repo signing key / reserveSigningKey**: the ATProto key a PDS reserves to sign a new repo's commits on the account's behalf, obtained via the `com.atproto.server.reserveSigningKey` call before a genesis op can reference it.
- **Identity assertion**: this codebase's short-lived signed credential proving control of a DID, used by agents when exchanging for OAuth tokens; children get their own re-mintable assertion.
- **ADR**: Architecture Decision Record — this repo's format for durably recording a design trade-off; this work amends ADR-0023.
- **Bruno**: the HTTP client / API collection format this repo uses to document and test every route; new or changed routes require a matching `.bru` file.
- **IPC (Tauri command)**: the mechanism by which the wallet's frontend (Svelte) calls into its Rust backend; new wallet features here are exposed as named Tauri commands like `mint_child_from_claim`.

## Architecture

An anonymous auth.md agent registration can now end, at the human's choice, with the
agent holding its **own account** (own `did:plc`, repo, and handle) under the user's
cryptographic ownership — instead of a credential to act as the user. Three layers
cooperate:

**Custody (wallet + `crates/crypto`).** Child rotation keys are hierarchically derived,
per the 2026-07-24 exploration's recommended shape: at the one moment the recovery seed
is legitimately in memory (share ceremony, or share-recovery verification), the wallet
derives an at-rest `delegation_seed` (HKDF-SHA256, salt `ezpds/delegation-seed/v1`) and
persists it in the per-DID Keychain namespace. Each child's seed is
`derive_child_seed(delegation_seed, index)` (salt `ezpds/child-seed/v1`, big-endian index
in the info string); the child keypair is the frozen `derive_recovery_keypair` applied to
that seed. Child `rotationKeys = [derived child key, PDS key]` — the parent's SE device
key is deliberately omitted (privacy: no public parent↔child linkage). Compromise of the
delegation seed exposes only the child subtree, never the recovery seed (one-way HKDF).

**Choreography (auth.md claim ceremony).** The agent registers anonymously, optionally
proposing a handle; the wallet's claim-approval screen offers "give access to my
account" (today's path) or "create its own account." The child path edits the handle,
passes the biometric gate, then the wallet reserves a repo signing key, derives the
child key at the next index, builds and signs the genesis op with the derived key
(it is `rotationKeys[0]`), and confirms the claim with a child block. The agent's
existing claim-grant poll then returns a credential whose subject is the child DID —
zero agent-side changes. The auth.md convention is silent-but-forward-compatible here
(`sub` is opaque; registration bodies and the `agent_auth` metadata block are
extensible); prior art: CIBA out-of-band approval, OIDC-A distinct agent subjects,
Entra child agent identities.

**Server (atomic confirm-with-child).** `POST /agent/identity/claim/confirm` gains an
optional child block. One transaction verifies the genesis op (via a mint core shared
with `POST /agent/child` — extracted to satisfy the route-isolation rule), creates the
child account + genesis repo, and converts the anonymous registration in place
(`did` → child DID, `registration_type` → `child`, `parent_did` recorded,
status → `claimed`). No second registration row; a failed transaction leaves only a
harmlessly reserved signing key.

### Contracts

Registration (`POST /agent/identity`, anonymous flow) — new optional field:

```json
{ "type": "anonymous", "handle_hint": "scribe.obsign.org" }
```

Claim confirm (`POST /agent/identity/claim/confirm`) — new optional block:

```json
{
  "user_code": "XXXX-XXXX",
  "child": { "handle": "scribe.obsign.org", "plcOp": { "…signed genesis op…" : "" } }
}
```

Response on the child arm adds `{ "child": { "did", "handle", "didDocument" } }` to the
existing confirm response. The claim-grant poll response shape is unchanged — the Bearer
and `identity_assertion` simply carry the child DID as subject.

Assertion re-mint (new, parent-owner-guarded like the other child routes):

```
POST /agent/child/assertion   { "did": "<child did>" }
→ { "did", "registrationId", "identityAssertion", "assertionExpires", "scopes": [...] }
```

Discovery: the `agent_auth` metadata block gains `"child_provisioning": true`; the served
auth.md document gains a section describing the flow.

Wallet IPC (Tauri commands, contract level): `mint_child_from_claim(did, user_code,
handle) → MintedChild`, `list_children(did) → ChildView[]`, `revoke_child(did,
child_did)`, `delete_child(did, child_did) → { deleteAfter }`,
`remint_child_assertion(did, child_did) → { identityAssertion, assertionExpires }`.

## Existing Patterns

From codebase investigation (all verified 2026-08-29):

- **Seed-in-memory hook**: `share_ceremony.rs` `load_or_create_in_account` holds the
  recovery seed as `Zeroizing<[u8; 32]>` between generation and envelope split
  (~lines 195–212); `share_recovery.rs` `verify_impl` reconstructs it via
  `combine_envelopes` (~line 721). Delegation-seed derivation inserts at both points.
- **Keychain secret pattern**: `identity_store.rs` namespaces per-DID secrets as
  `"{did}:suffix"` with store + read-back-verify (`store_recovery_signing_key`,
  ~lines 574–599) and a removal list in `remove_identity`. New slots:
  `{did}:delegation-seed`, `{did}:child-index`.
- **Genesis-op builders**: `crates/crypto/src/plc.rs` exports
  `build_did_plc_genesis_op_multi_rotation_with_external_signer` — the wallet signs with
  the derived child key via the external-signer callback. The server contract
  (`agent_child.rs::mint_child`) requires `rotationKeys[0]` to have signed the op and the
  `atproto` key to be PDS-reserved (`com.atproto.server.reserveSigningKey`).
- **Shared route helpers**: routes may not import from one another; shared agent-auth
  logic lives in `auth::agent_assertion`. The mint core extraction follows this pattern.
- **Approval screen phases**: `AgentClaimApprovalScreen.svelte` is a phase machine
  (enter → loading → review → approving → approved) with `authenticateBiometric()`
  abort-before-network. The child decision inserts as a phase.
- **Wallet PDS calls**: `SessionProvider::full_access_client(did)` → `OAuthClient`
  get/post with `classify_xrpc_response` error mapping (`pds_client.rs`, `agents.rs`).
- **Harness fakes**: `harness/registry.ts` already fakes `preview_agent_claim` /
  `confirm_agent_claim`; child handlers follow the same shape.
- **Golden-vector discipline**: `derive_recovery_keypair` is pinned in
  `crates/crypto/src/keys.rs`; both new derivations get the same pinning and warning.
- **No existing pattern**: per-identity index bookkeeping is new; the PDS child list
  (`GET /agent/child`) is authoritative, the Keychain counter an optimization
  (exploration doc §Recovery and discovery).

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: HD derivation primitives
**Goal:** The seed hierarchy exists in `crates/crypto`, pinned.

**Components:**
- `derive_delegation_seed(&[u8; 32]) -> Zeroizing<[u8; 32]>` and
  `derive_child_seed(&[u8; 32], index: u32) -> Zeroizing<[u8; 32]>` in
  `crates/crypto/src/keys.rs` (HKDF-SHA256, salts `ezpds/delegation-seed/v1` /
  `ezpds/child-seed/v1`, doc comments citing SLIP-0010 nist256p1 as the published
  relative and carrying the "changing this orphans identities" warning)
- Golden-vector tests in the style of the recovery-key pins, including a pinned
  child keypair via `derive_recovery_keypair(child_seed(i))`

**Dependencies:** None.

**Done when:** Golden-vector tests pass; covers agent-child-accounts.AC1.*.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Server mint core + assertion re-mint
**Goal:** Mint logic is shareable and children's assertions are renewable, with no
behavior change to existing routes.

**Components:**
- Extract the verify/mint transaction core from `crates/pds/src/routes/agent_child.rs`
  into a shared module (e.g. `crates/pds/src/agent_child_core.rs`), leaving
  `POST /agent/child` behavior identical
- New `POST /agent/child/assertion` route (parent-owner guard, refuses agent-derived
  tokens; active children only), registered in `app.rs`, with a Bruno file
- Audit event for assertion re-mint on the parent trail

**Dependencies:** None (parallel with Phase 1).

**Done when:** Existing agent_child tests still pass; new route tests cover
agent-child-accounts.AC4.4–4.5; `just bruno-check` green.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Cooperative claim protocol (server)
**Goal:** An anonymous registration can be confirmed into a child account.

**Components:**
- `handle_hint` on the anonymous arm of `POST /agent/identity`
  (`routes/agent_identity.rs`, new column on the registration row), surfaced in
  `POST /v1/agents/claim-preview` (`routes/agents.rs`)
- Optional `child: {handle, plcOp}` block on `POST /agent/identity/claim/confirm`
  (`routes/agent_claim.rs`), calling the Phase 2 mint core inside the same transaction
  that consumes the claim attempt; registration converted in place
- `child_provisioning` advertisement in the `agent_auth` metadata block; auth.md
  document section describing the flow
- Bruno updates; tools/mcp conformance case: register with `handle_hint` → claim as
  child → poll yields child-subject credential → write a record as the child

**Dependencies:** Phase 2.

**Done when:** Conformance + unit tests cover agent-child-accounts.AC3.*;
`just ci-pds` green.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Wallet custody
**Goal:** Delegation seed exists for new and provisioned accounts; child keys derivable.

**Components:**
- Delegation-seed derivation + persistence in
  `apps/identity-wallet/src-tauri/src/share_ceremony.rs` (after envelope split) and
  `share_recovery.rs::verify_impl` (after reconstruction)
- `{did}:delegation-seed` and `{did}:child-index` slots in `identity_store.rs`
  (store/read-back/removal-list per existing pattern)
- "Enable agent accounts" provisioning entry (settings/manage-identity surface) that
  runs the existing share-verification ceremony; unprovisioned state queryable by the
  frontend
- Harness state for provisioned/unprovisioned identities

**Dependencies:** Phase 1.

**Done when:** Wallet host tests (SDKROOT/ios-env harness) cover
agent-child-accounts.AC2.1–2.4; harness drives the unprovisioned gate.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Wallet cooperative mint flow
**Goal:** The approval screen can mint the agent its own account end to end.

**Components:**
- Decision + handle-edit phases in
  `apps/identity-wallet/src/lib/components/home/AgentClaimApprovalScreen.svelte`
  (pre-filled from `handle_hint` via claim-preview; biometric gate wording per the
  Obsign brief)
- `mint_child_from_claim` Tauri command in `src-tauri/src/agents.rs` (or sibling
  module): reserve signing key → derive child key at next index → build/sign genesis op
  → confirm-with-child; index increment on success
- IPC surface in `src/lib/ipc/agents.ts`; `just docs-generate` for the IPC reference
- Harness registry handlers + scenarios: happy mint, handle-taken error,
  unprovisioned gate routing to Phase 4's ceremony

**Dependencies:** Phases 3 and 4.

**Done when:** Browser harness drives the full flow; tests cover
agent-child-accounts.AC2.5 and the wallet halves of AC3.1/3.4.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Wallet child lifecycle
**Goal:** Children are visible and manageable under My Agents.

**Components:**
- Children rows (own-account badge) in `MyAgentsScreen.svelte`, fed by
  `GET /agent/child`; child detail screen with status/handle/DID/scopes, audit trail
  (existing `/v1/agents` parent arm), and revoke / delete (purge date shown) /
  re-mint assertion actions
- `list_children` / `revoke_child` / `delete_child` / `remint_child_assertion` IPC
  commands following the `agents.rs` + `pds_client.rs` pattern
- Harness handlers + scenarios for list/revoke/delete/re-mint

**Dependencies:** Phase 2 (assertion route), Phase 5 (children exist to manage).

**Done when:** Harness drives every lifecycle screen; tests cover
agent-child-accounts.AC4.1–4.3.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Recovery epilogue + ADR
**Goal:** Children survive device loss; decisions are durably recorded.

**Components:**
- Recovery epilogue in the wallet: after delegation-seed re-derivation, fetch
  `GET /agent/child`, re-derive candidate keys by index, verify each against the
  child's plc.directory audit log, rebuild `{did}:child-index`; surface mismatches
- ADR amending ADR-0023 (`docs/architecture/decisions/`): structural custody claim,
  delegation-seed trade-off, seed-rotation fan-out decision (same-seed re-split is a
  child no-op; true seed rotation requires an orchestrated per-child sweep, deferred
  and explicitly recorded), SE-key omission, grandchildren out of scope
- Superseded-by pointer in `docs/design-plans/2026-07-24-bip32-hd-child-identities.md`;
  `sites/docs` operator/config touch-ups if the metadata field lands in the capability
  table

**Dependencies:** Phases 4–6.

**Done when:** Recovery-path tests cover agent-child-accounts.AC5.*; docs gates
(`just docs-check`, capability-docs-check if touched) green; AC6.* satisfied.
<!-- END_PHASE_7 -->

## Additional Considerations

**Error handling:** a confirm-with-child whose handle fails validation or whose genesis
op is malformed rejects without consuming the claim attempt — the registration stays
claimable and the agent keeps polling; the only residue of any failed mint is a reserved
signing key. Auth.md-style `{error, error_description}` bodies throughout.

**Existing accounts:** identities provisioned before this feature have no delegation
seed; the child path gates on provisioning and routes through the share-verification
ceremony rather than failing. Until provisioned, claim approval simply doesn't offer the
child option's completion.

**Scope boundaries:** authorization is untouched (children get the operator's
`granted_scopes` clamp; ADR-0023's capability ladder applies as-is). Grandchildren stay
refused (`mint_child` keeps rejecting agent-derived tokens). No changes to
`POST /agent/child`'s external contract.

**Changelog:** every phase touching shipped surfaces carries a `changelog.d` fragment
per the gate.
