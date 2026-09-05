# Exploration: BIP-32-style hierarchical derivation for parent/child identities and agents

**Status: superseded — shipped.** The recommended shape below was built as designed. The
design that implemented it is
[2026-08-29-agent-child-accounts.md](2026-08-29-agent-child-accounts.md), and the decisions it
raised — the standing delegation seed, the seed-rotation fan-out, the omitted Secure-Enclave key,
and grandchildren — are recorded in
[ADR-0037](../architecture/decisions/0037-hd-derived-child-custody.md), which amends
[ADR-0023](../architecture/decisions/0023-sovereign-child-agent-identities.md). This document is
kept for the reasoning that got there, not as a live plan; where the two disagree, the ADR wins.

**Original status: exploration / assessment — no commitment.** Written to durably capture a research
session on applying BIP-32-style hierarchical deterministic (HD) key derivation to the
parent/child identity model of ADR-0023. Verdict up front: **the valuable idea is not
BIP-32's key tree — it is a hierarchy of *seeds*.** Derive each child identity's 32-byte
seed from a parent-held seed, then reuse the existing, frozen
`derive_recovery_keypair` on every node. That makes ADR-0023's custody promise ("the
agent's rotation/recovery key lives in the parent's Obsign wallet") *structural* instead of
procedural, gives every child free recursion and free recovery through the parent's
existing 2-of-3 Shamir ceremony, and requires **zero server changes** for the core scheme.
BIP-32's distinctive machinery — chain codes, xpubs, non-hardened public derivation,
integer paths — buys us nothing here and one of its pieces is an active hazard; we should
take the *shape* and leave the mechanism.

## What already exists (this is not greenfield)

- **A frozen level-0 deterministic derivation.** `derive_recovery_keypair`
  (`crates/crypto/src/keys.rs`) maps a 32-byte seed to a P-256 keypair via HKDF-SHA256
  (salt `ezpds/recovery-seed/v1`, fixed info string, rejection-sampled into `[1, n)`).
  It is pinned by a golden test; changing its bytes orphans every account whose
  `rotationKeys` carry the derived key. Any HD scheme must compose *around* it, not
  modify it.
- **A seed with a deliberate at-rest story.** The recovery seed exists at rest only as a
  2-of-3 Shamir split (`crates/crypto/src/shamir.rs`, v2 `ShareEnvelope`): Share 1 in
  iCloud Keychain, Share 2 KEK-wrapped in PDS escrow behind an OTP + 24h delay, Share 3
  human-custody (base32 QR or word phrase). The seed itself "lives nowhere at rest —
  re-derived only during a recovery ceremony"
  (`docs/architecture/identity-and-key-custody.md`). Crucially, the seed *is* in memory
  client-side during the share ceremony (`apps/identity-wallet/src-tauri/src/share_ceremony.rs`
  generates it before any network call) — that is the natural hook for deriving anything
  else from it.
- **Child identities exist server-side, but the link is a database row, not
  cryptography.** `POST /agent/child` (`crates/pds/src/routes/agent_child.rs`, ADR-0023)
  accepts a *client-signed* genesis op — the server verifies it, pins
  `rotationKeys[0]` as claimed, requires the repo-signing key to be PDS-reserved
  (ADR-0004), and records `parent_did` as a foreign key
  (`V047__agent_children.sql`). Nothing constrains where the child's rotation key came
  from.
- **The wallet half of ADR-0023 is unbuilt.** No child minting or child-key custody
  exists in `apps/identity-wallet/src-tauri/src/` — the only "wallet" holding a child
  rotation key today is the mcp-sidecar e2e test fixture
  (`tools/mcp-sidecar/test/e2e-fixture.ts`). This is the clean insertion point: we can
  choose the child-key derivation scheme before any real child key exists.
- **The rotation-key budget argues for children having their own DIDs.** ADR-0027 fixes
  `rotationKeys = [device (SE), recovery (derived), PDS]` — 3 of PLC's 5 slots spent —
  and states that growth happens *inside* the recovery key, never by adding rotation
  keys. HD child identities sidestep the cap entirely: each child is its own DID with
  its own 5 slots; the parent spends none.
- **BIP-32 / SLIP-0010 / HD appear nowhere in the repo today.** The "BIP-39-style"
  mnemonic (`crates/crypto/src/mnemonic.rs`) is a byte↔word bijection over the 42-byte
  share envelope with a permanently golden-pinned 256-word list — it encodes *shares*,
  not seeds, has no key stretching, and cannot be repurposed as a BIP-39 seed phrase.

## What BIP-32 actually offers, and what we'd keep

BIP-32 gives four separable things:

1. **Deterministic derivation of many keys from one secret** — the whole point; we want
   this.
2. **Hierarchy** (children can have children with no coordination) — we want this;
   agents that mint sub-agents fall out for free.
3. **Non-hardened public derivation** (derive child *public* keys from an xpub without
   any secret) — we do not want this. Its one benefit is watch-only enumeration, which
   we don't need (the PDS's `agent_identities` table enumerates children
   authoritatively), and it carries BIP-32's classic footgun: one leaked child private
   key plus the parent chain code reveals the parent private key.
4. **A standardized interop format** (xprv/xpub, `m/44'/…` paths, SLIP-0010 for P-256) —
   no interop target exists. No external wallet will ever import this seed; our golden
   tests are the compatibility contract, exactly as they already are for
   `derive_recovery_keypair`.

So: hardened-only, no chain codes, no integer paths — HKDF with domain-separated info
strings and a big-endian index, which is the crate's existing idiom. SLIP-0010's
nist256p1 variant is the closest published relative (BIP-32 proper is secp256k1-only)
and is worth citing in doc comments, but exact SLIP-0010 compliance adds machinery
without adding a consumer.

## Recommended shape: a hierarchy of seeds, not keys

Give every identity node the *same* structure the parent already has: a 32-byte seed
from which its recovery keypair is derived by the existing frozen function. Children are
new nodes whose seeds are derived from the parent's; recursion is free.

```
recovery_seed                      (parent; at rest only as 2-of-3 Shamir shares)
├─ derive_recovery_keypair(seed)         → parent rotationKeys[1]   [frozen v1, unchanged]
└─ delegation_seed = HKDF(seed, salt="ezpds/delegation-seed/v1")    [at rest in wallet Keychain]
   └─ child_seed(i) = HKDF(delegation_seed,
                           salt="ezpds/child-seed/v1",
                           info=domain || u32_be(i))                [derived on demand]
      ├─ derive_recovery_keypair(child_seed(i)) → child rotationKeys[0]  [frozen v1, reused]
      └─ child's own delegation subtree → grandchildren             [same rule, recursively]
```

Two deliberate structural choices:

**The tree roots in an at-rest *delegation seed*, one HKDF step below the recovery
seed — not in the recovery seed itself.** The recovery seed's whole design is that it is
*not* at rest (2-of-3 reconstruction, escrow release delay). If child keys required it,
every child mint would be a recovery-grade ceremony. Instead, at the one moment the
recovery seed is legitimately in memory — the share ceremony at onboarding (or a re-key /
recovery ceremony for existing accounts) — the wallet derives `delegation_seed` and
persists it in the per-DID Keychain namespace (`identity_store.rs`). Derivation is
one-way: possession of the delegation seed reveals nothing about the recovery seed, so
compromising the wallet's Keychain yields *the child subtree only* — never the parent's
recovery key, and never the parent's SE device key. The blast radius of the at-rest
secret is scoped to the identities it exists to manage.

**Every node reuses the frozen `derive_recovery_keypair` as its seed→keypair leaf
step.** No second scalar-derivation function, no second golden-vector discipline for the
rejection-sampling path, and perfect uniformity: a child identity is not a special kind
of identity, it is an identity whose seed has a parent. If a child ever needs recovery
custody *independent* of its parent (e.g. handing an agent identity off to another
person), its seed can be Shamir-split with the existing machinery and the derivation
edge severed by a rotation — graduation from child to sibling is a PLC op, not a
migration.

### Child DID layout

The child's genesis op (built and signed wallet-side, exactly as the existing
`POST /agent/child` contract expects):

- `rotationKeys[0]` — the derived child key (from `child_seed(i)`), held/managed by the
  parent's wallet.
- `rotationKeys[last]` — the PDS key, as today.
- `verificationMethods.atproto` — a PDS-reserved repo signing key (unchanged, ADR-0004).

**Open decision:** optionally insert the parent's SE device did:key as an additional
child rotation key. It would give the parent ceremony-free, strongest-key control over
every child and survive loss of the delegation seed — but it publishes the parent↔child
link in plaintext PLC documents (the same did:key appearing in both). That is either a
feature (public, verifiable parentage) or a privacy leak (correlatable identity graph)
depending on the product stance; it should be decided per-child at mint time, not
globally.

### Recovery and discovery

After device loss, the existing recovery ceremony reconstructs the recovery seed →
re-derives `delegation_seed` → re-derives every child key. Discovery needs no BIP-44 gap
limit: the PDS already knows the children (`agent_identities.parent_did`), so the
recovery epilogue lists child DIDs from the server, re-derives candidate keys by index,
and verifies each against the child's authoritative plc.directory audit log — the same
trust posture `verify_recovery_shares` already takes for the parent. The wallet's stored
index bookkeeping is an optimization, not a requirement.

### What this deliberately does *not* solve

- **Authorization.** The capability rung of ADR-0023's ladder — scope-clamped
  `identity_assertion`, 5-minute Bearer tokens, owner/provider revocation
  (auth.md, ADR-0019/0020) — is untouched. Derivation is custody, not delegation of
  authority; an HD child with no registration can sign nothing the PDS will accept.
- **Public proof of parentage.** Hardened derivation is unprovable without revealing
  secrets. If verifiable parentage is wanted, it is an attestation problem (signed
  records in parent and child repos, or the shared-rotation-key option above), layered
  on top — the DB row remains the operational source of truth either way.

## Trade-offs and open questions

1. **One at-rest secret vs. none.** Today no child keys exist at all; the implicit
   alternative design (mint a random key per child, store each in Keychain) puts N
   independent secrets at rest with no recovery story beyond per-child backup. One
   delegation seed is a strictly better recovery story at comparable exposure — but it
   *is* a new standing secret in the wallet, and that should be stated plainly in the
   eventual ADR.
2. **Seed rotation fans out.** The key-recovery plan already flagged "the seed *is* the
   key; share-set rotation is therefore also key rotation." HD widens that: rotating the
   recovery seed rotates the delegation tree, requiring a PLC rotation op per child.
   Re-*splitting* the same seed (new `set_id`) does not. The eventual design must either
   accept an orchestrated per-child sweep on seed rotation or rotate children lazily;
   silence is not an option.
3. **Existing accounts need a provisioning moment.** The delegation seed can only be
   derived while the recovery seed is in memory. New accounts get it at the share
   ceremony; existing accounts get it at their next re-key/recovery ceremony or via an
   explicit opt-in ceremony. Until then they simply cannot mint HD children — an
   acceptable gate, since no wallet minting flow ships before this lands anyway.
4. **Derivation-constant discipline.** Every new HKDF domain (`ezpds/delegation-seed/v1`,
   `ezpds/child-seed/v1`) gets the same golden-vector pinning as
   `ezpds/recovery-seed/v1`, with the same "changing this orphans identities" warning.
5. **Grandchildren policy.** The crypto recursion is free, but `mint_child` currently
   refuses agent-derived tokens (`authenticate_account_owner`), so an agent cannot mint
   sub-agents today. Whether to allow depth > 1 is a product/authorization decision, not
   a derivation one — the scheme should not preclude it, and doesn't.

## If pursued: smallest real slice

1. `crates/crypto`: `derive_delegation_seed(&[u8; 32]) -> Zeroizing<[u8; 32]>` and
   `derive_child_seed(&[u8; 32], index: u32) -> Zeroizing<[u8; 32]>`, both HKDF-SHA256
   with the salts above, golden-vector tests in the style of the recovery-key pins.
2. Wallet: derive + persist the delegation seed inside the existing share ceremony;
   add the child-mint flow (derive key at next index, build genesis op with the existing
   external-signer builders, `POST /agent/child`) and per-child Keychain bookkeeping.
3. Wallet: extend the recovery epilogue to re-derive children against the server's child
   list + plc.directory audit logs.
4. ADR amending ADR-0023: custody claim becomes structural; record the delegation-seed
   trade-off and the seed-rotation fan-out decision.

Server changes required for the core scheme: none.
