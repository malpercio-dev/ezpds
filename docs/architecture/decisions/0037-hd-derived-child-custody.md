# ADR-0037: Child rotation keys are HD-derived from a delegation seed

- **Status:** Accepted
- **Date:** 2026-08-30
- **Deciders:** malpercio
- **Related:** amends [ADR-0023](0023-sovereign-child-agent-identities.md) · [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0027](0027-rotation-key-ordering.md) · [agent child accounts design](../../design-plans/2026-08-29-agent-child-accounts.md) · supersedes the exploration in [2026-07-24 HD child identities](../../design-plans/2026-07-24-bip32-hd-child-identities.md) · `crates/crypto/src/keys.rs`, `apps/identity-wallet/src-tauri/src/agents.rs`

## Context

[ADR-0023](0023-sovereign-child-agent-identities.md) promised that a sovereign
child agent's rotation key "lives in the parent's Obsign wallet." It did not say
where that key comes from. The obvious reading — mint a random key per child and
store it in the Keychain — makes the promise *procedural*: it holds only for as
long as N independent secrets survive, each with no recovery story beyond its own
backup. A device loss would strand every child whose key was not separately
escrowed, and the parent's 2-of-3 Shamir ceremony would not help, because the
child keys were never derived from anything it reconstructs.

The wallet already has one deterministic derivation it trusts:
`derive_recovery_keypair` maps a 32-byte seed to a P-256 keypair, is pinned by a
golden test, and is frozen — changing its bytes orphans every account whose
`rotationKeys` carry the derived key. The recovery seed feeding it exists at rest
only as a Shamir split and is in memory at exactly two moments: the share ceremony
that creates it, and the share-recovery verification that reconstructs it.

The tension is that hierarchical derivation buys a recovery story for children
only by introducing something the wallet does not have today: a standing at-rest
secret from which child keys can be re-derived on demand, without the recovery
seed being present.

## Decision

We will derive every child account's rotation key hierarchically from a
**delegation seed** rooted in the parent's recovery seed, making ADR-0023's
custody claim structural rather than procedural.

- `delegation_seed = HKDF-SHA256(recovery_seed, salt "ezpds/delegation-seed/v1")`,
  derived only while the recovery seed is legitimately in memory (the share
  ceremony, or share-recovery verification) and persisted to the per-DID Keychain
  slot `{did}:delegation-seed`.
- `child_seed(i) = HKDF-SHA256(delegation_seed, salt "ezpds/child-seed/v1",
  info || i as big-endian u32)`; the child keypair is the frozen
  `derive_recovery_keypair` applied to that seed. Both new derivations carry the
  same golden-vector pinning and the same "changing this orphans identities"
  warning as the recovery-key derivation.
- A child's `rotationKeys` are `[derived child key, PDS key]`. The parent's
  Secure-Enclave device key is **deliberately omitted**.
- `{did}:child-index` is a local optimization, not a record of truth. The PDS
  child list (`GET /agent/child`) is authoritative, and the recovery epilogue
  rebuilds the counter from it.
- Depth stays at one. Grandchildren remain refused.
- On recovery-seed rotation, children are **not** swept automatically. See the
  fan-out consequence below.

We accept one new standing at-rest secret in the wallet to get this. It is
strictly better than the alternative it replaces — N independent secrets with no
recovery story — and HKDF is one-way, so compromising the delegation seed exposes
the child subtree and never the recovery seed above it.

## Consequences

- **Recovery is inherited, not bolted on.** Restoring the parent's shares
  re-derives the delegation seed and thereby every child key. Discovery needs no
  BIP-44-style gap scan: the server lists the children, the wallet re-derives
  candidate keys by index, and each is verified against that child's own
  plc.directory audit log — the same trust posture `verify_recovery_shares` takes
  for the parent. A child whose live rotation keys name nothing the seed derives
  is reported to the user; it is never silently dropped, and it is kept distinct
  from a directory read that simply failed.
- **The counter is disposable.** Losing `{did}:child-index` costs a rebuild, not
  a child. The rebuild never *lowers* the counter: a stored value above every
  surviving match means indices were spent on children since purged, and rewinding
  would re-derive a key a live child still holds.
- **One new standing secret.** `{did}:delegation-seed` is at rest for the life of
  the identity, unlike the recovery seed. It is per-DID, write-once, removed with
  the identity, and gates the whole child feature: an identity without it cannot
  mint, and is routed to provisioning rather than failing.
- **Seed rotation fans out; we defer the sweep.** Re-*splitting* the same seed
  (a new `set_id`, the ordinary share-rotation case) leaves the delegation seed
  unchanged and is a child no-op. A *true* recovery-seed rotation — the recovery
  epilogue's fresh-seed swap — changes the delegation root, so every existing
  child's `rotationKeys` would need a PLC rotation op to follow it. We do not
  attempt that sweep today: the write-once delegation slot keeps the *original*
  seed's delegation root, so existing children stay recoverable, and a true
  orchestrated per-child sweep is deferred work rather than a silent gap. The
  cost of the deferral is that children minted before and after a seed rotation
  can trace to different roots — acceptable while the sweep is unbuilt, and
  recorded here rather than left implicit.
- **No public parent↔child link.** Omitting the parent's device key from the
  child's `rotationKeys` keeps the relationship out of the child's public PLC
  audit log. The cost is that the parent's enclave cannot unilaterally rotate a
  child — recovery runs through the derived key instead — and that ADR-0027's
  enclave-supremacy ordering is a parent-identity rule, not a child one.
- **Parentage stays unprovable in public.** Hardened derivation cannot be proven
  without revealing secrets. The `agent_identities.parent_did` row remains the
  operational source of truth; verifiable parentage, if ever wanted, is a separate
  attestation problem layered on top.
- **Grandchildren are out of scope.** The crypto recurses for free, but
  `mint_child` refuses agent-derived tokens, so an agent cannot mint sub-agents.
  Whether to allow depth > 1 is a product and authorization decision; this scheme
  does not preclude it.
- **The derivation needs no server changes.** The PDS sees an ordinary
  client-signed genesis op and never learns that the key was derived rather than
  generated. (The cooperative-mint *ceremony* built on top of it did add a child
  arm to claim-confirm — that is choreography, not custody.)

## Alternatives considered

- **A random key per child, stored in the Keychain.** Rejected: N independent
  at-rest secrets with no recovery story, which is the procedural reading of
  ADR-0023 this ADR exists to replace. It avoids the standing delegation seed
  only by making device loss unrecoverable for every child.
- **BIP-32 proper (chain codes, xpubs, non-hardened derivation, integer paths).**
  Rejected: it buys nothing here — we need no public derivation and no watch-only
  wallets — and non-hardened derivation is an active hazard, since one leaked
  child private key plus the xpub reconstructs the parent. We take the *shape* (a
  hierarchy of seeds) and leave the mechanism.
- **Name the parent's device key in the child's `rotationKeys`.** Rejected: it
  would give the parent's enclave direct rotation authority over children and
  simplify recovery, at the cost of publishing the parent↔child relationship in
  the child's public audit log for anyone to read.
- **Sweep every child on seed rotation.** Not rejected — deferred. It is the
  correct end state, but it is an orchestrated multi-op ceremony with its own
  partial-failure semantics, and blocking child accounts on it would trade a
  recorded, bounded gap for an unbuilt one.
- **Derive the delegation seed on demand from the recovery seed.** Rejected: the
  recovery seed is in memory at two ceremonies only. Requiring one of them per
  mint would put a share ceremony in front of every agent the user approves.
