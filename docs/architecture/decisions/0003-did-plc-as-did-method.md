# ADR-0003: `did:plc` as the DID method

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0002](0002-wallet-authorized-account-migration.md) · [ADR-0012](0012-canonical-dag-cbor-for-plc-ops.md) · [`../identity-and-key-custody.md`](../identity-and-key-custody.md) · [`crates/crypto/src/plc.rs`](../../../crates/crypto/src/plc.rs)

## Context

ATProto identities are DIDs, and the network supports two methods in practice:

- **`did:web`** — the DID document is a JSON file hosted at a domain
  (`https://example.com/.well-known/did.json`). Simple, no ledger — but whoever
  controls the domain/host controls the identity, there is no rotation-key
  hierarchy, and there is no recovery window if a key is compromised.
- **`did:plc`** — a self-certifying DID whose document is the head of a
  hash-linked log of **signed operations**, served by a directory
  (plc.directory). It carries an *ordered* `rotationKeys` array and a fixed
  (72-hour) window in which a higher-priority key can override a lower-priority
  key's operation.

ezpds's entire thesis — sovereign custody, credible exit, tamper detection and
recovery — depends on identity operations being independently signable and
overridable by a key the user holds. That requires rotation keys and a recovery
window.

## Decision

We will mint and manage all ezpds accounts as **`did:plc`** identities.
`did:web` is not offered as an account identity method.

## Consequences

- **Enables the custody model** (ADR-0001): ordered rotation keys let the
  wallet hold the top key and the PDS a lower one; the recovery window makes
  `plc_monitor` + `recovery.rs` and wallet-authorized migration (ADR-0002)
  possible. None of these are expressible under `did:web`.
- **Introduces a dependency on plc.directory** as the operation ledger. This is
  a semi-centralized service; ezpds mitigates trust in it by verifying every
  operation's signatures client-side (the audit-log verification in
  `plc_monitor`) rather than trusting the directory's word.
- **Requires canonical DAG-CBOR** for operations, since the DID is the hash of
  its own signed op — see ADR-0012.
- Identities are portable across PDSes by construction (the DID isn't bound to a
  host), which is what makes migration a repointing operation rather than a
  re-issuance.

## Alternatives considered

- **`did:web`.** Rejected: host/domain-controlled, no rotation-key hierarchy, no
  recovery window — it cannot express user-held identity custody, which is the
  product.
- **`did:key`.** Rejected as an *account* identity: immutable, carries no service
  endpoint and no rotation, so it can neither point at a PDS nor be recovered.
  (`did:key` is still used throughout for representing individual public keys.)
