# ADR-0004: The PDS signs repo commits; the device constructs unsigned commits

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0007](0007-mobile-only-pds-is-full-pds.md) · [`../../pds-architecture.md`](../../pds-architecture.md) · [`crates/pds/src/record_write.rs`](../../../crates/pds/src/record_write.rs)

## Context

Every ATProto repo commit is signed by the account's **atproto signing key**
(the `verificationMethods.atproto` key in the DID document). There are two places
that signing can happen:

1. **Device-signed commits** — the device holds the repo signing key and signs
   each commit locally; the PDS stores and serves already-signed commits.
2. **PDS-signed commits** — the PDS holds a per-account repo signing key,
   constructs the signed commit from writes the device submits, and the device
   never holds the commit-signing key.

This is a *separate* question from who controls the **identity** (the rotation
keys). It interacts with the mobile-only phase (ADR-0007), where there is no
desktop host and the server must be able to produce commits itself.

## Decision

The **PDS holds the per-account repo signing key** and signs repo commits; the
device constructs unsigned writes and submits them. That signing key is placed at
`rotationKeys[1]` **and** `verificationMethods.atproto` in the genesis operation.
The **device key is reserved for identity/rotation operations** (ADR-0001), not
for commit signing.

## Consequences

- **Thin mobile clients.** The device doesn't manage a commit-signing key or MST
  signing; it sends records and the PDS commits + emits the firehose.
- **Server availability is on the write path.** Offline local writes are not
  possible in this model; a write needs the PDS.
- **Custody stays intact and is not confused with commit signing.** The PDS
  signing commits does *not* give it control of the identity — the user's device
  holds `rotationKeys[0]` (ADR-0001), which outranks the PDS's key. A malicious
  PDS could sign a bad *commit*, but the repo is self-certifying and the identity
  cannot be rotated away from the user.
- Consistent with ADR-0007: in the mobile-only phase the PDS *is* the PDS, so it
  must be the commit signer.

## Alternatives considered

- **Device-signed commits.** Enables offline writes and removes the PDS from the
  signing path, but pushes MST/commit-signing and key management onto every
  client and is incompatible with a server that must produce commits in the
  mobile-only phase. Rejected for v0.1; revisit if offline-first authoring
  becomes a requirement.
