# ADR-0004: The PDS holds the repo signing key and signs commits

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0007](0007-mobile-only-pds-is-full-pds.md) · [`../../pds-architecture.md`](../../pds-architecture.md) · [`crates/pds/src/record_write.rs`](../../../crates/pds/src/record_write.rs) · [`crates/pds/src/routes/create_record.rs`](../../../crates/pds/src/routes/create_record.rs)

## Context

Every ATProto repo commit is signed by the account's **atproto signing key**
(the `verificationMethods.atproto` key in the DID document). The question is who
holds that key and who performs the signing:

1. **Client-signed commits** — the client holds the repo signing key and signs
   each commit locally; the PDS stores and serves already-signed commits.
2. **PDS-signed commits** — the PDS holds a per-account repo signing key,
   constructs the whole commit from the record writes a client submits, and signs
   it. The client never holds the commit-signing key.

This is a *separate* question from who controls the **identity** (the rotation
keys, ADR-0001). It interacts with the mobile-only phase (ADR-0007), where there
is no desktop host and the server must be able to produce commits itself.

## Decision

The **PDS holds the per-account repo signing key and signs repo commits.** A
client authors records through the standard ATProto write XRPCs
(`com.atproto.repo.createRecord` / `putRecord` / `applyWrites`), submitting the
**record value** (JSON) — not a commit. The PDS's `record_write` flow builds the
MST, constructs the commit, and signs it with the account's repo signing key
(`load_repo_signer`). That signing key is placed at `rotationKeys[1]` **and**
`verificationMethods.atproto` in the genesis operation. The user's device key is
reserved for **identity/rotation operations** (ADR-0001), not commit signing.

**Terminology.** "Client" here means any ATProto client authoring records,
authenticated via OAuth or an app password — **not** the Obsign identity wallet.
The identity wallet holds `rotationKeys[0]` and performs *identity* operations
(genesis, claim, recovery); **it does not author repo records today** and has no
`createRecord`/`putRecord`/`applyWrites` path.

## Consequences

- **Thin clients.** A client sends record values; the PDS builds the MST,
  commits, signs, and emits the firehose. No client manages a commit-signing key.
- **Server availability is on the write path.** A write needs the PDS; there is
  no offline local authoring in this model.
- **Custody stays intact and is not confused with commit signing.** The PDS
  signing commits does *not* give it control of the identity — the user holds
  `rotationKeys[0]` (ADR-0001), which outranks the PDS's key. A malicious PDS
  could sign a bad *commit*, but the repo is self-certifying and the identity
  cannot be rotated away from the user.
- Consistent with ADR-0007: in the mobile-only phase the PDS *is* the PDS, so it
  must be the commit signer, including for the genesis repo.

## Not yet / future

`pds-architecture.md` describes a **desktop-enrolled (v0.2)** shape in which a
device *constructs an unsigned commit* and the PDS co-signs it ("PDS as
proxy+signer"). **That is not current behavior** — today clients submit record
values and the PDS builds and signs the entire commit. If/when the
desktop-enrolled phase lands, the unsigned-commit-from-device path would be a
refinement of *this* decision (the PDS still holds and applies the signing key),
recorded then.

## Alternatives considered

- **Client-signed commits.** Enables offline authoring and removes the PDS from
  the signing path, but pushes MST/commit construction, signing, and key
  management onto every client and is incompatible with a server that must
  produce commits (including genesis) in the mobile-only phase. Rejected for
  v0.1; revisit if offline-first authoring becomes a requirement.
