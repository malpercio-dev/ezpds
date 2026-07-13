# ADR-0012: Canonical DAG-CBOR encoding for did:plc operations

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0003](0003-did-plc-as-did-method.md) · [`crates/crypto/src/plc.rs`](../../../crates/crypto/src/plc.rs) · [`crates/crypto/AGENTS.md`](../../../crates/crypto/AGENTS.md)

## Context

A `did:plc` operation is **signed over its CBOR bytes**, and the DID is
`base32(sha256(signed-op CBOR))[..24]` — so the exact byte encoding is
load-bearing twice over. plc.directory requires **canonical DAG-CBOR**, where map
keys are ordered **by byte-length first, then bytewise**.

The natural Rust encoding path — `BTreeMap` + `ciborium` — emits map keys in
**pure bytewise** order. That is *not* canonical when keys differ in length: a
`services` map with `atproto_pds` (len 11) and `atproto_labeler` (len 15) would
serialize labeler-before-pds bytewise, but DAG-CBOR wants pds-before-labeler
(length-first). Such an op would be **rejected by plc.directory or derive a
different DID**. Single-entry maps (the common case) happen to be unaffected,
which makes the bug easy to miss until a multi-service op appears.

## Decision

Encode the `services` and `verificationMethods` maps through an internal
**`CanonicalMap`** that serializes keys in **DAG-CBOR length-first order**,
instead of relying on `BTreeMap`/`ciborium` bytewise order. Public APIs still
take and return plain `BTreeMap<String, _>`; the canonical ordering is internal
to the op encoder. Correctness is pinned by **golden tests** cross-checked
against `@ipld/dag-cbor` (the canonical JS DAG-CBOR library) — asserting the
encoded op bytes, the derived DID, and the CID are byte-identical.

## Consequences

- **Operations are byte-identical to the JS atproto stack**, so plc.directory
  accepts them and derives the same DID; multi-service ops encode correctly.
- **Existing single-entry-map DIDs stay stable** (that ordering was already
  correct), so the fix is non-breaking.
- **The subtlety is localized** to the crypto crate and guarded by tests; callers
  never see it.
- Because a matching DID transitively proves byte-identity (a hash can't match
  unless the bytes do), the golden tests are a strong conformance anchor for any
  future change to the op shape.

## Alternatives considered

- **Rely on `BTreeMap`/`ciborium` bytewise ordering.** Rejected: produces
  non-canonical ops for differing-length keys — plc.directory rejects them.
- **Hand-roll the CBOR encoding.** Rejected: error-prone; wrapping the maps and
  cross-checking against `@ipld/dag-cbor` is safer and localized.
