# Identity and Key Custody

Last verified: 2026-07-02

Reference sheet for how an ezpds identity is represented and who holds the keys
that control it. The custody model described here is ezpds's core
differentiator; the reasoning behind it is recorded in
[ADR-0001](decisions/0001-client-held-rotation-key-custody.md).

## Identity representation

An account is an ATProto `did:plc` identity. The DID is the SHA-256 hash of its
own signed genesis operation (base32-lowercase, first 24 chars), so it is
self-certifying and bound to the exact contents of the genesis op. Genesis-op
construction, verification, and rotation-op building live in
[`crates/crypto/src/plc.rs`](../../crates/crypto/src/plc.rs); the crate emits
canonical DAG-CBOR cross-checked against `@ipld/dag-cbor` so plc.directory
accepts our operations and derives the same DID.

## The rotation-key hierarchy

A `did:plc` document carries an **ordered** `rotationKeys` array. Order is
priority: a higher-priority key can override an operation signed by a
lower-priority key within plc.directory's recovery window. ezpds populates it
deliberately:

| Position | Holder | Key material | Where it lives |
| --- | --- | --- | --- |
| `rotationKeys[0]` | **The user's wallet** | P-256 device key | Secure Enclave (real iOS) / Keychain-stored software key (simulator + macOS) |
| `rotationKeys[1]` | The PDS | P-256 signing key | PDS-side key store |

`verificationMethods.atproto` is the PDS signing key (`rotationKeys[1]`) — it
signs repo commits. The user's device key does **not** sign commits; it exists
to *authorize identity operations*.

The consequence that matters: **the highest-priority key that controls the
identity is held by the user's wallet, not by the PDS.** The PDS is a
lower-priority rotation key for commit-signing convenience and standard-tooling
interop, not the custodian of the identity.

See the genesis-op builder for where this ordering is set:
[`build_did_plc_genesis_op_with_external_signer`](../../crates/crypto/src/plc.rs)
places `rotation_key` (device key) at index 0 and `signing_key` (PDS key) at
index 1.

## Where keys live (wallet)

Managed by the Obsign identity-wallet app
([`apps/identity-wallet`](../../apps/identity-wallet/CLAUDE.md)):

- **Device key** — `device_key.rs` dispatches at compile time: Secure Enclave
  `SecKey` on a real iOS device (private key never extractable), or a
  Keychain-stored software P-256 scalar on simulator/macOS. Signatures are
  low-S-normalized (plc.directory requires it).
- **Per-identity keys** — `identity_store.rs` namespaces keys per DID
  (`"{did}:device-key"`, …) so the wallet can hold multiple identities. The
  create flow signs the genesis op with the *global* device key before the DID
  exists, then `adopt_global_device_key` aliases the per-DID slot to it.
- **Shamir recovery shares** — the crypto crate splits the device key 2-of-3
  ([`split_secret`/`combine_shares`](../../crates/crypto/CLAUDE.md)). Share
  *generation* runs during the DID ceremony (Share 1 → Keychain/iCloud, Share 3
  → returned to the user). The full 2-of-3 recovery *ceremony* is future work
  (see [`../data-migration-spec.md`](../data-migration-spec.md), v1.0).

## What the custody model buys us

Because the wallet holds `rotationKeys[0]`, three capabilities are cryptographic
facts rather than PDS policy promises:

1. **Monitoring.** `plc_monitor.rs` polls plc.directory every 15 minutes and
   verifies each new audit-log entry's signature against the per-DID device key.
   Anything signed by another key (e.g. the PDS's `rotationKeys[1]`) is flagged
   as an unauthorized change.
2. **Recovery / override.** `recovery.rs` builds a counter-operation restoring
   pre-tamper state, signed by the device key, submittable within plc.directory's
   **72-hour** recovery window — overriding a lower-priority key's op.
3. **Wallet-authorized migration.** The same device key can sign the PLC
   operation that repoints the DID at a new PDS, with no dependency on the old
   PDS's cooperation. This reframes account migration; see
   [ADR-0002](decisions/0002-wallet-authorized-account-migration.md).

## Import ("claim") of an existing identity

`claim.rs` implements taking custody of an existing identity whose rotation keys
the wallet does **not** yet hold (e.g. a bsky.social account). It uses the
standard email-tokened old-PDS signature *once* to submit a PLC op that inserts
the wallet's device key as `rotationKeys[0]`. After that single step the wallet
is the sovereign controller and subsequent operations can be self-signed.

## Related

- Custody rationale and alternatives: [ADR-0001](decisions/0001-client-held-rotation-key-custody.md)
- Migration design: [ADR-0002](decisions/0002-wallet-authorized-account-migration.md)
- Crypto contracts: [`crates/crypto/CLAUDE.md`](../../crates/crypto/CLAUDE.md)
- Wallet contracts: [`apps/identity-wallet/CLAUDE.md`](../../apps/identity-wallet/CLAUDE.md)
