# Identity and Key Custody

Last verified: 2026-07-18

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
| `rotationKeys[1]` | **The recovery seed** | P-256 key deterministically derived from the reconstructed Shamir secret | Nowhere at rest — re-derived only during a recovery ceremony, from ≥2 of the 3 shares |
| `rotationKeys[2]` | The PDS | P-256 signing key | PDS-side key store |

`verificationMethods.atproto` is the PDS signing key (`rotationKeys[2]`) — it
signs repo commits. Neither the device key nor the recovery key signs commits;
they exist to *authorize identity operations*. The recovery key sits above the
PDS key so that a user who reconstructs the seed (from iCloud + escrow, or from
their two offline shares) can override a compromised PDS-signed op inside
plc.directory's recovery window without the PDS's cooperation.

The consequence that matters: **the highest-priority key that controls the
identity is held by the user's wallet, not by the PDS.** The PDS is the
*lowest*-priority rotation key — for commit-signing convenience and
standard-tooling interop, not the custodian of the identity.

See the genesis-op builder for where this ordering is set: the wallet builds the
op with [`build_did_plc_genesis_op_multi_rotation_with_external_signer`](../../crates/crypto/src/plc.rs)
(the PDS's test harness uses the sibling `build_did_plc_genesis_op_multi_rotation`),
placing the device key at index 0, the recovery key at index 1, and the PDS
signing key at index 2. The ordering rationale is recorded in
[ADR-0027](decisions/0027-rotation-key-ordering.md).

> **Transition note.** The three-key `[device, recovery, PDS]` layout above is
> what the current client-share `POST /v1/dids` ceremony writes. Two populations
> still carry the older two-key `[device, PDS]` layout: `did:web` accounts and
> pre-inversion wallet builds fall back to the server-side split path (which has
> no recovery slot). Pre-inversion **`did:plc` wallet** accounts are migrated onto
> the recovery slot **additively** by the wallet's re-key flow (`rekey.rs`) —
> device-key-signing a rotation op that inserts the derived recovery key at
> `rotationKeys[1]`; `rekey.rs` refuses `did:web` and interop accounts, which stay
> on the two-key layout. See *Where keys live* for the as-built ceremony split.

## Where keys live (wallet)

Managed by the Obsign identity-wallet app
([`apps/identity-wallet`](../../apps/identity-wallet/AGENTS.md)):

- **Device key** — `device_key.rs` dispatches at compile time: Secure Enclave
  `SecKey` on a real iOS device (private key never extractable), or a
  Keychain-stored software P-256 scalar on simulator/macOS. Signatures are
  low-S-normalized (plc.directory requires it).
- **Per-identity keys** — `identity_store.rs` namespaces keys per DID
  (`"{did}:device-key"`, …) so the wallet can hold multiple identities. The
  create flow signs the genesis op with the *global* device key before the DID
  exists, then `adopt_global_device_key` aliases the per-DID slot to it.
- **Shamir recovery shares** — at onboarding the **wallet** generates a fresh
  32-byte recovery seed and splits it 2-of-3 **client-side**
  ([`share_ceremony.rs`](../../apps/identity-wallet/src-tauri/src/share_ceremony.rs),
  `split_secret_into_envelopes`). It derives the seed's recovery keypair
  (`derive_recovery_keypair`), puts that key at `rotationKeys[1]` of the genesis
  op it signs, and submits to the `POST /v1/dids` ceremony
  ([`create_did.rs`](../../crates/pds/src/routes/create_did.rs)) **only** the
  escrow share — the server never sees the seed or the other two shares.
  Distribution (unchanged from ADR-0001's mapping):
  - **Share 1 → iCloud Keychain** — kept wallet-side under the per-DID
    `recovery-share-1:{did}` slot (auto-backed-up by iCloud).
  - **Share 2 → PDS escrow** — the one share the wallet hands to the server. It
    is the only share Custos ever holds, stored KEK-wrapped in the dedicated
    `recovery_escrow` table (V050), and the ceremony rejects any submitted
    envelope whose index isn't 2. Single-share escrow: worthless on its own.
  - **Share 3 → the user** — surfaced by the wallet for manual/offline backup.

  **As-built note (verified 2026-07-18).** The recovery seed is **not** the
  device key (a Secure-Enclave key is non-extractable and could never be the
  split input); it is a standalone secret whose *derived* public key is the
  `rotationKeys[1]` controller, so reconstructing the seed from ≥2 shares
  recovers real identity-controlling authority. Both reconstruction ceremonies
  exist: escrow-assisted (iCloud Share 1 + released escrow Share 2) and
  escrow-free/sovereign (offline Shares 1 + 3), implemented wallet-side in
  [`share_recovery.rs`](../../apps/identity-wallet/src-tauri/src/share_recovery.rs)
  against the server's `/v1/recovery/*` endpoints
  ([`recovery_escrow.rs`](../../crates/pds/src/routes/recovery_escrow.rs),
  [`recovery_release.rs`](../../crates/pds/src/routes/recovery_release.rs)). The
  device key's own 72-hour override supremacy (see *What the custody model buys
  us* below) remains the fast in-window safety net; share reconstruction is the
  recovery-of-last-resort for a lost device key.

  Two populations predate this and use a server-side split with **no** recovery
  slot: `did:web` accounts and pre-inversion `did:plc` wallet builds take the
  legacy fallback path in `create_did.rs` (fresh random secret, `split_secret`,
  Share 2 in the `accounts.recovery_share` column). Only the **pre-inversion
  `did:plc` wallet accounts** are migrated additively onto the recovery slot by
  the wallet's re-key flow (`rekey.rs`), which also voids the legacy column
  server-side; `rekey.rs` deliberately refuses `did:web` and non-root-device
  interop accounts, so those keep the two-key layout. The full design — the derived
  recovery key, the versioned share envelope, and both recovery paths — is
  specified in
  [Key recovery from Shamir shares](../archive/design-plans/2026-07-17-key-recovery-from-shares.md).

## What the custody model buys us

Because the wallet holds `rotationKeys[0]`, four capabilities are cryptographic
facts rather than PDS policy promises:

1. **Monitoring.** `plc_monitor.rs` polls plc.directory every 15 minutes and
   verifies each new audit-log entry's signature against the per-DID device key.
   Anything signed by another key (e.g. the PDS's `rotationKeys[2]`) is flagged
   as an unauthorized change.
2. **Recovery / override.** `recovery.rs` builds a counter-operation restoring
   pre-tamper state, signed by the device key, submittable within plc.directory's
   **72-hour** recovery window — overriding a lower-priority key's op.
3. **Wallet-authorized migration.** The same device key can sign the PLC
   operation that repoints the DID at a new PDS, with no dependency on the old
   PDS's cooperation. This reframes account migration; see
   [ADR-0002](decisions/0002-wallet-authorized-account-migration.md).
4. **Repo signing-key rotation.** The device key can authorize replacing the
   PDS-held repo signing key (`verificationMethods.atproto` / `rotationKeys[2]`)
   with a freshly generated one — the recovery mechanism when that key's
   at-rest encryption is compromised or its master key is lost, since the PDS
   key cannot re-authorize itself. The wallet composes and signs the key-swap
   op (`rotate_repo_key.rs`, a fourth strict allowlist beside claim / migration /
   handle change) and hands it to the PDS's `/v1/repo-keys/rotation` surface,
   which submits it to plc.directory and cuts its commit signer over atomically
   under the account's repo write lock; see
   [ADR-0025](decisions/0025-wallet-driven-repo-key-rotation.md).

## Import ("claim") of an existing identity

`claim.rs` implements taking custody of an existing identity whose rotation keys
the wallet does **not** yet hold (e.g. a bsky.social account). It uses the
standard email-tokened old-PDS signature *once* to submit a PLC op that inserts
the wallet's device key as `rotationKeys[0]`. After that single step the wallet
is the sovereign controller and subsequent operations can be self-signed.

## Related

- Custody rationale and alternatives: [ADR-0001](decisions/0001-client-held-rotation-key-custody.md)
- Migration design: [ADR-0002](decisions/0002-wallet-authorized-account-migration.md)
- Crypto contracts: [`crates/crypto/AGENTS.md`](../../crates/crypto/AGENTS.md)
- Wallet contracts: [`apps/identity-wallet/AGENTS.md`](../../apps/identity-wallet/AGENTS.md)
