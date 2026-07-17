# ADR-0001: The user's wallet holds `rotationKeys[0]`; the PDS holds `rotationKeys[1]`

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled; decision embodied in code since the DID ceremony landed)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0002](0002-wallet-authorized-account-migration.md) · [`../identity-and-key-custody.md`](../identity-and-key-custody.md) · [`crates/crypto/src/plc.rs`](../../../crates/crypto/src/plc.rs) · `apps/identity-wallet/src-tauri/src/{device_key,plc_monitor,recovery,claim}.rs`

## Context

A `did:plc` identity is controlled by an **ordered** `rotationKeys` array, where
a higher-priority key can override operations signed by a lower-priority key
within plc.directory's 72-hour recovery window. Whoever holds the top rotation
key is the real custodian of the identity.

In the mainstream ATProto deployment (Bluesky, and PDS distributions modelled on
it), the **PDS holds the rotation keys**. A user migrating or recovering must ask
the PDS to sign the identity operation on their behalf, gated by an email token.
This makes "credible exit" a *policy promise*: you can leave only if your PDS
cooperates. A hostile, compromised, or offline PDS can block you, and a
compromised PDS can rotate the identity out from under you.

ezpds mints identities from a wallet app that already has strong per-device key
custody available (Apple Secure Enclave). The question was who should hold the
top rotation key: the PDS (mainstream, simplest for standard tooling) or the
user's wallet.

## Decision

We will place **the user's wallet device key at `rotationKeys[0]`** (the
highest-priority key) and **the PDS signing key at `rotationKeys[1]`**. The PDS
key also serves as `verificationMethods.atproto` and signs repo commits; the
device key signs only identity operations.

The device key is held in the Secure Enclave on real iOS hardware (non-
extractable) and as a Keychain-stored software key on simulator/macOS. The
genesis operation is built and signed client-side via
`build_did_plc_genesis_op_with_external_signer`, with the wallet's key as the
external signer.

## Consequences

- **Sovereignty is cryptographic, not custodial.** The highest-priority key
  never leaves the user's device, so the PDS cannot unilaterally take over,
  block, or hold the identity hostage. This is the project's core
  differentiator.
- **Enables a client-side safety net** already built on top of this decision:
  `plc_monitor.rs` verifies audit-log entries against the device key and flags
  anything signed by another key (including the PDS's `rotationKeys[1]`);
  `recovery.rs` builds a device-key-signed counter-operation to override tamper
  within the 72-hour window.
- **Reframes migration** (see ADR-0002): the wallet can authorize the PLC op that
  moves the identity to a new PDS without the old PDS's cooperation.
- **The PDS is still a rotation key**, so standard email-tokened tooling
  (`signPlcOperation`, goat) can still operate on ezpds identities — required for
  interop and for the first-time import of a foreign identity.
- **New failure mode: user key loss.** If the wallet device key is lost with no
  other authorized key, the identity is unrecoverable. A 2-of-3 Shamir split runs
  at onboarding (Share 1 → iCloud Keychain, Share 2 → PDS escrow, Share 3 →
  user's choice), and the PDS remains a lower-priority rotation key. **As built,
  the split does not yet close this gap**: it splits a server-generated random
  secret that is bound to nothing and absent from `rotationKeys`, and no
  reconstruction ceremony exists — so the live mitigation for device-key loss is
  presently only the device key's own 72-hour override supremacy. Binding the
  seed to a derived recovery rotation key and building the reconstruction
  ceremonies is designed in
  [Key recovery from Shamir shares](../../design-plans/2026-07-17-key-recovery-from-shares.md).
- **Signatures must be low-S normalized** on every path (plc.directory rejects
  high-S); both the Secure Enclave and software signing paths enforce this.

## Alternatives considered

- **PDS holds the rotation keys (mainstream model).** Rejected: makes credible
  exit and tamper-recovery depend on PDS cooperation, defeating the reason to
  build a sovereign wallet at all.
- **Wallet holds the *only* rotation key.** Rejected: no lower-priority key means
  no server-side recovery lever and no path for standard email-tokened tooling;
  raises key-loss risk to catastrophic with no fallback.
- **PDS at `rotationKeys[0]`, wallet at `[1]`.** Rejected: inverts the priority
  so the PDS could override the user, which is precisely the custody we are
  trying to eliminate.
