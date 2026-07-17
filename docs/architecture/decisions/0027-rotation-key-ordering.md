# ADR-0027: Genesis rotation-key ordering is [device, recovery, PDS]

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** malpercio
- **Related:** ADR-0001 (client-held rotation-key custody), ADR-0002
  (wallet-authorized account migration),
  `docs/design-plans/2026-07-17-key-recovery-from-shares.md` (MM-405 epic)

## Context

The key-recovery design (MM-405/MM-407) adds a second wallet-controlled key to
every new did:plc identity: a **recovery rotation key**, HKDF-derived from the
recovery seed whose 2-of-3 Shamir split backs share-based recovery. The genesis
operation therefore carries three rotation keys — the Secure-Enclave device key,
the derived recovery key, and the PDS's per-account repo key — spending 3 of
PLC's 5 rotation-key slots.

PLC rotation-key order is **priority order**: during plc.directory's 72-hour
window, an operation signed by a higher-priority (earlier) key can nullify a
fork signed by a lower-priority one. The ordering chosen at genesis is
near-impossible to change ergonomically later — reordering keys is itself a PLC
operation every existing account would have to individually sign and submit —
so this decision is effectively permanent for each identity and deserves its
own record.

Two orderings were seriously considered (the PDS key is last in both — the
escrow agent must never outrank a user-held key, ADR-0001):

1. **`[device, recovery, PDS]`** — enclave supremacy. The device key can
   override anything the recovery key signs within the 72-hour window.
2. **`[recovery, device, PDS]`** — recovery supremacy. The recovery key can
   override the device key, protecting against a stolen-and-unlocked device.

## Decision

Rotation keys are ordered **`[device, recovery, PDS]`**: the Secure-Enclave
device key stays supreme, the recovery key sits above the PDS key, and the PDS
key keeps its existing dual role (lowest rotation priority +
`verificationMethods.atproto` repo-commit signer — it moves from slot [1] to
slot [2], but nothing else about it changes).

The wallet's genesis builder constructs this order; the server's genesis
validation deliberately checks only that the declared recovery key is a
*member* of `rotationKeys` (so the escrow deposit can never diverge from the
DID's public state) and stays permissive on count and order — the ordering is
the wallet's contract, pinned by the multi-rotation builder's tests.

## Rationale

Priority only matters inside the 72-hour override contest, so the question is:
which attacker do we let the other key beat?

- **A lost device is recoverable under either ordering.** Recovery after loss
  is not a contest — nobody signs with the lost enclave key — so the recovery
  key freely signs the op replacing `rotationKeys[0]` with a new device key.
  Ordering (1) gives up nothing on the primary recovery story.
- **A compromised share pair is survivable only under ordering (1).** The
  realistic worst case for the recovery key is an attacker assembling two
  shares — e.g. a malicious operator (Share 2) colluding with an Apple-account
  compromise (Share 1). Under `[device, recovery, PDS]`, the genuine device
  key can override that attacker's rotation within 72 hours. Under
  `[recovery, device, PDS]`, a share-collecting operator would *outrank the
  user's enclave* — inverting the project's core custody claim (ADR-0001's
  "the PDS holds at most one share and can never take the identity").
- **The stolen-unlocked-device threat that ordering (2) targets is not
  actually fixed by any ordering.** An attacker holding the user's unlocked
  device with biometric/passcode access already controls the enclave key *and*
  the iCloud Keychain (Share 1) — a strictly stronger position than any share
  pair. Demoting the device key buys nothing against that attacker while
  handing the share-collection attacker a supremacy win.

Enclave supremacy is also the honest continuation of ADR-0001: the device key
was sold as "the one key that controls your identity", and the recovery key is
a backstop for losing it, not a superior authority over it.

## Consequences

- Every client-share-ceremony identity spends 3 of PLC's 5 rotation-key slots,
  leaving headroom for a future second device or successor-key arrangement.
  k-of-n share growth happens *inside* the one recovery key (re-split the
  seed), never by adding rotation keys.
- Escrow-assisted recovery (Shares 1+2, MM-409/MM-410) inherits a structural
  backstop: even a fraudulently released escrow share yields a key the real
  device can override for 72 hours. The release-delay window and this ordering
  are the two independent brakes on escrow abuse.
- The recovery key can bootstrap a passwordless Custos session immediately
  after reconstruction (`/v1/sessions/sovereign` accepts any current rotation
  key) without weakening the device key's supremacy.
- The re-key migration for existing accounts (MM-411) must insert the recovery
  key at slot [1] — between the device and PDS keys — to land migrated
  accounts on this same layout.
- Reordering later requires a per-account PLC operation signed by a current
  key; there is no fleet-wide lever. If a future threat model demands recovery
  supremacy, it becomes a per-identity opt-in ceremony, not a default flip.
