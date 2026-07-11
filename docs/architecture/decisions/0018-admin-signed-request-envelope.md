# ADR-0018: Admin authentication via per-device signed-request envelopes

- **Status:** Accepted
- **Date:** 2026-06-28 (backfilled 2026-07-10)
- **Deciders:** ezpds maintainers
- **Related:** [design plan](../../archive/design-plans/2026-06-26-admin-companion-app.md) · [ADR-0017](0017-multi-relay-admin-pairings.md) (builds on this) · MM-188–MM-195 · `crates/pds/src/auth/guards.rs`

## Context

Before the Brass Console, the only admin credential was `EZPDS_ADMIN_TOKEN` — a
static bearer secret held by CI, Bruno, and the operator's laptop. Putting
admin authority on a phone forces the question of what credential the phone
holds. A bearer token on a phone is a replayable secret at rest: anyone who
reads it once owns the relay until rotation, and there is no way to cut off a
single lost device without rotating everyone. The tension: phone-resident
admin authority, without a replayable secret ever living on the phone.

## Decision

The `require_admin` guard accepts **either** the master token (unchanged,
constant-time compared, the break-glass path) **or** a per-device P-256
signed-request envelope.

Each phone generates its keypair in the iOS Secure Enclave (software P-256 on
macOS/simulator, where no Enclave exists); the relay stores only the `did:key`
public key in `admin_devices`. Every request is signed over the canonical
string `method‖path‖timestamp‖nonce‖sha256_hex(body)`, carried in
`X-Admin-Device` / `-Timestamp` / `-Nonce` / `-Signature` headers. The relay
enforces a ±60s timestamp window, single-use nonces per device (atomic
`INSERT OR IGNORE` into `admin_nonces`), and low-S signature normalization
(malleability defense). All failures return one generic 401 — except a revoked
device, which gets an explicit 403 so the operator can confirm the cutoff.

Enrollment is a master-token-minted, single-use pairing code (5-minute default
TTL) plus a self-signature over `pairing_code‖public_key‖timestamp` proving
the device holds the private key. Revocation is per-device and server-side —
reachable without the phone.

## Consequences

- No replayable admin secret exists on any phone. A captured request can't be
  replayed (nonce), redirected to another route (method+path are bound), or
  given a different body (hash is bound).
- A lost device is revoked individually; the master token never rotates for a
  device loss. `AdminActor` records which credential acted (`master-token` vs
  `device:<id>`), so admin actions are attributable.
- Pairing-code minting stays master-token-only, so a compromised device cannot
  enroll accomplices.
- The signature binds the bare path, not the query string. Admin routes must
  never carry authority-relevant data in query parameters.
- `admin_nonces` grows with every device request. `sweep_stale_nonces` is
  wired to a periodic background task (`admin_nonce_sweep.rs`, MM-286) that
  deletes rows older than a configurable retention (default 1 hour, well
  beyond the ±60s timestamp window); anti-replay itself doesn't depend on it
  (the primary key enforces single use).
- The `scopes` column defaults to `'full'` — a growth hook for narrowing
  device authority later without a schema change. The master token is unscoped.

## Alternatives considered

- **Per-device bearer tokens** (hashed server-side, like `devices`/`sessions`).
  The established pattern in this codebase, but the secret at rest on the
  phone is replayable. The chosen model is its public-key analogue: store a
  `did:key` and verify signatures instead of hashing a secret.
- **Distributing the master token to phones.** No per-device identity, no
  per-device revocation; one lost phone forces rotation everywhere, including
  CI.
- **Software keys everywhere.** The Secure Enclave holds the key
  non-extractably and gates signing behind biometrics; software P-256 is kept
  only where no Enclave exists (simulator, macOS dev builds).
