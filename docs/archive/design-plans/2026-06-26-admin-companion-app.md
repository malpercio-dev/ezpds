# Admin Companion App Design

## Summary

The admin companion app is a second iOS app in this repository — separate from the Obsign identity wallet — that lets a relay operator perform day-to-day administrative actions (generating account claim codes, managing paired devices) from their phone without needing a laptop or terminal. The core engineering challenge is giving the phone a secure credential it can use to authenticate to the relay: rather than storing a replayable secret, each phone generates a P-256 keypair in the iOS Secure Enclave and the relay stores only the corresponding public key. Every admin request the phone makes is signed with that key over a canonical envelope that binds the HTTP method, path, timestamp, nonce, and a hash of the body — so the relay can verify authenticity, reject replays, and enforce a time window without ever having seen the private key.

The design is additive. On the relay side, the existing master admin token (`EZPDS_ADMIN_TOKEN`) continues to work unchanged as a break-glass path for CI and Bruno; a new `require_admin` guard simply extends it to also accept verified device signatures. On the app side, a new `apps/admin-companion/` Tauri v2 + SvelteKit project reuses the iOS toolchain scripts and OKLCH token architecture already in place for Obsign, but forks the token values to express a terminal-native design register rather than Obsign's humane lane. The eight implementation phases sequence from crypto primitives outward — a standalone P-256 verify wrapper, then database tables, then relay endpoints, then the app itself — so relay work and app scaffold can proceed in parallel before converging in the pairing and request-signing phases.

## Definition of Done

- An operator can generate and share an account claim code from a companion app on their phone, without a laptop or terminal.
- Each phone authenticates to the relay with its own per-device P-256 key held in the iOS Secure Enclave, by signing every request — no replayable secret is stored on the device.
- A new phone is enrolled through QR pairing that only the holder of the master admin token can authorize.
- The existing static master admin token (`EZPDS_ADMIN_TOKEN`) keeps working unchanged for CI and Bruno (break-glass path).
- An admin device can be revoked server-side without physical access to the phone, and a revoked device is denied.
- Stale or replayed signed requests are rejected.
- The companion app speaks a distinct terminal-native design language (not Obsign's humane lane) and meets WCAG 2.2 AAA contrast.

## Acceptance Criteria

### admin-companion-app.AC1: Operator generates a claim code from the app
- **admin-companion-app.AC1.1 Success:** A paired device generates an account claim code via a signed `POST /v1/accounts/claim-codes`, and the code is displayed.
- **admin-companion-app.AC1.2 Success:** The displayed claim code can be copied and shared via the iOS share sheet.
- **admin-companion-app.AC1.3 Failure:** An unpaired app routes the operator to the Pair screen instead of calling the endpoint.

### admin-companion-app.AC2: Per-device signed-request authentication
- **admin-companion-app.AC2.1 Success:** A request signed by a registered, non-revoked device's key is accepted by `require_admin`.
- **admin-companion-app.AC2.2 Success:** The master Bearer token still authorizes the same endpoints (break-glass / CI).
- **admin-companion-app.AC2.3 Failure:** A signature that does not verify against the stored public key returns 401.
- **admin-companion-app.AC2.4 Failure:** A signature computed over a different method, path, or body than the actual request returns 401.
- **admin-companion-app.AC2.5 Edge:** Both the Secure-Enclave path (device) and the software-key fallback (simulator/macOS) produce signatures the relay verifies.

### admin-companion-app.AC3: Anti-replay
- **admin-companion-app.AC3.1 Failure:** A request whose timestamp is outside the ±60s window is rejected.
- **admin-companion-app.AC3.2 Failure:** A request reusing a previously-seen nonce is rejected.
- **admin-companion-app.AC3.3 Success:** A distinct nonce within the window is accepted exactly once.

### admin-companion-app.AC4: QR pairing bootstrap
- **admin-companion-app.AC4.1 Success:** The master token mints a single-use pairing code via `POST /v1/admin/pairing-codes`.
- **admin-companion-app.AC4.2 Success:** The app claims a pairing code with a self-signed public key and the device is registered via `POST /v1/admin/devices`.
- **admin-companion-app.AC4.3 Failure:** Minting a pairing code without the master token returns 401.
- **admin-companion-app.AC4.4 Failure:** Claiming an expired pairing code is rejected.
- **admin-companion-app.AC4.5 Failure:** Claiming an already-consumed pairing code is rejected.
- **admin-companion-app.AC4.6 Failure:** A claim whose self-signature does not verify against the supplied public key is rejected.
- **admin-companion-app.AC4.7 Edge:** A pairing code is single-use — a second claim with the same code fails.

### admin-companion-app.AC5: Device revocation
- **admin-companion-app.AC5.1 Success:** `GET /v1/admin/devices` lists paired devices with derived status (active/revoked) and last-seen.
- **admin-companion-app.AC5.2 Success:** `POST /v1/admin/devices/:id/revoke` sets `revoked_at`.
- **admin-companion-app.AC5.3 Failure:** A revoked device's signed request is denied with 403 (no phone access needed to cut it off).
- **admin-companion-app.AC5.4 Success:** Revocation is authorized by the master token or by another active admin device.

### admin-companion-app.AC6: Distinct terminal-native design language
- **admin-companion-app.AC6.1 Success:** The app references its own forked token values via CSS variables, with no hardcoded hex/px and no Obsign humane-lane tokens.
- **admin-companion-app.AC6.2 Success:** Status is conveyed by text + glyph (e.g. `● active` / `⊘ revoked`), never by color alone.
- **admin-companion-app.AC6.3 Success:** Color and type tokens meet WCAG 2.2 AAA contrast.
- **admin-companion-app.AC6.4 Success:** A separate product/design brief exists for the admin app (`apps/admin-companion/PRODUCT.md`).

### admin-companion-app.AC7: Error and recovery states
- **admin-companion-app.AC7.1 Failure:** A clock-skew (timestamp-window) rejection surfaces a "check this device's date & time" message.
- **admin-companion-app.AC7.2 Failure:** A revoked-device response surfaces "access revoked" and returns the app to the Pair screen.
- **admin-companion-app.AC7.3 Failure:** An unreachable relay surfaces a retry affordance with the relay URL visible.
- **admin-companion-app.AC7.4 Success:** Each signing action is gated by biometric (user presence).

## Glossary

- **P-256**: A standardized elliptic curve (also called secp256r1 or NIST P-256) used for generating asymmetric keypairs and producing ECDSA signatures. Chosen here because the iOS Secure Enclave natively supports it.
- **Secure Enclave**: A dedicated hardware security coprocessor in Apple devices that generates and holds cryptographic keys in a non-extractable way; the private key can sign data but can never be read out of the chip.
- **ECDSA**: Elliptic Curve Digital Signature Algorithm — the signing scheme used to produce the per-request signatures. A signature is a pair of integers (r, s) encoded here as a raw 64-byte concatenation.
- **did:key**: A decentralized identifier (DID) method that encodes a public key directly in the identifier string (e.g. `did:key:z…`), without requiring a registry. Used here to store and reference device public keys in the relay database.
- **anti-replay / nonce**: A nonce is a random value included once in a signed request to prevent an attacker who captures a valid request from re-submitting it. The relay records seen nonces and rejects duplicates.
- **canonical envelope / sign_string**: The exact byte sequence the signer commits to and the verifier reconstructs — here `method ‖ "\n" ‖ path ‖ "\n" ‖ timestamp ‖ "\n" ‖ nonce ‖ "\n" ‖ sha256(body)`. Both sides must produce the identical string for verification to pass.
- **low-S normalization**: ECDSA signatures have two valid (r, s) forms for any input; "low-S" picks the canonical one to prevent signature malleability (where an attacker swaps s for n−s to produce a different but still-valid signature over the same message).
- **pairing code**: A short-lived, single-use bearer secret the master admin token mints to bootstrap a new device. The phone scans it in a QR code, uses it to prove the operator authorized enrollment, and the code is consumed atomically on first use.
- **self-signature**: During device registration, the phone signs a message over `(pairing_code ‖ public_key ‖ timestamp)` using the private key it just generated. The relay verifies this signature against the supplied public key to prove the device actually holds the private key — not just a public key it copied from somewhere else.
- **derived status**: A status field (e.g. active/revoked, pending/consumed) computed from timestamp columns at query time rather than stored as an enumeration column, so there is no risk of the stored status diverging from the underlying data.
- **`require_admin`**: The Axum middleware extractor that gates admin endpoints; it accepts either the master Bearer token or a valid device signature, and is the single policy-enforcement point for admin access.
- **`require_admin_token`**: The existing, narrower guard that only accepts the master Bearer token. Routes currently using it are migrated to `require_admin` in Phase 4 with no behavior change for existing callers.
- **break-glass path**: A fallback credential (here the static `EZPDS_ADMIN_TOKEN`) reserved for emergencies or automated systems (CI, Bruno) that bypasses the normal per-device credential flow.
- **OKLCH**: A perceptually uniform color space used for the design token system; unlike hex/HSL it makes contrast calculations and palette derivation predictable. The project's `tokens.css` uses OKLCH values throughout.
- **terminal-native design language**: A visual register chosen for the admin app — monospace-forward typography, dark-first palette, CLI-output affordances — deliberately distinct from Obsign's humane security-instrument aesthetic to communicate that the audience is technical operators.
- **Tauri v2**: A framework for building cross-platform desktop and mobile apps with a web frontend (SvelteKit here) and a Rust backend; used for both the existing Obsign wallet and the new admin companion app.
- **SvelteKit**: A full-stack web framework for Svelte; used as the frontend layer inside Tauri.
- **WCAG 2.2 AAA**: The highest conformance level of the Web Content Accessibility Guidelines; the project targets this for color contrast in particular, meaning foreground/background pairs must exceed a 7:1 contrast ratio.
- **`DidKeyUri`**: The Rust type in `crates/crypto` that wraps the string form of a did:key identifier and carries the encoded public key for signature verification.
- **Bruno**: An open-source API client; the project maintains a Bruno collection in `bruno/` documenting every relay endpoint. The conventions require a `.bru` file update for each new route.
- **`schema_migrations` runner**: The project's custom forward-only SQL migration runner (not sqlx's built-in `migrate!()`) that tracks applied migrations in a `schema_migrations` table and uses a `V00x__name.sql` filename convention.
- **`scopes` column**: A growth hook on `admin_devices` defaulting to `full` that reserves the ability to narrow a device's authority (e.g. claim-codes-only) in a future schema-free change.

## Architecture

A new iOS companion app for the **operator** of an ezpds relay — distinct from the Obsign identity wallet and from any end-user credential wallet. It starts minimal (generate/share a claim code on the go) but is architected so a broader operator console can be added without reworking auth.

**Three actors, one root of trust.** The operator's laptop holds the master admin token (`EZPDS_ADMIN_TOKEN`) and remains the root of trust and break-glass path. The companion app holds a per-device P-256 keypair and authenticates by signing requests. The relay verifies either credential.

```
  laptop / CLI ──(master token)──▶ relay : mints pairing code (QR)
  companion app ──(signed reqs)──▶ relay : require_admin verifies device signature
```

**Per-device credential (no replayable secret at rest).** The phone generates a P-256 key in the Secure Enclave (non-extractable; signing only). The relay stores only the device's public key as a `did:key`. Every admin request carries a signature over a canonical envelope binding method, path, timestamp, nonce, and a hash of the body. The relay verifies the signature against the stored public key, enforces a timestamp window, and rejects reused nonces.

**Request-signing envelope.**

```
sign_string = method ‖ "\n" ‖ path ‖ "\n" ‖ timestamp ‖ "\n" ‖ nonce ‖ "\n" ‖ sha256(body)

Headers on every admin request from a device:
  X-Admin-Device:    <device_id>
  X-Admin-Timestamp: <unix seconds>
  X-Admin-Nonce:     <random 128-bit, base64url>
  X-Admin-Signature: <base64url(r‖s)>   # 64-byte raw P-256 signature, low-S
```

**Pairing handshake (bootstrap of trust).**

1. `POST /v1/admin/pairing-codes` (master token) → `{ pairing_code, expires_at }`. Single-use, ~5-minute TTL. A `just` recipe renders `{ "url": <relay base url>, "code": <pairing_code> }` as a terminal QR.
2. Phone scans the QR (learns relay URL + one-time code).
3. Phone generates its Secure-Enclave keypair → `did:key` public key.
4. `POST /v1/admin/devices` with the pairing code, a device label, the public key, and a self-signature over `(pairing_code ‖ public_key ‖ timestamp)`. The relay verifies the code is valid/unconsumed/unexpired **and** that the self-signature checks against the supplied public key, then inserts the device row and consumes the code in one transaction → `{ device_id }`.
5. From then on the phone signs each request; there is no separate login.

**Relay surface.** A new route module `crates/pds/src/routes/admin_devices.rs` exposes pairing/claim/list/revoke. The existing admin guard `require_admin_token` ([guards.rs](../../crates/pds/src/auth/guards.rs)) is widened to `require_admin`, which accepts the master Bearer token **or** a verified device signature. The existing admin routes (`POST /v1/accounts/claim-codes`, `POST /v1/relay/keys`) switch to `require_admin` with no behavior change.

**Endpoint contracts.**

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/admin/pairing-codes` | master token only | mint single-use pairing code |
| POST | `/v1/admin/devices` | pairing code + self-signature | register a device public key |
| GET | `/v1/admin/devices` | `require_admin` | list paired devices (id, label, last_seen, derived status) |
| POST | `/v1/admin/devices/:id/revoke` | `require_admin` | revoke a device |
| POST | `/v1/accounts/claim-codes` | `require_admin` (was `require_admin_token`) | unchanged behavior |
| POST | `/v1/relay/keys` | `require_admin` (was `require_admin_token`) | unchanged behavior |

Pairing-code minting stays master-token-only so a compromised device cannot enroll accomplices.

**Database schema** (one forward-only migration, following the `schema_migrations` runner and `V00x__name.sql` convention; status derived, not stored, matching [V004__claim_codes_invite.sql](../../crates/pds/src/db/migrations/V004__claim_codes_invite.sql)):

```sql
admin_pairing_codes(
  code TEXT PRIMARY KEY, expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL, consumed_at TEXT)

admin_devices(
  id TEXT PRIMARY KEY, label TEXT NOT NULL,
  public_key TEXT NOT NULL,                                    -- did:key:z…
  platform TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT 'full', -- growth hook
  created_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT)

admin_nonces(
  device_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at TEXT NOT NULL,
  PRIMARY KEY (device_id, nonce))   -- per-device scope; FK device_id → admin_devices
```

A device is *active* when `revoked_at IS NULL`; a pairing code is *pending* when `consumed_at IS NULL AND expires_at > now`. The `admin_nonces` table is swept of rows older than the timestamp window. `scopes` defaults to `full` for v1 and is the hook for narrowing device authority later.

**Companion app.** A new `apps/admin-companion/` (Tauri v2 + SvelteKit), reusing the Obsign iOS toolchain scripts and the OKLCH token *architecture* but with its own forked token *values* and components — a terminal-native skin (monospace-forward, dark-first, CLI-output affordances), not Obsign's humane lane. The Rust core ports the proven device-key module ([device_key.rs:174](../../apps/identity-wallet/src-tauri/src/device_key.rs)) for Secure-Enclave keygen/signing (with the existing simulator/macOS software-key fallback) and adds the request-signing envelope. v1 screens: **Pair** (scan QR), **Home** (generate/share claim code, biometric-gated), **Settings** (label, relay URL, unpair, biometric toggle). The operator is never an identity/DID and never registers in IdentityStore.

## Existing Patterns

This design reuses established patterns rather than introducing new machinery:

- **Per-device bearer credentials hashed in a table** — the relay already does this for `devices`/`sessions` (SHA-256 of the token) in [guards.rs](../../crates/pds/src/auth/guards.rs). The admin-device model is the public-key analogue: store the device's `did:key` and verify signatures instead of hashing a secret.
- **Derived status, not stored** — `admin_devices`/`admin_pairing_codes` follow `claim_codes` ([V004](../../crates/pds/src/db/migrations/V004__claim_codes_invite.sql)), computing pending/active/revoked from timestamps in queries.
- **Forward-only migrations** with the custom `schema_migrations` runner (not sqlx's built-in). New tables ship in a new `V00x__admin_devices.sql`.
- **Constant-time admin auth** — `require_admin` keeps the master-token comparison from [guards.rs](../../crates/pds/src/auth/guards.rs) (subtle ct_eq) as one of its two accepted credentials.
- **Route isolation** — a dedicated `routes/admin_devices.rs` per the relay's route-isolation rule in [crates/pds/AGENTS.md](../../crates/pds/AGENTS.md); each new route gets a matching `bruno/*.bru` per the AGENTS.md mandate.
- **P-256 in the Secure Enclave + external-signer callback** — Obsign already generates an SE key and signs via `ECDSASignatureMessageX962SHA256`, normalizing DER → raw 64-byte r‖s ([device_key.rs](../../apps/identity-wallet/src-tauri/src/device_key.rs)); the relay already verifies P-256 signatures against a `did:key` ([plc.rs:542](../../crates/crypto/src/plc.rs)). The companion app reuses both ends; the only new crypto surface is a thin public verify wrapper.
- **OKLCH CSS-variable token system** — the admin app forks the *architecture* of `apps/identity-wallet/src/lib/styles/{tokens,fonts,base}.css` (hex-free, `var(--*)` references) with new values.

**Divergence:** the companion app deliberately does **not** adopt Obsign's design language (PRODUCT.md/DESIGN.md), which is scoped to the identity wallet. The admin app gets its own terminal-native product/design brief because its audience is technical operators.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Signature verification primitive (relay/crypto)
**Goal:** A general-purpose P-256 verify entry point the relay can call for arbitrary messages.

**Components:**
- Public `verify_p256_signature(public_key: &DidKeyUri, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError>` in `crates/crypto/src/` — a thin wrapper over the existing internal `verify_signature_with_key` ([plc.rs:542](../../crates/crypto/src/plc.rs)), decoupled from genesis-op JSON.

**Dependencies:** None.

**Done when:** Tests pass for: a valid r‖s signature verifies; a signature from a different key is rejected; a tampered message is rejected; a malformed (non-64-byte) signature is rejected. Covers admin-companion-app.AC2.3.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Admin-device data model (relay db)
**Goal:** Tables and query functions for pairing codes, admin devices, and nonces.

**Components:**
- Migration `crates/pds/src/db/migrations/V00x__admin_devices.sql` — `admin_pairing_codes`, `admin_devices`, `admin_nonces`.
- Query functions in `crates/pds/src/db/` — insert/consume pairing code; insert/list/revoke device; lookup device by id; insert-nonce-if-absent; sweep stale nonces. Status derived in queries.

**Dependencies:** None (parallel to Phase 1).

**Done when:** Migration applies cleanly; round-trip insert/select tests pass; UNIQUE constraints enforced (pairing-code PK, nonce PK); derived-status queries return correct pending/active/revoked. Operational + covers data-layer portions of admin-companion-app.AC4/AC5.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Pairing endpoints (relay routes)
**Goal:** Mint a pairing code and register a device by claiming it.

**Components:**
- `crates/pds/src/routes/admin_devices.rs` — `POST /v1/admin/pairing-codes` (master-token authed) and `POST /v1/admin/devices` (pairing code + self-signature verified via Phase 1).
- Route registration in `crates/pds/src/app.rs`.
- `bruno/admin_pairing_codes.bru`, `bruno/admin_register_device.bru`.

**Dependencies:** Phase 1 (verify), Phase 2 (tables).

**Done when:** Tests pass for: minting requires the master token (else 401); a valid code + valid self-signature registers the device and consumes the code; expired code rejected; already-consumed code rejected; self-signature that doesn't verify against the supplied key rejected; second claim of the same code fails. Covers admin-companion-app.AC4.1–AC4.7.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Signed-request auth guard (relay)
**Goal:** `require_admin` accepts the master token or a verified, non-replayed device signature; existing admin routes adopt it.

**Components:**
- `require_admin(headers, body, state)` in `crates/pds/src/auth/guards.rs` — rebuilds the canonical `sign_string`, verifies against the device's stored key, enforces the ±60s timestamp window, and inserts the nonce (conflict ⇒ replay ⇒ reject); bumps `last_seen_at`. Retains the master-token path.
- Switch `POST /v1/accounts/claim-codes` and `POST /v1/relay/keys` from `require_admin_token` to `require_admin`.

**Dependencies:** Phases 1–3.

**Done when:** Tests pass for: master Bearer token still authorizes; a correctly signed device request authorizes; signature over a different method/path/body is rejected; timestamp outside the window is rejected; reused nonce is rejected; distinct nonce within window is accepted once. Covers admin-companion-app.AC2.1–AC2.4, AC3.1–AC3.3.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Device management endpoints (relay routes)
**Goal:** List and revoke admin devices.

**Components:**
- `GET /v1/admin/devices` and `POST /v1/admin/devices/:id/revoke` in `routes/admin_devices.rs`.
- `bruno/admin_list_devices.bru`, `bruno/admin_revoke_device.bru`.

**Dependencies:** Phases 2 and 4.

**Done when:** Tests pass for: list returns devices with derived status; revoke sets `revoked_at`; a revoked device's signed request is denied (integration with Phase 4); revoke is authorized by the master token or another active device. Covers admin-companion-app.AC5.1–AC5.4.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Companion app scaffold + admin device key (app)
**Goal:** A buildable `apps/admin-companion/` iOS app with its own SE-backed admin keypair and terminal-native token foundation.

**Components:**
- `apps/admin-companion/` — Tauri v2 + SvelteKit project reusing the Obsign iOS toolchain scripts (`ios-env.sh`, postinit patches).
- Rust core `device_key` module ported from [device_key.rs](../../apps/identity-wallet/src-tauri/src/device_key.rs) — SE keygen/signing on device, software-key fallback on simulator/macOS, `did:key` public key.
- `apps/admin-companion/src/lib/styles/{tokens,fonts,base}.css` — forked OKLCH token architecture with terminal-native values (mono type, dark-first, AAA contrast).
- `apps/admin-companion/PRODUCT.md` — terminal-native product/design brief (input for `/impeccable`).

**Dependencies:** None (parallel to relay work).

**Done when:** `cargo build` and the app build succeed; the ported `device_key::get_or_create()`/`sign()` round-trip passes on the software path (unit test). Operational; covers admin-companion-app.AC2.5 (software path) and AC6.4.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Pairing + request signing client (app)
**Goal:** The app can pair via QR and sign admin requests with the canonical envelope.

**Components:**
- QR-scan **Pair** screen and pairing exchange (self-signed `POST /v1/admin/devices`).
- Request-signing envelope in the Rust core (build `sign_string`, attach `X-Admin-*` headers) shared by all admin calls.
- Keychain persistence of `device_id` + relay URL (reusing the wallet's `keychain.rs` pattern).

**Dependencies:** Phase 6 (key module), Phases 3–4 (relay pairing + guard).

**Done when:** Tests pass for: the client's canonical `sign_string` matches the relay's expectation (shared canonicalization test); pairing happy-path registers a device and stores `device_id`; a signed claim-code request is accepted end-to-end against a test relay (software-key path). Covers admin-companion-app.AC4.2 and the client side of AC2.1.
<!-- END_PHASE_7 -->

<!-- START_PHASE_8 -->
### Phase 8: Claim-code screen, terminal-native UI, error states (app)
**Goal:** The demo-lifesaver flow and its failure states, in the terminal-native register.

**Components:**
- **Home** screen — biometric-gated **Generate claim code** with Share/Copy; code rendered as CLI-style output.
- **Settings** screen — device label, relay URL, unpair (self-revoke), biometric toggle.
- Error/recovery states — not-paired → Pair; clock-skew → "check device time"; revoked → "access revoked" → Pair; relay unreachable → retry with URL visible.
- Terminal-native components and status-as-text+glyph treatment.

**Dependencies:** Phase 7; Phase 5 (self-revoke).

**Done when:** Manual end-to-end demo on the simulator (software-key path) produces and shares a claim code; failure states render correctly; status never relies on color alone; tokens meet AAA contrast. Covers admin-companion-app.AC1.1–AC1.3, AC6.1–AC6.3, AC7.1–AC7.4.
<!-- END_PHASE_8 -->

## Additional Considerations

**Error handling:** Signature/timestamp/nonce failures return `401`; a revoked device returns `403`. Messages are generic server-side (no detail leakage); the app maps them to specific, honest UI states (clock skew, revoked, unreachable).

**Edge cases:** The ±60s timestamp window depends on device clock accuracy — surface a "check device time" hint rather than a generic auth error. The pairing code is a bearer secret while its QR is on screen; single-use + short TTL + the QR living only on the operator's own laptop screen keeps that exposure small (accepted for v1).

**Future extensibility:** The `scopes` column (defaulting to `full`) enables narrowing a device's authority later (e.g. claim-codes-only) without schema change. Widening `require_admin` once means any future admin endpoint (account list, relay health) is reachable by signed requests, so the broader operator console is additive. An in-app "Paired devices" manager is a later addition over the existing list/revoke endpoints.

**Security posture:** The private key never leaves the Secure Enclave and signing is biometric-gated. Revocation is server-side and reachable without the phone (the stolen-device case). The master token is unchanged, preserving the existing CI/break-glass path.
