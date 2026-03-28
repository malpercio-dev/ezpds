# Human Test Plan: Identity Store Per-DID Keychain Namespacing

**Implementation plan:** `docs/implementation-plans/2026-03-28-plc-key-management/`
**Generated:** 2026-03-28

## Prerequisites

- macOS Ventura (13) or later with Xcode installed (latest stable)
- Physical iOS device with Face ID or Touch ID enrolled, paired with Xcode
- Apple Developer account with provisioning profile matching bundle ID `dev.malpercio.identitywallet`
- Nix dev shell active from workspace root: `nix develop --impure --accept-flake-config`
- Frontend dependencies installed: `cd apps/identity-wallet && pnpm install`
- Xcode project generated: `cargo tauri ios init` (plus PATH and sandbox patches per CLAUDE.md)
- Automated tests passing: `cargo test -p identity-wallet -- --test-threads=1 identity_store`

## Phase 1: Secure Enclave Device Key Generation (AC2.1)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Build the app for a physical device: `cd apps/identity-wallet && cargo tauri ios build` | Build succeeds, IPA produced |
| 2 | Install the app on the physical iOS device via Xcode (Window > Devices and Simulators > Install App) | App appears on device home screen |
| 3 | Launch the app. Complete relay configuration (enter a valid relay URL, e.g. the staging relay). Proceed through onboarding to the point where an identity is created (complete claim code, email, handle, password, DID ceremony steps). | Onboarding flow completes. A biometric prompt (Face ID or Touch ID) appears during the DID ceremony step when the device key is generated. |
| 4 | After DID ceremony succeeds, navigate to the identity detail screen (via home screen). | The device key `multibase` value is displayed, starts with `z`. The `keyId` starts with `did:key:z`. |

## Phase 2: Secure Enclave Key Idempotency (AC2.4)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From Phase 1 step 4, note the displayed device key `multibase` and `keyId` values. | Values recorded. |
| 2 | Force-kill the app (swipe up from app switcher on iOS). | App is terminated. |
| 3 | Relaunch the app from the device home screen. Navigate to the same identity's detail screen. | The same `multibase` and `keyId` values are displayed as recorded in step 1. The key survived app restart, confirming Secure Enclave persistence. |

## Phase 3: Different DIDs Get Different Keys (AC2.5)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen, add a second identity (this requires a second valid claim code and distinct email/handle from the relay). Complete the full onboarding flow for the second identity. | Second identity is created. A biometric prompt appears during device key generation. |
| 2 | Navigate to the second identity's detail screen and note its device key `multibase` value. | The `multibase` value differs from the first identity's value recorded in Phase 2 step 1. |

## Phase 4: Remove Identity Cleans Up (AC2.3)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the home screen, select the second identity (created in Phase 3) and choose "Remove Identity" (or equivalent UI action). | Confirmation dialog appears. |
| 2 | Confirm removal. | The identity disappears from the identity list. |
| 3 | Verify the removed identity's data is no longer accessible: attempt to view its DID document or PLC log (if the UI exposes these views). | No data is displayed for the removed identity. The identity does not appear in the list. |
| 4 | (Stretch) Re-add the same DID if the relay allows re-registration, and verify the DID document and PLC log fields are empty (not carried over from the previous registration). | Fresh identity with no residual data. |

## End-to-End: Full Multi-Identity Lifecycle on Physical Device

**Purpose:** Validates that the complete identity lifecycle -- registration, key generation, data persistence, idempotent key retrieval, and cleanup -- works end-to-end through the Secure Enclave code path on real hardware.

1. Start with a fresh app install on a physical iOS device (delete and reinstall if previously installed).
2. Configure relay URL on first launch.
3. Create first identity (full onboarding flow). Verify biometric prompt appears, device key is generated, DID ceremony succeeds.
4. Kill and relaunch the app. Verify the first identity's device key is unchanged (idempotency).
5. Create a second identity. Verify its device key differs from the first.
6. Store and retrieve a DID document for the first identity (if the UI supports this; otherwise verify via the DID document screen).
7. Remove the second identity. Verify it disappears and its data is cleaned up.
8. Verify the first identity is unaffected by the second identity's removal.

## Human Verification Required

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| AC2.1 (Secure Enclave path) | The `#[cfg(all(target_os = "ios", not(target_env = "sim")))]` code path uses real Secure Enclave hardware for key generation. Automated tests only exercise the software fallback path. | Phase 1 steps 1-4 |
| AC2.3 (Secure Enclave cleanup) | Removing an identity must delete SE-backed key metadata (`{did}:device-key-pub`, `{did}:device-key-app-label`). The software test path does not create these entries. | Phase 4 steps 1-3 |
| AC2.4 (Secure Enclave idempotency) | The SE path caches the compressed public key and application_label in Keychain for fast retrieval. The cache-hit code path is only compiled on real iOS. | Phase 2 steps 1-3 |
| AC2.5 (Secure Enclave key isolation) | Each DID must get a distinct SE-backed key with its own `kSecAttrLabel` and `kSecAttrApplicationLabel`. The software path uses different key generation machinery. | Phase 3 steps 1-2 |

## Traceability

| Acceptance Criterion | Automated Test(s) | Manual Step(s) |
|----------------------|-------------------|----------------|
| AC2.1 -- add_identity stores DID + generates device key | `add_identity_and_list`, `get_or_create_device_key_success` | Phase 1 (SE path) |
| AC2.2 -- list_identities returns all DIDs | `list_multiple_identities` | N/A |
| AC2.3 -- remove_identity removes DID + Keychain entries | `remove_identity_from_list`, `remove_identity_cleans_up_all_entries` | Phase 4 (SE cleanup) |
| AC2.4 -- get_or_create_device_key is idempotent | `get_or_create_device_key_idempotent` | Phase 2 (SE idempotency) |
| AC2.5 -- different DIDs get different keys | `get_or_create_device_key_different_dids` | Phase 3 (SE key isolation) |
| AC2.6 -- DID document round-trip | `did_doc_round_trip` | N/A |
| AC2.7 -- PLC log round-trip | `plc_log_round_trip` | N/A |
| AC2.8 -- get_did_doc/get_plc_log return None when unset | `get_did_doc_returns_none_if_not_stored`, `get_plc_log_returns_none_if_not_stored` | N/A |
| AC2.9 -- error cases for nonexistent/duplicate DIDs | 8 tests (see automated coverage) | N/A |
