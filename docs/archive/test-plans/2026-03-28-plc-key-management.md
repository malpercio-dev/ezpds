# Human Test Plan: Identity Store Per-DID Keychain Namespacing

**Implementation plan:** `docs/implementation-plans/2026-03-28-plc-key-management/`
**Generated:** 2026-03-28

## Prerequisites

- macOS Ventura (13) or later with Xcode installed (latest stable)
- Physical iOS device with Face ID or Touch ID enrolled, paired with Xcode
- Apple Developer account with provisioning profile matching bundle ID `dev.malpercio.identitywallet`
- Nix dev shell active from workspace root: `nix develop --impure --accept-flake-config`
- Frontend dependencies installed: `cd apps/identity-wallet && pnpm install`
- Xcode project generated: `cargo tauri ios init` (plus PATH and sandbox patches per AGENTS.md)
- Automated tests passing: `cargo test -p identity-wallet -- --test-threads=1 identity_store`

## Phase 1: Secure Enclave Device Key Generation (AC2.1)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Build the app for a physical device: `cd apps/identity-wallet && cargo tauri ios build` | Build succeeds, IPA produced |
| 2 | Install the app on the physical iOS device via Xcode (Window > Devices and Simulators > Install App) | App appears on device home screen |
| 3 | Launch the app. Complete relay configuration (enter a valid relay URL, e.g. the staging relay). Proceed through onboarding to the point where an identity is created (complete claim code, email, handle, password, DID ceremony steps). | Onboarding flow completes. Device key generation succeeds (the SE path uses `kSecAccessControlPrivateKeyUsage` without biometric flags, so a biometric prompt is not expected during key generation itself -- it may appear during signing operations in later phases). |
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
| 1 | From the home screen, add a second identity (this requires a second valid claim code and distinct email/handle from the relay). Complete the full onboarding flow for the second identity. | Second identity is created. Device key generation succeeds without error. |
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
3. Create first identity (full onboarding flow). Verify device key is generated and DID ceremony succeeds.
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
| AC2.1 -- add_identity stores DID; get_or_create_device_key generates per-DID device key | `add_identity_and_list`, `get_or_create_device_key_success` | Phase 1 (SE path) |
| AC2.2 -- list_identities returns all DIDs | `list_multiple_identities` | N/A |
| AC2.3 -- remove_identity removes DID + Keychain entries | `remove_identity_from_list`, `remove_identity_cleans_up_all_entries` | Phase 4 (SE cleanup) |
| AC2.4 -- get_or_create_device_key is idempotent | `get_or_create_device_key_idempotent` | Phase 2 (SE idempotency) |
| AC2.5 -- different DIDs get different keys | `get_or_create_device_key_different_dids` | Phase 3 (SE key isolation) |
| AC2.6 -- DID document round-trip | `did_doc_round_trip` | N/A |
| AC2.7 -- PLC log round-trip | `plc_log_round_trip` | N/A |
| AC2.8 -- get_did_doc/get_plc_log return None when unset | `get_did_doc_returns_none_if_not_stored`, `get_plc_log_returns_none_if_not_stored` | N/A |
| AC2.9 -- error cases for nonexistent/duplicate DIDs | 7 tests + `error_serialization` (see automated coverage) | N/A |

---

# Phase 3: PDS Discovery & OAuth to Arbitrary PDS

**Automated tests:** `cargo test -p identity-wallet pds_client` (33 tests, 1 ignored)

## Phase 5: DNS TXT Handle Resolution (AC3.1)

| Step | Action | Expected |
|------|--------|----------|
| 1 | From the workspace root in the Nix dev shell, run: `cargo test -p identity-wallet test_resolve_handle_dns_txt_integration -- --ignored --nocapture` | Test passes. Output shows a resolved DID starting with `did:plc:` for the handle `jay.bsky.team`. |

## Phase 6: Full OAuth Safari/Deep-Link Flow (AC3.6)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Build the app for the iOS Simulator: `cd apps/identity-wallet && cargo tauri ios dev` | App launches in the Simulator. |
| 2 | Navigate to the claim/auth flow. Enter a valid AT Protocol handle (e.g., your own handle on bsky.social). | The app resolves the handle to a DID (no error displayed). |
| 3 | Observe that the app discovers the PDS endpoint and fetches OAuth authorization server metadata. | The app opens Safari to the PDS authorization page (not an error screen). |
| 4 | Authenticate in Safari using the account credentials for that handle. | Safari redirects back to the app via deep-link (`dev.malpercio.identitywallet:/oauth/callback?code=...&state=...`). |
| 5 | Confirm the app completes the OAuth token exchange and proceeds to the next step (e.g., home screen or PLC operation). | No error displayed. The app has a valid authenticated session against the arbitrary PDS. |

## Human Verification Required (Phase 3)

| Criterion | Why Manual | Steps |
|-----------|------------|-------|
| AC3.1 (DNS TXT resolution) | Requires real DNS infrastructure; `#[ignore]` in CI | Phase 5 step 1 |
| AC3.6 (Full OAuth flow) | Safari redirect + deep-link callback cannot be automated | Phase 6 steps 1-5 |

## Traceability (Phase 3)

| Acceptance Criterion | Automated Test(s) | Manual Step(s) |
|----------------------|-------------------|----------------|
| AC3.1 -- resolve_handle via DNS TXT | `test_resolve_handle_dns_txt_integration` (#[ignore]) | Phase 5 |
| AC3.2 -- HTTP fallback for resolve_handle | `test_try_resolve_http_success`, `test_try_resolve_http_with_whitespace`, `test_try_resolve_http_not_found`, `test_try_resolve_http_server_error` | N/A |
| AC3.3 -- HANDLE_NOT_FOUND when both fail | `test_resolve_handle_orchestration_nonexistent`, `test_pds_client_error_handle_not_found`, `test_pds_client_error_handle_not_found_serialization` | N/A |
| AC3.4 -- discover_pds extracts PDS endpoint | `test_discover_pds_extracts_endpoint`, `test_discover_pds_missing_service` | N/A |
| AC3.5 -- discover_auth_server fetches metadata | `test_discover_auth_server_success`, `test_discover_auth_server_missing_s256`, `test_discover_auth_server_missing_code_response_type` | N/A |
| AC3.6 -- OAuth PKCE+DPoP flow | 8 PAR/token/URL tests (see automated coverage) | Phase 6 (Safari flow) |
| AC3.7 -- DID_NOT_FOUND on 404 | `test_discover_pds_did_not_found`, `test_pds_client_error_did_not_found_serialization` | N/A |
| AC3.8 -- PDS_UNREACHABLE when down | `test_discover_pds_pds_unreachable`, `test_pds_client_error_pds_unreachable_serialization` | N/A |
| XRPC identity methods | 5 tests (request, sign, get_recommended + errors) | N/A |
