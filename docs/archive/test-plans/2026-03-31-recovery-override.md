# Human Test Plan: Recovery Override (plc-key-management.AC7)

## Prerequisites

- macOS workstation with Xcode and iOS Simulator installed
- Nix dev shell active (`nix develop --impure --accept-flake-config` from workspace root)
- `pnpm install` completed in `apps/identity-wallet/`
- `cargo tauri ios init` completed with PATH and sandboxing patches applied (see `apps/identity-wallet/AGENTS.md` First-Time Setup)
- All automated tests passing: `cargo test -p identity-wallet recovery`
- Ignored (integration) tests passing: `cargo test -p identity-wallet -- --ignored` (requires non-sandboxed environment)
- TypeScript compiles: `cd apps/identity-wallet && npx tsc --noEmit`
- SvelteKit builds: `cd apps/identity-wallet && pnpm build`

## Phase 1: Recovery Override Screen -- Layout and Visual Verification

| Step | Action | Expected |
|------|--------|----------|
| 1.1 | Launch the app in iOS Simulator via `cd apps/identity-wallet && cargo tauri ios dev`. If no identity exists, complete the Create flow to establish at least one claimed identity with a device key. | App launches, identity is visible in `IdentityListHome`. |
| 1.2 | Simulate an unauthorized PLC change. This requires either (a) using a test plc.directory that accepts externally-signed operations, or (b) mocking the monitoring response. The simplest approach: modify `plc_monitor.rs` locally to inject a fake `UnauthorizedChange` for the test DID, then trigger `checkIdentityStatus()` by backgrounding and foregrounding the app. | `IdentityListHome` displays an alert badge on the affected identity card. |
| 1.3 | Tap the identity card with the alert badge. This navigates to `identity_detail` (DIDDocumentScreen). Observe whether an alert indicator or navigation path to `AlertDetailScreen` is available. | Navigation reaches `AlertDetailScreen` showing the unauthorized change details. |
| 1.4 | On `AlertDetailScreen`, verify: (a) the signing key of the unauthorized operation is displayed, (b) the recovery deadline countdown is visible and shows a time remaining (formatted as "Xh Ym remaining"), (c) the urgency color matches the remaining time (green/safe if >24h, amber/warning if 4-24h, red/critical if <4h, red/expired if 0). | All three elements render correctly with appropriate styling. |
| 1.5 | Tap the "Review & Override" button on `AlertDetailScreen`. | App navigates to `RecoveryOverrideScreen`. A "Building recovery operation..." loading state appears briefly while `buildRecoveryOverride()` executes. |

## Phase 2: Recovery Override Screen -- Diff Display (AC7.6)

| Step | Action | Expected |
|------|--------|----------|
| 2.1 | After loading completes on `RecoveryOverrideScreen`, verify the Identity section displays the truncated DID. | DID is shown in monospace font, truncated (e.g. `did:plc:abc1...xyz9`). |
| 2.2 | Verify the Recovery Deadline section shows: (a) a countdown badge with colored dot (safe=green, warning=amber, critical/expired=red), (b) the formatted countdown text (e.g. "47h 30m remaining"), (c) the absolute deadline date/time below the countdown. | All three sub-elements render. The countdown badge dot color matches urgency. |
| 2.3 | Verify the Keys section displays rotation keys being restored with `+` prefix indicators on a green-tinted background. If keys are being removed, they show a `-` prefix on a red-tinted background. | Diff entries render with correct `+`/`-` prefixes, color coding (green for added, red for removed), and truncated key values in monospace. |
| 2.4 | Verify the Services section displays service changes with appropriate indicators: `+` for restored services (green), `-` for removed services (red), `~` for modified services (amber). Each entry shows the service ID and endpoint. | Service diff entries render with correct prefixes (`+`, `-`, `~`), color coding, and service ID/endpoint text. |
| 2.5 | Verify two buttons are visible at the bottom: "Confirm & Submit" (blue/primary) and "Cancel" (gray/secondary). Both buttons should be tappable (not disabled). | Both buttons render correctly, are properly styled, and respond to taps. |

## Phase 3: Recovery Override Screen -- Interaction (AC7.6)

| Step | Action | Expected |
|------|--------|----------|
| 3.1 | Tap the "Cancel" button on `RecoveryOverrideScreen`. | Navigation returns to `AlertDetailScreen`. No operation is submitted. |
| 3.2 | Re-enter `RecoveryOverrideScreen` by tapping "Review & Override" again on `AlertDetailScreen`. Wait for loading to complete. | Screen loads successfully a second time, showing the same diff. |
| 3.3 | Tap "Confirm & Submit". | Button text changes to "Submitting..." (loading state). If connected to a real or mock plc.directory that accepts the operation, the app navigates to the home screen on success. If the submission fails (e.g. no real plc.directory), an error message appears in a red error box. |
| 3.4 | Verify the Back button (< Back) in the header is disabled during the loading and submitting states. | Back button shows reduced opacity and does not respond to taps while loading or submitting. |

## Phase 4: Error State Verification

| Step | Action | Expected |
|------|--------|----------|
| 4.1 | Simulate an expired recovery window by injecting an `UnauthorizedChange` with a `createdAt` timestamp older than 72 hours. Navigate to `AlertDetailScreen`. | The "Review & Override" button should be disabled (urgency is "expired"). The deadline badge shows "Expired" in red. |
| 4.2 | If the expired-window check is bypassed (e.g. by modifying the `createdAt` locally), navigate to `RecoveryOverrideScreen`. | An error message appears: "Recovery window has expired. No longer possible to recover this identity." The "Confirm & Submit" button is NOT shown (only "Cancel" is visible since `signedOp` is null when an error occurs during build). |
| 4.3 | Simulate a network error by disconnecting from the network, then navigate to `RecoveryOverrideScreen`. | An error message appears in the red error box (e.g. "Network error: ..."). Only the "Cancel" button is visible. |

## End-to-End: Full Recovery Override Flow

1. Start with a claimed identity that has a device key registered in the Keychain.
2. Trigger an unauthorized PLC operation (either via a test plc.directory or by injecting a mock unauthorized change).
3. Background and foreground the app to trigger `checkIdentityStatus()` via the `visibilitychange` listener.
4. Verify the alert badge appears on the identity card in `IdentityListHome`.
5. Navigate through: identity card -> alert detail -> "Review & Override" -> `RecoveryOverrideScreen`.
6. Verify the diff shows the correct keys and services being restored (matching the pre-unauthorized state).
7. Tap "Confirm & Submit".
8. Verify the operation is submitted to plc.directory (check mock server logs or real plc.directory audit log).
9. Verify the app navigates to the home screen on success.
10. Verify the cached PLC audit log and DID document in Keychain reflect the recovered state (can be checked by re-navigating to the identity's DID document screen).

## Human Verification Required

| Criterion | Why Manual | Steps |
|-----------|-----------|-------|
| AC7.6: Recovery override screen shows the counter-operation diff with confirm/cancel | Visual verification of UI layout, diff rendering with `+`/`-`/`~` indicators, countdown timer animation, button positioning and styling, and interactive behavior on iOS cannot be meaningfully automated. | See Phase 2 (steps 2.1-2.5) and Phase 3 (steps 3.1-3.4) above. |
| Countdown timer updates | The 60-second `setInterval` timer in `RecoveryOverrideScreen` updates the countdown display. Verifying the visual update requires waiting and observing. | On `RecoveryOverrideScreen`, wait at least 60 seconds and observe the countdown text updates (minute value decrements). |
| iOS-specific rendering | Layout correctness on actual iOS viewport sizes, safe area handling, scroll behavior, and touch responsiveness. | Run all Phase 2 and 3 steps on an iPhone 15 simulator (or similar). Verify no content is clipped, all sections scroll correctly, and touch targets are adequately sized. |

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC7.1: `prev` points to fork point CID | `test_ac7_1_build_op_diff_includes_fork_cid`, `test_ac7_3_*` | -- |
| AC7.2: Restores pre-unauthorized keys, services, verificationMethods | `test_ac7_2_build_op_diff_restores_keys_and_services`, `test_ac7_3_*` | -- |
| AC7.3: Signed by device key | `test_ac7_3_build_recovery_override_signs_with_device_key` | -- |
| AC7.4: POSTs to plc.directory, updates cache | `test_ac7_4_submit_recovery_override` | -- |
| AC7.5: RECOVERY_WINDOW_EXPIRED for >72h | `test_ac7_5_recovery_window_rejects_expired` + 5 boundary tests | Phase 4, steps 4.1-4.2 |
| AC7.6: UI diff display with confirm/cancel | -- (human verification only) | Phase 2 steps 2.1-2.5, Phase 3 steps 3.1-3.4 |
| AC7.7: Multiple unauthorized ops target earliest fork point | `test_ac7_7_*` + `test_find_fork_point_multiple_*` | -- |
