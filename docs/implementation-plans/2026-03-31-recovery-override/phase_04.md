# Recovery Override Implementation Plan

**Goal:** Build the recovery override mechanism that allows the identity wallet to detect unauthorized PLC changes and submit counter-operations signed by the device key's root authority to restore the user's identity state.

**Architecture:** The recovery module (`recovery.rs`) sits in the identity-wallet Rust backend alongside the existing `plc_monitor.rs` and `claim.rs`. It reuses the crypto crate's `build_did_plc_rotation_op` for counter-operation construction, `parse_audit_log`/`verify_plc_operation` for fork point identification, and `IdentityStore` for per-DID key access and cached log persistence. The frontend adds a `RecoveryOverrideScreen` component wired into the existing state machine from `AlertDetailScreen`.

**Tech Stack:** Rust (Tauri v2 backend), SvelteKit 2 + Svelte 5 (frontend), crypto crate (PLC operations), iOS Keychain (key storage)

**Scope:** 4 phases from design Phase 7 (recovery override)

**Codebase verified:** 2026-03-31

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC7: Recovery override
- **plc-key-management.AC7.6 Success:** Recovery override screen shows the counter-operation diff with confirm/cancel

---

## Phase 4: RecoveryOverrideScreen and navigation wiring

This phase creates the recovery override UI screen and wires it into the state machine from AlertDetailScreen.

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Create RecoveryOverrideScreen component

**Verifies:** plc-key-management.AC7.6

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/RecoveryOverrideScreen.svelte`

**Implementation:**

Create the recovery override screen following the patterns from `ReviewOperationScreen.svelte` (diff display) and `AlertDetailScreen.svelte` (urgency/deadline display). The screen shows:
1. The counter-operation diff (keys being restored, services being restored)
2. Recovery deadline countdown
3. Confirm and Cancel buttons
4. Loading state during submission
5. Error display on failure

Props:
- `did: string` — the DID being recovered
- `operationCid: string` — CID of the unauthorized operation
- `createdAt: string` — ISO 8601 timestamp of the unauthorized operation (for deadline countdown)
- `onback: () => void` — navigate back to alert detail
- `onsuccess: () => void` — navigate to home after successful recovery

Behavior:
- On mount, calls `buildRecoveryOverride(did, operationCid)` to get the `SignedRecoveryOp`
- Shows a loading spinner while building
- Displays the diff using the same `+`/`−`/`~` diff pattern from `ReviewOperationScreen`
- Shows the recovery deadline countdown using `getDeadline`/`formatCountdown` from `deadline.ts`
- "Confirm & Submit" button calls `submitRecoveryOverride(did)` and navigates on success
- "Cancel" button calls `onback()`
- Error handling follows `isCodedError` pattern from `ReviewOperationScreen`
- If `RECOVERY_WINDOW_EXPIRED`, show a clear message that recovery is no longer possible

The component should import `buildRecoveryOverride`, `submitRecoveryOverride`, and `type SignedRecoveryOp` from `$lib/ipc`, plus `getDeadline`, `formatCountdown`, `getUrgency` from `$lib/utils/deadline`, and `isCodedError`, `truncateDid` from `$lib/did-doc-utils`.

Use the existing CSS patterns from `AlertDetailScreen.svelte` and `ReviewOperationScreen.svelte` (`.screen`, `.header`, `.section`, `.diff-entry`, `.cta`, etc.).

**Verification:**
Run: `cd apps/identity-wallet && npx tsc --noEmit`
Expected: No type errors from this component

**Commit:** `feat(identity-wallet): add RecoveryOverrideScreen component`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire RecoveryOverrideScreen into state machine

**Verifies:** plc-key-management.AC7.6 (navigation from alert detail to recovery screen)

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`
- Modify: `apps/identity-wallet/src/lib/components/home/AlertDetailScreen.svelte`

**Implementation:**

**In `+page.svelte`:**

1. Add `'recovery_override'` to the `OnboardingStep` union type (after `'alert_detail'`).

2. Add state variables for recovery context:
```typescript
let selectedRecoveryCid = $state<string | null>(null);
let selectedRecoveryCreatedAt = $state<string | null>(null);
```

3. Add the `RecoveryOverrideScreen` import:
```typescript
import RecoveryOverrideScreen from '$lib/components/home/RecoveryOverrideScreen.svelte';
```

4. Add the route block after the `alert_detail` block (around line 366):
```svelte
{:else if step === 'recovery_override'}
  <RecoveryOverrideScreen
    did={selectedAlertDid ?? ''}
    operationCid={selectedRecoveryCid ?? ''}
    createdAt={selectedRecoveryCreatedAt ?? ''}
    onback={() => goTo('alert_detail')}
    onsuccess={() => goTo('home')}
  />
```

**In `AlertDetailScreen.svelte`:**

1. Add an `onoverride` callback prop:
```typescript
let {
  did,
  changes,
  onback,
  onoverride,
}: {
  did: string;
  changes: UnauthorizedChange[];
  onback: () => void;
  onoverride: (cid: string, createdAt: string) => void;
} = $props();
```

2. Enable the "Review & Override" button and wire it to the callback. Replace the disabled button (line 72-74):
```svelte
{@const isExpired = urgency === 'expired'}
<button
  class="action-button"
  disabled={isExpired}
  onclick={() => onoverride(change.cid, change.createdAt)}
>
  {isExpired ? 'Recovery Window Expired' : 'Review & Override'}
</button>
```

3. Update the `.action-button` CSS to handle enabled state:
```css
.action-button {
  /* ... existing styles ... */
  cursor: pointer;
  opacity: 1;
}

.action-button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}
```

4. Update `+page.svelte` to pass the `onoverride` callback in the `alert_detail` route block:
```svelte
{:else if step === 'alert_detail'}
  <AlertDetailScreen
    did={selectedAlertDid ?? ''}
    changes={selectedAlertChanges}
    onback={() => goTo('home')}
    onoverride={(cid, createdAt) => {
      selectedRecoveryCid = cid;
      selectedRecoveryCreatedAt = createdAt;
      goTo('recovery_override');
    }}
  />
```

**Verification:**
Run: `cd apps/identity-wallet && npx tsc --noEmit`
Expected: No type errors

Run: `cd apps/identity-wallet && pnpm build`
Expected: Build succeeds

**Commit:** `feat(identity-wallet): wire RecoveryOverrideScreen into navigation state machine`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Run cargo clippy and cargo fmt

**Verifies:** None (code quality gate)

**Files:**
- Possibly modify: any files touched in Phases 1-3

**Implementation:**

Run the project's lint and formatting checks:
```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all --check
```

Fix any issues found. Common issues to watch for:
- Unused imports in `recovery.rs`
- Missing `#[allow(unused)]` for the SE path on non-iOS builds
- Formatting inconsistencies

**Verification:**
Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

Run: `cargo fmt --all --check`
Expected: No formatting issues

Run: `cargo test --workspace`
Expected: All tests pass

**Commit:** `fix(identity-wallet): address clippy and fmt issues in recovery module`

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Update identity-wallet CLAUDE.md

**Verifies:** None (documentation)

**Files:**
- Modify: `apps/identity-wallet/CLAUDE.md`

**Implementation:**

Add the recovery module documentation to the identity-wallet CLAUDE.md. Specifically:

1. Under **Contracts → Rust Backend → Exposes**, add:
```
- `src/recovery.rs` — Recovery override module: `build_recovery_override(pds_client, did, unauthorized_op_cid) -> Result<SignedRecoveryOp, RecoveryError>` (fetches audit log, identifies fork point, builds counter-operation restoring pre-unauthorized state, signs with per-DID device key), `submit_recovery_override(pds_client, did, signed_op) -> Result<ClaimResult, RecoveryError>` (POSTs to plc.directory, updates cached log and DID doc); Tauri IPC commands: `build_recovery_override_cmd`, `submit_recovery_override_cmd`. Types: `SignedRecoveryOp` { diff, signed_op }, `RecoveryState` { did, signed_op }, `RecoveryError` (RECOVERY_WINDOW_EXPIRED, SIGNING_FAILED, PLC_DIRECTORY_ERROR, NETWORK_ERROR, IDENTITY_NOT_FOUND, UNAUTHORIZED_CHANGE_NOT_FOUND)
```

2. Under **Contracts → Frontend → Exposes**, update `src/lib/ipc.ts` exports list to include:
```
buildRecoveryOverride(), submitRecoveryOverride(), SignedRecoveryOp, RecoveryError
```

3. Under **Contracts → Frontend → Exposes**, add RecoveryOverrideScreen to the home components list.

4. Under **Key Files**, add:
```
- `src-tauri/src/recovery.rs` — Recovery override: build_recovery_override_cmd, submit_recovery_override_cmd; fork-point identification, per-DID signing, recovery window check
```

5. Add relevant invariants:
```
- `RecoveryError` variant names serialize as SCREAMING_SNAKE_CASE to the frontend -- the TypeScript `RecoveryError` union in `ipc.ts` must match exactly
- `SignedRecoveryOp` serializes with `#[serde(rename_all = "camelCase")]` -- TypeScript receives `{ diff, signedOp }`
- Recovery window is 72 hours from the unauthorized operation's `created_at` timestamp; computed locally but enforced by plc.directory
- `RecoveryState` in `AppState` uses `tokio::sync::Mutex` (same as `ClaimState`) because recovery commands hold the lock across `.await` points
```

**Verification:**
Manually review the CLAUDE.md changes for accuracy.

**Commit:** `docs(identity-wallet): document recovery override module in CLAUDE.md`

<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_A -->
