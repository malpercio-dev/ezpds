# Claim Flow Frontend — Phase 2: IdentityInputScreen

**Goal:** Create IdentityInputScreen component that accepts a handle or DID, resolves it via `resolveIdentity()`, displays identity info (PDS, rotation keys), and hands off resolved data to the parent page.

**Architecture:** Self-contained screen component that manages its own async resolution state. The parent stores the `IdentityInfo` result and uses it across subsequent import flow screens. Adds import flow state variables (`identityInfo`, `verifiedClaim`, `claimResult`) to `+page.svelte` for cross-screen data sharing.

**Tech Stack:** Svelte 5 (runes), TypeScript, Tauri v2 IPC

**Scope:** 2 of 5 implementation phases

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.3 Success:** IdentityInputScreen accepts handle or DID, calls `resolveIdentity`, and displays resolved identity info (DID, handle, PDS URL, rotation key status)
- **plc-key-management.AC5.4 Failure:** IdentityInputScreen shows user-friendly error when resolution fails (handle not found, DID not found, PDS unreachable, network error)

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Create IdentityInputScreen component

**Verifies:** plc-key-management.AC5.3, plc-key-management.AC5.4

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/IdentityInputScreen.svelte`

**Implementation:**

Create a new screen component that handles identity resolution internally. Unlike the simple input screens (HandleScreen, EmailScreen) that delegate async work to the parent, this screen manages its own async state because it needs to display resolution results before the user can proceed.

**Props interface:**
```typescript
let {
  value = $bindable(''),
  onnext,
  onback,
}: {
  value: string;
  onnext: (info: IdentityInfo) => void;
  onback: () => void;
} = $props();
```

**Internal state:**
```typescript
let resolving = $state(false);
let resolved = $state<IdentityInfo | null>(null);
let error = $state<string | null>(null);
```

**Behavior:**
1. Text input for handle or DID (`bind:value`)
2. "Resolve" button (disabled while `resolving` or when input is empty)
3. On resolve: call `resolveIdentity(value.trim())` from `$lib/ipc`
4. On success: set `resolved` to the returned `IdentityInfo`, clear `error`
5. On error: map `ResolveError.code` to user-friendly messages:
   - `HANDLE_NOT_FOUND` → "Handle not found. Check the spelling and try again."
   - `DID_NOT_FOUND` → "DID not found on PLC directory."
   - `PDS_UNREACHABLE` → "Could not reach the PDS. It may be temporarily offline."
   - `NETWORK_ERROR` → "Network error. Check your connection and try again."
6. When `resolved` is non-null, display identity info card:
   - Handle: `@{resolved.handle}`
   - DID: truncated (reuse the same truncation pattern from HomeScreen)
   - PDS: `resolved.pdsUrl`
   - Rotation key status: "Your device is the root key" (green) if `deviceKeyIsRoot`, or "Device key is not the root key" (neutral) if not
7. "Continue" button appears only when resolved — calls `onnext(resolved)`
8. "Back" button at top or bottom — calls `onback()`
9. If user changes the input after resolving, clear `resolved` and `error`

**Styling:** Follow existing screen patterns — `.screen` container, centered layout, `#007aff` primary buttons, `12px` border-radius, `.error-text` for errors. The identity info card should use the same `.identity-card` pattern from HomeScreen (background: `#f9fafb`, border: `1px solid #d1d5db`, rounded corners).

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add IdentityInputScreen component`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Wire IdentityInputScreen into +page.svelte

**Verifies:** plc-key-management.AC5.3, plc-key-management.AC5.4

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1: Add import flow state variables** (after the existing `homeData` state, around line 65)

```typescript
// ── Import flow state ────────────────────────────────────────────────────
let identityInfo = $state<IdentityInfo | null>(null);
let verifiedClaim = $state<VerifiedClaimOp | null>(null);
let claimResult = $state<ClaimResult | null>(null);
```

Add the necessary type imports from `$lib/ipc`:
```typescript
import { ..., type IdentityInfo, type VerifiedClaimOp, type ClaimResult } from '$lib/ipc';
```

**Step 2: Extend the `form` object** (line 53)

Add `handleOrDid` to the form:
```typescript
let form = $state({ claimCode: '', email: '', handle: '', password: '', did: '', share3: '', registeredHandle: '', handleOrDid: '' });
```

**Step 3: Import IdentityInputScreen** (in the imports section)

```typescript
import IdentityInputScreen from '$lib/components/onboarding/IdentityInputScreen.svelte';
```

**Step 4: Add rendering block** (in the `{#if}` chain, after the mode_select block added in Phase 1)

Insert after the `mode_select` block, before any existing blocks that don't need to change:

```svelte
{:else if step === 'identity_input'}
  <IdentityInputScreen
    bind:value={form.handleOrDid}
    onnext={(info) => {
      identityInfo = info;
      goTo('pds_auth');
    }}
    onback={() => goTo('mode_select')}
  />
```

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): wire IdentityInputScreen into page state machine`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
