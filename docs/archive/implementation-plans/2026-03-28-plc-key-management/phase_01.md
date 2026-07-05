# Claim Flow Frontend — Phase 1: Foundation

**Goal:** Add `list_identities` Tauri command, create ModeSelectScreen component, wire mode selector as new entry point with identity-aware onMount logic.

**Architecture:** Extends the existing screen state machine in `+page.svelte` with a `mode_select` step that replaces `relay_config` as the first-launch entry point. Adds a thin Tauri command wrapper for `IdentityStore::list_identities()` so the frontend can check for existing identities on mount.

**Tech Stack:** Svelte 5 (runes), TypeScript, Tauri v2 IPC, Rust

**Scope:** 1 of 5 implementation phases (Phase 5 of the plc-key-management design)

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.1 Success:** Mode selector on first launch shows "Create new identity" and "I have an identity" options
- **plc-key-management.AC5.2 Success:** App skips mode selector and goes to home when `listIdentities()` returns non-empty

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add `list_identities` Tauri command and IPC wrapper

**Verifies:** plc-key-management.AC5.2 (provides the command the frontend needs to check for existing identities)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs:670-762` (add command + register in invoke_handler)
- Modify: `apps/identity-wallet/src/lib/ipc.ts:420-471` (add wrapper + error type)

**Implementation:**

**Rust side** — add a `#[tauri::command]` in `lib.rs` that wraps `IdentityStore::list_identities()`. The `IdentityStore` is a unit struct (no Tauri `State<>` needed). Place the command immediately before the `check_handle_resolution` command (around line 663). Add `IdentityStoreError` to the imports and register `list_identities` in `tauri::generate_handler![]`.

The command signature:
```rust
#[tauri::command]
fn list_identities() -> Result<Vec<String>, identity_store::IdentityStoreError> {
    identity_store::IdentityStore.list_identities()
}
```

`IdentityStoreError` already derives `Serialize` with `#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]`, so it works as a Tauri IPC error type out of the box.

**TypeScript side** — add to `ipc.ts` after the claim flow section (after line 470):

```typescript
// ── Identity Store ──────────────────────────────────────────────────────

export type IdentityStoreError =
  | { code: 'IDENTITY_NOT_FOUND' }
  | { code: 'IDENTITY_ALREADY_EXISTS' }
  | { code: 'KEYCHAIN_ERROR' }
  | { code: 'KEY_GENERATION_FAILED' }
  | { code: 'SERIALIZATION_ERROR' };

export const listIdentities = (): Promise<string[]> =>
  invoke('list_identities');
```

**Testing:**

The Rust `IdentityStore::list_identities()` is already tested in `identity_store.rs` (lines 517-547). The Tauri command is a thin passthrough — no additional test needed.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): add list_identities Tauri command and IPC wrapper`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create ModeSelectScreen component

**Verifies:** plc-key-management.AC5.1

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/ModeSelectScreen.svelte`

**Implementation:**

Create a new screen component following the existing pattern (see `WelcomeScreen.svelte` for reference). The component receives two callbacks via `$props()`:

```svelte
<script lang="ts">
  let { oncreate, onimport }: { oncreate: () => void; onimport: () => void } = $props();
</script>

<div class="screen">
  <div class="brand">
    <h1>Identity Wallet</h1>
    <p class="tagline">Your self-sovereign identity, in your pocket.</p>
  </div>
  <div class="actions">
    <button class="cta" onclick={oncreate}>Create new identity</button>
    <button class="cta cta--secondary" onclick={onimport}>I have an identity</button>
  </div>
</div>
```

Style the component consistently with WelcomeScreen: centered layout, `.cta` button style for primary action, `.cta--secondary` for the import option. Use the same spacing, colors, and border-radius as existing screens (`#007aff` primary, `#f3f4f6` secondary background, `12px` border-radius, `1.1rem` font-size).

**Testing:**

No automated frontend tests — this is a Svelte component in a WKWebView app. Verification is operational + manual.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add ModeSelectScreen component`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Wire mode selector into +page.svelte state machine

**Verifies:** plc-key-management.AC5.1, plc-key-management.AC5.2

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte:1-282`

**Implementation:**

**Step 1: Add imports** (top of `<script>` section)
- Import `ModeSelectScreen` from `$lib/components/onboarding/ModeSelectScreen.svelte`
- Import `listIdentities` from `$lib/ipc`

**Step 2: Expand `OnboardingStep` type** (lines 31-48)

Add new steps for the import flow. The full type becomes:
```typescript
type OnboardingStep =
  | 'mode_select'
  | 'relay_config'
  | 'welcome'
  | 'claim_code'
  | 'email'
  | 'handle'
  | 'password'
  | 'loading'
  | 'did_ceremony'
  | 'did_success'
  | 'shamir_backup'
  | 'handle_registration'
  | 'complete'
  | 'authenticating'
  | 'home'
  | 'did_document'
  | 'recovery_info'
  | 'auth_failed'
  | 'identity_input'
  | 'pds_auth'
  | 'email_verification'
  | 'review_operation'
  | 'claim_success';
```

**Step 3: Change initial step** (line 52)

Change from `'relay_config'` to `'mode_select'`:
```typescript
let step = $state<OnboardingStep>('mode_select');
```

**Step 4: Update `onMount`** (lines 76-92)

Replace the current onMount logic. The new flow:
1. Check `listIdentities()` — if non-empty, skip directly to `home`
2. Otherwise stay at `mode_select` (the default initial step)
3. Keep the `auth_ready` listener for the existing onboarding OAuth flow

```typescript
onMount(async () => {
  // If the user has claimed identities, skip to home.
  try {
    const identities = await listIdentities();
    if (identities.length > 0) {
      step = 'home';
      return;
    }
  } catch {
    // listIdentities failed (e.g. empty Keychain on first launch) — continue to mode_select
  }

  // Legacy user fallback: if a relay URL is already configured (from the old
  // single-identity flow before multi-identity), the user has used the app before
  // but has no managed-dids entry. Skip relay_config but still show mode_select
  // so they can choose create vs. import. Without this, legacy users would see
  // mode_select and then relay_config (asking them to configure a relay they
  // already configured).
  // Note: mode_select is already the default step, so this is a no-op for
  // mode_select itself, but it prevents the "Create new identity" path from
  // redundantly showing relay_config when the relay is already configured.
  // The relay_config screen itself already checks getRelayUrl() internally.

  // Listen for auth_ready from relay OAuth (existing onboarding flow).
  listen('auth_ready', () => {
    goTo('home');
  });
});
```

**Note:** PDS auth completion is handled by PdsAuthScreen via promise resolution callback (Phase 3), NOT via a separate event listener. This matches the AuthenticatingScreen pattern.

**Note on legacy users:** Users who configured a relay URL via the old single-identity flow (before multi-identity) will have `listIdentities()` return empty (no `managed-dids` Keychain entry) but will have a saved relay URL. These users see `mode_select` as their entry point, which is correct — they need to either create a new identity (goes to relay_config, which will detect the saved URL and skip the input) or import an existing one. The existing `RelayConfigScreen` already checks for a saved URL and pre-fills it, so the "Create new identity" path works correctly for legacy users without any additional migration. Full identity migration (moving flat Keychain data to per-DID format) is out of scope for Phase 5 and would be addressed in a future phase if needed.

**Step 5: Add mode_select rendering** (in the `{#if}` chain, at the top before `relay_config`)

Insert as the first condition in the `{#if}` chain:
```svelte
{#if step === 'mode_select'}
  <ModeSelectScreen
    oncreate={() => goTo('relay_config')}
    onimport={() => goTo('identity_input')}
  />
{:else if step === 'relay_config'}
```

The "Create new identity" path goes to `relay_config` → existing onboarding flow (unchanged).
The "I have an identity" path goes to `identity_input` (will be wired to IdentityInputScreen in Phase 2).

**Note:** The `identity_input` step has no rendering block yet — it will be added in Phase 2. If somehow navigated to before Phase 2, the app shows a blank screen (no crash). This is acceptable for incremental development.

**Testing:**

No automated frontend tests for UI components. AC5.1 and AC5.2 require human verification on the iOS Simulator.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors (svelte-check validates all Svelte files and TypeScript)

**Commit:** `feat(identity-wallet): wire mode selector as entry point with identity-aware onMount`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Verify existing onboarding flow unchanged

**Verifies:** plc-key-management.AC5.13 (partial — verifies the wiring doesn't break existing flow)

**Files:**
- No file changes — verification only

**Implementation:**

This is a verification-only task. After the mode selector changes:

1. The "Create new identity" path from mode_select → relay_config → welcome → claim_code → email → handle → password → loading → did_ceremony → did_success → shamir_backup → handle_registration → complete → authenticating → home should remain intact.

2. All existing screen components receive the same props as before.

3. The `submitAccount` function and `handleError` function are unchanged.

4. The `auth_ready` listener still routes to `home` for the existing OAuth flow.

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

Run: `cargo test -p identity-wallet`
Expected: All existing Rust tests pass

**Commit:** No commit — verification only
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
