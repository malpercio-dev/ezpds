# MM-150 Implementation Plan — Phase 4: State machine wiring

**Goal:** Connect all three home screens into the `+page.svelte` flat state machine.

**Architecture:** Extend the existing `OnboardingStep` discriminated union with `home`, `did_document`, and `recovery_info`. Rename the `authenticated` stub to `home`. Add page-level `homeData` state so sub-screens receive already-loaded data without re-fetching. Wire `HomeScreen`, `DIDDocumentScreen`, and `RecoveryInfoScreen` with props and back-navigation callbacks.

**Tech Stack:** Svelte 5, TypeScript

**Scope:** Phase 4 of 6

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### MM-150.AC3: Three action flows work
- **MM-150.AC3.4 Success:** Tapping View DID Document navigates to `did_document` step
- **MM-150.AC3.9 Success:** Back from DID document returns to home
- **MM-150.AC3.10 Success:** Tapping Recovery Info navigates to `recovery_info` step
- **MM-150.AC3.14 Success:** Back from recovery info returns to home

### MM-150.AC5: App launches to home when already onboarded
- **MM-150.AC5.1 Success:** App starts at the `home` step when OAuth tokens exist in Keychain on launch
- **MM-150.AC5.2 Success:** `homeData` is loaded on mount of `HomeScreen` regardless of entry path

---

<!-- START_SUBCOMPONENT_A (tasks 0-1) -->
<!-- START_TASK_0 -->
### Task 0: Create stub components for `DIDDocumentScreen` and `RecoveryInfoScreen`

**Verifies:** (prerequisite — allows Phase 4 imports to resolve before Phases 5 and 6 are executed)

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/DIDDocumentScreen.svelte` (stub)
- Create: `apps/identity-wallet/src/lib/components/home/RecoveryInfoScreen.svelte` (stub)

**Why:** Phase 4 adds imports for `DIDDocumentScreen` and `RecoveryInfoScreen` to `+page.svelte`. These imports will cause TypeScript errors until the component files exist. Phases 5 and 6 will replace these stubs with full implementations.

Create `apps/identity-wallet/src/lib/components/home/DIDDocumentScreen.svelte`:

```svelte
<script lang="ts">
  let {
    didDoc,
    onback,
  }: {
    didDoc: Record<string, unknown>;
    onback: () => void;
  } = $props();
</script>
<div>DIDDocumentScreen stub — replaced by Phase 5</div>
```

Create `apps/identity-wallet/src/lib/components/home/RecoveryInfoScreen.svelte`:

```svelte
<script lang="ts">
  let {
    share1InKeychain,
    onback,
  }: {
    share1InKeychain: boolean;
    onback: () => void;
  } = $props();
</script>
<div>RecoveryInfoScreen stub — replaced by Phase 6</div>
```

**Note:** Phase 5 overwrites `DIDDocumentScreen.svelte` with the full implementation. Phase 6 overwrites `RecoveryInfoScreen.svelte`. These stubs exist only to allow `pnpm check` to pass during Phase 4.

**Verification:**
Run from `apps/identity-wallet/`: `pnpm check`
Expected: No TypeScript errors from the stub components themselves

**Commit:** (defer — commit alongside the `+page.svelte` changes in Task 1)
<!-- END_TASK_0 -->

<!-- START_TASK_1 -->
### Task 1: Extend OnboardingStep union and wire home screens in `+page.svelte`

**Verifies:** MM-150.AC3.4, MM-150.AC3.9, MM-150.AC3.10, MM-150.AC3.14, MM-150.AC5.1, MM-150.AC5.2

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Current state of `+page.svelte` (verified 2026-03-27):**

- `OnboardingStep` union defined at lines 26–39; currently ends with `'authenticated'` and `'auth_failed'`
- The `auth_ready` event listener at line 66 calls `goTo('authenticated')`
- The `authenticated` stub at lines 207–212 is a simple `<div>` placeholder
- There is no `home`, `did_document`, or `recovery_info` step

**Changes required (in order):**

**1. Add new imports at the top of the `<script>` block**

After the existing Svelte/IPC imports (after line 14), add:

```typescript
  import HomeScreen from '$lib/components/home/HomeScreen.svelte';
  import DIDDocumentScreen from '$lib/components/home/DIDDocumentScreen.svelte';
  import RecoveryInfoScreen from '$lib/components/home/RecoveryInfoScreen.svelte';
  import { type HomeData } from '$lib/ipc';
```

**2. Replace `OnboardingStep` union definition**

Replace the current union (lines 26–39):

```typescript
  type OnboardingStep =
    | 'welcome'
    | 'claim_code'
    | 'email'
    | 'handle'
    | 'password'
    | 'loading'
    | 'did_ceremony'
    | 'did_success'
    | 'shamir_backup'
    | 'complete'
    | 'authenticating'
    | 'authenticated'
    | 'auth_failed';
```

With:

```typescript
  type OnboardingStep =
    | 'welcome'
    | 'claim_code'
    | 'email'
    | 'handle'
    | 'password'
    | 'loading'
    | 'did_ceremony'
    | 'did_success'
    | 'shamir_backup'
    | 'complete'
    | 'authenticating'
    | 'home'
    | 'did_document'
    | 'recovery_info'
    | 'auth_failed';
```

**3. Add `homeData` state variable**

After the `let authError` state declaration (after line 54), add:

```typescript
  let homeData = $state<HomeData | null>(null);
```

**4. Update auth_ready listener**

In `onMount` (line 66), change `goTo('authenticated')` to `goTo('home')`:

```typescript
    listen('auth_ready', () => {
      goTo('home');
    });
```

**5. Replace the `authenticated` stub block with the three home screens**

Replace the current `{:else if step === 'authenticated'}` block (lines 207–212):

```svelte
  {:else if step === 'authenticated'}
    <div class="oauth-screen">
      <div class="oauth-icon" aria-hidden="true">✓</div>
      <h2 class="oauth-title">Authenticated</h2>
      <p class="oauth-body">Your identity wallet is ready.</p>
    </div>
```

With three new blocks (place them in the same position in the `{#if}` chain):

```svelte
  {:else if step === 'home'}
    <HomeScreen
      onnavdiddoc={() => goTo('did_document')}
      onnavrecovery={() => goTo('recovery_info')}
      onlogout={() => goTo('welcome')}
    />

  {:else if step === 'did_document'}
    <DIDDocumentScreen
      didDoc={homeData?.session?.didDoc ?? {}}
      onback={() => goTo('home')}
    />

  {:else if step === 'recovery_info'}
    <RecoveryInfoScreen
      share1InKeychain={homeData?.share1InKeychain ?? false}
      onback={() => goTo('home')}
    />
```

**6. Update the `AuthenticatingScreen` `onresolved` callback**

The `AuthenticatingScreen` component (within `{:else if step === 'authenticating'}`) uses `onresolved={() => goTo('authenticated')}`. Since `'authenticated'` has been removed from `OnboardingStep`, this must also be updated.

Find:
```svelte
{:else if step === 'authenticating'}
  <AuthenticatingScreen onresolved={() => goTo('authenticated')} />
```

Change to:
```svelte
{:else if step === 'authenticating'}
  <AuthenticatingScreen onresolved={() => goTo('home')} />
```

---

**Note on `homeData` prop passing:** `HomeScreen` loads its own data via `loadHomeData()` on mount and stores it internally. However, `DIDDocumentScreen` and `RecoveryInfoScreen` receive data as props from the parent. The HomeScreen must emit the loaded data back to the parent so these sub-screens can receive it.

To achieve this, update the `onnavdiddoc` and `onnavrecovery` callbacks in `HomeScreen` to accept the loaded `HomeData` and store it in page-level state. Modify the HomeScreen `$props()` to pass `homeData` up:

The HomeScreen should emit `homeData` to the parent when navigating to sub-screens. Update the `HomeScreen.svelte` props definition (see Phase 3) to pass `homeData` back via the nav callbacks:

Update `HomeScreen.svelte`'s props to:

```typescript
  let {
    onnavdiddoc,
    onnavrecovery,
    onlogout,
  }: {
    onnavdiddoc: (data: HomeData) => void;
    onnavrecovery: (data: HomeData) => void;
    onlogout: () => void;
  } = $props();
```

And update the nav button handlers in `HomeScreen.svelte`:

```svelte
  <button class="action-btn" onclick={() => onnavdiddoc(homeData!)}>
    View DID Document
  </button>
  ...
  <button class="action-btn" onclick={() => onnavrecovery(homeData!)}>
    Recovery Info
  </button>
```

Then in `+page.svelte`, update the three home screen blocks:

```svelte
  {:else if step === 'home'}
    <HomeScreen
      onnavdiddoc={(data) => { homeData = data; goTo('did_document'); }}
      onnavrecovery={(data) => { homeData = data; goTo('recovery_info'); }}
      onlogout={() => goTo('welcome')}
    />

  {:else if step === 'did_document'}
    <DIDDocumentScreen
      didDoc={homeData?.session?.didDoc ?? {}}
      onback={() => goTo('home')}
    />

  {:else if step === 'recovery_info'}
    <RecoveryInfoScreen
      share1InKeychain={homeData?.share1InKeychain ?? false}
      onback={() => goTo('home')}
    />
```

**Summary of all edits to `+page.svelte`:**
1. Add 4 import lines after existing imports
2. Extend `OnboardingStep` union (add `'home'`, `'did_document'`, `'recovery_info'`; remove `'authenticated'`)
3. Add `let homeData = $state<HomeData | null>(null);` after `authError` state
4. Change `goTo('authenticated')` → `goTo('home')` in auth_ready listener
5. Replace `{:else if step === 'authenticated'} ... {:else if step === 'auth_failed'}` block with three new step blocks (`home`, `did_document`, `recovery_info`) followed by the existing `auth_failed` block
6. Change `AuthenticatingScreen onresolved={() => goTo('authenticated')}` → `onresolved={() => goTo('home')}`

**Also update `HomeScreen.svelte` (from Phase 3):**
- Change `onnavdiddoc: () => void` → `onnavdiddoc: (data: HomeData) => void`
- Change `onnavrecovery: () => void` → `onnavrecovery: (data: HomeData) => void`
- Add `import { loadHomeData, logOut, type HomeData } from '$lib/ipc';` (it likely already imports these — confirm)
- Update button onclick handlers to pass `homeData!`

**Verification:**
Run from `apps/identity-wallet/`: `pnpm check`
Expected: No TypeScript errors

Run: `cargo tauri ios dev` (requires Xcode + iOS Simulator)
Expected:
- App starts at welcome screen (no tokens)
- After full onboarding + OAuth flow, app navigates to home screen showing identity card
- `auth_ready` event (simulated by relaunching with tokens in Keychain) navigates to home screen
- "View DID Document" button only appears when `homeData.session.didDoc` is non-null
- Back buttons return to home

**Commit:**
```bash
git add apps/identity-wallet/src/routes/+page.svelte \
        apps/identity-wallet/src/lib/components/home/HomeScreen.svelte
git commit -m "feat: wire home, did_document, and recovery_info steps into OnboardingStep state machine"
```
<!-- END_TASK_1 -->
<!-- END_SUBCOMPONENT_A -->
