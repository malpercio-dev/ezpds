# MM-150 Implementation Plan — Phase 6: RecoveryInfoScreen component

**Goal:** Read-only display of Shamir recovery share status.

**Architecture:** Svelte 5 component. Accepts `share1InKeychain: boolean` (live Keychain result from `HomeData`) and `onback` callback. Shows three share rows: Share 1 reflects the live Keychain check, Share 2 is a static relay custody fact from onboarding, Share 3 is a reminder that the user holds it.

**Tech Stack:** Svelte 5, TypeScript

**Scope:** Phase 6 of 6

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### MM-150.AC3: Three action flows work
- **MM-150.AC3.11 Success:** Share 1 shows ✓ when `recovery-share-1` exists in Keychain
- **MM-150.AC3.12 Failure:** Share 1 shows ✗ when `recovery-share-1` is absent from Keychain
- **MM-150.AC3.13 Success:** Share 2 always shows ✓ (static relay custody fact from onboarding)
- **MM-150.AC3.14 Success:** Back from recovery info returns to home

---

<!-- START_SUBCOMPONENT_A (tasks 1-1) -->
<!-- START_TASK_1 -->
### Task 1: Create `RecoveryInfoScreen.svelte`

**Verifies:** MM-150.AC3.11, MM-150.AC3.12, MM-150.AC3.13, MM-150.AC3.14

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/RecoveryInfoScreen.svelte`

**Keychain account name for Share 1:** `"recovery-share-1"` (defined at `apps/identity-wallet/src-tauri/src/lib.rs:388` and documented in AGENTS.md invariants). The Rust `load_home_data` command already checks this key and returns `share1InKeychain: boolean` in HomeData. This component simply displays the result — no IPC calls.

**Share 3 status:** Share 3 is always shown as a manual backup reminder. It is the share returned to the user via `DIDCeremonyResult.share3` during onboarding and displayed in `ShamirBackupScreen`. This screen reminds the user that they are responsible for it.

**Implementation:**

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

<div class="screen">
  <div class="header">
    <button class="back-btn" onclick={onback} aria-label="Back">‹ Back</button>
    <h2 class="title">Recovery Info</h2>
  </div>

  <p class="description">
    Your identity can be recovered with any 2 of 3 recovery shares.
  </p>

  <!-- Share 1 -->
  <div class="share-row" class:share-row--ok={share1InKeychain} class:share-row--err={!share1InKeychain}>
    <div class="share-icon" class:share-icon--ok={share1InKeychain} class:share-icon--err={!share1InKeychain} aria-hidden="true">
      {share1InKeychain ? '✓' : '✗'}
    </div>
    <div class="share-info">
      <p class="share-label">Share 1 of 3</p>
      <p class="share-desc">
        {share1InKeychain
          ? 'Saved to iCloud Keychain — backed up automatically'
          : 'Not found in Keychain — this device may have lost it'}
      </p>
    </div>
  </div>

  <!-- Share 2 -->
  <div class="share-row share-row--ok">
    <div class="share-icon share-icon--ok" aria-hidden="true">✓</div>
    <div class="share-info">
      <p class="share-label">Share 2 of 3</p>
      <p class="share-desc">Held by the relay — stored during account setup</p>
    </div>
  </div>

  <!-- Share 3 -->
  <div class="share-row share-row--neutral">
    <div class="share-icon share-icon--neutral" aria-hidden="true">📋</div>
    <div class="share-info">
      <p class="share-label">Share 3 of 3</p>
      <p class="share-desc">Your manual backup — shown during setup. Keep it safe.</p>
    </div>
  </div>

  <div class="note">
    <p>Any 2 shares together can restore your identity. Keep Share 3 somewhere safe and offline.</p>
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 1.5rem;
    gap: 1.25rem;
    overflow-y: auto;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .back-btn {
    background: none;
    border: none;
    font-size: 1rem;
    color: #007aff;
    cursor: pointer;
    padding: 0;
    font-weight: 500;
    white-space: nowrap;
  }

  .title {
    font-size: 1.2rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .description {
    font-size: 0.9rem;
    color: #6b7280;
    margin: 0;
    line-height: 1.5;
  }

  .share-row {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    padding: 1rem 1.25rem;
    border-radius: 12px;
    border: 1px solid transparent;
  }

  .share-row--ok {
    background: #f0fdf4;
    border-color: #bbf7d0;
  }

  .share-row--err {
    background: #fef2f2;
    border-color: #fecaca;
  }

  .share-row--neutral {
    background: #f9fafb;
    border-color: #d1d5db;
  }

  .share-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    font-weight: 700;
    flex-shrink: 0;
  }

  .share-icon--ok {
    background: #22c55e;
    color: #fff;
  }

  .share-icon--err {
    background: #ef4444;
    color: #fff;
  }

  .share-icon--neutral {
    background: #e5e7eb;
    color: #374151;
    font-size: 1.1rem;
  }

  .share-info {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .share-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .share-desc {
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0;
    line-height: 1.4;
  }

  .note {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    margin-top: auto;
  }

  .note p {
    font-size: 0.85rem;
    color: #6b7280;
    margin: 0;
    line-height: 1.5;
  }
</style>
```

**Verification:**
Run from `apps/identity-wallet/`: `pnpm check`
Expected: No TypeScript errors

Run `cargo tauri ios dev` and navigate to Recovery Info:
- Share 1 shows ✓ with green background when `share1InKeychain` is `true`
- Share 1 shows ✗ with red background when `share1InKeychain` is `false`
- Share 2 always shows ✓ with green background
- Share 3 always shows clipboard icon with grey background
- Back button returns to home

**Commit:**
```bash
git add apps/identity-wallet/src/lib/components/home/RecoveryInfoScreen.svelte
git commit -m "feat: add RecoveryInfoScreen component showing Shamir share status"
```
<!-- END_TASK_1 -->
<!-- END_SUBCOMPONENT_A -->
