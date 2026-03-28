# MM-150 Implementation Plan — Phase 2: DIDAvatar component

**Goal:** Standalone, deterministic avatar component showing a stable gradient circle and handle initial for any DID.

**Architecture:** Pure Svelte 5 component with no side effects. Derives hue from a simple integer hash of the DID string; derives the initial letter from the handle (or `?` for `handle.invalid`). No external dependencies, no IPC calls.

**Tech Stack:** Svelte 5 (`$props()`, `$derived`)

**Scope:** Phase 2 of 6

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

### MM-150.AC1: Identity card displays correctly
- **MM-150.AC1.5 Success:** DID-derived avatar circle is visible with a stable hue derived from the DID hash
- **MM-150.AC1.6 Success:** Avatar shows the first letter of the handle as its initial
- **MM-150.AC1.7 Edge:** Avatar shows `?` when handle is `handle.invalid`

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Create `DIDAvatar.svelte`

**Verifies:** MM-150.AC1.5, MM-150.AC1.6, MM-150.AC1.7

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/DIDAvatar.svelte`

**Implementation:**

Create the directory first (it doesn't exist yet):

```bash
mkdir -p apps/identity-wallet/src/lib/components/home
```

Then create `apps/identity-wallet/src/lib/components/home/DIDAvatar.svelte`:

```svelte
<script lang="ts">
  let {
    did,
    handle,
  }: {
    did: string;
    handle: string;
  } = $props();

  // Derive a stable hue (0-359) from the DID string using a simple polynomial hash.
  // The same DID always produces the same hue across re-renders and app sessions.
  let hue = $derived.by(() => {
    let h = 0;
    for (let i = 0; i < did.length; i++) {
      h = (h * 31 + did.charCodeAt(i)) & 0xffffff;
    }
    return h % 360;
  });

  // Show '?' for the ATProto sentinel value that means "no handle registered".
  let initial = $derived(
    handle === 'handle.invalid' ? '?' : handle.charAt(0).toUpperCase()
  );
</script>

<div
  class="avatar"
  style="background: hsl({hue}, 65%, 45%)"
  aria-label="Avatar for {handle}"
>
  {initial}
</div>

<style>
  .avatar {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-size: 1.75rem;
    font-weight: 700;
    flex-shrink: 0;
    user-select: none;
  }
</style>
```

**Verification:**
Run from `apps/identity-wallet/`: `pnpm check`
Expected: No TypeScript errors

**Commit:**
```bash
git add apps/identity-wallet/src/lib/components/home/DIDAvatar.svelte
git commit -m "feat: add DIDAvatar component with deterministic DID-derived hue"
```
<!-- END_TASK_1 -->
<!-- END_SUBCOMPONENT_A -->
