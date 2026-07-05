# MM-144 Onboarding Flow — Phase 3: Onboarding Screen Components

**Goal:** Build the five Svelte screen components for the onboarding wizard. Each component is self-contained: it owns local validation state and communicates to the parent via callback props. No IPC calls in components.

**Architecture:** Five `.svelte` files in `src/lib/components/onboarding/`. Parent (`+page.svelte`, built in Phase 4) owns form state and passes `$bindable` values + callback props to each screen. Components use Svelte 5 `$props()`, `$bindable()`, and `$derived()`. Scoped CSS only — no CSS framework.

**Tech Stack:** Svelte 5.25, SvelteKit 2, TypeScript strict, `$state`/`$props`/`$derived`/`$bindable` runes

**Scope:** Phase 3 of 4

**Codebase verified:** 2026-03-15

---

## Acceptance Criteria Coverage

UI component ACs are verified by `pnpm build` (TypeScript compilation) and manual visual inspection in the iOS simulator. There is no frontend test framework configured in this project.

### MM-144.AC1: Onboarding screens render correctly
- **MM-144.AC1.1 Success:** Welcome screen shows app branding and a "Get Started" CTA button that advances to Claim Code step
- **MM-144.AC1.2 Success:** Claim Code screen shows a 6-character alphanumeric input; the Next button is disabled until exactly 6 characters are entered
- **MM-144.AC1.3 Success:** Email screen shows an email input; the Next button is disabled until a valid email format is entered
- **MM-144.AC1.4 Success:** Handle screen shows a handle input; the Next button is disabled until the handle is non-empty
- **MM-144.AC1.5 Success:** Loading screen shows a spinner and status message while account creation is in progress
- **MM-144.AC1.6 Success:** Each screen's Next/Submit button only advances when its validation condition is met

**Verification:** `pnpm build` (TypeScript type errors fail the build) + manual visual check in iOS simulator.

---

<!-- START_SUBCOMPONENT_A (tasks 1-6) -->

<!-- START_TASK_1 -->
### Task 1: Create the `onboarding` component directory

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/.gitkeep`

**Step 1: Create the directory structure**

```bash
mkdir -p apps/identity-wallet/src/lib/components/onboarding
touch apps/identity-wallet/src/lib/components/onboarding/.gitkeep
```

The `.gitkeep` is temporary — it will be replaced by the component files in subsequent tasks and can be deleted after Task 2.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/components/
git commit -m "chore(identity-wallet): create onboarding component directory"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create `WelcomeScreen.svelte`

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/WelcomeScreen.svelte`
- Delete: `apps/identity-wallet/src/lib/components/onboarding/.gitkeep`

**Verifies:** MM-144.AC1.1

**Step 1: Create the file**

```svelte
<script lang="ts">
  let { onstart }: { onstart: () => void } = $props();
</script>

<div class="screen">
  <div class="brand">
    <h1>Identity Wallet</h1>
    <p class="tagline">Your self-sovereign identity, in your pocket.</p>
  </div>
  <button class="cta" onclick={onstart}>Get Started</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 3rem;
  }

  .brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
    text-align: center;
  }

  h1 {
    font-size: 2rem;
    font-weight: 700;
    margin: 0;
  }

  .tagline {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
```

**Step 2: Remove `.gitkeep`**

```bash
rm apps/identity-wallet/src/lib/components/onboarding/.gitkeep
```

**Step 3: Commit**

```bash
git add apps/identity-wallet/src/lib/components/onboarding/
git commit -m "feat(identity-wallet): add WelcomeScreen component"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Create `ClaimCodeScreen.svelte`

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/ClaimCodeScreen.svelte`

**Verifies:** MM-144.AC1.2, MM-144.AC1.6

**Step 1: Create the file**

```svelte
<script lang="ts">
  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  let isValid = $derived(value.length === 6);

  function handleInput(e: Event) {
    const raw = (e.currentTarget as HTMLInputElement).value;
    value = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6);
  }
</script>

<div class="screen">
  <h2>Enter Your Claim Code</h2>
  <p class="hint">You'll receive a 6-character code from your administrator.</p>

  <input
    type="text"
    class="code-input"
    class:error={!!error}
    maxlength="6"
    placeholder="ABC123"
    autocomplete="off"
    autocorrect="off"
    autocapitalize="characters"
    spellcheck={false}
    {value}
    oninput={handleInput}
  />

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <button disabled={!isValid} onclick={onnext}>Next</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem;
    gap: 1rem;
    height: 100%;
    justify-content: center;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
  }

  .code-input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1.5rem;
    font-family: monospace;
    letter-spacing: 0.5rem;
    text-align: center;
    border: 2px solid #d1d5db;
    border-radius: 12px;
    text-transform: uppercase;
  }

  .code-input.error {
    border-color: #ef4444;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }
</style>
```

**Why `oninput` + manual value assignment instead of `bind:value`:** The claim code needs auto-uppercase and non-alphanumeric filtering. Controlling the input via `oninput` + `{value}` (one-way, parent-controlled) is cleaner than fighting Svelte's two-way bind for this transformation. The parent still owns the state via `$bindable` — the `handleInput` function mutates `value` directly.

**Why `error` prop:** The parent passes error messages back to the screen (e.g., "Claim code has expired") after a failed submission. The `error` prop allows the screen to display it without needing to know about the IPC layer.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/components/onboarding/ClaimCodeScreen.svelte
git commit -m "feat(identity-wallet): add ClaimCodeScreen component"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Create `EmailScreen.svelte`

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/EmailScreen.svelte`

**Verifies:** MM-144.AC1.3, MM-144.AC1.6

**Step 1: Create the file**

```svelte
<script lang="ts">
  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  let isValid = $derived(emailRegex.test(value));
</script>

<div class="screen">
  <h2>Enter Your Email</h2>
  <p class="hint">We'll associate this email with your new account.</p>

  <input
    type="email"
    class:error={!!error}
    placeholder="you@example.com"
    autocomplete="email"
    inputmode="email"
    bind:value
  />

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <button disabled={!isValid} onclick={onnext}>Next</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem;
    gap: 1rem;
    height: 100%;
    justify-content: center;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
  }

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
  }

  input.error {
    border-color: #ef4444;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }
</style>
```

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/components/onboarding/EmailScreen.svelte
git commit -m "feat(identity-wallet): add EmailScreen component"
```
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Create `HandleScreen.svelte`

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/HandleScreen.svelte`

**Verifies:** MM-144.AC1.4, MM-144.AC1.6

**Step 1: Create the file**

```svelte
<script lang="ts">
  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  let isValid = $derived(value.trim().length > 0);
</script>

<div class="screen">
  <h2>Choose Your Handle</h2>
  <p class="hint">This is your unique identifier on the network (e.g. alice.ezpds.com).</p>

  <input
    type="text"
    class:error={!!error}
    placeholder="alice"
    autocomplete="off"
    autocorrect="off"
    autocapitalize="none"
    spellcheck={false}
    bind:value
  />

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <button disabled={!isValid} onclick={onnext}>Create Account</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem;
    gap: 1rem;
    height: 100%;
    justify-content: center;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
  }

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
  }

  input.error {
    border-color: #ef4444;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
  }

  button {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }
</style>
```

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/components/onboarding/HandleScreen.svelte
git commit -m "feat(identity-wallet): add HandleScreen component"
```
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Create `LoadingScreen.svelte` and verify build

**Files:**
- Create: `apps/identity-wallet/src/lib/components/onboarding/LoadingScreen.svelte`

**Verifies:** MM-144.AC1.5

**Step 1: Create the file**

```svelte
<script lang="ts">
  let {
    statusText = 'Creating your account…',
  }: {
    statusText?: string;
  } = $props();
</script>

<div class="screen">
  <div class="spinner" aria-label="Loading"></div>
  <p class="status">{statusText}</p>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 1.5rem;
  }

  .spinner {
    width: 48px;
    height: 48px;
    border: 4px solid #e5e7eb;
    border-top-color: #007aff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .status {
    font-size: 1rem;
    color: #6b7280;
    margin: 0;
    text-align: center;
  }
</style>
```

**Step 2: Commit**

```bash
git add apps/identity-wallet/src/lib/components/onboarding/LoadingScreen.svelte
git commit -m "feat(identity-wallet): add LoadingScreen component"
```

**Step 3: Run TypeScript build check**

```bash
cd apps/identity-wallet && pnpm build
```

Expected: build succeeds with zero TypeScript errors. The components are not yet imported anywhere (that happens in Phase 4), so no "unused" warnings — SvelteKit does not warn about unused component files.

**Step 4: Run svelte-check**

```bash
cd apps/identity-wallet && pnpm exec svelte-check
```

Expected: zero errors. If any type errors appear, fix them before committing.
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_A -->
