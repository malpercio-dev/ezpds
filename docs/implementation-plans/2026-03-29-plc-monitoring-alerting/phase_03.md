# PLC Monitoring & Alerting Implementation Plan — Phase 3: Frontend Alerts

**Goal:** Display alert badges on identity cards when unauthorized PLC operations are detected, and provide an alert detail screen showing the signing key, timestamp, and recovery deadline countdown.

**Architecture:** `IdentityListHome.svelte` calls `checkIdentityStatus()` on mount (alongside existing identity loading) and renders a red alert badge on cards with `alertCount > 0`. Tapping an alerted card navigates to `AlertDetailScreen.svelte` which shows each unauthorized change with its signing key, timestamp, and a real-time countdown to the 72-hour recovery deadline. The frontend also listens for `"plc_alert"` Tauri events from the background monitoring timer to update badge counts without requiring user interaction.

**Tech Stack:** Svelte 5 (runes: $state, $derived, $props), SvelteKit 2, TypeScript, @tauri-apps/api (core + event)

**Scope:** 3 phases from design Phase 6. This is phase 3 of 3.

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC6: PLC monitoring and alerting
- **plc-key-management.AC6.4 Success:** Home screen shows red alert badge on identity cards with `alertCount > 0`
- **plc-key-management.AC6.5 Success:** Alert detail screen shows signing key, timestamp, and recovery deadline countdown

---

## Codebase Verification Findings

- ✓ `IdentityListHome.svelte` (375 lines) — multi-identity card list with existing badge pattern for rotation key status (`.badge--root`, `.badge--not-root`, `.badge--unknown`)
- ✓ Card rendering at lines 124-151 — flexbox horizontal layout: avatar + info + badge
- ✓ Existing badge CSS: `.badge { flex; gap; padding; border-radius: 6px; font-size: 0.75rem; font-weight: 600 }` with `.badge-dot { 6px circle }`
- ✓ Color palette: error red = `#ef4444`, error bg = (no existing red badge — will add `.badge--alert` with `#fef2f2` bg, `#ef4444` dot, `#991b1b` text)
- ✓ Props: `{ onadd, onselect }` via `$props()`
- ✓ Data loading on mount: `listIdentities()` → parallel `getStoredDidDoc()` + `getDeviceKeyId()` per DID
- ✓ State machine in `+page.svelte` — `step` variable, `goTo(step)` function
- ✓ Existing steps include `home`, `identity_detail`, `did_document`, `recovery_info`
- ✓ `DIDDocumentScreen.svelte` pattern: receives `{ didDoc, onback }` props
- ✓ `ipc.ts` (489 lines) — all IPC wrappers exported here; `checkIdentityStatus` to be added in Phase 2
- ✓ Svelte 5 runes: `$state`, `$derived`, `$props()`, `onMount()` (no `$effect`)
- ✓ Scoped CSS, hand-written (no Tailwind), consistent spacing (rem units)
- ✓ `@tauri-apps/api/event` — `listen()` function available for Tauri event subscription

---

<!-- START_SUBCOMPONENT_A (tasks 1-4) -->

<!-- START_TASK_1 -->
### Task 1: Add alert badge to IdentityListHome identity cards

**Verifies:** plc-key-management.AC6.4

**Files:**
- Modify: `apps/identity-wallet/src/lib/components/home/IdentityListHome.svelte`

**Implementation:**

Extend `IdentityListHome` to fetch alert status and display red alert badges on identity cards.

Changes to the component:

1. **Import `checkIdentityStatus`** from `$lib/ipc` (added in Phase 2).

2. **Add alert state** alongside existing `identities` state. Use a single `alertData` map (derive counts from array length to avoid redundant state):
   ```typescript
   let alertData = $state<Map<string, UnauthorizedChange[]>>(new Map());
   ```

3. **Fetch alert status on mount** — add a call to `checkIdentityStatus()` after the existing identity loading. This is a separate async call that runs in parallel; alert badge rendering is additive (cards render fine without alert data).
   ```typescript
   // In onMount, after existing identity loading:
   checkIdentityStatus()
     .then((statuses) => {
       const data = new Map<string, UnauthorizedChange[]>();
       for (const s of statuses) {
         if (s.alertCount > 0) data.set(s.did, s.unauthorizedChanges);
       }
       alertData = data;
     })
     .catch((e) => console.warn('Alert check failed:', e));
   ```

4. **Listen for `plc_alert` events** from the background monitoring timer (Phase 2). Subscribe in `onMount`, unsubscribe in `onDestroy`:
   ```typescript
   import { listen, type UnlistenFn } from '@tauri-apps/api/event';
   import { onDestroy } from 'svelte';

   let unlisten: UnlistenFn | null = null;

   onMount(async () => {
     // ... existing loading logic ...

     unlisten = await listen<IdentityStatus[]>('plc_alert', (event) => {
       const data = new Map<string, UnauthorizedChange[]>();
       for (const s of event.payload) {
         if (s.alertCount > 0) data.set(s.did, s.unauthorizedChanges);
       }
       alertData = data;
     });
   });

   onDestroy(() => {
     unlisten?.();
   });
   ```

5. **Render alert badge** on each card, alongside the existing rotation key badge. Add a conditional alert badge that appears ABOVE the rotation key badge when the DID has unauthorized changes (derive count from `alertData.get(did)?.length`):
   ```svelte
   <div class="card-badge">
     {#if alertData.get(card.did)?.length}
       <span class="badge badge--alert">
         <span class="badge-dot"></span>
         {alertData.get(card.did)?.length} {alertData.get(card.did)?.length === 1 ? 'Alert' : 'Alerts'}
       </span>
     {/if}
     <span
       class="badge"
       class:badge--root={card.deviceKeyIsRoot === true}
       class:badge--not-root={card.deviceKeyIsRoot === false}
       class:badge--unknown={card.deviceKeyIsRoot === null}
     >
       <span class="badge-dot"></span>
       {getBadgeLabel(card.deviceKeyIsRoot)}
     </span>
   </div>
   ```

6. **Add CSS for alert badge** — follows existing badge pattern with red color scheme:
   ```css
   .badge--alert {
     background: #fef2f2;
     color: #991b1b;
   }

   .badge--alert .badge-dot {
     background: #ef4444;
   }
   ```

7. **Update `onselect` callback** to also pass alert data. Modify the card click handler to include alert info so the parent can navigate to alert detail when appropriate:
   - The parent (`+page.svelte`) will need the alert data to decide whether to show the alert detail screen
   - Add alert statuses to the component's exported data by expanding the `onselect` callback or adding a separate `onalert` callback

   The cleaner approach: add an `onalert` prop callback:
   ```typescript
   let { onadd, onselect, onalert } = $props<{
     onadd: () => void;
     onselect: (did: string, didDoc: Record<string, unknown>) => void;
     onalert?: (did: string, changes: UnauthorizedChange[]) => void;
   }>();
   ```

   The `alertData` map (declared in step 2) already holds the full `UnauthorizedChange[]` per DID for navigation.

   Update the badge to be clickable when alerts exist — tapping the alert badge calls `onalert`:
   ```svelte
   {#if alertData.get(card.did)?.length}
     <button
       class="badge badge--alert"
       onclick={(e) => { e.stopPropagation(); onalert?.(card.did, alertData.get(card.did) ?? []); }}
     >
       <span class="badge-dot"></span>
       {alertData.get(card.did)?.length} {alertData.get(card.did)?.length === 1 ? 'Alert' : 'Alerts'}
     </button>
   {/if}
   ```

   Note: Svelte 5 does not support pipe modifiers on `onclick`. Use inline `e.stopPropagation()` to prevent the card's `onselect` handler from also firing.

**Testing:**

This is frontend UI code. Verify visually and via type checking:
- plc-key-management.AC6.4: When `checkIdentityStatus` returns identities with `alertCount > 0`, a red badge with the count appears on those cards. Cards with `alertCount: 0` show no alert badge.

**Verification:**

Run: `cd apps/identity-wallet && pnpm check`
Expected: Svelte type checking passes

**Commit:** `feat(identity-wallet): add alert badge to identity cards`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create AlertDetailScreen component

**Verifies:** plc-key-management.AC6.5

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/AlertDetailScreen.svelte`

**Implementation:**

Create a new Svelte 5 component following the pattern of `DIDDocumentScreen.svelte` and `RecoveryInfoScreen.svelte`.

Props:
```typescript
let { did, changes, onback } = $props<{
  did: string;
  changes: UnauthorizedChange[];
  onback: () => void;
}>();
```

The component displays:
1. **Header** with back button and title ("Security Alerts")
2. **Identity** — the DID this alert is for (truncated)
3. **Alert cards** — one per `UnauthorizedChange`, each showing:
   - **Signing key**: `change.signingKey` displayed as a truncated did:key URI, or "Unknown key" if null
   - **Timestamp**: `change.createdAt` formatted as a human-readable date/time
   - **Recovery deadline countdown**: computed from `change.createdAt + 72 hours`
     - Green if >24h remaining
     - Amber if 4-24h remaining
     - Red if <4h remaining or expired
   - **"Review & Override" button** (placeholder — wired in Phase 7 recovery override; disabled for now)

Recovery deadline computation (in component):
```typescript
const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000;

function getDeadline(createdAt: string): Date {
  return new Date(new Date(createdAt).getTime() + RECOVERY_WINDOW_MS);
}

function formatCountdown(deadline: Date): string {
  const remaining = deadline.getTime() - Date.now();
  if (remaining <= 0) return 'Expired';
  const hours = Math.floor(remaining / (1000 * 60 * 60));
  const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${minutes}m remaining`;
}
```

For a live countdown, use `setInterval` (started in `onMount`, cleared in `onDestroy`) to update a `$state` variable every 60 seconds:
```typescript
let now = $state(Date.now());
let timer: ReturnType<typeof setInterval> | null = null;

onMount(() => {
  timer = setInterval(() => { now = Date.now(); }, 60_000);
});

onDestroy(() => {
  if (timer) clearInterval(timer);
});
```

Then use `$derived` for each change's countdown:
```svelte
{#each changes as change (change.cid)}
  {@const deadline = getDeadline(change.createdAt)}
  {@const remaining = deadline.getTime() - now}
  {@const urgency = remaining <= 0 ? 'expired' : remaining < 4 * 3600000 ? 'critical' : remaining < 24 * 3600000 ? 'warning' : 'safe'}

  <div class="alert-card">
    <div class="alert-header">
      <span class="alert-urgency alert-urgency--{urgency}">
        <span class="badge-dot"></span>
        {remaining <= 0 ? 'Expired' : `${Math.floor(remaining / 3600000)}h ${Math.floor((remaining % 3600000) / 60000)}m remaining`}
      </span>
    </div>

    <div class="alert-field">
      <span class="alert-label">Signing Key</span>
      <span class="alert-value monospace">{change.signingKey ?? 'Unknown key'}</span>
    </div>

    <div class="alert-field">
      <span class="alert-label">Detected</span>
      <span class="alert-value">{new Date(change.createdAt).toLocaleString()}</span>
    </div>

    <div class="alert-field">
      <span class="alert-label">Recovery Deadline</span>
      <span class="alert-value">{deadline.toLocaleString()}</span>
    </div>

    <button class="action-button" disabled>
      Review & Override
    </button>
  </div>
{/each}
```

Styling follows existing patterns:
- `.alert-card`: same card styling as identity cards (12px radius, 1.25rem padding, border)
- `.alert-label`: 0.75rem, 600 weight, uppercase, letter-spacing 0.04em (matches existing label style)
- `.alert-value`: 1rem, `#374151` color
- `.monospace`: font-family monospace, 0.8rem, word-break break-all
- `.alert-urgency--safe`: green (`#dcfce7` bg, `#16a34a` dot)
- `.alert-urgency--warning`: amber (`#fef3c7` bg, `#f59e0b` dot)
- `.alert-urgency--critical` / `.alert-urgency--expired`: red (`#fef2f2` bg, `#ef4444` dot)
- `.action-button`: `#007aff` blue, full-width, 12px radius, 0.9rem padding — disabled state has `opacity: 0.5, cursor: not-allowed`
- Back button: same pattern as `DIDDocumentScreen` (← arrow + "Back" text)

**Testing:**

This is frontend UI code with time-based rendering logic:
- plc-key-management.AC6.5: Alert detail screen shows signing key, timestamp, and recovery deadline countdown. Visual verification — component renders all fields from `UnauthorizedChange` data.

**Verification:**

Run: `cd apps/identity-wallet && pnpm check`
Expected: Svelte type checking passes

**Commit:** `feat(identity-wallet): create AlertDetailScreen component`

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Wire AlertDetailScreen into page state machine

**Verifies:** plc-key-management.AC6.4, plc-key-management.AC6.5

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

1. **Add `'alert_detail'` to `OnboardingStep` type** (around line 38-62):
   ```typescript
   type OnboardingStep = /* existing steps */ | 'alert_detail';
   ```

2. **Add alert state variables:**
   ```typescript
   let selectedAlertDid = $state<string | null>(null);
   let selectedAlertChanges = $state<UnauthorizedChange[]>([]);
   ```

3. **Import AlertDetailScreen** and the `UnauthorizedChange` type:
   ```typescript
   import AlertDetailScreen from '$lib/components/home/AlertDetailScreen.svelte';
   import type { UnauthorizedChange } from '$lib/ipc';
   ```

4. **Update `IdentityListHome` usage** to include the `onalert` callback (around lines 310-320):
   ```svelte
   {:else if step === 'home'}
     <IdentityListHome
       onadd={() => goTo('mode_select')}
       onselect={(_did, didDoc) => {
         selectedDidDoc = didDoc;
         goTo('identity_detail');
       }}
       onalert={(did, changes) => {
         selectedAlertDid = did;
         selectedAlertChanges = changes;
         goTo('alert_detail');
       }}
     />
   ```

5. **Add `alert_detail` step rendering** (after the `identity_detail` block):
   ```svelte
   {:else if step === 'alert_detail'}
     <AlertDetailScreen
       did={selectedAlertDid ?? ''}
       changes={selectedAlertChanges}
       onback={() => goTo('home')}
     />
   ```

**Testing:**

Integration wiring — verified via type checking and the end-to-end flow:
- plc-key-management.AC6.4: Tapping alert badge navigates to alert detail screen
- plc-key-management.AC6.5: AlertDetailScreen renders with correct data from parent state

**Verification:**

Run: `cd apps/identity-wallet && pnpm check`
Expected: Svelte type checking passes

**Commit:** `feat(identity-wallet): wire AlertDetailScreen into page state machine`

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Extract and test deadline computation utilities

**Verifies:** plc-key-management.AC6.3, plc-key-management.AC6.5

**Files:**
- Create: `apps/identity-wallet/src/lib/utils/deadline.ts`
- Create: `apps/identity-wallet/src/lib/utils/deadline.test.ts`
- Modify: `apps/identity-wallet/src/lib/components/home/AlertDetailScreen.svelte` (import from utils instead of inline)

**Implementation:**

Extract the deadline computation functions from `AlertDetailScreen.svelte` into a testable utility module:

```typescript
// $lib/utils/deadline.ts

export const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000; // 72 hours

export function getDeadline(createdAt: string): Date {
  return new Date(new Date(createdAt).getTime() + RECOVERY_WINDOW_MS);
}

export type Urgency = 'safe' | 'warning' | 'critical' | 'expired';

export function getUrgency(deadline: Date, now: number = Date.now()): Urgency {
  const remaining = deadline.getTime() - now;
  if (remaining <= 0) return 'expired';
  if (remaining < 4 * 60 * 60 * 1000) return 'critical';
  if (remaining < 24 * 60 * 60 * 1000) return 'warning';
  return 'safe';
}

export function formatCountdown(deadline: Date, now: number = Date.now()): string {
  const remaining = deadline.getTime() - now;
  if (remaining <= 0) return 'Expired';
  const hours = Math.floor(remaining / (1000 * 60 * 60));
  const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${minutes}m remaining`;
}
```

Update `AlertDetailScreen.svelte` to import from `$lib/utils/deadline` instead of defining inline.

**Testing:**

Write tests in `deadline.test.ts` covering:
- plc-key-management.AC6.3: `getDeadline('2026-03-29T12:00:00.000Z')` returns `Date` exactly 72h later (`2026-04-01T12:00:00.000Z`)
- plc-key-management.AC6.5: Urgency thresholds:
  - `getUrgency(deadline, deadline - 48h)` → `'safe'` (48h remaining, >24h)
  - `getUrgency(deadline, deadline - 12h)` → `'warning'` (12h remaining, 4-24h)
  - `getUrgency(deadline, deadline - 2h)` → `'critical'` (2h remaining, <4h)
  - `getUrgency(deadline, deadline + 1h)` → `'expired'` (1h past)
  - `getUrgency(deadline, deadline)` → `'expired'` (exactly at deadline)
- `formatCountdown` edge cases:
  - Exactly 72h remaining → `'72h 0m remaining'`
  - 0h remaining → `'Expired'`
  - 23h 59m remaining → `'23h 59m remaining'`

Follow the project's test runner. Check if `vitest` is configured in `apps/identity-wallet/package.json` or if tests run via another mechanism.

**Verification:**

Run: `cd apps/identity-wallet && pnpm test` (or the project's test command)
Expected: All deadline utility tests pass

**Commit:** `feat(identity-wallet): extract and test deadline computation utilities`

<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_A -->

---

## Identity-Wallet CLAUDE.md Updates

After completing Phase 3, the following updates should be made to `apps/identity-wallet/CLAUDE.md`:

**Exposes section additions:**
- Add `checkIdentityStatus()` to the `ipc.ts` exports list
- Add `UnauthorizedChange` and `IdentityStatus` to the exported types list
- Add `AlertDetailScreen.svelte` to the home components list
- Add `plc_monitor::check_identity_status` to the Rust backend commands list
- Add `plc_monitor.rs` to the Rust backend module descriptions
- Add `'alert_detail'` to the OnboardingStep type and state machine documentation

**Guarantees section additions:**
- `MonitorError` variants serialize as `{ code: "SCREAMING_SNAKE_CASE" }` matching existing error pattern
- `check_identity_status` always returns Ok for individual identity errors — per-identity network failures are logged and produce `alert_count: 0` (graceful degradation matching `load_home_data` pattern)
- `run_monitoring_loop` uses `MissedTickBehavior::Delay` — no burst of catch-up ticks after iOS suspension
- `UnauthorizedChange.created_at` is a raw ISO 8601 string; frontend computes 72h recovery deadline
