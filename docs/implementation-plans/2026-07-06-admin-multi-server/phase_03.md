# Admin Multi-Server Support — Phase 3: Frontend — Switcher, Loud Identity, Screens

**Goal:** Operator-visible multi-server UX: a tappable identity block on Home that expands into a one-tap server switcher, the active server's nickname + host loudly visible on every screen (text + position, never color alone), a nickname field on Pair (reachable while already paired), a per-server "Servers" section in Settings (rename / unpair / revoke, biometric-gated), and server-attributed error states.

**Architecture:** `src/lib/ipc.ts` (the single `invoke()` chokepoint) gains the Phase 2 command bindings and types. A new pure module `src/lib/server-identity.ts` derives the display identity (nickname + host) from a pairing. `ScreenShell` gains an optional server-context slot (nickname in display type, host in monospace beneath — optionally tappable, which is how Home's identity block opens the inline switcher). `ErrorState` attributes every classified failure to a named server and adds the revoked-state CTAs ("Forget this server" / "Switch server"). Screens keep the existing per-screen load-on-mount pattern (no global store) — `list_pairings()` is cheap local keychain I/O.

**Tech Stack:** SvelteKit 2 + Svelte 5 runes (`$state`/`$derived`/`$props`, snippets), TypeScript, vitest 4 (logic-only tests, per the app's convention), Brass Console token layer (`var(--color-*)`, `var(--font-*)`, `var(--space-*)` — never hardcode hex/px), WCAG 2.2 AAA, status always glyph + text + position.

**Scope:** Phase 3 of 4 from `docs/design-plans/2026-07-06-admin-multi-server.md`. Depends on Phase 2 being complete (the Rust commands exist).

**Codebase verified:** 2026-07-06

---

## Acceptance Criteria Coverage

This phase implements and tests:

### admin-multi-server.AC2: One-tap switch, loud identity
- **admin-multi-server.AC2.2 Success:** Home and Settings render the active nickname + host by text + position (never color alone); the claim-code reveal shows the server identity adjacent to the code
- **admin-multi-server.AC2.5 Edge:** Removing the active pairing auto-promotes when exactly one remains; with two or more remaining, active is cleared and Home requires an explicit pick *(this phase: the UI half — the "pick a server" state on Home; the document semantics were Phase 1)*

### admin-multi-server.AC3: Pair and manage servers
- **admin-multi-server.AC3.1 Success:** Pair is reachable while already paired; a successful pair appends and becomes active
- **admin-multi-server.AC3.2 Success:** Settings lists every pairing; `rename_pairing` updates the nickname locally without contacting any relay
- **admin-multi-server.AC3.4 Failure:** `revoke_self` against an unreachable relay reports the failure attributed to that server's nickname + host; the pairing is retained and local unpair is offered as fallback

Note on verification split: the app's frontend test convention is **logic-only vitest** (`errors.test.ts`, `ipc.test.ts`, `biometric.test.ts` — no Svelte component/DOM tests exist). New pure logic (server identity, error classification/attribution) gets unit tests; screen behavior is verified by `pnpm check` (svelte-check), the `/preview` gallery, and the manual/simulator pass recorded in `test-requirements.md`. Do not introduce a component-DOM test harness in this phase.

---

## Environment

Rust side: unchanged this phase. Frontend commands also run through the main checkout's devenv (pnpm/node come from it), but execute **in this worktree's app directory**. The worktree has no `node_modules` — run `pnpm install` once first.

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c sh -c \
  'cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/apps/admin-companion && pnpm install && pnpm test'
```

- `pnpm test` = `vitest run`; `pnpm check` = svelte-check (type-checks every screen).
- **Sequencing note:** Task 1 removes `pairingState()` from `ipc.ts`, which makes `pnpm check` fail until the screens are reworked (Tasks 5–7). Tasks 1–7 therefore verify with `pnpm test` (vitest only type-checks the modules the tests import); Task 8 is the full `pnpm check` + `pnpm test` gate for the phase. This is the same mid-branch posture Phase 2 declared for the frontend.
- Sandbox: same as the Rust phases — run these through the main checkout with the sandbox disabled if `nix develop` hits daemon-socket errors.

UI rules (from `apps/admin-companion/CLAUDE.md` + DESIGN.md — read both before Tasks 3–7):
- Tokens only: `var(--color-*)`, `var(--font-*)`, `var(--space-*)`; never hex/px literals.
- Status/identity always by glyph + text + position, never color alone; WCAG 2.2 AAA pairs only (use existing token pairs — do not invent new color combinations).
- Svelte 5 runes and snippets (`$props()`, `{@render children()}`), matching the existing components.
- No new `invoke()` call sites outside `src/lib/ipc.ts`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `ipc.ts` bindings + `server-identity.ts` pure helpers

**Verifies:** None directly (bindings + helper groundwork; Task 2 tests the pure logic).

**Files:**
- Modify: `apps/admin-companion/src/lib/ipc.ts`
- Create: `apps/admin-companion/src/lib/server-identity.ts`

**Implementation:**

**A. `ipc.ts` type changes:**

1. Replace the `Pairing` interface (lines 45–53) to mirror the Rust struct exactly:

```typescript
/** One stored relay pairing. `id` is the stable local handle (a UUID minted at pair
 * time); `deviceId` is relay-assigned and changes on re-pair. `nickname` is the
 * operator's local display name and never leaves the device. */
export interface Pairing {
  id: string;
  nickname: string;
  relayUrl: string;
  deviceId: string;
  deviceLabel: string;
}

/** Every stored pairing plus the active selection (`null` when nothing is selected —
 * fresh install, or the active entry was removed with two or more remaining). */
export interface PairingsState {
  active: string | null;
  pairings: Pairing[];
}
```

2. Add the new error shape to the `RelayClientError` union (lines 35–42): `{ code: 'NO_SUCH_PAIRING' }` (no extra fields — mirrors the Rust variant).

**B. `ipc.ts` function changes** (keep the file's existing doc-comment style; every function still wraps `invoke` from `@tauri-apps/api/core`):

1. `pairDevice` gains a `nickname` parameter:

```typescript
export async function pairDevice(
  relayUrl: string,
  pairingCode: string,
  label: string,
  nickname: string,
): Promise<string> {
  return invoke('pair_device', { relayUrl, pairingCode, label, nickname });
}
```

2. Delete `pairingState()` and add:

```typescript
export async function listPairings(): Promise<PairingsState> {
  return invoke('list_pairings');
}

export async function setActivePairing(id: string): Promise<void> {
  return invoke('set_active_pairing', { id });
}

export async function renamePairing(id: string, nickname: string): Promise<void> {
  return invoke('rename_pairing', { id, nickname });
}
```

3. `revokeSelf` and `unpair` gain the id:

```typescript
export async function revokeSelf(id: string): Promise<void> {
  return invoke('revoke_self', { id });
}

export async function unpair(id: string): Promise<void> {
  return invoke('unpair', { id });
}
```

Everything else in `ipc.ts` (device key, biometric, QR payload parsing) is unchanged.

**C. Create `apps/admin-companion/src/lib/server-identity.ts`:**

```typescript
// pattern: Functional Core
//
// Display identity for a paired relay. The nickname is the operator's word for the
// server; the host is the ground truth that disambiguates duplicate nicknames. Both
// are always shown together (text + position — never color) so the operator can tell
// staging from production at a glance on every screen.

import type { Pairing } from './ipc';

export interface ServerIdentity {
  /** Operator-facing name. Falls back to the host when the nickname is empty (a
   * pairing created before nicknames existed). */
  nickname: string;
  /** The relay URL's host (with port when present) — shown in monospace beneath the
   * nickname everywhere. */
  host: string;
}

/** The relay URL's host, or the raw string when it does not parse as a URL — a broken
 * URL should read as itself, not vanish. */
export function hostOf(relayUrl: string): string {
  try {
    return new URL(relayUrl).host;
  } catch {
    return relayUrl.trim();
  }
}

export function serverIdentity(pairing: Pick<Pairing, 'nickname' | 'relayUrl'>): ServerIdentity {
  const host = hostOf(pairing.relayUrl);
  const nickname = pairing.nickname.trim();
  return { nickname: nickname === '' ? host : nickname, host };
}
```

**Verification:**

`pnpm test` (see Environment) — existing `ipc.test.ts` (QR payload parsing) still passes; the app-wide `pnpm check` is deferred to Task 8 by design.

**Commit:** `feat(admin-companion): multi-server IPC bindings and server identity helpers`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Error classification for multi-server + pure-logic tests

**Verifies:** admin-multi-server.AC3.4 (classification half: unreachable/revoked failures carry a recovery contract the UI attributes to a named server).

**Files:**
- Modify: `apps/admin-companion/src/lib/errors.ts`
- Modify: `apps/admin-companion/src/lib/errors.test.ts`
- Create: `apps/admin-companion/src/lib/server-identity.test.ts`

**Implementation:**

**A. `errors.ts`:**

1. Extend `ErrorView.recovery` (line 25) from `'pair' | 'retry' | 'none'` to `'pair' | 'retry' | 'forget-or-switch' | 'none'`.
2. Change the `RELAY_REJECTED` 403 row of `classifyRelayError` (previously recovery `'pair'`): status stays `'revoked'`, chip stays `'access revoked'`, recovery becomes `'forget-or-switch'` — a revoked credential is scoped to the pairing that produced it; the operator forgets that server or switches to another, they do not blindly re-pair.
3. Add a `NO_SUCH_PAIRING` row: status `'error'`, chip `'no such server'`, recovery `'none'`, message (in `describeRelayError`) along the lines of: "That server is no longer in this device's list. It may have been removed on another screen." (Screens reload `list_pairings()` after any failed action, so the stale row disappears.)
4. No persisted revoked flag anywhere — the relay stays the source of truth (a 403 renders as revoked for that action; the pairing itself is untouched until the operator acts).

**B. `errors.test.ts`:** update the 403 expectations to `recovery: 'forget-or-switch'`, and add cases: `classifyRelayError({ code: 'NO_SUCH_PAIRING' })` (status/chip/recovery as above) and the corresponding `describeRelayError` message. Keep every existing case green.

**C. `server-identity.test.ts`** (same vitest style as `errors.test.ts` — `describe`/`it`/`expect`):

```typescript
// Cases to cover (write each out):
// hostOf:
//   - 'https://relay.example'         -> 'relay.example'
//   - 'https://relay.example/'        -> 'relay.example'
//   - 'https://relay.example:8443'    -> 'relay.example:8443' (port retained)
//   - 'http://10.0.0.41:3000/base'    -> '10.0.0.41:3000'
//   - 'not a url'                     -> 'not a url' (falls back to the raw string)
//   - '  spaced  '                    -> 'spaced' (trimmed fallback)
// serverIdentity:
//   - nickname 'staging' -> { nickname: 'staging', host: <host> }
//   - nickname ''        -> nickname falls back to the host
//   - nickname '   '     -> whitespace-only also falls back to the host
```

**Verification:**

`pnpm test` — all suites pass (`errors`, `ipc`, `biometric`, `server-identity`).

**Commit:** `feat(admin-companion): classify NO_SUCH_PAIRING and scope revoked recovery to the pairing`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: `ScreenShell` server-context slot

**Verifies:** admin-multi-server.AC2.2 (structural half: the slot renders nickname + host as text in a fixed position under the title).

**Files:**
- Modify: `apps/admin-companion/src/lib/components/ui/ScreenShell.svelte`

**Implementation:**

Extend the props (`ScreenShell.svelte:8-23`) with two optional entries:

```typescript
  server?: { nickname: string; host: string } | null;
  /** When provided, the server-context block renders as a button (Home uses this to
   * open the inline switcher). Without it, the block is static text (Settings). */
  onservertap?: () => void;
```

Render the block directly after the `<h1 class="title">`:

```svelte
{#if server}
  {#if onservertap}
    <button type="button" class="server server-tappable" onclick={onservertap}>
      <span class="server-nickname">{server.nickname}</span>
      <span class="server-host">{server.host}</span>
      <span class="server-affordance" aria-hidden="true">▾</span>
      <span class="visually-hidden">Switch server</span>
    </button>
  {:else}
    <div class="server">
      <span class="server-nickname">{server.nickname}</span>
      <span class="server-host">{server.host}</span>
    </div>
  {/if}
{/if}
```

Styling (tokens only; follow the file's existing style block conventions):
- `.server` — block layout, nickname and host stacked (position is part of the identity signal), spacing via `var(--space-*)`.
- `.server-nickname` — display/sans type (`var(--font-sans)`), a step below the `h1` scale, high-contrast text token.
- `.server-host` — `var(--font-mono)`, the muted-but-AAA text token the `.prompt` line already uses.
- `.server-tappable` — resets button chrome (background none, border none, inherit text alignment), adds a visible focus style consistent with existing buttons, and the `▾` affordance in the muted token so tappability is signalled by glyph + the hidden "Switch server" text, not color.
- If the codebase has no `.visually-hidden` utility, add the standard clip-rect implementation scoped to this component.

Identity is conveyed by text + position (title → nickname → host, same spot on every screen). Do not use color as the only differentiator anywhere in this block.

**Verification:**

`pnpm test` still green. (`pnpm check` still expected to fail app-wide until Task 7 — the screens still reference the removed `pairingState`.)

**Commit:** `feat(admin-companion): ScreenShell server-context slot (nickname + monospace host)`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `ErrorState` server attribution + revoked CTAs

**Verifies:** admin-multi-server.AC3.4 (rendering half: failures attributed to nickname + host; local unpair offered as fallback), admin-multi-server.AC2.2 (attribution is text + position).

**Files:**
- Modify: `apps/admin-companion/src/lib/components/ui/ErrorState.svelte`

**Implementation:**

Rework the props (`ErrorState.svelte:12-25`):

```typescript
  let {
    view,
    /** The server the failed action targeted. Every classified failure is attributed
     * to a named server so "unreachable" can never be misread against the wrong relay. */
    server = null,
    retrying = false,
    onpair,
    onretry,
    /** recovery === 'forget-or-switch' (revoked) and the unreachable fallback. */
    onforget,
    onswitch,
    /** Offered alongside a retry when the relay is unreachable: local-only forget. */
    onforgetlocally,
  }: {
    view: ErrorView;
    server?: { nickname: string; host: string } | null;
    retrying?: boolean;
    onpair?: () => void;
    onretry?: () => void;
    onforget?: () => void;
    onswitch?: () => void;
    onforgetlocally?: () => void;
  } = $props();
```

Markup changes:
1. **Attribution line** (replaces the old `relayUrl` CodeOutput, which only showed for unreachable): when `server` is provided, render under the StatusChip, before the message — nickname in sans, host in mono, e.g. `<p class="attribution"><span class="attribution-nickname">{server.nickname}</span> <span class="attribution-host">{server.host}</span></p>`. Always shown when provided, for every classification — attribution is not an unreachable-only detail anymore.
2. **Recovery actions:**
   - `view.recovery === 'pair' && onpair` → existing "Pair this device" primary button (unchanged).
   - `view.recovery === 'retry' && onretry` → existing "Retry" secondary button (unchanged); additionally, when `onforgetlocally` is provided, render a destructive "Forget on this device anyway" button beneath it (this is Settings' unreachable fallback, moved into the component so the pairing-retained-plus-local-fallback contract renders consistently).
   - `view.recovery === 'forget-or-switch'` → destructive "Forget this server" button when `onforget` is provided, and secondary "Switch server" button when `onswitch` is provided.
   - `view.recovery === 'none'` → no button (unchanged).

Remove the now-unused `relayUrl` prop and its CodeOutput import if nothing else in the file uses it. Keep all text/type/spacing on tokens; AAA pairs only.

**Verification:**

`pnpm test` still green.

**Commit:** `feat(admin-companion): server-attributed error states with forget/switch recovery`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 5-7) -->

<!-- START_TASK_5 -->
### Task 5: Home — switcher, no-active pick state, attributed reveal

**Verifies:** admin-multi-server.AC2.2 (Home half), admin-multi-server.AC2.5 (UI half: explicit pick required when active is cleared), admin-multi-server.AC3.1 (UI half: "Pair another server…" reachable while paired).

**Files:**
- Modify: `apps/admin-companion/src/routes/+page.svelte`

**Implementation:**

Rework Home around `PairingsState` (the existing per-screen load-on-mount pattern — no global store):

1. **State:** `let state = $state<PairingsState | 'loading' | 'error'>('loading')`; `let switcherOpen = $state(false)`. `reloadPairings()` replaces `reloadPairing()` and calls `listPairings()`. Derived values:
   - `pairings` — the list (empty while loading/error),
   - `activePairing` — `state.pairings.find(p => p.id === state.active) ?? null`,
   - `needsPick` — loaded, `pairings.length > 0`, and `active === null` (the post-removal ambiguous state),
   - `identity` — `activePairing ? serverIdentity(activePairing) : null`.
2. **Loud identity + switcher trigger:** pass `server={identity}` and `onservertap={() => (switcherOpen = !switcherOpen)}` to `ScreenShell`. The identity block under the title IS Home's tappable switcher trigger.
3. **Inline switcher list** (rendered at the top of the body when `switcherOpen || needsPick`; when `needsPick` it cannot be dismissed): one button row per pairing — nickname (sans) + host (mono) stacked; the active row carries a leading `▸` glyph AND the mono text `active` (glyph + text + position, not color). Tapping a row: `await setActivePairing(id)`, then `await reloadPairings()`, close the switcher, and clear any stale `claimCode`/error so the reveal never shows a code minted for a different server next to the new identity. Last row: "Pair another server…" → `goto('/pair')`. Keep the markup local to Home (it is screen layout, not a reusable primitive) and style with tokens.
4. **No-active pick state** (`needsPick`): a `pending` StatusChip with the mono label `pick a server` and the message "Two or more servers remain — choose which one this console acts on." The mint button is not rendered in this state; the forced-open switcher is the only affordance. This is AC2.5's "Home requires an explicit pick".
5. **Unpaired state** (`pairings.length === 0`): keep the existing pending chip + "Pair this device" footer CTA exactly as today.
6. **Mint flow:** unchanged gate (`requireUserPresence`) and `generateClaimCode()` (still zero-arg — the Rust side resolves the active pairing; the UI never passes a server, which is what makes shown-vs-acted-on divergence impossible). The reveal block gains the server identity adjacent to the code: directly above the `CodeOutput`, a line with `{identity.nickname}` (sans) + `{identity.host}` (mono). 
7. **Errors:** `ErrorState` now receives `server={identity}` plus the new CTAs: `onforget={forgetActive}` (calls `unpair(activePairing.id)` then `reloadPairings()`) and `onswitch={() => (switcherOpen = true)}` for the revoked case; `onretry` unchanged. After ANY failed action, `reloadPairings()` so a `NO_SUCH_PAIRING` stale row disappears.

**Verification:**

`pnpm test` green. Manually read the rendered markup paths for the four states (active, needsPick, unpaired, error) — the full type gate lands in Task 8.

**Commit:** `feat(admin-companion): Home server switcher with explicit-pick state and attributed reveal`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Pair — nickname field, reachable while paired

**Verifies:** admin-multi-server.AC3.1 (UI half: reachable while paired; success appends and becomes active).

**Files:**
- Modify: `apps/admin-companion/src/routes/pair/+page.svelte`

**Implementation:**

1. Add `let nickname = $state('')` and a `TextField` for it in the form (label "Nickname", placeholder e.g. `staging`, `mono` to match the terminal register): nicknames are required — on submit, `nickname.trim() === ''` sets the field's `error` ("Give this server a name — it's how you'll tell environments apart.") and blocks the request. Not unique by design: the host is always displayed beneath the nickname elsewhere, so duplicates disambiguate themselves.
2. Pass it through: `pairDevice(relayUrl, pairingCode, label, nickname.trim())`.
3. Reachable while paired: the screen already has no paired-guard (verified) — keep it that way, and keep `onback={() => goto('/')}`. The QR/manual flow, scanning overlay, and success navigation (`goto('/')`) are unchanged — on return, Home reloads `list_pairings()` on mount and the new pairing renders as active (append-becomes-active is the Rust side's contract).
4. The QR payload stays `{"relayUrl","pairingCode"}` — nicknames are the operator's local word for the server and are typed, not encoded into QR codes minted by the relay tooling.

**Verification:**

`pnpm test` green (`ipc.test.ts`'s `parsePairingPayload` cases unchanged and still passing).

**Commit:** `feat(admin-companion): nickname field on Pair; pairing appends while already paired`
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->
### Task 7: Settings — per-server list with rename / unpair / revoke

**Verifies:** admin-multi-server.AC2.2 (Settings half), admin-multi-server.AC3.2 (UI half), admin-multi-server.AC3.4 (flow half: unreachable revoke keeps the pairing and offers local unpair).

**Files:**
- Modify: `apps/admin-companion/src/routes/settings/+page.svelte`

**Implementation:**

1. **Load:** `Promise.allSettled([getOrCreateDeviceKey(), listPairings(), biometricEnabled()])` on mount; keep the existing settled-state handling. Pass `server={activeIdentity}` (derived like Home's, no `onservertap`) to `ScreenShell` — Settings always shows the active identity under its title (AC2.2).
2. **Device panel:** now shows only the global device identity — the admin key `CodeOutput` (read-only) as today. The single relay-URL panel and the per-device label/deviceId rows move into the per-server list (label and device id are per-pairing state now).
3. **"Servers" section:** a panel headed `Servers`, one row per pairing using the existing `DeviceRow` primitive (this is the repurposing the design calls for — its props map cleanly): `label={serverIdentity(p).nickname}`, `deviceId={p.deviceId}`, `lastSeen={serverIdentity(p).host}` (the metadata line renders the host in mono), `status={p.id === active ? 'active' : 'ready'}`, `current={p.id === active}`, `onclick` toggles that row's expanded panel. If `DeviceRow`'s "this device" badge text reads wrong for servers, add an optional `currentLabel` prop to `DeviceRow` (default `'this device'`) and pass `'active'` — do not fork the component.
4. **Expanded per-server panel** (one open at a time; `let expandedId = $state<string | null>(null)`):
   - Rename: a `TextField` seeded with the nickname + a secondary "Save name" button → `renamePairing(id, nickname.trim())` (required, same validation message as Pair) → `reloadPairings()`. Local-only — no network, no biometric gate.
   - `deviceLabel` shown as static mono text (the label that relay knows this device by).
   - Destructive "Revoke on this server" button → biometric gate (`requireUserPresence('Revoke this server pairing')`, existing `presenceAllows` handling) → `revokeSelf(id)` → `reloadPairings()`. On failure: `classifyRelayError`, rendered in an `ErrorState` scoped to that row with `server={serverIdentity(p)}` — and when the classification is unreachable, pass `onforgetlocally={() => forgetLocally(id)}` so the retained-pairing + local-fallback contract renders (AC3.4). The pairing row must still be present after a failed revoke (no local removal on failure — the Rust side guarantees this; the UI just re-lists).
   - Secondary "Forget locally" button (no biometric gate — it signs nothing) → `unpair(id)` → `reloadPairings()`.
5. **Footer:** the old global "Unpair this device" button is removed — unpair/revoke are per-server actions now. The biometric toggle section is unchanged.
6. After any removal, the reloaded state reflects the Rust removal semantics automatically (auto-promoted active or cleared selection); Settings renders whatever `list_pairings()` reports.

**Verification:**

`pnpm test` green.

**Commit:** `feat(admin-companion): per-server Settings list with rename, revoke, and local forget`
<!-- END_TASK_7 -->

<!-- END_SUBCOMPONENT_C -->

<!-- START_TASK_8 -->
### Task 8: `/preview` states + full frontend gate

**Verifies:** Phase exit criteria — `pnpm check` and the unit-test lane green; `/preview` exercises the new states (design "Done when").

**Files:**
- Modify: `apps/admin-companion/src/routes/preview/+page.svelte`

**Implementation:**

1. Pass a `server` example to the preview's own `ScreenShell` (e.g. nickname `staging`, host `staging.ezpds.example`) so the slot is exercised on every preview load; add a second inline example with `onservertap` (no-op or a `console.log`) to show the tappable affordance.
2. Extend the **Error states** section with: a revoked view rendered with `server` attribution + `onforget`/`onswitch` handlers (no-ops), an unreachable view with `onforgetlocally`, and a `NO_SUCH_PAIRING` classification (built through the real `classifyRelayError`, same as the existing examples).
3. Extend the **Device rows** section with a server-list example: two rows styled as the Settings server list (active row `status='active'`/`current` with the `active` badge, second row `ready`).

Then run the full gate:

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c sh -c \
  'cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/apps/admin-companion && pnpm install && pnpm check && pnpm test'
```

Expected: `pnpm check` reports 0 errors (this is the first task where the whole app must type-check — any survivor references to `pairingState`, the old `Pairing.label` field, no-arg `revokeSelf`/`unpair`, or `ErrorState.relayUrl` will surface here; fix them in this task), and all vitest suites pass.

Also re-run the Rust suite once (`phase_01.md` Task 6 Step 1 command) to confirm the frontend phase touched nothing on the Rust side.

**Commit:** `feat(admin-companion): preview coverage for multi-server states`
<!-- END_TASK_8 -->
