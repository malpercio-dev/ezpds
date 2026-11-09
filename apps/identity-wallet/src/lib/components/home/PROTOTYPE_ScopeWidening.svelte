<script lang="ts">
  // PROTOTYPE — throwaway. Three variants of the "more permissions available" affordance on the
  // agent detail screens, switchable via `?variant=A|B|C` or the floating bar (← / → keys).
  // The operator's scope profile is hardcoded below: there is no server route for it yet.
  // The shape question only: how the clamped grant, suspended scopes, the widening
  // affordance, and the consent step read. Approve mutates local state only.
  import { onMount } from 'svelte';
  import { describeScopes, type ScopeDescription } from '$lib/agent-scopes';
  import { authenticateBiometric } from '$lib/biometric';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    scopes,
    noun = 'agent',
    inactive = false,
  }: {
    /** The stored grant. */
    scopes: string[];
    /** "agent" (claimed) or "agent account" (child) — copy only. */
    noun?: string;
    /** Revoked / deleting: show the list, never the affordance. */
    inactive?: boolean;
  } = $props();

  // Fake profile: drops `repo:*?action=delete` (→ suspended) and adds one plain and one
  // elevated scope (→ available), so every row kind is on screen at once.
  const PROFILE = [
    'atproto',
    'repo:*?action=create&action=update',
    'blob:*/*',
    'rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app',
    'account:email',
  ];

  const VARIANTS = [
    { key: 'A', name: 'Ledger' },
    { key: 'B', name: 'Grouped' },
    { key: 'C', name: 'Banner' },
  ];
  let variant = $state('A');

  // eslint-disable-next-line svelte/prefer-writable-derived -- prototype: approve mutates it
  let grant = $state<string[]>([]);
  $effect(() => {
    grant = [...scopes];
  });

  let held = $derived(describeScopes(grant.filter((t) => PROFILE.includes(t))));
  let suspended = $derived(describeScopes(grant.filter((t) => !PROFILE.includes(t))));
  let available = $derived(describeScopes(PROFILE.filter((t) => !grant.includes(t))));
  let showAffordance = $derived(!inactive && available.length > 0);

  let consenting = $state(false);
  let approving = $state(false);
  let justWidened = $state(false);

  async function approve() {
    if (approving) return;
    approving = true;
    try {
      await authenticateBiometric(`Give this ${noun} more permissions`);
    } catch {
      approving = false;
      return;
    }
    // Grant only grows: union, suspended scopes stay stored.
    grant = [...grant, ...PROFILE.filter((t) => !grant.includes(t))];
    approving = false;
    consenting = false;
    justWidened = true;
  }

  function reset() {
    grant = [...scopes];
    consenting = false;
    justWidened = false;
  }

  function setVariant(key: string) {
    variant = key;
    consenting = false;
    const url = new URL(window.location.href);
    url.searchParams.set('variant', key);
    history.replaceState(history.state, '', url);
  }
  function cycle(step: number) {
    const i = VARIANTS.findIndex((v) => v.key === variant);
    setVariant(VARIANTS[(i + step + VARIANTS.length) % VARIANTS.length].key);
  }

  onMount(() => {
    const v = new URLSearchParams(window.location.search).get('variant');
    if (v && VARIANTS.some((x) => x.key === v)) variant = v;
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.closest('input, textarea, [contenteditable]')) return;
      if (e.key === 'ArrowLeft') cycle(-1);
      if (e.key === 'ArrowRight') cycle(1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  let currentName = $derived(VARIANTS.find((v) => v.key === variant)?.name ?? '');
  let isNew = (t: string) => available.some((a) => a.token === t);
</script>

{#snippet warnIcon()}
  <span class="ic ic--warn" aria-hidden="true">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
  </span>
{/snippet}

{#snippet pauseIcon()}
  <span class="ic ic--muted" aria-hidden="true">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M10 9v6M14 9v6"/></svg>
  </span>
{/snippet}

{#snippet plusIcon()}
  <span class="ic ic--accent" aria-hidden="true">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/></svg>
  </span>
{/snippet}

<!-- One scope row. `tag` is the word that carries the row's state (never colour alone). -->
{#snippet row(scope: ScopeDescription, kind: 'held' | 'suspended' | 'available' | 'new')}
  <li
    class="grant grant--{kind}"
    class:grant--elevated={scope.elevated && kind !== 'suspended'}
  >
    <span class="grant-row">
      {#if kind === 'suspended'}{@render pauseIcon()}
      {:else if kind === 'available' || kind === 'new'}{@render plusIcon()}
      {:else if scope.elevated}{@render warnIcon()}{/if}
      <span class="grant-t">
        {scope.summary}
        {#if scope.elevated && kind !== 'suspended'}<em class="warn">(elevated access)</em>{/if}
      </span>
      {#if kind === 'suspended'}<span class="tag tag--muted">Suspended</span>{/if}
      {#if kind === 'available'}<span class="tag tag--accent">Not granted</span>{/if}
      {#if kind === 'new'}<span class="tag tag--accent">New</span>{/if}
    </span>
    {#if scope.elevated && kind === 'new'}
      <span class="grant-row grant-row--sub">{@render warnIcon()}<span class="warn">New and elevated: this reaches your account settings.</span></span>
    {/if}
    <code class="grant-token">{scope.token}</code>
  </li>
{/snippet}

<!-- Shared consent step: the full profile, new scopes marked, one biometric tap. -->
{#snippet consent()}
  <div class="consent" role="group" aria-label="Approve more permissions">
    <p class="consent-h">Give this {noun} everything your server allows?</p>
    <p class="consent-p">
      Your server now allows {available.length} more permission{available.length === 1 ? '' : 's'}.
      This approves the whole set below — you cannot pick some. It can be undone only by revoking
      the {noun}.
    </p>
    <ul class="grants u-list-reset">
      {#each describeScopes(PROFILE) as scope (scope.token)}
        {@render row(scope, isNew(scope.token) ? 'new' : 'held')}
      {/each}
    </ul>
    {#if suspended.length}
      <p class="consent-foot">
        {suspended.length} suspended permission{suspended.length === 1 ? ' stays' : 's stay'} suspended. Approving does not bring
        {suspended.length === 1 ? 'it' : 'them'} back.
      </p>
    {/if}
    <Button onclick={approve} disabled={approving}>
      {#if approving}<Spinner size={16} /> Approving…{:else}Approve with biometrics{/if}
    </Button>
    <Button variant="secondary" onclick={() => (consenting = false)} disabled={approving}>
      Not now
    </Button>
  </div>
{/snippet}

{#snippet suspendedExplainer()}
  <p class="sub">
    Your server no longer allows {suspended.length === 1 ? 'this' : 'these'}. The {noun} cannot use
    {suspended.length === 1 ? 'it' : 'them'} now; if the server allows {suspended.length === 1 ? 'it' : 'them'} again,
    {suspended.length === 1 ? 'it comes' : 'they come'} back without asking you.
  </p>
{/snippet}

{#if justWidened}
  <p class="done" role="status">Permissions updated. The {noun} has everything your server allows.</p>
{/if}

<!-- ───────────── Variant A: one ledger, every row tagged ───────────── -->
{#if variant === 'A'}
  <p class="label">Permissions</p>
  <ul class="grants u-list-reset">
    {#each held as s (s.token)}{@render row(s, 'held')}{/each}
    {#each suspended as s (s.token)}{@render row(s, 'suspended')}{/each}
    {#if showAffordance}
      {#each available as s (s.token)}{@render row(s, 'available')}{/each}
    {/if}
  </ul>
  {#if showAffordance}
    {#if consenting}
      {@render consent()}
    {:else}
      <Button variant="secondary" onclick={() => (consenting = true)}>
        Review {available.length} more permission{available.length === 1 ? '' : 's'}
      </Button>
    {/if}
  {/if}

<!-- ───────────── Variant B: grouped sections ───────────── -->
{:else if variant === 'B'}
  <p class="label">Can do now</p>
  <ul class="grants u-list-reset">
    {#each held as s (s.token)}{@render row(s, 'held')}{/each}
  </ul>
  {#if suspended.length}
    <p class="label">Suspended by your server</p>
    {@render suspendedExplainer()}
    <ul class="grants u-list-reset">
      {#each suspended as s (s.token)}{@render row(s, 'suspended')}{/each}
    </ul>
  {/if}
  {#if showAffordance}
    {#if consenting}
      {@render consent()}
    {:else}
      <div class="card">
        <p class="card-h">{@render plusIcon()} Your server allows more</p>
        <ul class="plain u-list-reset">
          {#each available as s (s.token)}
            <li>{s.summary}{#if s.elevated}{' '}<em class="warn">(elevated access)</em>{/if}</li>
          {/each}
        </ul>
        <Button onclick={() => (consenting = true)}>Review and approve</Button>
      </div>
    {/if}
  {/if}

<!-- ───────────── Variant C: banner first, clean list ───────────── -->
{:else}
  {#if showAffordance}
    {#if consenting}
      {@render consent()}
    {:else}
      <button class="banner" onclick={() => (consenting = true)}>
        {@render plusIcon()}
        <span class="banner-body">
          <span class="banner-t">More permissions available</span>
          <span class="banner-s">Your server allows {available.length} more. Tap to review.</span>
        </span>
        <span class="chev" aria-hidden="true">›</span>
      </button>
    {/if}
  {/if}
  <p class="label">Permissions</p>
  <ul class="grants u-list-reset">
    {#each held as s (s.token)}{@render row(s, 'held')}{/each}
  </ul>
  {#if suspended.length}
    <details class="disclosure">
      <summary>{@render pauseIcon()} {suspended.length} suspended</summary>
      {@render suspendedExplainer()}
      <ul class="grants u-list-reset">
        {#each suspended as s (s.token)}{@render row(s, 'suspended')}{/each}
      </ul>
    </details>
  {/if}
{/if}

{#if import.meta.env.DEV}
  <div class="proto-bar" role="toolbar" aria-label="Prototype variant switcher">
    <button onclick={() => cycle(-1)} aria-label="Previous variant">←</button>
    <span>{variant} ({currentName})</span>
    <button onclick={() => cycle(1)} aria-label="Next variant">→</button>
    <button onclick={reset}>reset</button>
  </div>
{/if}

<style>
  .label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: var(--space-xs) 0 0;
  }
  .sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.45;
  }
  .grants {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .grant {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-md);
  }
  .grant--elevated {
    border-color: var(--color-warning);
    background: var(--color-warning-surface);
  }
  .grant--suspended {
    background: var(--color-surface-sunk);
    border-style: dashed;
  }
  .grant--suspended .grant-t {
    color: var(--color-muted);
    text-decoration: line-through;
  }
  .grant--available {
    border-style: dashed;
    border-color: var(--color-accent);
  }
  .grant-row {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
  }
  .grant-row--sub {
    font-size: var(--text-label);
  }
  .grant-t {
    flex: 1;
    font-size: var(--text-body);
    color: var(--color-ink);
  }
  .grant-token {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    overflow-wrap: anywhere;
  }
  .ic {
    flex-shrink: 0;
    margin-top: var(--space-3xs);
    display: inline-flex;
  }
  .ic--warn { color: var(--color-warning); }
  .ic--muted { color: var(--color-muted); }
  .ic--accent { color: var(--color-accent); }
  .warn {
    font-style: normal;
    font-weight: var(--weight-semibold);
    color: var(--color-warning);
  }
  .tag {
    flex-shrink: 0;
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    border-radius: var(--radius-sm);
    padding: var(--space-3xs) var(--space-xs);
  }
  .tag--muted { background: var(--color-surface-sunk); color: var(--color-muted); border: 1px solid var(--color-line); }
  .tag--accent { background: var(--color-bg); color: var(--color-accent); border: 1px solid var(--color-accent); }

  .consent {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .consent-h {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .consent-p, .consent-foot {
    font-size: var(--text-body);
    color: var(--color-ink);
    margin: 0;
    line-height: 1.5;
  }
  .consent-foot { color: var(--color-muted); font-size: var(--text-label); }

  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .card-h {
    display: flex;
    gap: var(--space-sm);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .plain {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    font-size: var(--text-body);
    color: var(--color-ink);
  }

  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    min-height: var(--size-tap, 44px); /* px-ok: prototype */
    text-align: left;
    background: var(--color-surface);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    cursor: pointer;
    color: var(--color-ink);
  }
  .banner-body { display: flex; flex-direction: column; gap: var(--space-3xs); flex: 1; }
  .banner-t { font-weight: var(--weight-semibold); }
  .banner-s { font-size: var(--text-label); color: var(--color-muted); }
  .chev { color: var(--color-muted); font-size: var(--text-title); }

  .disclosure summary {
    display: flex;
    gap: var(--space-sm);
    align-items: center;
    cursor: pointer;
    font-size: var(--text-label);
    color: var(--color-muted);
    padding: var(--space-xs) 0;
  }
  .disclosure[open] { display: flex; flex-direction: column; gap: var(--space-sm); }

  .done {
    margin: 0;
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--radius-lg);
    background: var(--color-safe-surface);
    color: var(--color-safe);
    font-size: var(--text-label);
  }

  .proto-bar {
    position: fixed;
    bottom: var(--space-md);
    left: 50%;
    transform: translateX(-50%);
    z-index: 999;
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    background: black;
    color: yellow;
    font-family: var(--font-mono);
    font-size: var(--text-label);
    padding: var(--space-xs) var(--space-md);
    border-radius: var(--radius-full);
    box-shadow: 0 2px 12px rgb(0 0 0 / 0.4); /* px-ok: prototype */
  }
  .proto-bar span { white-space: nowrap; }
  .proto-bar button {
    background: none;
    border: 1px solid yellow;
    color: yellow;
    border-radius: var(--radius-sm);
    padding: var(--space-3xs) var(--space-sm);
    cursor: pointer;
  }
</style>
