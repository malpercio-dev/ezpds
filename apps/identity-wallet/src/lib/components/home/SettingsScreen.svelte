<script lang="ts">
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import {
    readLocalMirror,
    setAppearance,
    type AppearancePreference,
  } from '$lib/appearance';
  import { exportDiagnostics, shareTextNative } from '$lib/ipc';

  let { onback }: { onback: () => void } = $props();

  // initAppearance() reconciled the mirror against the Keychain at launch,
  // so the mirror is authoritative by the time this screen opens.
  let selected = $state<AppearancePreference>(readLocalMirror());
  let saveError = $state(false);

  const OPTIONS: { value: AppearancePreference; label: string }[] = [
    { value: 'system', label: 'System' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
  ];

  let segmentEls: (HTMLButtonElement | undefined)[] = Array.from(
    { length: OPTIONS.length },
    () => undefined
  );

  async function choose(preference: AppearancePreference) {
    selected = preference;
    saveError = false;
    try {
      // Applies instantly (inline color-scheme + localStorage mirror);
      // the awaited part is only the durable Keychain write.
      await setAppearance(preference);
    } catch (e) {
      console.error('Failed to persist appearance preference:', e);
      saveError = true;
    }
  }

  // ── Diagnostics export ──────────────────────────────────────────────────
  // A user-initiated share of the session's redacted network-error log. The report is
  // built on the Rust side (operation names, server hosts, HTTP statuses, short error
  // codes only — no tokens, bodies, handles, or DIDs) and handed to the native share
  // sheet. Nothing is collected passively, so there is no opt-in toggle to manage.
  let exportBusy = $state(false);
  let exportError = $state(false);

  async function shareDiagnostics() {
    exportBusy = true;
    exportError = false;
    try {
      const report = await exportDiagnostics();
      await shareTextNative(report);
    } catch (e) {
      console.error('Failed to export diagnostics:', e);
      exportError = true;
    } finally {
      exportBusy = false;
    }
  }

  /** Radiogroup keyboard pattern: arrows move selection, focus follows. */
  function onSegmentKeydown(event: KeyboardEvent, index: number) {
    let next: number;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      next = (index + 1) % OPTIONS.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      next = (index - 1 + OPTIONS.length) % OPTIONS.length;
    } else {
      return;
    }
    event.preventDefault();
    segmentEls[next]?.focus();
    choose(OPTIONS[next].value);
  }
</script>

<div class="screen">
  <ScreenHeader title="Settings" {onback} />

  <section class="group" aria-labelledby="appearance-title">
    <div class="group-head">
      <h2 class="group-title" id="appearance-title">Appearance</h2>
      <p class="group-sub">System follows your iPhone’s appearance setting.</p>
    </div>

    <div class="segmented" role="radiogroup" aria-labelledby="appearance-title">
      {#each OPTIONS as opt, i (opt.value)}
        <button
          bind:this={segmentEls[i]}
          class="segment"
          class:segment--selected={selected === opt.value}
          role="radio"
          aria-checked={selected === opt.value}
          tabindex={selected === opt.value ? 0 : -1}
          onclick={() => choose(opt.value)}
          onkeydown={(e) => onSegmentKeydown(e, i)}
        >
          {#if selected === opt.value}
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2.6"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <path d="m5 12 5 5L20 7" />
            </svg>
          {/if}
          {opt.label}
        </button>
      {/each}
    </div>

    {#if saveError}
      <p class="save-error" role="alert">
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </svg>
        Couldn’t save this choice to your device. It applies now, but may not stick after a
        relaunch.
      </p>
    {/if}
  </section>

  <section class="group" aria-labelledby="diagnostics-title">
    <div class="group-head">
      <h2 class="group-title" id="diagnostics-title">Diagnostics</h2>
      <p class="group-sub">
        Share a log of this session’s network errors when troubleshooting. It lists operation
        names, server addresses, and error codes only — never your keys, tokens, or account
        details.
      </p>
    </div>

    <Button variant="secondary" disabled={exportBusy} onclick={shareDiagnostics}>
      {exportBusy ? 'Preparing…' : 'Export diagnostics'}
    </Button>

    {#if exportError}
      <p class="save-error" role="alert">
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </svg>
        Couldn’t open the share sheet just now. Please try again.
      </p>
    {/if}
  </section>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }

  /* One parchment group, flat at rest — depth is a tonal step and a hairline. */
  .group {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md) var(--space-md) var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
  .group-head {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .group-title {
    font-family: var(--font-sans);
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .group-sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }

  .segmented {
    display: flex;
    gap: var(--space-2xs);
    background: var(--color-surface-sunk);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-2xs);
  }
  .segment {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: var(--size-tap-target);
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    cursor: pointer;
    transition:
      background var(--duration-base) var(--ease-standard),
      color var(--duration-base) var(--ease-standard);
  }
  .segment:active {
    background: var(--color-seal-tint);
  }
  /* Selection is check glyph + label weight + position + the pale-seal ground
     (which takes ink text at AAA in both appearances) — never color alone. */
  .segment--selected {
    background: var(--color-seal-pale);
    color: var(--color-ink);
    font-weight: var(--weight-semibold);
  }

  .save-error {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    font-size: var(--text-label);
    line-height: var(--leading-label);
    color: var(--color-critical);
    margin: 0;
  }
  .save-error svg {
    flex-shrink: 0;
    margin-top: 1px;
  }
</style>
